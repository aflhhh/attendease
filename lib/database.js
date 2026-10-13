'use strict';

const { MongoClient } = require('mongodb');
const { normalizeText, normalizeKey } = require('./domain');

const DEFAULT_DB = 'attendanceDB';
const CACHE_KEY = '__attendEaseV6Mongo';

async function getDatabase() {
  const uri = process.env.MONGODB_URI || (process.env.NODE_ENV === 'production' ? '' : 'mongodb://127.0.0.1:27017');
  if (!uri) throw new Error('MONGODB_URI is required. Configure MongoDB Atlas before deploying.');
  let cache = global[CACHE_KEY];
  if (!cache) cache = global[CACHE_KEY] = { client: null, connectPromise: null, initPromise: null, db: null };
  if (!cache.connectPromise) {
    const client = new MongoClient(uri, {
      maxPoolSize: Number(process.env.MONGO_MAX_POOL_SIZE) || 10,
      minPoolSize: 0,
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
      maxIdleTimeMS: 45000
    });
    cache.client = client;
    cache.connectPromise = client.connect().then(() => {
      cache.db = client.db(process.env.DB_NAME || DEFAULT_DB);
      return cache.db;
    }).catch(error => {
      cache.connectPromise = null;
      cache.db = null;
      throw error;
    });
  }
  const db = await cache.connectPromise;
  if (!cache.initPromise) {
    cache.initPromise = initializeDatabase(db).catch(error => {
      cache.initPromise = null;
      throw error;
    });
  }
  await cache.initPromise;
  return db;
}

async function initializeDatabase(db) {
  const users = db.collection('users');
  const students = db.collection('students');
  const classes = db.collection('classes');
  const academicYears = db.collection('academicYears');
  const subjects = db.collection('subjects');
  const calendar = db.collection('calendarEvents');
  const timetable = db.collection('timetable');
  const sessions = db.collection('sessions');
  const attendance = db.collection('attendance');

  // Bring v5 students forward without deleting existing data.
  const studentCursor = students.find({});
  for await (const student of studentCursor) {
    const set = {};
    const cls = normalizeText(student.cls || student.className || 'Unassigned');
    const roll = normalizeText(student.roll || '');
    if (!student.cls && student.className) set.cls = cls;
    if (!student.cls && !student.className) set.cls = cls;
    if (!student.rollNorm) set.rollNorm = normalizeKey(roll);
    if (!student.classNameNorm) set.classNameNorm = normalizeKey(cls);
    if (student.active === undefined) set.active = true;
    if (!student.createdAt) set.createdAt = new Date();
    if (!student.updatedAt) set.updatedAt = new Date();
    if (Object.keys(set).length) await students.updateOne({ _id: student._id }, { $set: set });
  }

  // Seed class records for existing v5 student class labels.
  const classCursor = students.aggregate([
    { $match: { active: true } },
    { $group: { _id: '$cls' } }
  ]);
  for await (const row of classCursor) {
    const name = normalizeText(row._id || 'Unassigned');
    const nameNorm = normalizeKey(name);
    if (!nameNorm) continue;
    await classes.updateOne(
      { nameNorm },
      { $setOnInsert: { name, nameNorm, academicYearId: null, archived: false, createdAt: new Date(), updatedAt: new Date(), migratedFromV5: true } },
      { upsert: true }
    );
  }

  // Migrate the v5 date/student attendance shape into session-based attendance.
  // A partial historic day stays a draft so it cannot inflate report denominators.
  const legacyCursor = attendance.find({ sessionId: { $exists: false }, date: { $type: 'string' }, studentId: { $exists: true } });
  for await (const mark of legacyCursor) {
    const student = await students.findOne({ _id: mark.studentId });
    const className = normalizeText(student?.cls || 'Unassigned');
    const date = mark.date;
    const sessionKey = `legacy|${date}|${normalizeKey(className)}`;
    await sessions.updateOne(
      { sessionKey },
      { $setOnInsert: {
        sessionKey, date, className, classNameNorm: normalizeKey(className), name: 'Imported daily attendance',
        subjectId: null, subjectName: null, status: 'draft', legacy: true,
        createdAt: new Date(), updatedAt: new Date(), createdBy: null
      } },
      { upsert: true }
    );
    const session = await sessions.findOne({ sessionKey });
    await attendance.updateOne({ _id: mark._id }, { $set: { sessionId: session._id, updatedAt: mark.updatedAt || new Date(), migratedFromV5: true } });
  }

  // Finalize migrated historic sessions only when every active student has a mark.
  const legacySessions = sessions.find({ legacy: true, status: 'draft' });
  for await (const session of legacySessions) {
    const expected = await students.countDocuments({ active: true, classNameNorm: session.classNameNorm });
    const recorded = await attendance.countDocuments({ sessionId: session._id });
    if (expected > 0 && recorded >= expected) {
      await sessions.updateOne({ _id: session._id }, { $set: { status: 'finalized', finalizedAt: new Date(), updatedAt: new Date(), finalizedBy: null } });
    }
  }

  // Drop the v5 unique date/student index after the records have been migrated.
  const oldIndexes = await attendance.indexes().catch(() => []);
  for (const index of oldIndexes) {
    if (index.unique && index.key?.date === 1 && index.key?.studentId === 1 && index.key?.sessionId === undefined) {
      await attendance.dropIndex(index.name).catch(() => {});
    }
  }

  await users.createIndex({ email: 1 }, { unique: true, name: 'users_email_unique' });
  await users.createIndex({ initialAdmin: 1 }, { unique: true, partialFilterExpression: { initialAdmin: true }, name: 'single_initial_admin_unique' });
  await students.createIndex({ classNameNorm: 1, rollNorm: 1 }, { unique: true, partialFilterExpression: { active: true }, name: 'active_student_roll_class_unique' });
  await students.createIndex({ cls: 1, active: 1, rollNorm: 1 }, { name: 'students_class_active_roll' });
  await classes.createIndex({ nameNorm: 1 }, { unique: true, name: 'class_name_unique' });
  await academicYears.createIndex({ nameNorm: 1 }, { unique: true, name: 'academic_year_name_unique' });
  await subjects.createIndex({ codeNorm: 1, academicYearKey: 1 }, { unique: true, name: 'subject_code_year_unique' });
  await calendar.createIndex({ date: 1, archived: 1, type: 1 }, { name: 'calendar_date_archived_type' });
  await timetable.createIndex({ classNameNorm: 1, dayOfWeek: 1, startTime: 1 }, { name: 'timetable_class_day_start' });
  await sessions.createIndex({ sessionKey: 1 }, { unique: true, name: 'session_key_unique' });
  await sessions.createIndex({ date: -1, classNameNorm: 1, status: 1 }, { name: 'sessions_date_class_status' });
  await attendance.createIndex({ sessionId: 1, studentId: 1 }, { unique: true, name: 'attendance_session_student_unique' });
  await attendance.createIndex({ studentId: 1, updatedAt: -1 }, { name: 'attendance_student_history' });
  await db.collection('auditLogs').createIndex({ createdAt: -1 }, { name: 'audit_created_desc' });
}

module.exports = { getDatabase };
