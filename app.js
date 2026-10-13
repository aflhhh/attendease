'use strict';
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const { ObjectId } = require('mongodb');
const path = require('path');
const crypto = require('crypto');
const { getDatabase } = require('./lib/database');
const { normalizeText, normalizeKey, validDate, validEmail, validStatus, summarizeMarks, safeUser, canAccessClass } = require('./lib/domain');

const app = express();
const PUBLIC_DIR = path.join(__dirname, 'public');
const IS_PROD = process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL);
const COOKIE_NAME = 'attendease_session';
const SESSION_MS = 8 * 60 * 60 * 1000;
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], fontSrc: ["'self'", 'data:'], objectSrc: ["'none'"],
      baseUri: ["'self'"], frameAncestors: ["'none'"]
    }
  }, crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
if (!process.env.VERCEL) app.use(express.static(PUBLIC_DIR, { index: 'index.html', maxAge: '1h' }));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many requests. Try again shortly.' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many login attempts. Try again in 15 minutes.' } });
const setupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Setup attempts are temporarily limited.' } });
app.use('/api', apiLimiter);

function jwtSecret() {
  const value = process.env.SESSION_SECRET;
  if (!value || value.length < 40 || value.startsWith('replace-with-')) {
    throw Object.assign(new Error('SESSION_SECRET is not configured. Set a random secret of at least 40 characters.'), { status: 503 });
  }
  return value;
}
function newId(value) { return typeof value === 'string' && /^[a-f\d]{24}$/i.test(value); }
function asObjectId(value) { return new ObjectId(value); }
function now() { return new Date(); }
function dateToday() { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; }
function cookieOptions() { return { httpOnly: true, secure: IS_PROD, sameSite: 'strict', path: '/', maxAge: SESSION_MS }; }
function clearCookie(res) { res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', path: '/' }); }
function sendError(res, status, message) { return res.status(status).json({ error: message }); }
function makeSessionToken(user) {
  return jwt.sign({ sub: String(user._id), ver: user.tokenVersion || 0 }, jwtSecret(), { expiresIn: '8h', issuer: 'attendease', audience: 'attendease-web' });
}
function userFromReq(req) { return req.user || null; }
function requireAuth(req, res, next) { if (!req.user) return sendError(res, 401, 'Please sign in to continue.'); next(); }
function requireRole(...roles) { return (req, res, next) => { if (!req.user) return sendError(res, 401, 'Please sign in to continue.'); if (!roles.includes(req.user.role)) return sendError(res, 403, 'You do not have permission to perform this action.'); next(); }; }
function canWrite(user) { return ['admin', 'teacher'].includes(user?.role); }
function requireClass(req, res, className) { if (!canAccessClass(req.user, className)) { sendError(res, 403, 'You do not have access to this class.'); return false; } return true; }
function safeRegex(value) { return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function studentInput(body) {
  if (!body || typeof body !== 'object') return { error: 'Student details are required.' };
  const roll = normalizeText(body.roll), name = normalizeText(body.name), cls = normalizeText(body.cls || body.className), email = normalizeText(body.email || '');
  if (!roll || !name || !cls) return { error: 'Roll number, full name and class are required.' };
  if ([roll, name, cls].some(v => v.length > 120)) return { error: 'Roll number, name and class must be 120 characters or fewer.' };
  if (!validEmail(email)) return { error: 'Enter a valid email address.' };
  return { value: { roll, rollNorm: normalizeKey(roll), name, cls, classNameNorm: normalizeKey(cls), email: email.toLowerCase(), updatedAt: now() } };
}
function classInput(body) {
  const name = normalizeText(body?.name);
  if (!name || name.length > 100) return { error: 'Class name is required and must be 100 characters or fewer.' };
  return { value: { name, nameNorm: normalizeKey(name), academicYearId: newId(body.academicYearId) ? asObjectId(body.academicYearId) : null, updatedAt: now() } };
}
function audit(db, req, action, entity, entityId, details = {}) {
  return db.collection('auditLogs').insertOne({
    action, entity, entityId: entityId ? String(entityId) : null,
    actorId: req.user?._id || null, actorName: req.user?.name || 'System', actorEmail: req.user?.email || null,
    role: req.user?.role || 'system', details, ip: String(req.ip || '').slice(0, 80),
   userAgent: String(req.headers?.['user-agent'] || '').slice(0, 250), createdAt: now()
  }).catch(err => console.error('Audit write failed:', err.message));
}
async function findUser(db, id) {
  if (!newId(String(id))) return null;
  return db.collection('users').findOne({ _id: asObjectId(String(id)) });
}
async function emailTransport() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASSWORD || !process.env.EMAIL_FROM) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
  });
}
function escapeCsv(value) {
  let text = String(value ?? '');
  // Prefix formula-leading text so spreadsheet software does not execute user-supplied cells.
  if (/^[\s]*[=+@\-]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}
function csvResponse(res, filename, header, rows) {
  const content = [header, ...rows].map(row => row.map(escapeCsv).join(',')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  return res.send('\ufeff' + content);
}

// Reject cross-origin browser mutations. HttpOnly, SameSite=Strict cookies provide an additional CSRF barrier.
app.use('/api', (req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (!origin) return IS_PROD ? sendError(res, 403, 'A same-origin request is required.') : next();
  try {
    const originHost = new URL(origin).host;
    const requestHost = req.get('x-forwarded-host') || req.get('host');
    if (originHost !== requestHost) return sendError(res, 403, 'Cross-origin request blocked.');
  } catch { return sendError(res, 403, 'Invalid request origin.'); }
  next();
});

app.use('/api', async (req, res, next) => {
  try {
    req.db = await getDatabase();
    req.c = {
      users: req.db.collection('users'), students: req.db.collection('students'), classes: req.db.collection('classes'),
      academicYears: req.db.collection('academicYears'), subjects: req.db.collection('subjects'), calendar: req.db.collection('calendarEvents'), timetable: req.db.collection('timetable'), sessions: req.db.collection('sessions'),
      attendance: req.db.collection('attendance'), audit: req.db.collection('auditLogs'), settings: req.db.collection('settings')
    };
    const token = req.cookies[COOKIE_NAME];
    if (token) {
      try {
        const claims = jwt.verify(token, jwtSecret(), { issuer: 'attendease', audience: 'attendease-web' });
        const user = await req.c.users.findOne({ _id: asObjectId(claims.sub), active: { $ne: false } });
        if (user && (user.tokenVersion || 0) === (claims.ver || 0)) req.user = user;
      } catch (err) {
        if (err.status === 503) throw err;
        // Invalid/expired cookie is treated as signed out, not as a server error.
      }
    }
    next();
  } catch (err) { next(err); }
});

app.get('/api/health', async (req, res) => {
  try {
    await req.db.command({ ping: 1 });
    res.json({ status: 'ok', database: req.db.databaseName, timestamp: now().toISOString(), mailConfigured: Boolean(process.env.SMTP_HOST && process.env.EMAIL_FROM) });
  } catch { sendError(res, 503, 'Database unavailable. Check MONGODB_URI and Atlas network access.'); }
});

app.get('/api/setup/status', async (req, res) => {
  const count = await req.c.users.countDocuments({});
  res.json({ setupRequired: count === 0, setupTokenConfigured: Boolean(process.env.SETUP_SECRET && process.env.SETUP_SECRET.length >= 40 && !process.env.SETUP_SECRET.startsWith('replace-with-')) });
});
app.post('/api/setup', setupLimiter, async (req, res) => {
  const count = await req.c.users.countDocuments({});
  if (count > 0) return sendError(res, 409, 'Initial setup has already been completed. Sign in instead.');
  if (!process.env.SETUP_SECRET || process.env.SETUP_SECRET.length < 40 || process.env.SETUP_SECRET.startsWith('replace-with-')) return sendError(res, 503, 'SETUP_SECRET is not configured securely on the server.');
  const secret = String(req.body?.setupSecret || '');
  const configured = String(process.env.SETUP_SECRET);
  const a = Buffer.from(secret), b = Buffer.from(configured);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return sendError(res, 403, 'Setup key is incorrect.');
  const name = normalizeText(req.body?.name), email = normalizeText(req.body?.email).toLowerCase(), password = String(req.body?.password || '');
  if (!name || name.length > 100 || !validEmail(email) || !email || password.length < 12 || password.length > 128) return sendError(res, 400, 'Enter a name, valid email and password of 12–128 characters.');
  const createdAt = now();
  const user = { name, email, passwordHash: await bcrypt.hash(password, 12), role: 'admin', classNames: [], active: true, initialAdmin: true, tokenVersion: 0, createdAt, updatedAt: createdAt, lastLoginAt: createdAt };
  try {
    const result = await req.c.users.insertOne(user);
    user._id = result.insertedId;
  } catch (err) {
    if (err.code === 11000) return sendError(res, 409, 'Setup has already been completed.');
    throw err;
  }
  res.cookie(COOKIE_NAME, makeSessionToken(user), cookieOptions());
  await audit(req.db, { ...req, user }, 'setup.completed', 'user', user._id, { role: 'admin' });
  res.status(201).json({ user: safeUser(user) });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const email = normalizeText(req.body?.email).toLowerCase(), password = String(req.body?.password || '');
  if (!email || !password) return sendError(res, 400, 'Email and password are required.');
  const user = await req.c.users.findOne({ email, active: { $ne: false } });
  const matches = user ? await bcrypt.compare(password, user.passwordHash) : await bcrypt.compare(password, '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6A9qhrdM7J8zA0z9M7mGgVpf4p1G2');
  if (!user || !matches) return sendError(res, 401, 'Email or password is incorrect.');
  user.lastLoginAt = now();
  await req.c.users.updateOne({ _id: user._id }, { $set: { lastLoginAt: user.lastLoginAt } });
  res.cookie(COOKIE_NAME, makeSessionToken(user), cookieOptions());
  await audit(req.db, { ...req, user }, 'auth.login', 'user', user._id, {});
  res.json({ user: safeUser(user) });
});
app.post('/api/auth/logout', async (req, res) => {
  if (req.user) await audit(req.db, req, 'auth.logout', 'user', req.user._id, {});
  clearCookie(res); res.json({ message: 'Signed out.' });
});
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: safeUser(req.user) }));
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const currentPassword = String(req.body?.currentPassword || ''), newPassword = String(req.body?.newPassword || '');
  if (newPassword.length < 12 || newPassword.length > 128) return sendError(res, 400, 'New password must be 12–128 characters.');
  if (!await bcrypt.compare(currentPassword, req.user.passwordHash)) return sendError(res, 400, 'Current password is incorrect.');
  const hash = await bcrypt.hash(newPassword, 12), tokenVersion = (req.user.tokenVersion || 0) + 1;
  await req.c.users.updateOne({ _id: req.user._id }, { $set: { passwordHash: hash, tokenVersion, updatedAt: now() } });
  const updated = { ...req.user, tokenVersion };
  res.cookie(COOKIE_NAME, makeSessionToken(updated), cookieOptions());
  await audit(req.db, req, 'auth.password_changed', 'user', req.user._id, {});
  res.json({ message: 'Password changed.' });
});

// Users and role assignment.
app.get('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const users = await req.c.users.find({}, { projection: { passwordHash: 0 } }).sort({ createdAt: -1 }).limit(500).toArray();
  res.json({ items: users.map(safeUser) });
});
app.post('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const name = normalizeText(req.body?.name), email = normalizeText(req.body?.email).toLowerCase();
  const password = String(req.body?.password || ''), role = req.body?.role;
  const classNames = Array.isArray(req.body?.classNames) ? [...new Set(req.body.classNames.map(normalizeText).filter(Boolean))] : [];
  if (!name || name.length > 100 || !email || !validEmail(email)) return sendError(res, 400, 'Enter a valid name and email.');
  if (!['admin', 'teacher', 'viewer'].includes(role)) return sendError(res, 400, 'Role must be admin, teacher or viewer.');
  if (password.length < 12 || password.length > 128) return sendError(res, 400, 'Temporary password must be 12–128 characters.');
  if (role === 'admin' && classNames.length) return sendError(res, 400, 'Administrators do not need class assignments.');
  if (role !== 'admin' && classNames.length === 0) return sendError(res, 400, 'Assign at least one class to teachers and viewers.');
  const known = new Set((await req.c.classes.find({ archived: { $ne: true } }).toArray()).map(c => normalizeKey(c.name)));
  if (classNames.some(c => !known.has(normalizeKey(c)))) return sendError(res, 400, 'One or more assigned classes do not exist.');
  const createdAt = now(), user = { name, email, passwordHash: await bcrypt.hash(password, 12), role, classNames, active: true, tokenVersion: 0, createdAt, updatedAt: createdAt };
  try { const result = await req.c.users.insertOne(user); user._id = result.insertedId; }
  catch (err) { if (err.code === 11000) return sendError(res, 409, 'An account with that email already exists.'); throw err; }
  await audit(req.db, req, 'user.created', 'user', user._id, { role, classNames });
  res.status(201).json({ user: safeUser(user) });
});
app.patch('/api/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid user ID.');
  const targetId = asObjectId(req.params.id), target = await req.c.users.findOne({ _id: targetId });
  if (!target) return sendError(res, 404, 'User not found.');
  const changes = {};
  if (req.body?.name !== undefined) { const name = normalizeText(req.body.name); if (!name || name.length > 100) return sendError(res, 400, 'Enter a valid name.'); changes.name = name; }
  if (req.body?.role !== undefined) { if (!['admin', 'teacher', 'viewer'].includes(req.body.role)) return sendError(res, 400, 'Invalid role.'); changes.role = req.body.role; }
  if (req.body?.classNames !== undefined) {
    if (!Array.isArray(req.body.classNames)) return sendError(res, 400, 'Class assignments must be a list.');
    changes.classNames = [...new Set(req.body.classNames.map(normalizeText).filter(Boolean))];
    const known = new Set((await req.c.classes.find({ archived: { $ne: true } }).toArray()).map(c => normalizeKey(c.name)));
    if (changes.classNames.some(c => !known.has(normalizeKey(c)))) return sendError(res, 400, 'One or more assigned classes do not exist.');
    if ((changes.role || target.role) !== 'admin' && changes.classNames.length === 0) return sendError(res, 400, 'Assign at least one class to teachers and viewers.');
  }
  const resultingRole = changes.role || target.role;
  const resultingClasses = changes.classNames !== undefined ? changes.classNames : (target.classNames || []);
  if (resultingRole !== 'admin' && resultingClasses.length === 0) return sendError(res, 400, 'Assign at least one active class to every teacher and viewer.');
  if (req.body?.active !== undefined) {
    if (typeof req.body.active !== 'boolean') return sendError(res, 400, 'Active must be true or false.');
    if (String(target._id) === String(req.user._id) && req.body.active === false) return sendError(res, 400, 'You cannot deactivate your own account.');
    changes.active = req.body.active;
  }
  if (target.role === 'admin' && changes.active === false && await req.c.users.countDocuments({ role: 'admin', active: true }) <= 1) return sendError(res, 400, 'At least one active administrator must remain.');
  if (changes.role && target.role === 'admin' && changes.role !== 'admin' && await req.c.users.countDocuments({ role: 'admin', active: true }) <= 1) return sendError(res, 400, 'At least one active administrator must remain.');
  if (changes.role !== undefined && changes.role !== target.role || changes.active === false || changes.active === true) changes.tokenVersion = (target.tokenVersion || 0) + 1;
  changes.updatedAt = now();
  await req.c.users.updateOne({ _id: targetId }, { $set: changes });
  await audit(req.db, req, 'user.updated', 'user', targetId, { changedFields: Object.keys(changes).filter(k => k !== 'tokenVersion') });
  res.json({ user: safeUser({ ...target, ...changes }) });
});

// Classes, academic years and subjects.
app.get('/api/academic-years', requireAuth, async (req, res) => {
  res.json({ items: await req.c.academicYears.find({}).sort({ startDate: -1 }).limit(100).toArray() });
});
app.post('/api/academic-years', requireAuth, requireRole('admin'), async (req, res) => {
  const name = normalizeText(req.body?.name), startDate = req.body?.startDate, endDate = req.body?.endDate, isCurrent = Boolean(req.body?.isCurrent);
  if (!name || name.length > 80 || !validDate(startDate) || !validDate(endDate) || startDate > endDate) return sendError(res, 400, 'Enter a name and a valid start/end date range.');
  const nameNorm = normalizeKey(name);
  if (await req.c.academicYears.findOne({ nameNorm })) return sendError(res, 409, 'Academic year already exists.');
  const doc = { name, nameNorm, startDate, endDate, isCurrent, createdAt: now(), updatedAt: now() };
  try {
    if (isCurrent) await req.c.academicYears.updateMany({}, { $set: { isCurrent: false, updatedAt: now() } });
    const result = await req.c.academicYears.insertOne(doc); doc._id = result.insertedId;
  } catch (err) { if (err.code === 11000) return sendError(res, 409, 'Academic year already exists.'); throw err; }
  await audit(req.db, req, 'academic_year.created', 'academicYear', doc._id, { name });
  res.status(201).json({ item: doc });
});
app.put('/api/academic-years/:id', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid academic year ID.');
  const id = asObjectId(req.params.id), current = await req.c.academicYears.findOne({ _id: id });
  if (!current) return sendError(res, 404, 'Academic year not found.');
  const name = normalizeText(req.body?.name ?? current.name), startDate = req.body?.startDate ?? current.startDate, endDate = req.body?.endDate ?? current.endDate, isCurrent = Boolean(req.body?.isCurrent);
  if (!name || name.length > 80 || !validDate(startDate) || !validDate(endDate) || startDate > endDate) return sendError(res, 400, 'Enter a name and a valid date range.');
  if (await req.c.academicYears.findOne({ nameNorm: normalizeKey(name), _id: { $ne: id } })) return sendError(res, 409, 'Academic year already exists.');
  if (isCurrent) await req.c.academicYears.updateMany({ _id: { $ne: id } }, { $set: { isCurrent: false, updatedAt: now() } });
  try { await req.c.academicYears.updateOne({ _id: id }, { $set: { name, nameNorm: normalizeKey(name), startDate, endDate, isCurrent, updatedAt: now() } }); }
  catch (err) { if (err.code === 11000) return sendError(res, 409, 'Academic year already exists.'); throw err; }
  await audit(req.db, req, 'academic_year.updated', 'academicYear', id, { name, isCurrent });
  res.json({ item: { ...current, name, nameNorm: normalizeKey(name), startDate, endDate, isCurrent } });
});

app.get('/api/classes', requireAuth, async (req, res) => {
  const filter = { archived: { $ne: true } };
  if (req.user.role !== 'admin') filter.nameNorm = { $in: (req.user.classNames || []).map(normalizeKey) };
  const rows = await req.c.classes.find(filter).sort({ name: 1 }).limit(500).toArray();
  res.json({ items: rows });
});
app.post('/api/classes', requireAuth, requireRole('admin'), async (req, res) => {
  const parsed = classInput(req.body); if (parsed.error) return sendError(res, 400, parsed.error);
  if (parsed.value.academicYearId && !await req.c.academicYears.findOne({ _id: parsed.value.academicYearId })) return sendError(res, 400, 'Academic year not found.');
  const doc = { ...parsed.value, archived: false, createdAt: now() };
  try { const result = await req.c.classes.insertOne(doc); doc._id = result.insertedId; }
  catch (err) { if (err.code === 11000) return sendError(res, 409, 'Class already exists.'); throw err; }
  await audit(req.db, req, 'class.created', 'class', doc._id, { name: doc.name });
  res.status(201).json({ item: doc });
});
app.put('/api/classes/:id', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid class ID.');
  const id = asObjectId(req.params.id), current = await req.c.classes.findOne({ _id: id });
  if (!current) return sendError(res, 404, 'Class not found.');
  const parsed = classInput({ ...current, ...req.body }); if (parsed.error) return sendError(res, 400, parsed.error);
  try {
    await req.c.classes.updateOne({ _id: id }, { $set: parsed.value });
    if (current.name !== parsed.value.name) {
      await req.c.students.updateMany({ classNameNorm: current.nameNorm }, { $set: { cls: parsed.value.name, classNameNorm: parsed.value.nameNorm, updatedAt: now() } });
      await req.c.sessions.updateMany({ classNameNorm: current.nameNorm }, { $set: { className: parsed.value.name, classNameNorm: parsed.value.nameNorm, updatedAt: now() } });
      await req.c.timetable.updateMany({ classNameNorm: current.nameNorm }, { $set: { className: parsed.value.name, classNameNorm: parsed.value.nameNorm, updatedAt: now() } });
      await req.c.users.updateMany({ classNames: current.name }, { $set: { 'classNames.$': parsed.value.name } });
      await req.c.subjects.updateMany({ classNames: current.name }, { $set: { 'classNames.$': parsed.value.name, updatedAt: now() } });
      await req.c.calendar.updateMany({ classNameNorm: current.nameNorm }, { $set: { className: parsed.value.name, classNameNorm: parsed.value.nameNorm, updatedAt: now() } });
    }
  } catch (err) { if (err.code === 11000) return sendError(res, 409, 'Class already exists.'); throw err; }
  await audit(req.db, req, 'class.updated', 'class', id, { previousName: current.name, name: parsed.value.name });
  res.json({ item: { ...current, ...parsed.value } });
});
app.post('/api/classes/:id/archive', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid class ID.');
  const id = asObjectId(req.params.id), row = await req.c.classes.findOne({ _id: id });
  if (!row) return sendError(res, 404, 'Class not found.');
  const archivedAt = now();
  await req.c.classes.updateOne({ _id: id }, { $set: { archived: true, archivedAt, updatedAt: archivedAt } });
  const studentArchive = await req.c.students.updateMany({ classNameNorm: row.nameNorm, active: true }, { $set: { active: false, archivedAt, archivedBy: req.user._id, updatedAt: archivedAt } });
  await req.c.timetable.updateMany({ classNameNorm: row.nameNorm, archived: { $ne: true } }, { $set: { archived: true, archivedAt, updatedAt: archivedAt } });
  await req.c.calendar.updateMany({ classNameNorm: row.nameNorm, archived: { $ne: true } }, { $set: { archived: true, archivedAt, updatedAt: archivedAt } });
  await audit(req.db, req, 'class.archived', 'class', id, { name: row.name, studentsArchived: studentArchive.modifiedCount });
  res.json({ message: 'Class archived. Historical records are retained.' });
});

app.get('/api/subjects', requireAuth, async (req, res) => {
  const rows = await req.c.subjects.find({ archived: { $ne: true } }).sort({ name: 1 }).limit(500).toArray();
  res.json({ items: rows.filter(s => req.user.role === 'admin' || (s.classNames || []).some(c => canAccessClass(req.user, c))) });
});
app.post('/api/subjects', requireAuth, requireRole('admin'), async (req, res) => {
  const name = normalizeText(req.body?.name), code = normalizeText(req.body?.code).toUpperCase(), classNames = Array.isArray(req.body?.classNames) ? [...new Set(req.body.classNames.map(normalizeText).filter(Boolean))] : [];
  const academicYearId = newId(req.body?.academicYearId) ? asObjectId(req.body.academicYearId) : null;
  if (!name || name.length > 100 || !code || code.length > 30 || !classNames.length) return sendError(res, 400, 'Subject name, code and at least one class are required.');
  const known = new Set((await req.c.classes.find({ archived: { $ne: true } }).toArray()).map(c => normalizeKey(c.name)));
  if (classNames.some(c => !known.has(normalizeKey(c)))) return sendError(res, 400, 'One or more classes do not exist.');
  const doc = { name, code, codeNorm: normalizeKey(code), classNames, academicYearId, academicYearKey: academicYearId ? String(academicYearId) : 'default', archived: false, createdAt: now(), updatedAt: now() };
  try { const result = await req.c.subjects.insertOne(doc); doc._id = result.insertedId; }
  catch (err) { if (err.code === 11000) return sendError(res, 409, 'Subject code already exists for this academic year.'); throw err; }
  await audit(req.db, req, 'subject.created', 'subject', doc._id, { name, code, classNames });
  res.status(201).json({ item: doc });
});
app.put('/api/subjects/:id', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid subject ID.');
  const id = asObjectId(req.params.id), current = await req.c.subjects.findOne({ _id: id });
  if (!current) return sendError(res, 404, 'Subject not found.');
  const name = normalizeText(req.body?.name ?? current.name), code = normalizeText(req.body?.code ?? current.code).toUpperCase();
  const classNames = Array.isArray(req.body?.classNames) ? [...new Set(req.body.classNames.map(normalizeText).filter(Boolean))] : current.classNames;
  if (!name || !code || !classNames?.length) return sendError(res, 400, 'Subject name, code and classes are required.');
  const academicYearId = req.body?.academicYearId === undefined ? current.academicYearId : (newId(req.body.academicYearId) ? asObjectId(req.body.academicYearId) : null);
  const updates = { name, code, codeNorm: normalizeKey(code), classNames, academicYearId, academicYearKey: academicYearId ? String(academicYearId) : 'default', updatedAt: now() };
  try { await req.c.subjects.updateOne({ _id: id }, { $set: updates }); }
  catch (err) { if (err.code === 11000) return sendError(res, 409, 'Subject code already exists for this academic year.'); throw err; }
  await audit(req.db, req, 'subject.updated', 'subject', id, { name, code, classNames });
  res.json({ item: { ...current, ...updates } });
});
app.post('/api/subjects/:id/archive', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid subject ID.');
  const id = asObjectId(req.params.id), subject = await req.c.subjects.findOne({ _id: id });
  if (!subject) return sendError(res, 404, 'Subject not found.');
  await req.c.subjects.updateOne({ _id: id }, { $set: { archived: true, archivedAt: now(), updatedAt: now() } });
  await audit(req.db, req, 'subject.archived', 'subject', id, { name: subject.name });
  res.json({ message: 'Subject archived; past sessions are retained.' });
});

// School calendar: holidays are informational unless a teacher explicitly records an override reason.
app.get('/api/calendar', requireAuth, async (req, res) => {
  const filter = { archived: { $ne: true } };
  if (req.query.date) {
    if (!validDate(req.query.date)) return sendError(res, 400, 'Invalid calendar date.');
    filter.date = req.query.date;
  } else if (req.query.from || req.query.to) {
    if ((req.query.from && !validDate(req.query.from)) || (req.query.to && !validDate(req.query.to))) return sendError(res, 400, 'Invalid calendar date range.');
    if (req.query.from && req.query.to && req.query.from > req.query.to) return sendError(res, 400, 'Start date must be on or before end date.');
    filter.date = {}; if (req.query.from) filter.date.$gte = req.query.from; if (req.query.to) filter.date.$lte = req.query.to;
  }
  if (req.query.className) {
    const className = normalizeText(req.query.className); if (!requireClass(req, res, className)) return;
    filter.$or = [{ classNameNorm: null }, { classNameNorm: normalizeKey(className) }];
  } else if (req.user.role !== 'admin') {
    filter.classNameNorm = { $in: [null, ...(req.user.classNames || []).map(normalizeKey)] };
  }
  const items = await req.c.calendar.find(filter).sort({ date: 1, name: 1 }).limit(2000).toArray();
  res.json({ items });
});
app.post('/api/calendar', requireAuth, requireRole('admin'), async (req, res) => {
  const date = req.body?.date, name = normalizeText(req.body?.name), type = req.body?.type, className = normalizeText(req.body?.className || ''), note = normalizeText(req.body?.note || '');
  if (!validDate(date) || !name || name.length > 120 || !['holiday', 'working-day'].includes(type) || note.length > 500) return sendError(res, 400, 'Enter a valid date, name, event type and optional note (maximum 500 characters).');
  let classDoc = null;
  if (className) { classDoc = await req.c.classes.findOne({ nameNorm: normalizeKey(className), archived: { $ne: true } }); if (!classDoc) return sendError(res, 400, 'Select an active class or leave the class blank for a campus-wide event.'); }
  const doc = { date, name, type, className: classDoc?.name || null, classNameNorm: classDoc?.nameNorm || null, note, archived: false, createdAt: now(), updatedAt: now(), createdBy: req.user._id };
  const result = await req.c.calendar.insertOne(doc); doc._id = result.insertedId;
  await audit(req.db, req, 'calendar_event.created', 'calendarEvent', doc._id, { date, name, type, className: doc.className });
  res.status(201).json({ item: doc });
});
app.put('/api/calendar/:id', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid calendar event ID.');
  const id = asObjectId(req.params.id), current = await req.c.calendar.findOne({ _id: id, archived: { $ne: true } });
  if (!current) return sendError(res, 404, 'Calendar event not found.');
  const merged = { ...current, ...req.body };
  const date = merged.date, name = normalizeText(merged.name), type = merged.type, className = normalizeText(merged.className || ''), note = normalizeText(merged.note || '');
  if (!validDate(date) || !name || name.length > 120 || !['holiday', 'working-day'].includes(type) || note.length > 500) return sendError(res, 400, 'Enter a valid date, name, event type and optional note.');
  let classDoc = null;
  if (className) { classDoc = await req.c.classes.findOne({ nameNorm: normalizeKey(className), archived: { $ne: true } }); if (!classDoc) return sendError(res, 400, 'Select an active class or leave the class blank for a campus-wide event.'); }
  const update = { date, name, type, className: classDoc?.name || null, classNameNorm: classDoc?.nameNorm || null, note, updatedAt: now() };
  await req.c.calendar.updateOne({ _id: id }, { $set: update });
  await audit(req.db, req, 'calendar_event.updated', 'calendarEvent', id, { date, name, type, className: update.className });
  res.json({ item: { ...current, ...update } });
});
app.post('/api/calendar/:id/archive', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid calendar event ID.');
  const id = asObjectId(req.params.id), result = await req.c.calendar.updateOne({ _id: id, archived: { $ne: true } }, { $set: { archived: true, archivedAt: now(), updatedAt: now() } });
  if (!result.matchedCount) return sendError(res, 404, 'Calendar event not found.');
  await audit(req.db, req, 'calendar_event.archived', 'calendarEvent', id, {});
  res.json({ message: 'Calendar event archived.' });
});

// Students. Delete means archive; attendance records are never cascaded away.
app.get('/api/students/export.csv', requireAuth, async (req, res) => {
  const filter = { active: true };
  if (req.query.className) {
    if (!requireClass(req, res, req.query.className)) return;
    filter.classNameNorm = normalizeKey(req.query.className);
  } else if (req.user.role !== 'admin') filter.classNameNorm = { $in: (req.user.classNames || []).map(normalizeKey) };
  const rows = await req.c.students.find(filter).sort({ cls: 1, rollNorm: 1 }).limit(20000).toArray();
  return csvResponse(res, `attendease_students_${dateToday()}.csv`, ['Roll No', 'Name', 'Class', 'Email', 'Enrolled On'], rows.map(s => [s.roll, s.name, s.cls, s.email || '', s.enrolledOn || '']));
});
app.get('/api/students', requireAuth, async (req, res) => {
  const page = Math.max(1, Math.min(100000, Number.parseInt(req.query.page, 10) || 1));
  const pageSize = Math.max(5, Math.min(100, Number.parseInt(req.query.pageSize, 10) || 20));
  const filter = { active: req.query.includeArchived === 'true' && req.user.role === 'admin' ? false : true };
  const sortFields = { class: { cls: 1, rollNorm: 1 }, name: { name: 1, rollNorm: 1 }, roll: { rollNorm: 1 }, enrolledOn: { enrolledOn: -1, rollNorm: 1 } };
  const sortSpec = sortFields[req.query.sortBy] || sortFields.class;
  if (req.query.className) {
    if (!requireClass(req, res, req.query.className)) return;
    filter.classNameNorm = normalizeKey(req.query.className);
  } else if (req.user.role !== 'admin') filter.classNameNorm = { $in: (req.user.classNames || []).map(normalizeKey) };
  if (req.query.search) {
    const term = safeRegex(String(req.query.search).slice(0, 100));
    filter.$or = [{ name: { $regex: term, $options: 'i' } }, { roll: { $regex: term, $options: 'i' } }, { email: { $regex: term, $options: 'i' } }];
  }
  const [total, items] = await Promise.all([
    req.c.students.countDocuments(filter),
    req.c.students.find(filter, { projection: { roll: 1, name: 1, cls: 1, email: 1, enrolledOn: 1, createdAt: 1, updatedAt: 1, active: 1 } }).sort(sortSpec).skip((page - 1) * pageSize).limit(pageSize).toArray()
  ]);
  res.json({ items, total, page, pageSize, pages: Math.ceil(total / pageSize) });
});
app.get('/api/students/:id', requireAuth, async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid student ID.');
  const student = await req.c.students.findOne({ _id: asObjectId(req.params.id) });
  if (!student) return sendError(res, 404, 'Student not found.');
  if (!requireClass(req, res, student.cls)) return;
  const recentMarks = await req.c.attendance.find({ studentId: student._id }).sort({ updatedAt: -1 }).limit(100).toArray();
  const sessionIds = recentMarks.map(m => m.sessionId).filter(Boolean);
  const sessions = sessionIds.length ? await req.c.sessions.find({ _id: { $in: sessionIds } }).toArray() : [];
  const sessionMap = new Map(sessions.map(s => [String(s._id), s]));
  const history = recentMarks.map(m => {
    const s = sessionMap.get(String(m.sessionId));
    return { date: s?.date || m.date || '', sessionName: s?.name || 'Imported attendance', className: s?.className || student.cls, subjectName: s?.subjectName || 'Daily', status: m.status, sessionStatus: s?.status || 'legacy' };
  }).sort((a, b) => b.date.localeCompare(a.date));
  res.json({ student, history });
});
app.post('/api/students', requireAuth, async (req, res) => {
  if (!canWrite(req.user)) return sendError(res, 403, 'Read-only accounts cannot add students.');
  const parsed = studentInput(req.body); if (parsed.error) return sendError(res, 400, parsed.error);
  if (!requireClass(req, res, parsed.value.cls)) return;
  const classDoc = await req.c.classes.findOne({ nameNorm: parsed.value.classNameNorm, archived: { $ne: true } });
  if (!classDoc) return sendError(res, 400, 'Select a valid active class. Create the class first if it is missing.');
  const enrolledOn = validDate(req.body.enrolledOn) ? req.body.enrolledOn : dateToday();
  const doc = { ...parsed.value, academicYearId: classDoc.academicYearId || null, enrolledOn, active: true, createdAt: now(), createdBy: req.user._id };
  try { const result = await req.c.students.insertOne(doc); doc._id = result.insertedId; }
  catch (err) { if (err.code === 11000) return sendError(res, 409, 'An active student with that roll number already exists in this class.'); throw err; }
  await audit(req.db, req, 'student.created', 'student', doc._id, { roll: doc.roll, cls: doc.cls });
  res.status(201).json({ student: doc });
});
app.post('/api/students/import', requireAuth, async (req, res) => {
  if (!canWrite(req.user)) return sendError(res, 403, 'Read-only accounts cannot import students.');
  const rows = req.body?.records;
  if (!Array.isArray(rows) || rows.length === 0 || rows.length > 500) return sendError(res, 400, 'Upload between 1 and 500 student rows at a time.');
  const classRows = await req.c.classes.find({ archived: { $ne: true } }).toArray();
  const classMap = new Map(classRows.map(c => [c.nameNorm, c]));
  const result = { inserted: 0, skipped: 0, errors: [] };
  for (let i = 0; i < rows.length; i++) {
    const parsed = studentInput(rows[i]);
    if (parsed.error) { result.skipped++; result.errors.push({ row: i + 2, error: parsed.error }); continue; }
    const v = parsed.value;
    if (!canAccessClass(req.user, v.cls)) { result.skipped++; result.errors.push({ row: i + 2, error: 'You do not have access to this class.' }); continue; }
    const classDoc = classMap.get(v.classNameNorm);
    if (!classDoc) { result.skipped++; result.errors.push({ row: i + 2, error: `Class "${v.cls}" does not exist.` }); continue; }
    try {
      await req.c.students.insertOne({ ...v, academicYearId: classDoc.academicYearId || null, enrolledOn: validDate(rows[i].enrolledOn) ? rows[i].enrolledOn : dateToday(), active: true, createdAt: now(), updatedAt: now(), createdBy: req.user._id, imported: true });
      result.inserted++;
    } catch (err) {
      result.skipped++;
      result.errors.push({ row: i + 2, error: err.code === 11000 ? 'Duplicate active roll number in this class.' : 'Could not insert this row.' });
    }
  }
  await audit(req.db, req, 'students.imported', 'student', null, { inserted: result.inserted, skipped: result.skipped });
  res.status(200).json(result);
});
app.put('/api/students/:id', requireAuth, async (req, res) => {
  if (!canWrite(req.user)) return sendError(res, 403, 'Read-only accounts cannot edit students.');
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid student ID.');
  const id = asObjectId(req.params.id), current = await req.c.students.findOne({ _id: id, active: true });
  if (!current) return sendError(res, 404, 'Active student not found.');
  if (!requireClass(req, res, current.cls)) return;
  const parsed = studentInput({ ...current, ...req.body }); if (parsed.error) return sendError(res, 400, parsed.error);
  if (!requireClass(req, res, parsed.value.cls)) return;
  const classDoc = await req.c.classes.findOne({ nameNorm: parsed.value.classNameNorm, archived: { $ne: true } });
  if (!classDoc) return sendError(res, 400, 'Select a valid active class.');
  const updates = { ...parsed.value, academicYearId: classDoc.academicYearId || null, enrolledOn: validDate(req.body.enrolledOn) ? req.body.enrolledOn : current.enrolledOn || dateToday(), updatedAt: now() };
  try { await req.c.students.updateOne({ _id: id }, { $set: updates }); }
  catch (err) { if (err.code === 11000) return sendError(res, 409, 'An active student with that roll number already exists in this class.'); throw err; }
  await audit(req.db, req, 'student.updated', 'student', id, { previousClass: current.cls, className: updates.cls });
  res.json({ student: { ...current, ...updates } });
});
app.post('/api/students/:id/archive', requireAuth, async (req, res) => {
  if (!canWrite(req.user)) return sendError(res, 403, 'Read-only accounts cannot archive students.');
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid student ID.');
  const id = asObjectId(req.params.id), student = await req.c.students.findOne({ _id: id, active: true });
  if (!student) return sendError(res, 404, 'Active student not found.');
  if (!requireClass(req, res, student.cls)) return;
  await req.c.students.updateOne({ _id: id }, { $set: { active: false, archivedAt: now(), archivedBy: req.user._id, updatedAt: now() } });
  await audit(req.db, req, 'student.archived', 'student', id, { roll: student.roll, cls: student.cls });
  res.json({ message: 'Student archived. Attendance history has been retained.' });
});
app.post('/api/students/:id/restore', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid student ID.');
  const id = asObjectId(req.params.id), student = await req.c.students.findOne({ _id: id, active: false });
  if (!student) return sendError(res, 404, 'Archived student not found.');
  const activeClass = await req.c.classes.findOne({ nameNorm: student.classNameNorm || normalizeKey(student.cls), archived: { $ne: true } });
  if (!activeClass) return sendError(res, 409, 'Restore or recreate the student’s class before restoring this student.');
  try { await req.c.students.updateOne({ _id: id }, { $set: { active: true, updatedAt: now() }, $unset: { archivedAt: '', archivedBy: '' } }); }
  catch (err) { if (err.code === 11000) return sendError(res, 409, 'An active student already uses this roll number in that class.'); throw err; }
  await audit(req.db, req, 'student.restored', 'student', id, { roll: student.roll, cls: student.cls });
  res.json({ message: 'Student restored.' });
});

// Weekly timetable templates; attendance sessions remain separate, date-specific records.
app.get('/api/timetable', requireAuth, async (req, res) => {
  const filter = { archived: { $ne: true } };
  if (req.query.className) {
    if (!requireClass(req, res, req.query.className)) return;
    filter.classNameNorm = normalizeKey(req.query.className);
  } else if (req.user.role !== 'admin') filter.classNameNorm = { $in: (req.user.classNames || []).map(normalizeKey) };
  if (req.query.dayOfWeek !== undefined) {
    const day = Number(req.query.dayOfWeek);
    if (!Number.isInteger(day) || day < 0 || day > 6) return sendError(res, 400, 'dayOfWeek must be between 0 (Sunday) and 6 (Saturday).');
    filter.dayOfWeek = day;
  }
  const rows = await req.c.timetable.find(filter).sort({ dayOfWeek: 1, startTime: 1 }).limit(1000).toArray();
  res.json({ items: rows });
});
app.post('/api/timetable', requireAuth, requireRole('admin'), async (req, res) => {
  const className = normalizeText(req.body?.className), subjectId = newId(req.body?.subjectId) ? asObjectId(req.body.subjectId) : null;
  const dayOfWeek = Number(req.body?.dayOfWeek), startTime = String(req.body?.startTime || ''), endTime = String(req.body?.endTime || ''), name = normalizeText(req.body?.name || 'Class session'), room = normalizeText(req.body?.room || '');
  if (!className || !Number.isInteger(dayOfWeek) || dayOfWeek < 0 || dayOfWeek > 6 || !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(endTime) || startTime >= endTime) return sendError(res, 400, 'Enter a class, weekday and valid time range.');
  if (name.length > 100 || room.length > 80) return sendError(res, 400, 'Session name or room is too long.');
  const classDoc = await req.c.classes.findOne({ nameNorm: normalizeKey(className), archived: { $ne: true } });
  if (!classDoc) return sendError(res, 400, 'Active class not found.');
  const overlappingSlot = await req.c.timetable.findOne({ classNameNorm: normalizeKey(className), dayOfWeek, archived: { $ne: true }, startTime: { $lt: endTime }, endTime: { $gt: startTime } });
  if (overlappingSlot) return sendError(res, 409, `This time overlaps the existing ${overlappingSlot.startTime}–${overlappingSlot.endTime} slot for this class.`);
  let subject = null;
  if (subjectId) {
    subject = await req.c.subjects.findOne({ _id: subjectId, archived: { $ne: true } });
    if (!subject || !(subject.classNames || []).some(c => normalizeKey(c) === normalizeKey(className))) return sendError(res, 400, 'Subject is not assigned to this class.');
  }
  const doc = { className, classNameNorm: normalizeKey(className), academicYearId: classDoc.academicYearId || null, subjectId, subjectName: subject?.name || null, subjectCode: subject?.code || null, dayOfWeek, dayName: ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][dayOfWeek], startTime, endTime, name, room, archived: false, createdAt: now(), updatedAt: now(), createdBy: req.user._id };
  const result = await req.c.timetable.insertOne(doc); doc._id = result.insertedId;
  await audit(req.db, req, 'timetable.created', 'timetable', doc._id, { className, dayOfWeek, startTime, endTime, subjectName: doc.subjectName });
  res.status(201).json({ item: doc });
});
app.put('/api/timetable/:id', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid timetable ID.');
  const id = asObjectId(req.params.id), current = await req.c.timetable.findOne({ _id: id, archived: { $ne: true } });
  if (!current) return sendError(res, 404, 'Timetable entry not found.');
  const merged = { ...current, ...req.body };
  const className = normalizeText(merged.className), subjectId = newId(String(merged.subjectId || '')) ? asObjectId(String(merged.subjectId)) : null;
  const dayOfWeek = Number(merged.dayOfWeek), startTime = String(merged.startTime || ''), endTime = String(merged.endTime || ''), name = normalizeText(merged.name || 'Class session'), room = normalizeText(merged.room || '');
  if (!className || !Number.isInteger(dayOfWeek) || dayOfWeek < 0 || dayOfWeek > 6 || !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(endTime) || startTime >= endTime) return sendError(res, 400, 'Enter a valid class, weekday and time range.');
  if (name.length > 100 || room.length > 80) return sendError(res, 400, 'Session name or room is too long.');
  const classDoc = await req.c.classes.findOne({ nameNorm: normalizeKey(className), archived: { $ne: true } });
  if (!classDoc) return sendError(res, 400, 'Active class not found.');
  const overlappingSlot = await req.c.timetable.findOne({ _id: { $ne: id }, classNameNorm: normalizeKey(className), dayOfWeek, archived: { $ne: true }, startTime: { $lt: endTime }, endTime: { $gt: startTime } });
  if (overlappingSlot) return sendError(res, 409, `This time overlaps the existing ${overlappingSlot.startTime}–${overlappingSlot.endTime} slot for this class.`);
  let subject = null;
  if (subjectId) { subject = await req.c.subjects.findOne({ _id: subjectId, archived: { $ne: true } }); if (!subject || !(subject.classNames || []).some(c => normalizeKey(c) === normalizeKey(className))) return sendError(res, 400, 'Subject is not assigned to this class.'); }
  const update = { className, classNameNorm: normalizeKey(className), academicYearId: classDoc.academicYearId || null, subjectId, subjectName: subject?.name || null, subjectCode: subject?.code || null, dayOfWeek, dayName: ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][dayOfWeek], startTime, endTime, name, room, updatedAt: now() };
  await req.c.timetable.updateOne({ _id: id }, { $set: update });
  await audit(req.db, req, 'timetable.updated', 'timetable', id, { className, dayOfWeek, startTime, endTime });
  res.json({ item: { ...current, ...update } });
});
app.post('/api/timetable/:id/archive', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid timetable ID.');
  const id = asObjectId(req.params.id), result = await req.c.timetable.updateOne({ _id: id, archived: { $ne: true } }, { $set: { archived: true, archivedAt: now(), updatedAt: now() } });
  if (!result.matchedCount) return sendError(res, 404, 'Timetable entry not found.');
  await audit(req.db, req, 'timetable.archived', 'timetable', id, {});
  res.json({ message: 'Timetable entry archived. Historical sessions are retained.' });
});

// Session-based attendance; draft sessions never enter percentages until finalized.
app.get('/api/sessions', requireAuth, async (req, res) => {
  const filter = {};
  if (req.query.date) { if (!validDate(req.query.date)) return sendError(res, 400, 'Invalid date.'); filter.date = req.query.date; }
  if (req.query.from || req.query.to) {
    if ((req.query.from && !validDate(req.query.from)) || (req.query.to && !validDate(req.query.to))) return sendError(res, 400, 'Invalid date range.');
    if (req.query.from && req.query.to && req.query.from > req.query.to) return sendError(res, 400, 'Start date must be on or before end date.');
    filter.date = {}; if (req.query.from) filter.date.$gte = req.query.from; if (req.query.to) filter.date.$lte = req.query.to;
  }
  if (req.query.className) { if (!requireClass(req, res, req.query.className)) return; filter.classNameNorm = normalizeKey(req.query.className); }
  else if (req.user.role !== 'admin') filter.classNameNorm = { $in: (req.user.classNames || []).map(normalizeKey) };
  if (req.query.subjectId) { if (!newId(req.query.subjectId)) return sendError(res, 400, 'Invalid subject ID.'); filter.subjectId = asObjectId(req.query.subjectId); }
  else filter.subjectId = null;
  const rows = await req.c.sessions.find(filter).sort({ date: -1, createdAt: -1 }).limit(100).toArray();
  const counts = rows.length ? await req.c.attendance.aggregate([{ $match: { sessionId: { $in: rows.map(s => s._id) } } }, { $group: { _id: '$sessionId', count: { $sum: 1 } } }]).toArray() : [];
  const countMap = new Map(counts.map(c => [String(c._id), c.count]));
  res.json({ items: rows.map(s => ({ ...s, marksCount: countMap.get(String(s._id)) || 0 })) });
});
app.post('/api/sessions', requireAuth, async (req, res) => {
  if (!canWrite(req.user)) return sendError(res, 403, 'Read-only accounts cannot create sessions.');
  const date = req.body?.date, className = normalizeText(req.body?.className), name = normalizeText(req.body?.name || 'Daily attendance'), subjectId = newId(req.body?.subjectId) ? asObjectId(req.body.subjectId) : null;
  const scheduleId = req.body?.scheduleId ? (newId(req.body.scheduleId) ? asObjectId(req.body.scheduleId) : null) : null;
  if (req.body?.scheduleId && !scheduleId) return sendError(res, 400, 'Invalid timetable slot ID.');
  if (!validDate(date) || !className || !name || name.length > 100) return sendError(res, 400, 'Date, class and session name are required.');
  if (!requireClass(req, res, className)) return;
  const classDoc = await req.c.classes.findOne({ nameNorm: normalizeKey(className), archived: { $ne: true } });
  if (!classDoc) return sendError(res, 400, 'Active class not found.');
  let subject = null;
  if (subjectId) {
    subject = await req.c.subjects.findOne({ _id: subjectId, archived: { $ne: true } });
    if (!subject || !(subject.classNames || []).some(c => normalizeKey(c) === normalizeKey(className))) return sendError(res, 400, 'This subject is not assigned to the selected class.');
  }
  if (scheduleId) {
    const schedule = await req.c.timetable.findOne({ _id: scheduleId, archived: { $ne: true } });
    const scheduledWeekday = new Date(`${date}T12:00:00Z`).getUTCDay();
    if (!schedule || schedule.classNameNorm !== normalizeKey(className) || Number(schedule.dayOfWeek) !== scheduledWeekday || String(schedule.subjectId || '') !== String(subjectId || '')) return sendError(res, 400, 'The selected timetable slot does not match this date, class or subject.');
  }
  const holiday = await req.c.calendar.findOne({ date, type: 'holiday', archived: { $ne: true }, $or: [{ classNameNorm: null }, { classNameNorm: normalizeKey(className) }] });
  const holidayOverrideReason = normalizeText(req.body?.holidayOverrideReason || '');
  if (holiday && holidayOverrideReason.length < 5) return sendError(res, 409, `“${holiday.name}” is marked as a holiday. Enter a reason of at least 5 characters to override the calendar.`);
  if (holidayOverrideReason.length > 300) return sendError(res, 400, 'Holiday override reason must be 300 characters or fewer.');
  const sessionKey = `${date}|${normalizeKey(className)}|${subjectId ? String(subjectId) : 'daily'}|${normalizeKey(name)}`;
  const doc = { sessionKey, date, className, classNameNorm: normalizeKey(className), name, subjectId, subjectName: subject?.name || null, scheduleId, calendarOverride: holiday ? { eventId: holiday._id, name: holiday.name, reason: holidayOverrideReason, overriddenBy: req.user._id, overriddenAt: now() } : null, status: 'draft', legacy: false, createdBy: req.user._id, createdAt: now(), updatedAt: now() };
  try { const result = await req.c.sessions.insertOne(doc); doc._id = result.insertedId; }
  catch (err) {
    if (err.code === 11000) {
      const existing = await req.c.sessions.findOne({ sessionKey });
      return res.status(409).json({ error: 'A session with these details already exists.', session: existing });
    }
    throw err;
  }
  await audit(req.db, req, 'attendance_session.created', 'session', doc._id, { date, className, subjectName: doc.subjectName, scheduleId: scheduleId ? String(scheduleId) : null, holidayOverride: Boolean(holiday), holidayOverrideReason: holiday ? holidayOverrideReason : null });
  res.status(201).json({ session: doc });
});
app.get('/api/sessions/:id/attendance', requireAuth, async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid session ID.');
  const session = await req.c.sessions.findOne({ _id: asObjectId(req.params.id) });
  if (!session) return sendError(res, 404, 'Session not found.');
  if (!requireClass(req, res, session.className)) return;
  const students = await req.c.students.find({ active: true, classNameNorm: session.classNameNorm }).sort({ rollNorm: 1 }).toArray();
  const marks = await req.c.attendance.find({ sessionId: session._id }).toArray();
  const map = new Map(marks.map(m => [String(m.studentId), m.status]));
  res.json({ session, students: students.map(s => ({ _id: s._id, roll: s.roll, name: s.name, cls: s.cls, status: map.get(String(s._id)) || '' })) });
});
app.put('/api/sessions/:id/attendance', requireAuth, async (req, res) => {
  if (!canWrite(req.user)) return sendError(res, 403, 'Read-only accounts cannot mark attendance.');
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid session ID.');
  const id = asObjectId(req.params.id), session = await req.c.sessions.findOne({ _id: id });
  if (!session) return sendError(res, 404, 'Session not found.');
  if (!requireClass(req, res, session.className)) return;
  if (session.status === 'finalized') return sendError(res, 409, 'Finalized sessions are locked. An administrator must reopen the session with a reason before changing marks.');
  const records = req.body?.records;
  if (!Array.isArray(records) || records.length > 2000) return sendError(res, 400, 'Attendance records must be a list of no more than 2000 entries.');
  const seen = new Set();
  for (const record of records) {
    if (!newId(record?.studentId) || !validStatus(record?.status)) return sendError(res, 400, 'Each marked record requires a valid student ID and status P, A, L or E.');
    if (seen.has(record.studentId)) return sendError(res, 400, 'Duplicate student in the attendance request.');
    seen.add(record.studentId);
  }
  const ids = records.map(r => asObjectId(r.studentId));
  const students = ids.length ? await req.c.students.find({ _id: { $in: ids }, active: true, classNameNorm: session.classNameNorm }).toArray() : [];
  if (students.length !== ids.length) return sendError(res, 400, 'One or more students are inactive or do not belong to this class.');
  const priorMarks = await req.c.attendance.find({ sessionId: id }).toArray();
  const beforeByStudent = new Map(priorMarks.map(mark => [String(mark.studentId), mark.status]));
  const afterByStudent = new Map(records.map(record => [record.studentId, record.status]));
  const changedIds = new Set([...beforeByStudent.keys(), ...afterByStudent.keys()]);
  const changes = [...changedIds].filter(studentId => (beforeByStudent.get(studentId) || '') !== (afterByStudent.get(studentId) || '')).map(studentId => ({ studentId, from: beforeByStudent.get(studentId) || null, to: afterByStudent.get(studentId) || null }));
  if (records.length) {
    const operations = records.map(record => ({ updateOne: { filter: { sessionId: id, studentId: asObjectId(record.studentId) }, update: { $set: { sessionId: id, studentId: asObjectId(record.studentId), status: record.status, markedBy: req.user._id, updatedAt: now() }, $setOnInsert: { createdAt: now() } }, upsert: true } }));
    await req.c.attendance.bulkWrite(operations, { ordered: true });
  }
  await req.c.attendance.deleteMany({ sessionId: id, studentId: { $nin: ids } });
  await req.c.sessions.updateOne({ _id: id }, { $set: { updatedAt: now(), lastEditedBy: req.user._id } });
  await audit(req.db, req, 'attendance.draft_saved', 'session', id, { date: session.date, className: session.className, marked: records.length, changedCount: changes.length, changes: changes.slice(0, 500), changesTruncated: changes.length > 500 });
  res.json({ message: 'Draft saved.', marked: records.length, totalActiveStudents: await req.c.students.countDocuments({ active: true, classNameNorm: session.classNameNorm }) });
});
app.post('/api/sessions/:id/finalize', requireAuth, async (req, res) => {
  if (!canWrite(req.user)) return sendError(res, 403, 'Read-only accounts cannot finalize attendance.');
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid session ID.');
  const id = asObjectId(req.params.id), session = await req.c.sessions.findOne({ _id: id });
  if (!session) return sendError(res, 404, 'Session not found.');
  if (!requireClass(req, res, session.className)) return;
  if (session.status === 'finalized') return sendError(res, 409, 'Session is already finalized.');
  const students = await req.c.students.find({ active: true, classNameNorm: session.classNameNorm }, { projection: { _id: 1 } }).toArray();
  if (!students.length) return sendError(res, 400, 'Cannot finalize a session with no active students.');
  const studentIds = students.map(s => s._id);
  const marked = await req.c.attendance.countDocuments({ sessionId: id, studentId: { $in: studentIds }, status: { $in: ['P', 'A', 'L', 'E'] } });
  if (marked !== students.length) return sendError(res, 400, `Attendance is incomplete: ${marked} of ${students.length} active students have a status. Mark every student before finalizing.`);
  await req.c.sessions.updateOne({ _id: id }, { $set: { status: 'finalized', finalizedAt: now(), finalizedBy: req.user._id, updatedAt: now() } });
  await audit(req.db, req, 'attendance.finalized', 'session', id, { date: session.date, className: session.className, students: students.length });
  res.json({ message: 'Attendance finalized. The session is now included in reports.', sessionId: String(id), students: students.length });
});
app.post('/api/sessions/:id/reopen', requireAuth, requireRole('admin'), async (req, res) => {
  if (!newId(req.params.id)) return sendError(res, 400, 'Invalid session ID.');
  const reason = normalizeText(req.body?.reason);
  if (reason.length < 5 || reason.length > 500) return sendError(res, 400, 'Enter a reason of at least 5 characters.');
  const id = asObjectId(req.params.id), session = await req.c.sessions.findOne({ _id: id });
  if (!session) return sendError(res, 404, 'Session not found.');
  if (session.status !== 'finalized') return sendError(res, 409, 'Only finalized sessions can be reopened.');
  await req.c.sessions.updateOne({ _id: id }, { $set: { status: 'draft', reopenedAt: now(), reopenedBy: req.user._id, reopenReason: reason, updatedAt: now() }, $unset: { finalizedAt: '', finalizedBy: '' } });
  await audit(req.db, req, 'attendance.reopened', 'session', id, { reason, date: session.date, className: session.className });
  res.json({ message: 'Session reopened. Corrections are now allowed.' });
});

// Reports include only finalized sessions. Exempt marks are excluded from the denominator.
async function makeReport(req, from, to, className) {
  const sessionFilter = { status: 'finalized' };
  if (from || to) { sessionFilter.date = {}; if (from) sessionFilter.date.$gte = from; if (to) sessionFilter.date.$lte = to; }
  if (className) sessionFilter.classNameNorm = normalizeKey(className);
  else if (req.user && req.user.role !== 'admin') sessionFilter.classNameNorm = { $in: (req.user.classNames || []).map(normalizeKey) };
  const sessions = await req.c.sessions.find(sessionFilter, { projection: { _id: 1, date: 1, className: 1, subjectName: 1 } }).sort({ date: 1 }).limit(5000).toArray();
  const sessionIds = sessions.map(s => s._id);
  const studentFilter = { active: true };
  if (className) studentFilter.classNameNorm = normalizeKey(className);
  else if (req.user && req.user.role !== 'admin') studentFilter.classNameNorm = { $in: (req.user.classNames || []).map(normalizeKey) };
  const students = await req.c.students.find(studentFilter).sort({ cls: 1, rollNorm: 1 }).limit(10000).toArray();
  const markGroups = sessionIds.length ? await req.c.attendance.aggregate([
    { $match: { sessionId: { $in: sessionIds } } },
    { $group: { _id: '$studentId', marks: { $push: '$status' } } }
  ]).toArray() : [];
  const markMap = new Map(markGroups.map(m => [String(m._id), m.marks]));
  const rows = students.map(student => {
    const stats = summarizeMarks(markMap.get(String(student._id)) || []);
    return { studentId: String(student._id), roll: student.roll, name: student.name, cls: student.cls, email: student.email || '', ...stats };
  });
  const inRange = rows.filter(r => r.pct !== null);
  const avgPct = inRange.length ? Math.round(inRange.reduce((sum, r) => sum + r.pct, 0) / inRange.length) : null;
  const totals = rows.reduce((a, r) => ({ present: a.present + r.present, absent: a.absent + r.absent, late: a.late + r.late, excused: a.excused + r.excused, days: a.days + r.days }), { present: 0, absent: 0, late: 0, excused: 0, days: 0 });
  return { rows, summary: { studentCount: rows.length, studentsWithData: inRange.length, averageAttendance: avgPct, finalizedSessions: sessions.length, ...totals }, sessions };
}
app.get('/api/reports/attendance', requireAuth, async (req, res) => {
  const from = req.query.from || '', to = req.query.to || '', className = normalizeText(req.query.className || '');
  if ((from && !validDate(from)) || (to && !validDate(to))) return sendError(res, 400, 'Invalid report date.');
  if (from && to && from > to) return sendError(res, 400, 'Start date must be on or before end date.');
  if (className && !requireClass(req, res, className)) return;
  const report = await makeReport(req, from, to, className);
  res.json({ ...report, filters: { from, to, className } });
});
app.get('/api/dashboard', requireAuth, async (req, res) => {
  const date = req.query.date || dateToday();
  if (!validDate(date)) return sendError(res, 400, 'Invalid dashboard date.');
  const className = normalizeText(req.query.className || '');
  if (className && !requireClass(req, res, className)) return;
  const classFilter = className ? { classNameNorm: normalizeKey(className) } : (req.user.role === 'admin' ? {} : { classNameNorm: { $in: (req.user.classNames || []).map(normalizeKey) } });
  const activeStudents = await req.c.students.countDocuments({ active: true, ...classFilter });
  const daySessions = await req.c.sessions.find({ date, ...classFilter }).sort({ className: 1, createdAt: 1 }).limit(200).toArray();
  const sessionIds = daySessions.map(s => s._id);
  const dailyCounts = sessionIds.length ? await req.c.attendance.aggregate([
    { $match: { sessionId: { $in: sessionIds } } }, { $group: { _id: { status: '$status', sessionId: '$sessionId' }, count: { $sum: 1 } } }
  ]).toArray() : [];
  const counts = { present: 0, absent: 0, late: 0, excused: 0 };
  const marksBySession = new Map();
  const finalizedIds = new Set(daySessions.filter(s => s.status === 'finalized').map(s => String(s._id)));
  for (const group of dailyCounts) {
    const sid = String(group._id.sessionId); marksBySession.set(sid, (marksBySession.get(sid) || 0) + group.count);
    if (!finalizedIds.has(sid)) continue;
    if (group._id.status === 'P') counts.present += group.count;
    if (group._id.status === 'A') counts.absent += group.count;
    if (group._id.status === 'L') counts.late += group.count;
    if (group._id.status === 'E') counts.excused += group.count;
  }
  const finalized = daySessions.filter(s => s.status === 'finalized').length;
  const drafts = daySessions.filter(s => s.status !== 'finalized').length;
  const setting = await req.c.settings.findOne({ _id: 'global' }) || { attendanceThreshold: 75 };
  const until = date; const fromDate = new Date(`${until}T00:00:00Z`); fromDate.setUTCDate(fromDate.getUTCDate() - 89); const from = fromDate.toISOString().slice(0, 10);
  const report = await makeReport(req, from, until, className);
  const lowAttendance = report.rows.filter(r => r.pct !== null && r.pct < setting.attendanceThreshold).sort((a,b) => a.pct - b.pct).slice(0, 12);
  const classes = new Map();
  for (const row of report.rows) {
    if (row.pct === null) continue;
    const group = classes.get(row.cls) || { className: row.cls, studentCount: 0, totalPct: 0 };
    group.studentCount += 1; group.totalPct += row.pct; classes.set(row.cls, group);
  }
  const classSummary = [...classes.values()].map(group => ({ className: group.className, studentCount: group.studentCount, averageAttendance: Math.round(group.totalPct / group.studentCount) })).sort((a,b) => a.className.localeCompare(b.className)).slice(0, 20);
  const dateWindow = [];
  for (let i = 6; i >= 0; i--) { const d = new Date(`${date}T00:00:00Z`); d.setUTCDate(d.getUTCDate() - i); dateWindow.push(d.toISOString().slice(0, 10)); }
  const windowSessions = report.sessions.filter(session => dateWindow.includes(session.date));
  const sessionDate = new Map(windowSessions.map(session => [String(session._id), session.date]));
  const trendGroups = windowSessions.length ? await req.c.attendance.aggregate([
    { $match: { sessionId: { $in: windowSessions.map(session => session._id) } } },
    { $group: { _id: { sessionId: '$sessionId', status: '$status' }, count: { $sum: 1 } } }
  ]).toArray() : [];
  const dailyTrend = new Map(dateWindow.map(day => [day, { attended: 0, total: 0 }]));
  for (const group of trendGroups) {
    const day = sessionDate.get(String(group._id.sessionId)); if (!day) continue;
    const stats = dailyTrend.get(day); const status = group._id.status;
    if (['P', 'L'].includes(status)) { stats.attended += group.count; stats.total += group.count; }
    else if (status === 'A') stats.total += group.count;
  }
  const sessionCountByDate = new Map();
  for (const session of windowSessions) sessionCountByDate.set(session.date, (sessionCountByDate.get(session.date) || 0) + 1);
  const last7 = dateWindow.map(day => { const stats = dailyTrend.get(day); return { date: day, pct: stats.total ? Math.round(stats.attended / stats.total * 100) : null, sessions: sessionCountByDate.get(day) || 0 }; });
  res.json({ date, className: className || null, activeStudents, sessionsToday: daySessions.length, finalizedSessionsToday: finalized, draftSessionsToday: drafts, marksToday: counts, last7, classSummary, lowAttendance, attendanceThreshold: setting.attendanceThreshold, recentSessions: daySessions.slice(-8).reverse().map(s => ({ id: String(s._id), date: s.date, className: s.className, subjectName: s.subjectName || 'Daily', name: s.name, status: s.status, marksCount: marksBySession.get(String(s._id)) || 0 })) });
});

app.get('/api/settings', requireAuth, async (req, res) => {
  const s = await req.c.settings.findOne({ _id: 'global' }) || { attendanceThreshold: 75 };
  res.json({ attendanceThreshold: s.attendanceThreshold || 75, mailConfigured: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD && process.env.EMAIL_FROM) });
});
app.put('/api/settings', requireAuth, requireRole('admin'), async (req, res) => {
  const threshold = Number(req.body?.attendanceThreshold);
  if (!Number.isInteger(threshold) || threshold < 50 || threshold > 100) return sendError(res, 400, 'Attendance threshold must be an integer from 50 to 100.');
  await req.c.settings.updateOne({ _id: 'global' }, { $set: { attendanceThreshold: threshold, updatedAt: now(), updatedBy: req.user._id } }, { upsert: true });
  await audit(req.db, req, 'settings.updated', 'settings', 'global', { attendanceThreshold: threshold });
  res.json({ attendanceThreshold: threshold });
});
app.get('/api/audit', requireAuth, requireRole('admin'), async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1), pageSize = Math.min(100, Math.max(10, Number.parseInt(req.query.pageSize, 10) || 50));
  const filter = {};
  if (req.query.action) filter.action = String(req.query.action).slice(0, 100);
  const [total, items] = await Promise.all([req.c.audit.countDocuments(filter), req.c.audit.find(filter).sort({ createdAt: -1 }).skip((page-1)*pageSize).limit(pageSize).toArray()]);
  res.json({ items, total, page, pageSize, pages: Math.ceil(total / pageSize) });
});
app.get('/api/admin/backup', requireAuth, requireRole('admin'), async (req, res) => {
  const limit = 50000;
  const [users, students, classes, academicYears, subjects, calendar, timetable, sessions, attendance, auditLogs, settings] = await Promise.all([
    req.c.users.find({}, { projection: { passwordHash: 0 } }).limit(1000).toArray(), req.c.students.find({}).limit(limit).toArray(), req.c.classes.find({}).limit(5000).toArray(),
    req.c.academicYears.find({}).limit(500).toArray(), req.c.subjects.find({}).limit(5000).toArray(), req.c.calendar.find({}).limit(20000).toArray(), req.c.timetable.find({}).limit(10000).toArray(), req.c.sessions.find({}).limit(limit).toArray(),
    req.c.attendance.find({}).limit(limit).toArray(), req.c.audit.find({}).sort({ createdAt: -1 }).limit(10000).toArray(), req.c.settings.find({}).toArray()
  ]);
  const backup = { product: 'AttendEase', schemaVersion: 6, exportedAt: now().toISOString(), note: 'User password hashes omitted. This backup is sensitive; store securely.', data: { users, students, classes, academicYears, subjects, calendar, timetable, sessions, attendance, auditLogs, settings } };
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="attendease-backup-${dateToday()}.json"`);
  res.send(JSON.stringify(backup, null, 2));
  await audit(req.db, req, 'backup.exported', 'backup', null, { records: students.length + sessions.length + attendance.length });
});

async function getRiskReport(req) {
  const end = dateToday(), d = new Date(`${end}T00:00:00Z`); d.setUTCDate(d.getUTCDate()-29); const start = d.toISOString().slice(0,10);
  const report = await makeReport(req, start, end, '');
  const setting = await req.c.settings.findOne({ _id:'global' }) || { attendanceThreshold:75 };
  return { ...report, low: report.rows.filter(r => r.pct !== null && r.pct < setting.attendanceThreshold).sort((a,b) => a.pct-b.pct), threshold: setting.attendanceThreshold, from: start, to: end };
}
async function sendRiskEmail(db, toList, report) {
  const transport = await emailTransport();
  if (!transport) return { sent: false, reason: 'Email is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD and EMAIL_FROM.' };
  if (!toList.length) return { sent: false, reason: 'No notification recipients are configured.' };
  const rows = report.low.map(s => `<tr><td>${escapeHtml(s.roll)}</td><td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.cls)}</td><td>${s.pct}%</td></tr>`).join('');
  const html = `<p>Attendance risk summary from ${report.from} to ${report.to}.</p><p>Threshold: ${report.threshold}%</p><table border="1" cellpadding="6" cellspacing="0"><thead><tr><th>Roll</th><th>Student</th><th>Class</th><th>Attendance</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No students are below the threshold.</td></tr>'}</tbody></table><p>This message contains student information. Handle it according to your institution's privacy policy.</p>`;
  const info = await transport.sendMail({ from: process.env.EMAIL_FROM, to: toList.join(','), subject: `AttendEase attendance alerts (${report.low.length})`, html, text: `Attendance risk summary ${report.from} to ${report.to}. ${report.low.length} students are below ${report.threshold}%.` });
  return { sent: true, messageId: info.messageId, recipients: toList.length };
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])); }
app.post('/api/alerts/send', requireAuth, requireRole('admin'), async (req, res) => {
  const report = await getRiskReport(req);
  const admins = await req.c.users.find({ role: 'admin', active: true }, { projection: { email: 1 } }).toArray();
  const to = (process.env.ALERT_EMAIL_TO || admins.map(a => a.email).join(',')).split(',').map(s=>s.trim()).filter(s=>validEmail(s) && s);
  const result = await sendRiskEmail(req.db, to, report);
  await audit(req.db, req, 'attendance_alerts.sent', 'alert', null, { studentsBelowThreshold: report.low.length, sent: result.sent });
  if (!result.sent) return res.status(503).json(result);
  res.json({ ...result, studentsBelowThreshold: report.low.length });
});
app.get('/api/cron/attendance-alerts', async (req, res) => {
  const secret = process.env.CRON_SECRET;
  const header = req.get('authorization') || '';
  const expectedHeader = secret ? `Bearer ${secret}` : '';
  const supplied = Buffer.from(header), expected = Buffer.from(expectedHeader);
  if (!secret || secret.length < 40 || secret.startsWith('replace-with-') || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return sendError(res, 401, 'Unauthorized scheduled task.');
  const admins = await req.c.users.find({ role: 'admin', active: true }, { projection: { email: 1 } }).toArray();
  const to = (process.env.ALERT_EMAIL_TO || admins.map(a=>a.email).join(',')).split(',').map(s=>s.trim()).filter(s=>validEmail(s) && s);
  const report = await getRiskReport(req);
  const result = await sendRiskEmail(req.db, to, report);
  await req.c.audit.insertOne({ action: 'attendance_alerts.scheduled', entity: 'alert', actorName: 'System', role: 'system', details: { studentsBelowThreshold: report.low.length, sent: result.sent }, createdAt: now() }).catch(()=>{});
  res.status(result.sent ? 200 : 503).json({ ...result, studentsBelowThreshold: report.low.length });
});

app.use('/api', (req, res) => sendError(res, 404, 'API route not found.'));
app.use((req, res, next) => {
  if (!['GET', 'HEAD'].includes(req.method) || req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'), err => { if (err) next(err); });
});
app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', message: err.message, path: req.path, time: now().toISOString() }));
  if (res.headersSent) return next(err);
  const status = Number(err.status) >= 400 && Number(err.status) < 600 ? Number(err.status) : 500;
  res.status(status).json({ error: status === 500 ? 'Unexpected server error. Check deployment logs for the request details.' : err.message });
});

if (require.main === module && !process.env.VERCEL) {
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => console.log(`AttendEase v6 listening at http://localhost:${port}`));
}
module.exports = app;
