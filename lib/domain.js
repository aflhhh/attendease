'use strict';

const VALID_STATUSES = new Set(['P', 'A', 'L', 'E']);

function normalizeText(value) {
  return String(value ?? '').normalize('NFKC').trim().replace(/\s+/g, ' ');
}

function normalizeKey(value) {
  return normalizeText(value).toLocaleLowerCase('en-US');
}

function validDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    !Number.isNaN(Date.parse(`${value}T00:00:00.000Z`)) &&
    new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) === value;
}

function validEmail(value) {
  if (!value) return true;
  return typeof value === 'string' && value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function validStatus(value) {
  return VALID_STATUSES.has(value);
}

function summarizeMarks(marks) {
  const result = { present: 0, absent: 0, late: 0, excused: 0, days: 0, pct: null };
  for (const mark of marks || []) {
    const status = typeof mark === 'string' ? mark : mark.status;
    if (status === 'P') result.present += 1;
    else if (status === 'A') result.absent += 1;
    else if (status === 'L') result.late += 1;
    else if (status === 'E') result.excused += 1;
  }
  result.days = result.present + result.absent + result.late;
  result.pct = result.days ? Math.round(((result.present + result.late) / result.days) * 100) : null;
  return result;
}

function safeUser(user) {
  if (!user) return null;
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    role: user.role,
    classNames: Array.isArray(user.classNames) ? user.classNames : [],
    active: user.active !== false,
    createdAt: user.createdAt || null,
    lastLoginAt: user.lastLoginAt || null
  };
}

function canAccessClass(user, className) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  const allow = new Set((user.classNames || []).map(normalizeKey));
  return allow.has(normalizeKey(className));
}

module.exports = { VALID_STATUSES, normalizeText, normalizeKey, validDate, validEmail, validStatus, summarizeMarks, safeUser, canAccessClass };
