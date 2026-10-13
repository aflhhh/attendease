'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeText, normalizeKey, validDate, validEmail, validStatus, summarizeMarks, safeUser, canAccessClass } = require('../lib/domain');

test('normalization trims and collapses repeated whitespace', () => {
  assert.equal(normalizeText('  BSc   Computer   Science '), 'BSc Computer Science');
  assert.equal(normalizeKey(' BSc   Computer Science '), 'bsc computer science');
});

test('date validation accepts real calendar dates only', () => {
  assert.equal(validDate('2024-02-29'), true);
  assert.equal(validDate('2025-02-29'), false);
  assert.equal(validDate('2026-13-01'), false);
  assert.equal(validDate('13-01-2026'), false);
  assert.equal(validDate(''), false);
});

test('email validation accepts optional blank emails and rejects malformed values', () => {
  assert.equal(validEmail(''), true);
  assert.equal(validEmail('student@example.edu'), true);
  assert.equal(validEmail('name at example.com'), false);
  assert.equal(validEmail('bad@'), false);
});

test('attendance percentage counts late as attended and excludes excused marks', () => {
  const result = summarizeMarks(['P', 'P', 'L', 'A', 'E']);
  assert.deepEqual(result, { present: 2, absent: 1, late: 1, excused: 1, days: 4, pct: 75 });
});

test('attendance percentage is null without countable marks', () => {
  assert.deepEqual(summarizeMarks(['E', 'E']), { present: 0, absent: 0, late: 0, excused: 2, days: 0, pct: null });
  assert.equal(summarizeMarks([]).pct, null);
});

test('only supported attendance marks are valid', () => {
  for (const status of ['P', 'A', 'L', 'E']) assert.equal(validStatus(status), true);
  for (const status of ['', 'X', 'present', null, 0]) assert.equal(validStatus(status), false);
});

test('role access respects assigned classes and admins access all classes', () => {
  assert.equal(canAccessClass({ role: 'admin', classNames: [] }, 'BSc CS A'), true);
  assert.equal(canAccessClass({ role: 'teacher', classNames: ['BSc CS A'] }, ' bsc cs a '), true);
  assert.equal(canAccessClass({ role: 'teacher', classNames: ['BSc CS A'] }, 'BSc CS B'), false);
  assert.equal(canAccessClass({ role: 'viewer', classNames: [] }, 'BSc CS A'), false);
});

test('safe user projection never exposes a password hash', () => {
  const user = safeUser({ _id: 'abc', name: 'Admin', email: 'admin@example.edu', role: 'admin', passwordHash: 'secret-hash', classNames: [] });
  assert.equal(user.email, 'admin@example.edu');
  assert.equal(Object.hasOwn(user, 'passwordHash'), false);
});
