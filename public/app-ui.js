'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    user: null, classes: [], years: [], subjects: [], timetable: [], calendarEvents: [], students: [], studentPage: 1, studentPages: 1,
    report: null, dashboard: null, session: null, roster: [], marks: {}, originalMarks: {}, dirty: false,
    auditPage: 1, auditPages: 1, auditRows: [], users: [], settings: { attendanceThreshold: 75 }, activePage: 'overview',
    studentFilters: { search: '', className: '', archived: false }, pendingScheduleId: null
  };
  const ICONS = {
    enrolled: 'users', sessions: 'calendar', present: 'check-circle', risk: 'alert'
  };
  const STATUS = { P: 'Present', A: 'Absent', L: 'Late', E: 'Excused' };
  const API_ERROR_RE = /^(Bad Request|Unauthorized|Forbidden|Not Found|Internal Server Error)$/i;

  class ApiError extends Error { constructor(message, status, data) { super(message); this.name = 'ApiError'; this.status = status; this.data = data; } }
  async function api(url, options = {}) {
    const opts = { method: 'GET', credentials: 'same-origin', ...options };
    opts.headers = { ...(opts.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...(opts.headers || {}) };
    if (opts.body && typeof opts.body !== 'string' && !(opts.body instanceof FormData)) opts.body = JSON.stringify(opts.body);
    let response;
    try { response = await fetch(url, opts); }
    catch { throw new ApiError('Could not reach the application server. Check your internet connection and retry.', 0, null); }
    const contentType = response.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await response.json().catch(() => ({})) : await response.text().catch(() => '');
    if (!response.ok) {
      const message = typeof data === 'object' && data?.error ? data.error : (typeof data === 'string' && data && !API_ERROR_RE.test(data) ? data.slice(0, 200) : `Request failed (${response.status}).`);
      if (response.status === 401 && state.user && !opts.suppressAuthRedirect) forceSignIn();
      throw new ApiError(message, response.status, data);
    }
    return data;
  }
  function toast(message, type = 'info', duration = 4200) {
    const node = document.createElement('div'); node.className = `toast ${type}`;
    const icon = document.createElement('span'); icon.className = 'toast-icon'; icon.textContent = type === 'error' ? '!' : type === 'success' ? '✓' : 'i';
    const text = document.createElement('span'); text.textContent = message;
    node.append(icon, text); $('toastRegion').appendChild(node);
    window.setTimeout(() => node.remove(), duration);
  }
  function setBusy(busy, message = 'Working…') { $('busyOverlay').hidden = !busy; $('busyText').textContent = message; }
  function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function fmtDate(value, opts = {}) {
    if (!value) return '—';
    const dt = new Date(`${String(value).slice(0, 10)}T12:00:00`);
    if (Number.isNaN(dt.getTime())) return String(value);
    return dt.toLocaleDateString(undefined, opts.year ? { day: 'numeric', month: 'short', year: 'numeric' } : { day: 'numeric', month: 'short' });
  }
  function todayStr() { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }
  function dateOffset(days) { const d = new Date(); d.setDate(d.getDate() + days); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; }
  function initial(value) { return String(value || '?').trim().split(/\s+/).slice(0, 2).map(p => p[0] || '').join('').toUpperCase(); }
  function isAdmin() { return state.user?.role === 'admin'; }
  function canWrite() { return ['admin', 'teacher'].includes(state.user?.role); }
  function selectOptions(select, items, { value = x => x.name, label = x => x.name, empty = null, multiple = false } = {}) {
    const previous = multiple ? [...select.selectedOptions].map(o => o.value) : select.value;
    const opts = [];
    if (!multiple && empty !== null) opts.push(`<option value="">${escapeHtml(empty)}</option>`);
    for (const item of items) opts.push(`<option value="${escapeHtml(value(item))}">${escapeHtml(label(item))}</option>`);
    select.innerHTML = opts.join('');
    if (multiple) [...select.options].forEach(o => { o.selected = previous.includes(o.value); });
    else if ([...select.options].some(o => o.value === previous)) select.value = previous;
  }
  function setConnection(ok, text = ok ? 'Connected to database' : 'Connection needs attention') {
    $('connectionDot').className = `status-dot ${ok ? 'online' : 'offline'}`;
    $('connectionText').textContent = text;
    if ($('settingsHealthDot')) $('settingsHealthDot').className = `status-dot ${ok ? 'online' : 'offline'}`;
    if ($('settingsHealthText')) $('settingsHealthText').textContent = text;
  }
  function updateRoleVisibility() {
    document.querySelectorAll('.admin-nav').forEach(el => { el.hidden = !isAdmin(); });
    document.querySelectorAll('.write-control').forEach(el => { el.hidden = !canWrite(); });
    document.querySelectorAll('.admin-settings').forEach(el => { el.hidden = !isAdmin(); });
    $('userName').textContent = state.user.name;
    $('userRole').textContent = state.user.role;
    $('userAvatar').textContent = initial(state.user.name);
    $('topRole').textContent = state.user.role;
    $('userClasses').disabled = false;
  }
  async function checkApiHealth() {
    try { const h = await api('/api/health', { suppressAuthRedirect: true }); setConnection(h.status === 'ok', h.status === 'ok' ? `Database connected · ${h.database}` : 'Database unavailable'); return h; }
    catch (err) { setConnection(false, err.message); throw err; }
  }
  function renderAuth(mode, error = '') {
    $('appShell').hidden = true; $('authScreen').hidden = false;
    const setup = mode === 'setup';
    $('authMount').innerHTML = setup ? `
      <p class="section-kicker">FIRST-TIME SETUP</p><h1>Create your administrator</h1><p class="auth-subtitle">Secure your workspace before adding students or staff.</p>
      ${error ? `<div class="auth-error" role="alert">${escapeHtml(error)}</div>` : ''}
      <form class="auth-form" id="setupForm">
        <label>Setup key<input type="password" name="setupSecret" required autocomplete="off" placeholder="Enter SETUP_SECRET from your environment"></label>
        <label>Administrator name<input name="name" required maxlength="100" autocomplete="name" placeholder="Full name"></label>
        <label>Email address<input type="email" name="email" required autocomplete="email" placeholder="you@institution.edu"></label>
        <label>Password<input type="password" name="password" required minlength="12" maxlength="128" autocomplete="new-password" placeholder="At least 12 characters"></label>
        <button type="submit" class="button button-primary">Create secure workspace</button>
      </form><div class="security-note"><svg class="i"><use href="#i-lock"/></svg><span>The setup key can only create the first account. Keep it private and remove or rotate it after setup.</span></div>` : `
      <p class="section-kicker">SECURE SIGN IN</p><h1>Welcome back</h1><p class="auth-subtitle">Sign in to manage student attendance and reports.</p>
      ${error ? `<div class="auth-error" role="alert">${escapeHtml(error)}</div>` : ''}
      <form class="auth-form" id="loginForm"><label>Email address<input type="email" name="email" required autocomplete="username" placeholder="you@institution.edu"></label><label>Password<input type="password" name="password" required autocomplete="current-password" placeholder="Your password"></label><button type="submit" class="button button-primary">Sign in</button></form>
      <div class="security-note"><svg class="i"><use href="#i-shield"/></svg><span>Your session is protected by an HttpOnly, secure cookie. Student data is not stored in browser local storage.</span></div>`;
  }
  async function initializeAuth() {
    try {
      await checkApiHealth();
      const status = await api('/api/setup/status', { suppressAuthRedirect: true });
      if (status.setupRequired) {
        if (!status.setupTokenConfigured) renderAuth('setup', 'Server setup is incomplete: set SETUP_SECRET and SESSION_SECRET in the environment first.');
        else renderAuth('setup');
        return;
      }
      try {
        const result = await api('/api/auth/me', { suppressAuthRedirect: true });
        await enterApp(result.user);
      } catch (err) {
        if (err.status === 401) renderAuth('login'); else renderAuth('login', err.message);
      }
    } catch (err) {
      renderAuth('login', `${err.message} Ensure MongoDB is running and the environment variables are configured, then refresh.`);
    }
  }
  function forceSignIn() {
    if (!state.user) return;
    state.user = null; state.session = null; state.dirty = false;
    renderAuth('login', 'Your session has expired. Sign in again to continue.');
  }
  $('authMount').addEventListener('submit', async e => {
    const form = e.target;
    if (form.id !== 'setupForm' && form.id !== 'loginForm') return;
    e.preventDefault(); const data = Object.fromEntries(new FormData(form).entries());
    const submit = form.querySelector('button[type="submit"]'); submit.disabled = true; submit.textContent = form.id === 'setupForm' ? 'Setting up…' : 'Signing in…';
    try {
      const result = form.id === 'setupForm' ? await api('/api/setup', { method: 'POST', body: data, suppressAuthRedirect: true }) : await api('/api/auth/login', { method: 'POST', body: data, suppressAuthRedirect: true });
      await enterApp(result.user); toast(form.id === 'setupForm' ? 'Administrator created. Workspace is ready.' : 'Signed in successfully.', 'success');
    } catch (err) { renderAuth(form.id === 'setupForm' ? 'setup' : 'login', err.message); }
  });

  async function enterApp(user) {
    state.user = user; $('authScreen').hidden = true; $('appShell').hidden = false;
    updateRoleVisibility(); $('todayText').textContent = new Date().toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' });
    document.documentElement.classList.add('reveal-ready'); setupRevealObserver();
    await loadSupportData(); await navigate('overview', { force: true });
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
  async function loadSupportData() {
    try {
      const [classes, years, subjects, settings, timetable, calendar] = await Promise.all([
        api('/api/classes'), api('/api/academic-years'), api('/api/subjects'), api('/api/settings'), api('/api/timetable'), api('/api/calendar')
      ]);
      state.classes = classes.items || []; state.years = years.items || []; state.subjects = subjects.items || []; state.settings = settings; state.timetable = timetable.items || []; state.calendarEvents = calendar.items || [];
      populateSelects(); setConnection(true, `Database connected · ${state.classes.length} classes`);
      $('thresholdForm').elements.attendanceThreshold.value = state.settings.attendanceThreshold || 75;
      if (!settings.mailConfigured) { $('mailStatus').hidden = false; $('mailStatus').textContent = 'Email alerts are not configured. Add the SMTP settings described in README.md to enable delivery.'; }
    } catch (err) { setConnection(false, err.message); toast(err.message, 'error'); }
  }
  function populateSelects() {
    selectOptions($('studentClassFilter'), state.classes, { empty: 'All accessible classes' });
    selectOptions($('attClass'), state.classes, { empty: 'Select a class' });
    selectOptions($('repClass'), state.classes, { empty: 'All accessible classes' });
    selectOptions($('dashboardClass'), state.classes, { empty: 'All accessible classes' });
    selectOptions($('studentClassInput'), state.classes, { empty: 'Select class' });
    selectOptions($('classYear'), state.years, { empty: 'Not specified', value: y => String(y._id), label: y => y.name });
    selectOptions($('subjectYear'), state.years, { empty: 'Not specified', value: y => String(y._id), label: y => y.name });
    selectOptions($('subjectClasses'), state.classes, { value: c => c.name, label: c => c.name, multiple: true });
    selectOptions($('userClasses'), state.classes, { value: c => c.name, label: c => c.name, multiple: true });
    selectOptions($('timetableClass'), state.classes, { empty: 'Select class' });
    selectOptions($('calendarClass'), state.classes, { empty: 'All classes / campus-wide' });
    selectOptions($('timetableSubject'), state.subjects, { empty: 'Daily / general session', value: s => String(s._id), label: s => `${s.code} · ${s.name}` });
    selectOptions($('attSubject'), state.subjects.filter(s => !s.classNames?.length || !state.user || state.user.role === 'admin' || s.classNames.some(c => state.user.classNames.includes(c))), { empty: 'Daily / general attendance', value: s => String(s._id), label: s => `${s.code} · ${s.name}` });
  }

  const PAGE_INFO = {
    overview: ['Overview', 'WORKSPACE'], students: ['Students', 'DIRECTORY'], attendance: ['Attendance', 'DAILY OPERATIONS'],
    reports: ['Reports', 'INSIGHTS'], academics: ['Academics', 'MANAGEMENT'], users: ['Accounts & roles', 'SECURITY'],
    audit: ['Audit history', 'ACCOUNTABILITY'], settings: ['Settings', 'PREFERENCES']
  };
  async function navigate(page, options = {}) {
    if (!PAGE_INFO[page]) return;
    if (!options.force && state.dirty && state.activePage === 'attendance' && page !== 'attendance') {
      if (!confirm('You have unsaved attendance changes. Discard them and leave this page?')) return;
      state.marks = { ...state.originalMarks }; state.dirty = false;
    }
    if (['academics', 'users', 'audit'].includes(page) && !isAdmin()) { toast('This area is available to administrators only.', 'error'); return; }
    state.activePage = page;
    document.querySelectorAll('.page').forEach(el => { const on = el.id === `page-${page}`; el.hidden = !on; el.classList.toggle('active', on); });
    document.querySelectorAll('.nav-link[data-page]').forEach(el => el.classList.toggle('active', el.dataset.page === page));
    $('pageTitle').textContent = PAGE_INFO[page][0]; $('pageEyebrow').textContent = PAGE_INFO[page][1];
    $('sidebar').classList.remove('open'); window.scrollTo({ top: 0, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    requestAnimationFrame(() => observeReveals(document.querySelector(`#page-${page}`)));
    try {
      if (page === 'overview') await loadDashboard();
      if (page === 'students') await loadStudents();
      if (page === 'attendance') { if (!$('attDate').value) $('attDate').value = todayStr(); renderAttendanceEmpty(); }
      if (page === 'reports') { if (!$('repTo').value) $('repTo').value = todayStr(); if (!$('repFrom').value) $('repFrom').value = dateOffset(-29); await runReport(); }
      if (page === 'academics') await loadAcademics();
      if (page === 'users') await loadUsers();
      if (page === 'audit') await loadAudit();
      if (page === 'settings') await loadSettings();
    } catch (err) { toast(err.message, 'error'); }
  }
  document.querySelectorAll('.nav-link').forEach(btn => btn.addEventListener('click', () => navigate(btn.dataset.page)));
  document.querySelectorAll('[data-go]').forEach(btn => btn.addEventListener('click', () => navigate(btn.dataset.go)));
  $('mobileMenuBtn').addEventListener('click', () => $('sidebar').classList.toggle('open'));
  $('logoutBtn').addEventListener('click', async () => {
    if (state.dirty && !confirm('Attendance changes are unsaved. Sign out anyway?')) return;
    try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
    state.user = null; state.session = null; state.dirty = false; renderAuth('login'); toast('You have signed out.', 'success');
  });

  function setupRevealObserver() {
    if (!('IntersectionObserver' in window) || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (!window._attendEaseRevealObserver) window._attendEaseRevealObserver = new IntersectionObserver(entries => {
      entries.forEach(entry => { if (entry.isIntersecting) { entry.target.classList.add('is-visible'); window._attendEaseRevealObserver.unobserve(entry.target); } });
    }, { threshold: .08, rootMargin: '0px 0px -24px 0px' });
  }
  function observeReveals(root = document) {
    root.querySelectorAll?.('.panel,.stats-grid,.stat-card,.page-intro').forEach(el => {
      if (el.classList.contains('reveal-on-scroll')) return;
      el.classList.add('reveal-on-scroll');
      if (!('IntersectionObserver' in window) || matchMedia('(prefers-reduced-motion: reduce)').matches) el.classList.add('is-visible');
      else window._attendEaseRevealObserver?.observe(el);
    });
  }

  // Dashboard
  async function loadDashboard() {
    if (!$('dashboardDate').value) $('dashboardDate').value = todayStr();
    const dashboardDate = $('dashboardDate').value || todayStr(), dashboardClass = $('dashboardClass').value;
    $('dashboardStats').innerHTML = Array.from({ length: 4 }, () => '<div class="skeleton stat-skeleton"></div>').join('');
    const query = new URLSearchParams({ date: dashboardDate }); if (dashboardClass) query.set('className', dashboardClass);
    const data = await api(`/api/dashboard?${query.toString()}`); state.dashboard = data;
    $('welcomeDate').textContent = new Date().toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' }).toUpperCase();
    const hour = new Date().getHours(); $('welcomeTitle').textContent = `${hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening'}, ${state.user.name.split(/\s+/)[0]}.`;
    const cards = [
      { label: 'Active students', value: data.activeStudents, note: 'In accessible classes', icon: 'users', color: '' },
      { label: 'Sessions today', value: data.sessionsToday, note: `${data.finalizedSessionsToday} finalized · ${data.draftSessionsToday} draft`, icon: 'calendar', color: 'blue' },
      { label: 'Finalized attendance', value: data.marksToday.present + data.marksToday.late + data.marksToday.absent, note: `${data.marksToday.present} present · ${data.marksToday.late} late · ${data.marksToday.absent} absent`, icon: 'check-circle', color: 'green' },
      { label: 'Below threshold', value: data.lowAttendance.length, note: `Configured threshold ${data.attendanceThreshold}%`, icon: 'alert', color: 'amber' }
    ];
    $('dashboardStats').innerHTML = cards.map(c => `<article class="stat-card"><div class="stat-top"><span>${c.label}</span><span class="stat-icon ${c.color}"><svg class="i"><use href="#i-${c.icon}"/></svg></span></div><div class="stat-value">${c.value}</div><div class="stat-foot">${escapeHtml(c.note)}</div></article>`).join('');
    $('riskCount').textContent = data.lowAttendance.length;
    $('riskList').innerHTML = data.lowAttendance.length ? data.lowAttendance.slice(0, 5).map(s => `<div class="risk-item"><div class="risk-avatar">${escapeHtml(initial(s.name))}</div><div class="risk-copy"><strong>${escapeHtml(s.name)}</strong><span>${escapeHtml(s.roll)} · ${escapeHtml(s.cls)}</span></div><span class="risk-pct">${s.pct}%</span></div>`).join('') : '<div class="empty-state compact">No students are below the threshold for finalized sessions in the last 90 days.</div>';
    $('trendChart').innerHTML = data.last7.map(d => `<div class="trend-col"><div class="trend-value">${d.pct === null ? '—' : `${d.pct}%`}</div><div class="trend-bar-track"><div class="trend-bar ${d.pct === null ? 'no-data' : ''}" style="height:${d.pct === null ? 3 : Math.max(3, d.pct)}%"></div></div><span class="trend-label">${escapeHtml(fmtDate(d.date))}</span></div>`).join('');
    $('classChart').innerHTML = data.classSummary.length ? data.classSummary.map(c => `<div class="class-chart-item"><div class="class-chart-top"><strong>${escapeHtml(c.className)}</strong><span>${c.averageAttendance===null?'—':`${c.averageAttendance}%`}</span></div><div class="class-chart-track"><div class="class-chart-fill" style="width:${c.averageAttendance===null?0:c.averageAttendance}%"></div></div><div class="class-chart-meta">${c.studentCount} students with finalized marks</div></div>`).join('') : '<div class="empty-state compact">No finalized class data in this period.</div>';
    $('recentSessions').innerHTML = data.recentSessions.length ? data.recentSessions.map(s => `<tr><td>${escapeHtml(s.className)}</td><td><strong>${escapeHtml(s.name)}</strong><div class="muted tiny">${escapeHtml(s.subjectName)}</div></td><td>${fmtDate(s.date, { year: true })}</td><td>${s.marksCount} marks</td><td><span class="status-badge ${s.status === 'finalized' ? 'status-finalized' : 'status-draft'}">${s.status === 'finalized' ? 'Finalized' : 'Draft'}</span></td></tr>`).join('') : '<tr><td colspan="5" class="empty-cell">No sessions found for today. Open Attendance to create one.</td></tr>';
    observeReveals($('page-overview'));
  }
  $('refreshDashboardBtn').addEventListener('click', () => loadDashboard().then(() => toast('Dashboard refreshed.', 'success')).catch(e => toast(e.message, 'error')));
  $('applyDashboardFilters').addEventListener('click', () => loadDashboard().then(() => toast('Dashboard filters applied.', 'success')).catch(e => toast(e.message, 'error')));

  // Student directory, profile, CSV import/export
  async function loadStudents() {
    const params = new URLSearchParams({ page: String(state.studentPage), pageSize: '20' });
    const search = $('studentSearch').value.trim(), className = $('studentClassFilter').value;
    if (search) params.set('search', search); if (className) params.set('className', className);
    params.set('sortBy', $('studentSort').value || 'class');
    state.studentFilters.archived = isAdmin() && $('studentStatusFilter').value === 'archived';
    if (state.studentFilters.archived) params.set('includeArchived', 'true');
    $('studentTable').innerHTML = '<tr><td colspan="6" class="empty-cell"><span class="spinner"></span> Loading students…</td></tr>';
    const data = await api(`/api/students?${params.toString()}`); state.students = data.items; state.studentPages = Math.max(1, data.pages || 1);
    $('studentPageInfo').textContent = data.total ? `Showing ${(data.page - 1) * data.pageSize + 1}–${Math.min(data.page * data.pageSize, data.total)} of ${data.total} students` : 'No students found';
    $('studentPrev').disabled = data.page <= 1; $('studentNext').disabled = data.page >= state.studentPages;
    $('studentNotice').hidden = true;
    $('studentTable').innerHTML = data.items.length ? data.items.map(s => `<tr><td><div class="student-cell"><div class="student-initial">${escapeHtml(initial(s.name))}</div><div><strong>${escapeHtml(s.name)}</strong><small>${escapeHtml(s.email || 'No email on file')}</small></div></div></td><td>${escapeHtml(s.roll)}</td><td>${escapeHtml(s.cls)}</td><td>${fmtDate(s.enrolledOn, { year: true })}</td><td><span class="status-badge ${s.active === false ? 'status-archived' : 'status-finalized'}">${s.active === false ? 'Archived' : 'Active'}</span></td><td><div class="row-actions"><button class="button button-secondary button-small" data-student-profile="${s._id}">View</button>${canWrite() && s.active !== false ? `<button class="button button-secondary button-small" data-student-edit="${s._id}">Edit</button><button class="button button-danger button-small" data-student-archive="${s._id}">Archive</button>` : ''}${isAdmin() && s.active === false ? `<button class="button button-secondary button-small" data-student-restore="${s._id}">Restore</button>` : ''}</div></td></tr>`).join('') : '<tr><td colspan="6" class="empty-cell">No students match these filters. Add a student or import a CSV register.</td></tr>';
    observeReveals($('page-students'));
  }
  $('studentSearchBtn').addEventListener('click', () => { state.studentPage = 1; loadStudents().catch(e => toast(e.message, 'error')); });
  $('studentSearch').addEventListener('keydown', e => { if (e.key === 'Enter') { state.studentPage = 1; loadStudents().catch(err => toast(err.message, 'error')); } });
  $('studentClassFilter').addEventListener('change', () => { state.studentPage = 1; loadStudents().catch(e => toast(e.message, 'error')); });
  $('studentSort').addEventListener('change', () => { state.studentPage = 1; loadStudents().catch(e => toast(e.message, 'error')); });
  $('studentStatusFilter').addEventListener('change', () => { state.studentPage = 1; loadStudents().catch(e => toast(e.message, 'error')); });
  $('studentPrev').addEventListener('click', () => { state.studentPage = Math.max(1, state.studentPage - 1); loadStudents().catch(e => toast(e.message, 'error')); });
  $('studentNext').addEventListener('click', () => { state.studentPage = Math.min(state.studentPages, state.studentPage + 1); loadStudents().catch(e => toast(e.message, 'error')); });
  $('studentTable').addEventListener('click', async e => {
    const button = e.target.closest('button[data-student-profile],button[data-student-edit],button[data-student-archive],button[data-student-restore]'); if (!button) return;
    const id = button.dataset.studentProfile || button.dataset.studentEdit || button.dataset.studentArchive || button.dataset.studentRestore;
    try {
      if (button.dataset.studentProfile) await showStudentProfile(id);
      if (button.dataset.studentEdit) openStudentDialog(state.students.find(s => String(s._id) === id));
      if (button.dataset.studentArchive && confirm('Archive this student? Their attendance history will be retained and the record can be restored by an administrator.')) { await api(`/api/students/${id}/archive`, { method: 'POST', body: {} }); toast('Student archived; historical attendance retained.', 'success'); await loadStudents(); }
      if (button.dataset.studentRestore && confirm('Restore this archived student?')) { await api(`/api/students/${id}/restore`, { method: 'POST', body: {} }); toast('Student restored.', 'success'); await loadStudents(); }
    } catch (err) { toast(err.message, 'error'); }
  });
  function openStudentDialog(student = null) {
    const form = $('studentForm'); form.reset(); form.elements.id.value = student?._id || '';
    $('studentDialogTitle').textContent = student ? 'Edit student' : 'Add student';
    $('studentSaveBtn').textContent = student ? 'Save changes' : 'Save student';
    if (student) { form.elements.roll.value = student.roll || ''; form.elements.name.value = student.name || ''; form.elements.cls.value = student.cls || ''; form.elements.email.value = student.email || ''; form.elements.enrolledOn.value = student.enrolledOn || ''; }
    else form.elements.enrolledOn.value = todayStr();
    $('studentDialog').showModal();
  }
  $('addStudentBtn').addEventListener('click', () => openStudentDialog());
  $('studentForm').addEventListener('submit', async e => {
    e.preventDefault(); const f = e.currentTarget, id = f.elements.id.value;
    const payload = { roll: f.elements.roll.value, name: f.elements.name.value, cls: f.elements.cls.value, email: f.elements.email.value, enrolledOn: f.elements.enrolledOn.value };
    const btn = $('studentSaveBtn'); btn.disabled = true;
    try {
      await api(id ? `/api/students/${id}` : '/api/students', { method: id ? 'PUT' : 'POST', body: payload });
      $('studentDialog').close(); toast(id ? 'Student updated.' : 'Student created.', 'success'); await loadStudents(); await loadSupportData();
    } catch (err) { toast(err.message, 'error'); } finally { btn.disabled = false; }
  });
  async function showStudentProfile(id) {
    $('profileContent').innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading student history…</div>'; $('profileDialog').showModal();
    const data = await api(`/api/students/${id}`), s = data.student;
    $('profileTitle').textContent = s.name;
    const stats = { P:0, A:0, L:0, E:0 }; data.history.filter(h => h.sessionStatus === 'finalized').forEach(h => { if (stats[h.status] !== undefined) stats[h.status]++; });
    const counted = stats.P + stats.A + stats.L, pct = counted ? Math.round((stats.P + stats.L) / counted * 100) : null;
    $('profileContent').innerHTML = `<div class="profile-grid"><div class="profile-field"><span>Roll number</span><strong>${escapeHtml(s.roll)}</strong></div><div class="profile-field"><span>Class</span><strong>${escapeHtml(s.cls)}</strong></div><div class="profile-field"><span>Email</span><strong>${escapeHtml(s.email || 'Not provided')}</strong></div><div class="profile-field"><span>Enrolled on</span><strong>${fmtDate(s.enrolledOn, { year: true })}</strong></div><div class="profile-field"><span>Attendance (finalized history shown)</span><strong>${pct === null ? 'No finalized marks' : `${pct}%`}</strong></div><div class="profile-field"><span>Marks counted</span><strong>${counted} sessions</strong></div></div><div class="profile-history"><h3>Recent attendance history</h3><div class="table-wrap"><table><thead><tr><th>Date</th><th>Session</th><th>Subject</th><th>Status</th></tr></thead><tbody>${data.history.length ? data.history.map(h => `<tr><td>${fmtDate(h.date,{year:true})}</td><td>${escapeHtml(h.sessionName)}</td><td>${escapeHtml(h.subjectName || 'Daily')}</td><td><span class="status-badge ${h.sessionStatus === 'finalized' ? 'status-finalized' : 'status-draft'}">${escapeHtml(STATUS[h.status] || 'Unmarked')}${h.sessionStatus !== 'finalized' ? ' · Draft' : ''}</span></td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No attendance history found.</td></tr>'}</tbody></table></div></div>`;
  }
  $('exportStudentsBtn').addEventListener('click', async () => {
    try { const resp = await fetch('/api/students/export.csv', { credentials: 'same-origin' }); if (!resp.ok) throw new Error('Could not export student register.'); const blob = await resp.blob(); downloadBlob(blob, `attendease_students_${todayStr()}.csv`); toast('Student CSV exported.', 'success'); }
    catch (e) { toast(e.message, 'error'); }
  });
  $('importStudentsBtn').addEventListener('click', () => $('importFile').click());
  $('importFile').addEventListener('change', async e => {
    const file = e.target.files?.[0]; if (!file) return; e.target.value = '';
    if (file.size > 5 * 1024 * 1024) return toast('CSV must be 5 MB or smaller.', 'error');
    try {
      const text = await file.text(), grid = parseCsv(text); if (grid.length < 2) return toast('CSV needs a header and at least one data row.', 'error');
      const headers = grid[0].map(v => v.trim().toLowerCase().replace(/[ _-]+/g,''));
      const locate = (...names) => headers.findIndex(h => names.includes(h));
      const indexes = { roll: locate('roll','rollno','rollnumber','studentid'), name: locate('name','fullname','studentname'), cls: locate('cls','class','section','classsection'), email: locate('email','emailaddress'), enrolledOn: locate('enrolledon','enrollmentdate') };
      if (indexes.roll < 0 || indexes.name < 0 || indexes.cls < 0) return toast('CSV headers must include roll, name and class (cls).', 'error');
      const records = grid.slice(1).filter(row => row.some(v => v.trim())).map(row => Object.fromEntries(Object.entries(indexes).filter(([,idx]) => idx >= 0).map(([key,idx]) => [key, row[idx] || ''])));
      if (records.length > 500) return toast('Import at most 500 students per CSV file.', 'error');
      setBusy(true, `Importing ${records.length} students…`);
      const result = await api('/api/students/import', { method:'POST', body: { records } }); setBusy(false);
      const note = `${result.inserted} students imported; ${result.skipped} skipped.`;
      $('studentNotice').hidden = false; $('studentNotice').className = `inline-notice ${result.skipped ? '' : 'success'}`; $('studentNotice').textContent = result.errors?.length ? `${note} First issues: ${result.errors.slice(0,5).map(x=>`row ${x.row}: ${x.error}`).join(' · ')}` : note;
      toast(note, result.skipped ? 'info' : 'success'); state.studentPage = 1; await loadStudents();
    } catch (err) { setBusy(false); toast(err.message, 'error'); }
  });
  function parseCsv(text) {
    const rows = []; let row = [], field = '', quote = false;
    const input = text.replace(/^\uFEFF/, '');
    for (let i=0;i<input.length;i++) { const c=input[i]; if (quote) { if (c==='"' && input[i+1]==='"') { field+='"'; i++; } else if (c==='"') quote=false; else field+=c; }
      else if (c==='"') quote=true; else if (c===',') { row.push(field); field=''; } else if (c==='\n') { row.push(field.replace(/\r$/,'')); rows.push(row); row=[]; field=''; } else field+=c; }
    if (field.length || row.length) { row.push(field.replace(/\r$/,'')); rows.push(row); }
    return rows;
  }
  function downloadBlob(blob, name) { const url = URL.createObjectURL(blob), a = document.createElement('a'); a.href=url; a.download=name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url), 1000); }

  // Attendance session flow
  function renderAttendanceEmpty() {
    if (state.session && state.activePage === 'attendance') { renderAttendanceRegister(); return; }
    $('attTable').innerHTML = '<tr><td colspan="3" class="empty-cell">Choose a date and class, then select Load / create.</td></tr>';
  }
  async function loadSession() {
    const date = $('attDate').value, className = $('attClass').value, subjectId = $('attSubject').value, name = $('attSessionName').value.trim() || 'Daily attendance';
    if (!date || !className) return toast('Choose a date and class first.', 'error');
    if (state.dirty && !confirm('Discard your unsaved marks and load another session?')) return;
    state.dirty = false; setBusy(true, 'Loading attendance register…');
    try {
      const query = new URLSearchParams({ date, className }); if (subjectId) query.set('subjectId', subjectId);
      const existing = await api(`/api/sessions?${query.toString()}`);
      let session = existing.items.find(s => s.name.toLowerCase() === name.toLowerCase());
      if (!session) {
        try { const payload = { date, className, name, subjectId: subjectId || undefined, holidayOverrideReason: $('holidayOverrideReason').value.trim() || undefined }; if (state.pendingScheduleId) payload.scheduleId = state.pendingScheduleId; const created = await api('/api/sessions', { method:'POST', body:payload }); session = created.session; toast('New draft session created.', 'success'); }
        catch (err) { if (err.status !== 409 || !err.data?.session) throw err; session = err.data.session; }
      }
      const sessionsForChooser = existing.items.some(item => String(item._id) === String(session._id)) ? existing.items : [session, ...existing.items];
      await loadSessionRecord(session._id, sessionsForChooser); state.pendingScheduleId = null; await refreshCalendarNotice();
      setBusy(false);
    } catch (err) { setBusy(false); toast(err.message, 'error'); }
  }
  async function loadSessionRecord(id, sameDaySessions = null) {
    if (state.dirty && !confirm('Discard unsaved attendance marks?')) return;
    state.dirty = false;
    const data = await api(`/api/sessions/${id}/attendance`); state.session = data.session; state.roster = data.students;
    state.marks = Object.fromEntries(data.students.filter(s => s.status).map(s => [String(s._id), s.status]));
    state.originalMarks = { ...state.marks };
    $('attDate').value = state.session.date; $('attClass').value = state.session.className;
    $('attSubject').value = state.session.subjectId ? String(state.session.subjectId) : '';
    $('attSessionName').value = state.session.name;
    if (sameDaySessions) {
      $('sessionChooserWrap').hidden = sameDaySessions.length === 0;
      selectOptions($('sessionChooser'), sameDaySessions, { value: s => String(s._id), label: s => `${s.name} · ${s.subjectName || 'Daily'} · ${s.status === 'finalized' ? 'Finalized' : 'Draft'}` });
      $('sessionChooser').value = String(id);
    } else $('sessionChooserWrap').hidden = true;
    renderAttendanceRegister();
  }
  function marksEqual(a,b) { const ids = new Set([...Object.keys(a||{}),...Object.keys(b||{})]); for (const id of ids) if ((a[id]||'') !== (b[id]||'')) return false; return true; }
  function renderAttendanceRegister() {
    if (!state.session) return renderAttendanceEmpty();
    const locked = state.session.status === 'finalized';
    $('attendanceSessionTitle').textContent = `${state.session.className} · ${state.session.name}`;
    $('attendanceSessionMeta').textContent = `${fmtDate(state.session.date, {year:true})}${state.session.subjectName ? ` · ${state.session.subjectName}` : ' · Daily attendance'} · ${state.roster.length} active students`;
    $('attendanceSessionStatus').innerHTML = `<span class="status-badge ${locked?'status-finalized':'status-draft'}">${locked?'Finalized':'Draft session'}</span>`;
    $('attendanceToolbar').hidden = locked || !canWrite(); $('attendanceCompletion').hidden = false; $('attendanceFooter').hidden = false;
    $('reopenBtn').hidden = !(locked && isAdmin()); $('saveDraftBtn').hidden = locked || !canWrite(); $('finalizeBtn').hidden = locked || !canWrite();
    $('saveDraftBtn').disabled = !state.dirty; $('unsavedText').textContent = state.dirty ? 'Unsaved changes' : 'All changes saved.'; $('unsavedText').classList.toggle('dirty', state.dirty);
    $('attTable').innerHTML = state.roster.length ? state.roster.map(s => {
      const status = state.marks[String(s._id)] || '';
      const buttons = ['P','L','A','E'].map(code => `<button type="button" class="mark-button ${status===code?'selected':''}" data-status="${code}" data-student="${s._id}" aria-pressed="${status===code?'true':'false'}" ${locked || !canWrite() ? 'disabled' : ''}>${STATUS[code]}</button>`).join('');
      return `<tr><td><div class="student-cell"><div class="student-initial">${escapeHtml(initial(s.name))}</div><div><strong>${escapeHtml(s.name)}</strong><small>${escapeHtml(s.cls)}</small></div></div></td><td>${escapeHtml(s.roll)}</td><td><div class="attendance-markers">${buttons}</div></td></tr>`;
    }).join('') : '<tr><td colspan="3" class="empty-cell">There are no active students in this class.</td></tr>';
    updateAttendanceCompletion();
  }
  function updateAttendanceCompletion() {
    const total = state.roster.length, marked = state.roster.filter(s => STATUS[state.marks[String(s._id)]]).length, pct = total ? Math.round(marked/total*100) : 0;
    $('completionText').textContent = `${marked} of ${total} students marked`; $('completionPct').textContent = `${pct}% complete`; $('completionBar').style.width = `${pct}%`;
    $('saveDraftBtn').disabled = !state.dirty || !canWrite() || state.session?.status === 'finalized';
    $('unsavedText').textContent = state.dirty ? 'Unsaved changes' : 'All changes saved.'; $('unsavedText').classList.toggle('dirty', state.dirty);
  }
  $('loadSessionBtn').addEventListener('click', loadSession);
  $('sessionChooser').addEventListener('change', async e => { if (e.target.value) { try { await loadSessionRecord(e.target.value); } catch (err) { toast(err.message,'error'); } } });
  ['attDate','attClass','attSubject','attSessionName'].forEach(id => $(id).addEventListener('change', () => { if (state.dirty) toast('Unsaved marks are still in memory. Save the draft before loading another session.', 'info'); }));
  $('attTable').addEventListener('click', e => {
    const btn = e.target.closest('button[data-status]'); if (!btn || btn.disabled) return;
    const id = btn.dataset.student, status = btn.dataset.status;
    if (state.marks[id] === status) delete state.marks[id]; else state.marks[id] = status;
    state.dirty = !marksEqual(state.marks, state.originalMarks);
    btn.parentElement.querySelectorAll('button[data-status]').forEach(other => {
      const selected = state.marks[id] === other.dataset.status;
      other.classList.toggle('selected', selected); other.setAttribute('aria-pressed', selected ? 'true' : 'false');
    });
    updateAttendanceCompletion();
  });
  $('markAllPresent').addEventListener('click', () => bulkMark('P'));
  $('markAllAbsent').addEventListener('click', () => bulkMark('A'));
  $('clearMarksBtn').addEventListener('click', () => { state.marks = {}; state.dirty = !marksEqual(state.marks,state.originalMarks); renderAttendanceRegister(); });
  function bulkMark(status) { state.roster.forEach(s => { state.marks[String(s._id)] = status; }); state.dirty = !marksEqual(state.marks,state.originalMarks); renderAttendanceRegister(); }
  async function saveDraft() {
    if (!state.session) return toast('Load or create a session first.', 'error');
    const records = state.roster.filter(s => STATUS[state.marks[String(s._id)]]).map(s => ({ studentId:String(s._id), status:state.marks[String(s._id)] }));
    setBusy(true,'Saving draft…');
    try { const result = await api(`/api/sessions/${state.session._id}/attendance`, { method:'PUT', body:{ records } }); state.originalMarks = { ...state.marks }; state.dirty = false; state.session.updatedAt = new Date().toISOString(); renderAttendanceRegister(); toast(`Draft saved. ${result.marked} of ${result.totalActiveStudents} students marked.`, 'success'); await loadDashboardQuiet(); }
    catch (err) { toast(err.message,'error'); return false; } finally { setBusy(false); }
    return true;
  }
  $('saveDraftBtn').addEventListener('click', saveDraft);
  $('finalizeBtn').addEventListener('click', async () => {
    if (!state.session) return;
    const unmarked = state.roster.filter(s => !STATUS[state.marks[String(s._id)]]);
    if (unmarked.length) { toast(`${unmarked.length} students are unmarked. Every student needs Present, Late, Absent or Excused status.`, 'error'); const first = $('attTable').querySelector('button[data-status]'); first?.focus(); return; }
    if (!confirm('Finalize this session? It will be included in reports and locked against further changes.')) return;
    try {
      if (state.dirty) { const saved = await saveDraft(); if (!saved) return; }
      setBusy(true,'Finalizing attendance…'); const result = await api(`/api/sessions/${state.session._id}/finalize`,{method:'POST',body:{}});
      state.session.status='finalized';state.dirty=false;state.originalMarks={...state.marks};renderAttendanceRegister();toast(result.message,'success');await loadDashboardQuiet();
    } catch(err){toast(err.message,'error');} finally {setBusy(false);}
  });
  $('reopenBtn').addEventListener('click', async () => {
    if (!state.session || !isAdmin()) return;
    const reason = prompt('Why must this finalized session be reopened? This reason is saved in the audit history.');
    if (reason === null) return;
    try { const result = await api(`/api/sessions/${state.session._id}/reopen`,{method:'POST',body:{reason}}); toast(result.message,'success'); await loadSessionRecord(state.session._id); }
    catch(err){toast(err.message,'error');}
  });
  async function loadDashboardQuiet() { if (state.activePage === 'overview') return loadDashboard(); }

  // Reports: only finalized sessions are included by the backend.
  async function runReport() {
    const from = $('repFrom').value, to = $('repTo').value, className = $('repClass').value;
    if (from && to && from > to) return toast('Start date must be on or before the end date.', 'error');
    $('repTable').innerHTML = '<tr><td colspan="9" class="empty-cell">Generating report…</td></tr>';
    const params = new URLSearchParams(); if (from) params.set('from',from); if (to) params.set('to',to); if (className) params.set('className',className);
    const data = await api(`/api/reports/attendance?${params.toString()}`); state.report = data;
    const s = data.summary;
    $('reportMetrics').innerHTML = [
      ['Active students',s.studentCount],['Average attendance',s.averageAttendance===null?'—':`${s.averageAttendance}%`],['Finalized sessions',s.finalizedSessions],['Counted marks',s.days]
    ].map(([label,value])=>`<div class="metric-box"><span>${label}</span><strong>${value}</strong></div>`).join('');
    $('repTable').innerHTML = data.rows.length ? data.rows.map(r=>`<tr><td>${escapeHtml(r.roll)}</td><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.cls)}</td><td>${r.present}</td><td>${r.late}</td><td>${r.absent}</td><td>${r.excused}</td><td>${r.days}</td><td><span class="status-badge ${r.pct===null?'status-draft':r.pct<state.settings.attendanceThreshold?'status-low':r.pct<85?'status-warn':'status-good'}">${r.pct===null?'No data':`${r.pct}%`}</span></td></tr>`).join('') : '<tr><td colspan="9" class="empty-cell">No students or finalized sessions match the chosen filters.</td></tr>';
    observeReveals($('page-reports'));
  }
  $('repRun').addEventListener('click', () => runReport().catch(e => toast(e.message,'error')));
  $('reportCsvBtn').addEventListener('click', () => {
    if (!state.report) return toast('Generate a report first.', 'error');
    const r = state.report, header = ['Roll','Name','Class','Present','Late','Absent','Excused','Counted sessions','Attendance %'];
    const rows = r.rows.map(s=>[s.roll,s.name,s.cls,s.present,s.late,s.absent,s.excused,s.days,s.pct===null?'':s.pct]);
    downloadBlob(new Blob(['\ufeff'+[header,...rows].map(row=>row.map(csvQuote).join(',')).join('\r\n')],{type:'text/csv;charset=utf-8'}),`attendease_report_${r.filters.from||'start'}_${r.filters.to||todayStr()}.csv`);
    toast('Report CSV exported.', 'success');
  });
  function csvQuote(value) { let text=String(value ?? ''); if (/^[\s]*[=+@\-]/.test(text)) text=`'${text}`; return `"${text.replace(/"/g,'""')}"`; }
  $('reportPrintBtn').addEventListener('click', () => { if (!state.report) return toast('Generate a report first.', 'error'); window.print(); });

  // Academic administration
  async function loadAcademics() {
    await loadSupportData();
    $('yearList').innerHTML = state.years.length ? state.years.map(y=>`<div class="simple-list-item"><div class="list-main"><strong>${escapeHtml(y.name)} ${y.isCurrent?'<span class="admin-badge">Current</span>':''}</strong><small>${fmtDate(y.startDate,{year:true})} – ${fmtDate(y.endDate,{year:true})}</small></div>${!y.isCurrent?`<button class="button button-small button-secondary" data-year-current="${y._id}">Set current</button>`:''}</div>`).join('') : '<div class="empty-state compact">No academic years created.</div>';
    $('classList').innerHTML = state.classes.length ? state.classes.map(c=>`<div class="simple-list-item"><div class="list-main"><strong>${escapeHtml(c.name)}</strong><small>${escapeHtml(state.years.find(y=>String(y._id)===String(c.academicYearId))?.name || 'No academic year')}</small></div><div class="list-actions"><button class="button button-small button-secondary" data-class-rename="${c._id}">Rename</button><button class="button button-small button-danger" data-class-archive="${c._id}">Archive</button></div></div>`).join('') : '<div class="empty-state compact">No active classes. Add your first class above.</div>';
    $('subjectList').innerHTML = state.subjects.length ? state.subjects.map(s=>`<div class="simple-list-item"><div class="list-main"><strong>${escapeHtml(s.code)} · ${escapeHtml(s.name)}</strong><small>${escapeHtml((s.classNames||[]).join(', '))}</small></div><div class="list-actions"><button class="button button-small button-secondary" data-subject-edit="${s._id}">Edit</button><button class="button button-small button-danger" data-subject-archive="${s._id}">Archive</button></div></div>`).join('') : '<div class="empty-state compact">No subjects configured.</div>';
    $('timetableList').innerHTML = state.timetable.length ? state.timetable.map(t=>`<div class="simple-list-item"><div class="list-main"><strong><span class="timetable-day-chip">${escapeHtml(t.dayName || ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][t.dayOfWeek])}</span>${escapeHtml(t.startTime)}–${escapeHtml(t.endTime)} · ${escapeHtml(t.name)}</strong><small>${escapeHtml(t.className)} · ${escapeHtml(t.subjectName || 'Daily / general')}${t.room ? ` · ${escapeHtml(t.room)}` : ''}</small></div><div class="timetable-actions"><button class="button button-small button-primary" data-schedule-use="${t._id}">Use in attendance</button><button class="button button-small button-secondary" data-timetable-edit="${t._id}">Edit</button><button class="button button-small button-danger" data-timetable-archive="${t._id}">Archive</button></div></div>`).join('') : '<div class="empty-state compact">No timetable slots yet. Add a recurring class slot above.</div>';
    $('calendarList').innerHTML = state.calendarEvents.length ? state.calendarEvents.map(c=>`<div class="simple-list-item"><div class="list-main"><strong><span class="timetable-day-chip">${c.type==='holiday'?'HOLIDAY':'WORKING DAY'}</span>${fmtDate(c.date,{year:true})} · ${escapeHtml(c.name)}</strong><small>${escapeHtml(c.className || 'All classes / campus-wide')}${c.note ? ` · ${escapeHtml(c.note)}` : ''}</small></div><div class="list-actions"><button class="button button-small button-secondary" data-calendar-edit="${c._id}">Edit</button><button class="button button-small button-danger" data-calendar-archive="${c._id}">Archive</button></div></div>`).join('') : '<div class="empty-state compact">No calendar events added yet.</div>';
    observeReveals($('page-academics'));
  }
  $('yearForm').addEventListener('submit', async e => { e.preventDefault(); const f=e.currentTarget,p=Object.fromEntries(new FormData(f).entries());p.isCurrent=f.elements.isCurrent.checked;try{await api('/api/academic-years',{method:'POST',body:p});f.reset();toast('Academic year added.','success');await loadAcademics();}catch(err){toast(err.message,'error');} });
  $('yearList').addEventListener('click', async e=>{const b=e.target.closest('[data-year-current]');if(!b)return;const y=state.years.find(x=>String(x._id)===b.dataset.yearCurrent);if(!y)return;try{await api(`/api/academic-years/${y._id}`,{method:'PUT',body:{...y,isCurrent:true}});toast('Current academic year updated.','success');await loadAcademics();}catch(err){toast(err.message,'error');}});
  $('classForm').addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,p=Object.fromEntries(new FormData(f).entries());try{await api('/api/classes',{method:'POST',body:p});f.reset();toast('Class added.','success');await loadAcademics();await loadSupportData();}catch(err){toast(err.message,'error');}});
  $('classList').addEventListener('click',async e=>{const r=e.target.closest('[data-class-rename]'),a=e.target.closest('[data-class-archive]');if(r){const c=state.classes.find(x=>String(x._id)===r.dataset.classRename);const name=prompt('Rename class:',c?.name||'');if(name===null||!name.trim())return;try{await api(`/api/classes/${c._id}`,{method:'PUT',body:{...c,name:name.trim()}});toast('Class renamed.','success');await loadAcademics();await loadSupportData();}catch(err){toast(err.message,'error');}}if(a){const c=state.classes.find(x=>String(x._id)===a.dataset.classArchive);if(!c||!confirm(`Archive ${c.name}? Existing student and attendance records will remain available in history.`))return;try{await api(`/api/classes/${c._id}/archive`,{method:'POST',body:{}});toast('Class archived.','success');await loadAcademics();await loadSupportData();}catch(err){toast(err.message,'error');}}});
  $('subjectForm').addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,p=Object.fromEntries(new FormData(f).entries());p.classNames=[...f.elements.classNames.selectedOptions].map(o=>o.value);try{await api('/api/subjects',{method:'POST',body:p});f.reset();toast('Subject added.','success');await loadAcademics();await loadSupportData();}catch(err){toast(err.message,'error');}});
  $('subjectList').addEventListener('click',async e=>{const a=e.target.closest('[data-subject-archive]'),ed=e.target.closest('[data-subject-edit]');if(a){const s=state.subjects.find(x=>String(x._id)===a.dataset.subjectArchive);if(!s||!confirm(`Archive ${s.name}? Historical sessions will be retained.`))return;try{await api(`/api/subjects/${s._id}/archive`,{method:'POST',body:{}});toast('Subject archived.','success');await loadAcademics();await loadSupportData();}catch(err){toast(err.message,'error');}}if(ed){const s=state.subjects.find(x=>String(x._id)===ed.dataset.subjectEdit);if(!s)return;const name=prompt('Subject name:',s.name);if(name===null)return;const code=prompt('Subject code:',s.code);if(code===null)return;try{await api(`/api/subjects/${s._id}`,{method:'PUT',body:{...s,name,code}});toast('Subject updated.','success');await loadAcademics();await loadSupportData();}catch(err){toast(err.message,'error');}}});
  function resetTimetableForm() { $('timetableForm').reset(); $('timetableId').value = ''; $('timetableSubmit').textContent = 'Add timetable slot'; $('timetableCancel').hidden = true; }
  $('timetableForm').addEventListener('submit', async e => {
    e.preventDefault(); const form=e.currentTarget; const id=$('timetableId').value;
    const payload=Object.fromEntries(new FormData(form).entries()); delete payload.id; payload.dayOfWeek=Number(payload.dayOfWeek); payload.subjectId=payload.subjectId||null;
    try { await api(id?`/api/timetable/${id}`:'/api/timetable',{method:id?'PUT':'POST',body:payload}); resetTimetableForm(); toast(id?'Timetable slot updated.':'Timetable slot added.','success'); await loadSupportData(); await loadAcademics(); }
    catch(err){toast(err.message,'error');}
  });
  $('timetableCancel').addEventListener('click',resetTimetableForm);
  $('timetableList').addEventListener('click',async e=>{
    const edit=e.target.closest('[data-timetable-edit]'), archive=e.target.closest('[data-timetable-archive]'), use=e.target.closest('[data-schedule-use]');
    if(edit){const item=state.timetable.find(t=>String(t._id)===edit.dataset.timetableEdit);if(!item)return; $('timetableId').value=String(item._id);$('timetableClass').value=item.className;$('timetableSubject').value=item.subjectId?String(item.subjectId):'';$('timetableDay').value=String(item.dayOfWeek);$('timetableStart').value=item.startTime;$('timetableEnd').value=item.endTime;$('timetableName').value=item.name;$('timetableRoom').value=item.room||'';$('timetableSubmit').textContent='Save timetable changes';$('timetableCancel').hidden=false;$('timetableForm').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'});return;}
    if(archive){const item=state.timetable.find(t=>String(t._id)===archive.dataset.timetableArchive);if(!item||!confirm(`Archive the ${item.dayName} ${item.startTime} slot for ${item.className}? Existing attendance sessions are retained.`))return;try{await api(`/api/timetable/${item._id}/archive`,{method:'POST',body:{}});toast('Timetable slot archived.','success');await loadSupportData();await loadAcademics();}catch(err){toast(err.message,'error');}return;}
    if(use){const item=state.timetable.find(t=>String(t._id)===use.dataset.scheduleUse);if(!item)return;state.pendingScheduleId=String(item._id);await navigate('attendance');$('attDate').value=nextScheduleDate(item);$('attClass').value=item.className;$('attSubject').value=item.subjectId?String(item.subjectId):'';$('attSessionName').value=item.name;await refreshCalendarNotice();if(!$('holidayOverrideWrap').hidden&&!$('holidayOverrideReason').value.trim()){toast('This date is a holiday. Enter an override reason, then use Load / create.','info');return;}await loadSession();}
  });
  function nextScheduleDate(item) { const d=new Date(); let offset=(Number(item.dayOfWeek)-d.getDay()+7)%7; const time=`${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`; if(offset===0 && time>String(item.startTime||'00:00')) offset=7; d.setDate(d.getDate()+offset); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; }

  function resetCalendarForm() { $('calendarForm').reset(); $('calendarId').value=''; $('calendarDate').value=todayStr(); $('calendarType').value='holiday'; $('calendarSubmit').textContent='Add calendar event'; $('calendarCancel').hidden=true; }
  $('calendarDate').value=todayStr();
  $('calendarForm').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget,id=$('calendarId').value,payload=Object.fromEntries(new FormData(form).entries());delete payload.id;payload.className=payload.className||'';try{await api(id?`/api/calendar/${id}`:'/api/calendar',{method:id?'PUT':'POST',body:payload});resetCalendarForm();toast(id?'Calendar event updated.':'Calendar event added.','success');await loadSupportData();await loadAcademics();await refreshCalendarNotice();}catch(err){toast(err.message,'error');}});
  $('calendarCancel').addEventListener('click',resetCalendarForm);
  $('calendarList').addEventListener('click',async e=>{const edit=e.target.closest('[data-calendar-edit]'),archive=e.target.closest('[data-calendar-archive]');if(edit){const item=state.calendarEvents.find(c=>String(c._id)===edit.dataset.calendarEdit);if(!item)return;$('calendarId').value=String(item._id);$('calendarDate').value=item.date;$('calendarName').value=item.name;$('calendarType').value=item.type;$('calendarClass').value=item.className||'';$('calendarNote').value=item.note||'';$('calendarSubmit').textContent='Save calendar changes';$('calendarCancel').hidden=false;$('calendarForm').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'});return;}if(archive){const item=state.calendarEvents.find(c=>String(c._id)===archive.dataset.calendarArchive);if(!item||!confirm(`Archive “${item.name}” on ${item.date}? Past sessions and audit records will be retained.`))return;try{await api(`/api/calendar/${item._id}/archive`,{method:'POST',body:{}});toast('Calendar event archived.','success');await loadSupportData();await loadAcademics();await refreshCalendarNotice();}catch(err){toast(err.message,'error');}}});
  async function refreshCalendarNotice() {
    const date=$('attDate').value,className=$('attClass').value;
    if(!date||!className){$('calendarNotice').hidden=true;$('holidayOverrideWrap').hidden=true;return;}
    try {
      const params=new URLSearchParams({date,className}),data=await api(`/api/calendar?${params.toString()}`);
      const holiday=(data.items||[]).find(item=>item.type==='holiday');
      if(holiday){$('calendarNotice').hidden=false;$('calendarNotice').className='inline-notice warning';$('calendarNotice').textContent=`${holiday.name} is marked as a holiday for ${holiday.className||'all classes'}. To create a session anyway, enter an approved reason below.`;$('holidayOverrideWrap').hidden=false;}
      else {const working=(data.items||[]).find(item=>item.type==='working-day');$('calendarNotice').hidden=!working;$('calendarNotice').className='inline-notice';$('calendarNotice').textContent=working?`${working.name} is recorded as an exceptional working day.`:'';$('holidayOverrideWrap').hidden=true;$('holidayOverrideReason').value='';}
    } catch(err){$('calendarNotice').hidden=false;$('calendarNotice').className='inline-notice error';$('calendarNotice').textContent=`Calendar could not be checked: ${err.message}`;}
  }
  $('attDate').addEventListener('change',()=>refreshCalendarNotice());
  $('attClass').addEventListener('change',()=>refreshCalendarNotice());

  // Users and audit trail
  async function loadUsers() {
    const data=await api('/api/users');state.users=data.items;
    $('userList').innerHTML=data.items.length?data.items.map(u=>`<div class="simple-list-item"><div class="avatar">${escapeHtml(initial(u.name))}</div><div class="list-main"><strong>${escapeHtml(u.name)} ${u.active===false?'<span class="admin-badge">Inactive</span>':''}</strong><small>${escapeHtml(u.email)} · ${escapeHtml(u.role)}${u.role!=='admin'?` · ${escapeHtml((u.classNames||[]).join(', ')||'No class access')}`:''}</small></div><div class="list-actions"><button class="button button-small button-secondary" data-user-role="${u.id}">Role</button><button class="button button-small ${u.active===false?'button-secondary':'button-danger'}" data-user-toggle="${u.id}" data-active="${u.active===false?'false':'true'}">${u.active===false?'Activate':'Deactivate'}</button></div></div>`).join(''):'<div class="empty-state compact">No accounts found.</div>';
  }
  $('refreshUsersBtn').addEventListener('click',()=>loadUsers().catch(e=>toast(e.message,'error')));
  $('userForm').addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,p=Object.fromEntries(new FormData(f).entries());p.classNames=[...f.elements.classNames.selectedOptions].map(o=>o.value);try{await api('/api/users',{method:'POST',body:p});f.reset();toast('Account created. Share the temporary password securely.','success');await loadUsers();}catch(err){toast(err.message,'error');}});
  $('userList').addEventListener('click',async e=>{const toggle=e.target.closest('[data-user-toggle]'),role=e.target.closest('[data-user-role]');if(toggle){const u=state.users.find(x=>x.id===toggle.dataset.userToggle);const active=toggle.dataset.active==='true';if(!confirm(`${active?'Deactivate':'Activate'} ${u?.email}?`))return;try{await api(`/api/users/${u.id}`,{method:'PATCH',body:{active:!active}});toast('Account status updated.','success');await loadUsers();}catch(err){toast(err.message,'error');}}if(role){const u=state.users.find(x=>x.id===role.dataset.userRole);if(!u)return;const newRole=prompt('Role: admin, teacher or viewer',u.role);if(!newRole||!['admin','teacher','viewer'].includes(newRole))return;let classNames=u.classNames||[];if(newRole!=='admin'){const input=prompt('Comma-separated assigned class names (must match existing classes):',classNames.join(', '));if(input===null)return;classNames=input.split(',').map(s=>s.trim()).filter(Boolean);}else classNames=[];try{await api(`/api/users/${u.id}`,{method:'PATCH',body:{role:newRole,classNames}});toast('Account permissions updated.','success');await loadUsers();}catch(err){toast(err.message,'error');}}});
  async function loadAudit() {
    const params=new URLSearchParams({page:String(state.auditPage),pageSize:'50'}), action=$('auditActionFilter').value.trim();if(action)params.set('action',action);
    const data=await api(`/api/audit?${params.toString()}`);state.auditRows=data.items;state.auditPages=Math.max(1,data.pages||1);$('auditPageInfo').textContent=data.total?`Page ${data.page} of ${data.pages} · ${data.total} events`:'No events found';$('auditPrev').disabled=data.page<=1;$('auditNext').disabled=data.page>=state.auditPages;
    $('auditTable').innerHTML=data.items.length?data.items.map(a=>`<tr><td>${new Date(a.createdAt).toLocaleString()}</td><td><strong>${escapeHtml(a.actorName||'System')}</strong><div class="muted tiny">${escapeHtml(a.actorEmail||a.role||'')}</div></td><td><code>${escapeHtml(a.action)}</code></td><td>${escapeHtml(a.entity||'—')} ${a.entityId?`<small class="muted">${escapeHtml(String(a.entityId).slice(-8))}</small>`:''}</td><td title="${escapeHtml(JSON.stringify(a.details||{}))}">${escapeHtml(JSON.stringify(a.details||{}).slice(0,120))}</td></tr>`).join(''):'<tr><td colspan="5" class="empty-cell">No audit events match your filter.</td></tr>';
  }
  $('refreshAuditBtn').addEventListener('click',()=>loadAudit().catch(e=>toast(e.message,'error')));$('applyAuditFilter').addEventListener('click',()=>{state.auditPage=1;loadAudit().catch(e=>toast(e.message,'error'));});$('auditPrev').addEventListener('click',()=>{state.auditPage=Math.max(1,state.auditPage-1);loadAudit().catch(e=>toast(e.message,'error'));});$('auditNext').addEventListener('click',()=>{state.auditPage=Math.min(state.auditPages,state.auditPage+1);loadAudit().catch(e=>toast(e.message,'error'));});

  // Account and system settings
  async function loadSettings() {
    const [settings, health] = await Promise.all([api('/api/settings'), checkApiHealth()]);
    state.settings=settings;$('thresholdForm').elements.attendanceThreshold.value=settings.attendanceThreshold||75;
    $('mailStatus').hidden=settings.mailConfigured;if(!settings.mailConfigured){$('mailStatus').textContent='SMTP is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD and EMAIL_FROM to enable email alerts.';}
    setConnection(health.status==='ok',health.status==='ok'?`Database connected · ${health.database}`:'Database unavailable');
  }
  $('passwordForm').addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,p=Object.fromEntries(new FormData(f).entries());try{await api('/api/auth/change-password',{method:'POST',body:p});f.reset();toast('Password changed successfully.','success');}catch(err){toast(err.message,'error');}});
  $('thresholdForm').addEventListener('submit',async e=>{e.preventDefault();const threshold=Number(e.currentTarget.elements.attendanceThreshold.value);try{const data=await api('/api/settings',{method:'PUT',body:{attendanceThreshold:threshold}});state.settings.attendanceThreshold=data.attendanceThreshold;toast(`Attendance threshold set to ${data.attendanceThreshold}%.`,'success');}catch(err){toast(err.message,'error');}});
  $('sendAlertsBtn').addEventListener('click',async()=>{if(!confirm('Send the attendance risk summary to the configured administrator/notification email recipients?'))return;setBusy(true,'Preparing attendance email…');try{const data=await api('/api/alerts/send',{method:'POST',body:{}});$('mailStatus').hidden=false;$('mailStatus').className='inline-notice success';$('mailStatus').textContent=`Email sent. ${data.studentsBelowThreshold} students are below the threshold.`;toast('Attendance risk email sent.','success');}catch(err){$('mailStatus').hidden=false;$('mailStatus').className='inline-notice error';$('mailStatus').textContent=err.message;toast(err.message,'error');}finally{setBusy(false);}});
  $('backupBtn').addEventListener('click',async()=>{setBusy(true,'Creating data backup…');try{const response=await fetch('/api/admin/backup',{credentials:'same-origin'});if(!response.ok){const data=await response.json().catch(()=>({}));throw new Error(data.error||'Could not create backup.');}downloadBlob(await response.blob(),`attendease-backup-${todayStr()}.json`);toast('Backup downloaded. Store it securely.','success');}catch(err){toast(err.message,'error');}finally{setBusy(false);}});
  $('healthCheckBtn').addEventListener('click',()=>checkApiHealth().then(h=>toast(`API and database are healthy (${h.database}).`,'success')).catch(e=>toast(e.message,'error')));

  // Global dialog close, offline status and unsaved-work guard.
  document.querySelectorAll('[data-close-dialog]').forEach(btn=>btn.addEventListener('click',()=>btn.closest('dialog')?.close()));
  document.querySelectorAll('dialog').forEach(dialog=>dialog.addEventListener('click',e=>{if(e.target===dialog)dialog.close();}));
  window.addEventListener('beforeunload',e=>{if(state.dirty){e.preventDefault();e.returnValue='';}});
  window.addEventListener('online',()=>{ $('offlineBanner').hidden=true; checkApiHealth().catch(()=>{}); });
  window.addEventListener('offline',()=>{ $('offlineBanner').hidden=false; setConnection(false,'Offline'); });
  if (!navigator.onLine) $('offlineBanner').hidden=false;
  if ('serviceWorker' in navigator) window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}),{once:true});

  // Date defaults are initialized once, not recalculated after filters are used.
  $('attDate').value=todayStr();$('repFrom').value=dateOffset(-29);$('repTo').value=todayStr();$('dashboardDate').value=todayStr();
  initializeAuth();
})();
