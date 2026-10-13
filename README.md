# AttendEase v6 — Secure attendance management

A progressively deployable attendance application built with Express, MongoDB, plain JavaScript and a professional responsive UI. It includes account security, class-scoped permissions, session-based attendance, reports, archive/history, bulk import, CSV export, audit records, backup export, optional email alerts, and a small offline shell cache.

## What changed from v5

- **Authentication:** initial admin setup is guarded by a server-only `SETUP_SECRET`; passwords use bcrypt; sessions use signed HttpOnly cookies; session expiry is eight hours; rate limits protect login and setup.
- **Roles:** `admin`, `teacher`, `viewer`. Teachers and viewers can access only explicitly assigned classes. Viewers are read-only. At least one active admin is protected from deactivation/demotion.
- **Accurate attendance:** attendance is stored by session and student. Draft sessions do not contribute to percentages. Finalization requires a status for each active student. Statuses are Present (P), Absent (A), Late (L), Excused (E). Excused marks are excluded from the denominator; late counts as attended.
- **Audit and reversibility:** archiving students/classes/subjects preserves historical records. Finalized attendance is locked. Only an admin can reopen it, with a reason captured in audit history.
- **Academics:** academic years, classes, subjects, weekly timetable slots and a school calendar for holidays/exceptional working days can be managed. A new attendance session on a holiday requires an override reason, which is kept on the session and audit log. One class label should be unique across the workspace; to distinguish sections/years, include that label in the class name.
- **Reporting:** reports query finalized-session data server-side; CSV export, print/save-as-PDF and a JSON backup are provided. Student CSV import validates rows and reports skipped rows.
- **Alerts:** threshold-based low-attendance list, optional SMTP email delivery and a weekday Vercel Cron endpoint.
- **UX:** responsive accessible UI, subtle scroll reveal, loading states, useful empty states, retry-oriented errors, keyboard-focus indicators, unsaved attendance warnings, reduced-motion support and installable PWA shell.

## 1. Requirements

- Node.js 22.x
- MongoDB Community Server for local development, or MongoDB Atlas for Vercel
- VS Code is optional

## 2. Local development (Windows PowerShell)

1. Extract the project and open the `attendance-system` folder in VS Code.
2. Install dependencies:

   ```powershell
   npm.cmd install
   Copy-Item .env.example .env
   ```

3. Generate three different secret values, each at least 40 characters. In PowerShell you can run the following three times and copy each output into the corresponding `.env` variable:

   ```powershell
   [Convert]::ToBase64String([byte[]](1..48 | ForEach-Object { Get-Random -Maximum 256 }))
   ```

   Replace `SESSION_SECRET`, `SETUP_SECRET` and `CRON_SECRET` with different generated values. Do not commit `.env` to GitHub.

4. For local MongoDB, keep `MONGODB_URI=mongodb://127.0.0.1:27017`. Ensure the MongoDB service is running.
5. Start the app:

   ```powershell
   npm.cmd start
   ```

6. Open `http://localhost:3000/`. The first visit prompts you to create the administrator. Enter the value you set for `SETUP_SECRET`. This key is accepted only when the user collection is empty.
7. Check `http://localhost:3000/api/health` for the database status.
8. Tests and syntax checks:

   ```powershell
   npm.cmd test
   npm.cmd run check
   ```

PowerShell note: use `npm.cmd` if script policy prevents running `npm.ps1`.

## 3. MongoDB Atlas and Vercel

1. Create a MongoDB Atlas cluster and a database user with access only to the AttendEase database.
2. Copy the Atlas `mongodb+srv://...` URI. URL-encode any special characters in the database password.
3. In Atlas **Network Access**, allow only the network paths that your deployment requires. Do not assume Vercel has one fixed outbound IP unless you configured a static outbound IP/private connection. Temporary `0.0.0.0/0` access is not recommended for production. See the Atlas connectivity documentation: https://www.mongodb.com/docs/atlas/connect-to-database-deployment/
4. Push the project to a private GitHub repository. Keep `.env`, secrets and backups out of the repository.
5. Import the repository into Vercel. The Express app is the server entry point; static assets are under `public/`. Vercel serves files from `public/` through its static asset handling, so no extra static rewrite is required for this project. Official guide: https://vercel.com/docs/frameworks/backend/express
6. Configure Production environment variables in Vercel:
   - `MONGODB_URI` — Atlas connection string
   - `DB_NAME` — `attendanceDB` (or another database name)
   - `SESSION_SECRET` — random secret, at least 40 characters
   - `SETUP_SECRET` — a different random initial setup key
   - `CRON_SECRET` — a third random secret for the scheduled alert endpoint
   - Optional: `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASSWORD`, `EMAIL_FROM`, `ALERT_EMAIL_TO`
7. Deploy and open the Vercel URL. The setup screen appears only if there are no user accounts. Enter `SETUP_SECRET` to create the first administrator.
8. After creating the first admin, remove `SETUP_SECRET` from the production environment and redeploy if you prefer; setup is also permanently blocked once any account exists. Keep `SESSION_SECRET` configured so login cookies remain valid across deployments.
9. Test `/api/health`, sign in, create one test class and student, save a draft, finalize a session, and confirm the report updates.

The weekday alert cron runs at **03:30 UTC (09:00 India Standard Time)** on weekdays. Vercel Cron availability/limits depend on the Vercel plan. Set `CRON_SECRET`; scheduled execution returns 401 without the expected `Authorization: Bearer <CRON_SECRET>` header. SMTP variables are required for actual email delivery.

## 4. First-run data model

- `users`: password hash, role, class permissions, active flag and token version
- `students`: class label, normalized roll/class keys, enrollment date and archive state
- `classes`, `academicYears`, `subjects`, `calendarEvents`, `timetable`
- `sessions`: date, class, optional subject, draft/finalized status and audit fields
- `attendance`: one status per student per session
- `auditLogs`, `settings`

Database indexes are created on first API request. If opening a database that previously used v5, the app migrates v5 attendance records into session records. A migrated historic session is finalized only if every currently active student in that class has a mark; incomplete legacy sessions remain drafts and are excluded from attendance percentages. Back up important data before upgrading.

## 5. User and attendance workflows

- Initial setup: create the first admin.
- Admin: create classes, years, subjects and staff accounts; assign teachers/viewers to class names; set attendance threshold; export a backup; reopen finalized sessions with an audit reason.
- Teacher: access only assigned class names, add/edit/archive students in those classes, create sessions, save drafts and finalize complete attendance.
- Viewer: read-only access to assigned class rosters, dashboards and reports.
- Attendance: select date/class/subject and a session label; mark P/A/L/E; save a draft if incomplete; finalize when every active student has a status. Draft sessions do not count toward reports.
- CSV import format requires headers `roll,name,cls`; optional headers are `email,enrolledOn`. Import at most 500 records at a time. Classes must already exist. Use a UTF-8 CSV file.
- Reports can be printed or saved to PDF through the browser's print dialog.
- JSON backup is downloadable by admins only. It omits password hashes; still treat the file as sensitive because it contains student details, attendance and audit data.

## 6. Optional SMTP alerts

Set `SMTP_HOST`, `SMTP_PORT` (usually 587), `SMTP_SECURE` (`false` for STARTTLS on 587), `SMTP_USER`, `SMTP_PASSWORD`, and `EMAIL_FROM`. Optionally set `ALERT_EMAIL_TO` as a comma-separated recipient list; otherwise active administrators receive the message. The alert is a summary of students below the configured attendance threshold over the prior 30 days of finalized sessions.

## 7. Production hardening checklist

Before using real student records:

- Use MongoDB Atlas with least-privilege database credentials and restrictive network access.
- Set unique, random secrets and keep them out of source control.
- Configure a supported Vercel plan/region for the scheduled alert job and verify it actually runs.
- Test all routes with admin, teacher, viewer and unauthenticated accounts.
- Add an institutional privacy/retention policy, restrict backups, and run backups regularly.
- Review consent/notification requirements before mailing student information.
- Monitor Vercel logs and Atlas metrics; arrange a restoration drill for backups.
- Consider MFA, email-based password recovery, persistent shared rate limiting, dedicated monitoring, and external backup storage for a larger deployment.

## 8. Current limitations to understand

- This is a substantial starter application, not a compliance-certified SIS. There is no MFA or password-reset email workflow.
- SMTP alert sends to configured administrators (or `ALERT_EMAIL_TO`); it does not mail individual students/guardians.
- Backup is an export endpoint, not an automated database restore tool. MongoDB Atlas backup policies should be configured separately where available.
- The PWA caches only the static shell. It deliberately never caches authenticated API responses or student data; offline attendance edits are not supported.
- There is no automatic data migration preview/rollback tool. Take an external backup before migrating important v5 data.
- Automated tests currently cover domain validation/calculations; live MongoDB, Atlas access, SMTP delivery and Vercel deployment still require environment-specific verification.
