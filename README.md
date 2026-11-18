# MediCore — Medical Portal

Four working portals, using **Render Free** application hosting and **Supabase Free** PostgreSQL + private report storage. No paid Azure service is required. Includes the blue-and-white MediCore interface, responsive navigation, health charts, real server-side authentication and authorization, and an isolated synthetic demo.

## Features

| Portal | Workflows |
| --- | --- |
| Doctor | Login, register patients, search authorized patients by unique ID/name, patient dashboards, shared clinical notes, BP/glucose readings, test orders, view/download reports |
| Patient | Login, personal records and read-only doctor notes, BP/glucose history and charts, view/download reports, grant/revoke doctor access |
| Laboratory | Login, assigned authorized orders, mark processing, upload PDF reports, uploaded history |
| Admin | Register organizations, create/approve/suspend accounts, manage staff roles, register patients, doctor assignments, audit log |

Patient registration generates a unique ID. To give that patient a login, create a **Patient** account in Accounts & approvals using the same ID, then approve it. New accounts remain pending until approved. Admin is a care-network-wide role; organizations are not isolated tenants.

## Run locally

Python 3.12+:

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
DEMO_MODE=1 .venv/bin/python app.py
```

Open http://localhost:8000. Choose a role on the login page:

| Role | ID | Password |
| --- | --- | --- |
| Doctor | DOC-101 | DemoPass123! |
| Patient | PAT-4921 | DemoPass123! |
| Laboratory | LAB-101 | DemoPass123! |
| Admin | ADM-101 | DemoPass123! |

Demo uses ignored `data/demo.db` and local private report files. Do not use real records. The demo signing key changes on restart unless SECRET_KEY is supplied. Delete `data/` to reset synthetic data.

## Deploy with free providers

[Deploy this repository to Render](https://render.com/deploy?repo=https://github.com/ktssupports/Medical-Portal)

See [step-by-step setup](deploy/FREE_HOSTING.md). The repository includes a Render Blueprint (`render.yaml`), Supabase SQL setup, a first-admin initialization command, encrypted database backup workflow, and restore helpers.

**Deployment is not automatic from a Git push:** you must create/connect your Render and Supabase accounts and supply secrets in their dashboards. No live hosted URL or database is provisioned in this repository. Verify current provider plans before creating resources; free allowances and eligibility change.

## Tests

```sh
DEMO_MODE=1 .venv/bin/python -m unittest discover -s tests -v
node --check static/app.js
```

Tests run against temporary isolated SQLite data using Flask's test client, covering role boundaries, CSRF, login/logout, suspended sessions, patient isolation, doctor revocation, input validation, orders, PDF report authorization, admin approvals, and page rendering. Cloud PostgreSQL/Supabase behavior needs an integration run with your configured services.

## Security and operational scope

- Salted scrypt password hashes. Server-side sessions with hashed tokens and eight-hour expiry; HttpOnly, SameSite=Strict, Secure cookies in production. CSRF protection on every POST. Account login rate limiting over a 15-minute window.
- The backend checks authorization before record reads/writes and report downloads. Patient revocation prevents subsequent doctor access. A laboratory retains its assigned orders and own reports. Account role/status changes immediately revoke its sessions.
- Reports are private and proxied through authorized routes. The service-role key never enters browser code. Uploads are capped at 5 MB with PDF signature checks; production malware scanning is not included.
- PostgreSQL lives in an unexposed `medicore` schema. Run the included hardening SQL and keep the schema out of the Supabase Data API. No browser connects directly to the database.
- HTTPS is supplied by Render. Database connections require TLS. Storage/database at-rest encryption depends on provider configuration. This is not end-to-end encryption.
- Audit events include login, record views, searches, modifications, and report downloads. They exclude clinical contents; database owners can modify them. An immutable audit sink is not included.
- Gunicorn supplies production HTTP transport. `/health` checks database connectivity. Render offers deployment/health logs; external alerting needs setup.
- Free hosting may sleep and database projects may pause. Free plans are for evaluation/synthetic data; no uptime, medical compliance, automatic backups, or paid features are assumed. Before real clinical use, arrange appropriate provider agreements and add recovery/MFA, malware scanning, immutable auditing, tested backups, retention policies, and operational review.

## Patient consultation workspace

The patient detail page places a free-text clinical-notes editor on the left and consultation history, BP/glucose charts, reading entry, and reading history on the right. Notes are saved as separate dated entries rather than overwriting previous consultations. Authorized doctors can add notes; patients can read notes on their own records but cannot edit them. Existing admin oversight is preserved. Laboratories and doctors whose patient access was revoked cannot read or write notes. Notes are rendered as plain text, with HTML escaped.

Startup creates the `clinical_notes` table and patient/date index. In PostgreSQL, it enables RLS and denies browser roles access, matching the server-authorized access model of the other private tables. No historical notes are backfilled.

## Daily patient queue

Admin handles reception tasks using the existing Admin login. Open **Patient queue**, select a registered patient and approved doctor, then add the patient. Queue assignment also grants the selected doctor access to that patient’s record, as explained on the form. Patients retain permission to revoke access.

Doctors see their own queue on Overview and Patient queue, refreshed every 10 seconds while the tab is visible. Numbering restarts daily in Asia/Kolkata time. A doctor starts the first waiting patient, then saves clinical notes/readings and completes the consultation. Only one consultation per doctor may be active at a time. Admin can cancel active entries; completed/cancelled entries remain visible for the day. Duplicate active entries for the same patient/doctor/day are rejected.

Startup creates the private patient_queue table and indexes. PostgreSQL uses a transaction-scoped advisory lock per doctor/day for token allocation and status changes. SQLite demo uses an immediate write transaction. Queues are persisted in the database; automatic refreshing uses authenticated, non-cached HTML fragments, not full-page reloads. Patients and laboratories cannot access staff queue endpoints, and revoked doctor access hides the associated queue entry. No separate Reception role is added.
