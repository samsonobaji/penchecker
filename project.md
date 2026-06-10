# PenChecker — Full Project Documentation

> A web-based, AI-powered penetration testing and vulnerability scanning SaaS platform built for Africa and the world.

**Supabase Project:** `https://kjbnebgskvxpigkttrpi.supabase.co`
**Architecture:** Static, no-build HTML/CSS/JS (zero bundler) served via Python HTTP server
**Last Updated:** June 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Mission & Vision](#2-mission--vision)
3. [Tech Stack](#3-tech-stack)
4. [Architecture Decisions](#4-architecture-decisions)
5. [Subscription Plans](#5-subscription-plans)
6. [User Roles & Permissions](#6-user-roles--permissions)
7. [48-Page Roadmap & Phase Breakdown](#7-48-page-roadmap--phase-breakdown)
8. [Progress Tracker](#8-progress-tracker)
9. [Core Feature Specifications](#9-core-feature-specifications)
10. [Database Schema Summary](#10-database-schema-summary)
11. [Authentication Flow](#11-authentication-flow)
12. [Design System](#12-design-system)
13. [File Structure](#13-file-structure)
14. [Known Issues & Bug Log](#14-known-issues--bug-log)
15. [Decisions & Notes Log](#15-decisions--notes-log)
16. [Build Rules](#16-build-rules)
17. [Next Steps](#17-next-steps)

---

## 1. Project Overview

| Field | Details |
|---|---|
| **Project Name** | PenChecker |
| **Type** | SaaS Web Application |
| **Category** | Cybersecurity / Vulnerability Scanning |
| **Target Market** | Africa (primary), Global (secondary) |
| **Payment Gateway** | Paystack (NGN primary; USD/EUR displayed on pricing) |
| **Total Pages** | 48 |
| **Total Phases** | 7 |
| **Auth Provider** | Supabase Auth (Email/Password + Google OAuth + GitHub OAuth) |
| **Database** | Supabase (PostgreSQL with Row Level Security) |
| **Hosting** | To be defined (Vercel / Netlify recommended) |

---

## 2. Mission & Vision

**Mission:** Make professional-grade penetration testing and vulnerability scanning accessible, affordable, and understandable for individuals, teams, and enterprises across Africa and beyond.

**Vision:** Become the leading security scanning platform on the African continent, rivalling global players like Detectify and Qualys, with local payment support and plain-English reporting.

---

## 3. Tech Stack

### Frontend (Current: Static Architecture)
- **HTML5** — semantic page structure
- **Vanilla CSS** — custom CSS variables design system (no Tailwind, no framework)
- **Vanilla JavaScript** — all interactivity inline or via `dashboard-config.js`
- **Supabase JS CDN** — `https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2`

### Future React Architecture (Main_penchecker v4)
- **React + Vite** — frontend framework (in `penchecker-v4-source/`)
- **Tailwind CSS** — utility-first styling
- **React Router** — client-side routing
- **Supabase JS** — auth + database client

### Backend / Services
- **Supabase** — Auth, PostgreSQL database, Row Level Security, Storage
- **Paystack** — payment processing (NGN), subscription management
- **SendGrid / SMTP** — transactional email (email verification, alerts)
- **WhatsApp Business API** — scan completion alerts (planned)
- **Slack / Discord Webhooks** — team notification integration (planned)
- **AI Integration** — OpenAI / Claude API for the AI Chat Assistant

### Tooling
- **Python `http.server`** — local development server (port 5500)
- **Supabase CLI** — schema migrations
- **PostgreSQL** — production database via Supabase

---

## 4. Architecture Decisions

### Why Static (No Build)?
The project was built as a static, no-build architecture to:
1. Avoid environment setup friction during early development
2. Allow rapid iteration without build steps
3. Keep files self-contained and easy to deploy anywhere

### Key Rule: No `file://` Protocol
All pages must be served via HTTP (Python `http.server` or any static server) because:
- Supabase OAuth callbacks require an HTTP origin
- `localStorage` and `sessionStorage` behave differently on `file://`
- CORS restrictions apply on `file://` protocol

### Environment Detection Pattern
The `pc_dev_url` override in `localStorage` allows local development without hardcoding:
```javascript
const origin = localStorage.getItem('pc_dev_url') ||
  (location.protocol === 'file:' ? 'http://127.0.0.1:5500' : location.origin);
```

### Global Config (`dashboard-config.js`)
A single shared JS file handles:
- Session validation (`pc_session`, `pc_user_id`, `pc_user_email` in `localStorage`)
- Sidebar navigation building
- Theme toggle (dark/light mode)
- Toast notification system
- Logout functionality

---

## 5. Subscription Plans

| Plan | Users | Scans/Week | Price (NGN/mo) | Key Features |
|---|---|---|---|---|
| **Free** | 1 | 3 | Free | Basic scanning, no export |
| **Individual** | 1 | Unlimited | 9,900 | Full scans, AI chat, reports, badge, monitoring |
| **Team** | Up to 10 | 5/member | 29,900 | Team dashboard, admin controls, API access |
| **Enterprise** | Unlimited | Unlimited | 99,900 | White-label, sub-admins, audit logs, custom reports |

Annual billing available at ~20% discount.

---

## 6. User Roles & Permissions

| Role | Access Level |
|---|---|
| **Guest** | Public pages only |
| **Free User** | Limited dashboard (no export, no AI, no monitoring) |
| **Individual** | Full individual dashboard |
| **Team Member** | Individual dashboard + team features |
| **Team Admin** | Team management + member oversight + invite |
| **Sub-Admin** | Enterprise-defined permission scope |
| **Enterprise Admin** | Full enterprise dashboard + white-label |
| **Super Admin / Owner** | Full platform access including owner admin panel |

---

## 7. 48-Page Roadmap & Phase Breakdown

### Phase 1 — Public Facing Pages (Pages 1–7)
Marketing and informational pages visible to all visitors.

| # | Page | File | Status |
|---|---|---|---|
| 1 | Landing / Home Page | `index.html` | Complete |
| 2 | Features Page | `features.html` | Complete |
| 3 | Pricing Page | `pricing.html` | Complete |
| 4 | About Page | `about.html` | Complete |
| 5 | Blog / Security Learning Hub | `blog.html` | Complete |
| 6 | Contact Page | `contact.html` | Complete |
| 7 | Legal Pages (ToS, Privacy, AUP) | `terms.html`, `privacy.html`, `acceptable-use.html` | Complete |

---

### Phase 2 — Authentication Pages (Pages 8–14)
All login, registration, and identity verification flows.

| # | Page | File | Status |
|---|---|---|---|
| 8 | Sign Up Page | `signup.html` | Complete |
| 9 | Login Page | `login.html` | Complete |
| 10 | Forgot Password Page | `forgot-password.html` | Complete |
| 11 | Reset Password Page | `reset-password.html` | Complete |
| 12 | Email Verification Page | `verify-email.html` | Complete |
| 13 | Two-Factor Authentication (2FA) Page | `setup-2fa.html` | Complete |
| 14 | Onboarding Page (First Login Only) | `onboarding.html` | Complete |

**Auth Callback:** `auth-callback.html` — Handles Supabase OAuth redirect, reads `localStorage` state, and routes user to correct destination.

---

### Phase 3 — Individual User Dashboard (Pages 15–25)
Core user experience for Individual plan subscribers.

| # | Page | File | Status |
|---|---|---|---|
| 15 | Dashboard Home | `dashboard.html` | Complete |
| 16 | New Scan Page | `dashboard-scan.html` | Complete |
| 17 | Scan Results / Report Page | `dashboard-report.html` | Complete |
| 18 | Scan History Page | `dashboard-history.html` | Complete |
| 19 | Vulnerability Detail | (inline in report page) | Complete |
| 20 | Continuous Monitoring Page | `dashboard-monitoring.html` | Complete |
| 21 | Reports Page | `dashboard-reports.html` | Complete |
| 22 | Security Badge Page | `dashboard-badges.html` | Complete |
| 23 | AI Chat Page | `dashboard-ai.html` | Complete |
| 24 | Account Settings Page | `dashboard-settings.html` | Complete |
| 25 | Billing & Subscription Page | `dashboard-billing.html` | Complete |

**Domain Management:** `dashboard-domains.html` — Add/verify domains using DNS TXT record, file upload, or meta tag method.

---

### Phase 4 — Team Dashboard (Pages 26–29)
Additional pages on top of Individual for Team plan users.

| # | Page | File | Status |
|---|---|---|---|
| 26 | Team Overview Page | `dashboard-team.html` | Complete |
| 27 | Team Invite Page | `dashboard-team-invite.html` | Complete |
| 28 | Team Scan Results Page | `dashboard-team-scans.html` | Complete |
| 29 | Team Reports Export Page | `dashboard-team-reports.html` | Complete |

---

### Phase 5 — Enterprise Dashboard (Pages 30–34)
Additional pages on top of Team for Enterprise plan users.

| # | Page | File | Status |
|---|---|---|---|
| 30 | Enterprise Overview Page | — | Not Started |
| 31 | Sub-Admin Management Page | — | Not Started |
| 32 | Enterprise Audit Log Page | — | Not Started |
| 33 | White-Label Report Page | — | Not Started |
| 34 | Enterprise Billing Page | — | Not Started |

---

### Phase 6 — Owner / Super Admin Dashboard (Pages 35–42)
Internal-only pages accessible by the platform owner.

| # | Page | File | Status |
|---|---|---|---|
| 35 | Owner Dashboard Home | — | Not Started |
| 36 | User Management Page | — | Not Started |
| 37 | Subscription Management Page | — | Not Started |
| 38 | Revenue & Analytics Page | — | Not Started |
| 39 | Scan Blacklist Management Page | — | Not Started |
| 40 | Platform Settings Page | — | Not Started |
| 41 | Abuse & Security Monitoring Page | — | Not Started |
| 42 | Affiliate / Referral Management Page | — | Not Started |

---

### Phase 7 — Notification & Utility Pages (Pages 43–48)
System-level pages and utility screens.

| # | Page | File | Status |
|---|---|---|---|
| 43 | Notifications Center | — | Not Started |
| 44 | 404 Error Page | — | Not Started |
| 45 | 500 Error Page | — | Not Started |
| 46 | Maintenance Page | — | Not Started |
| 47 | Changelog / What's New Page | `changelog.html` | Complete |
| 48 | Referral / Affiliate Page (User Facing) | `affiliates.html` | Complete |

---

## 8. Progress Tracker

| Phase | Pages | Completed | Progress |
|---|---|---|---|
| Phase 1 — Public | 1–7 | 7 / 7 | Complete |
| Phase 2 — Auth | 8–14 | 7 / 7 | Complete |
| Phase 3 — Individual Dashboard | 15–25 | 11 / 11 | Complete |
| Phase 4 — Team Dashboard | 26–29 | 4 / 4 | Complete |
| Phase 5 — Enterprise Dashboard | 30–34 | 0 / 5 | Not Started |
| Phase 6 — Owner Admin | 35–42 | 0 / 8 | Not Started |
| Phase 7 — Utilities | 43–48 | 2 / 6 | In Progress |
| **Total** | **1–48** | **31 / 48** | **~65%** |

---

## 9. Core Feature Specifications

### Scanning Engine
- **Scan Types:** Quick (~2 min), Standard (~8 min), Deep (~20 min)
- **Scan Modes:** Passive (observe only), Active (probe & test)
- **Industry Profiles:** General, E-Commerce, Healthcare, FinTech, Blog/Media
- **Real-time Progress Visualization:** animated step-by-step progress bar with phase labels
- **Scan Phases:** Initialization → DNS Lookup → SSL Check → Header Analysis → Crawler → Vulnerability Engine → Port Scanner → Report Generation
- **Domain Ownership Verification:** DNS TXT record, file upload (`/.well-known/penchecker-verify.txt`), or HTML meta tag
- **Consent Logging:** Legal disclaimer logged with timestamp on every scan submission

### Vulnerability Reporting
- **Severity Levels:** Critical / High / Medium / Low / Info
- **Per-Finding Data:** Evidence, confidence score, CVSS score, OWASP reference, CVE reference, fix difficulty rating
- **View Toggle:** Plain English mode vs. Technical mode (per vulnerability)
- **AI-Suggested Fixes:** Code snippets in detected tech stack
- **Rescan:** Re-run scan on a single vulnerability
- **Export:** PDF and JSON report generation
- **Shared Reports:** Unique share token, optional expiry date

### AI Assistant (`dashboard-ai.html`)
- Context-aware chat loaded with current scan data
- Full-screen ChatGPT-style interface
- Session history persisted per scan
- Can generate code for security fixes
- Can assist with platform navigation

### Security Badge System (`dashboard-badges.html`)
- Badges earned automatically after a high-scoring scan
- Levels: Excellent (9+), Good (7–9), Fair (5–7), Needs Improvement (<5)
- Embeddable HTML/script code for users' external websites
- Badge validity: 90 days (refreshed on rescan)
- Unique embed token per badge

### Domain Monitoring (`dashboard-monitoring.html` + `dashboard-domains.html`)
- Add and verify domains via DNS TXT, file upload, or meta tag
- Monitoring frequency: Daily / Weekly / Monthly
- Automated re-scan on schedule
- Alert on new vulnerabilities found
- Email + WhatsApp notifications on scan completion

### Notifications
- In-app notification center
- Email alerts (scan complete, billing, new vulnerability found)
- WhatsApp alerts (planned)
- Slack / Discord webhook integration (planned)

### Billing (`dashboard-billing.html`)
- Paystack integration for NGN payments
- Monthly and annual billing cycles
- Grace period management
- Plan upgrades / downgrades
- Invoice history
- Refund processing (owner-initiated)
- Affiliate / referral commission tracking

---

## 10. Database Schema Summary

All tables live in the `public` schema in Supabase with Row Level Security enabled.

| # | Table | Purpose |
|---|---|---|
| 1 | `profiles` | Extends `auth.users` — stores user role, plan, preferences, 2FA, referrals |
| 2 | `plans` | Plan definitions with feature flags and pricing |
| 3 | `subscriptions` | User subscription state, Paystack references, billing cycle |
| 4 | `payments` | Payment transaction history |
| 5 | `teams` | Team workspace (name, domain, admin) |
| 6 | `team_members` | Team membership with per-member scan limits |
| 7 | `enterprises` | Enterprise workspace with branding |
| 8 | `enterprise_members` | Enterprise membership with role scope |
| 9 | `invitations` | Pending team/enterprise invite tokens |
| 10 | `domains` | Registered + verified domains for scanning/monitoring |
| 11 | `consent_logs` | Legal scan consent records with IP + timestamp |
| 12 | `scan_blacklist` | Domains prohibited from scanning |
| 13 | `scans` | Scan records with status, progress, and summary counts |
| 14 | `scan_vulnerabilities` | Individual vulnerability findings per scan |
| 15 | `reports` | Generated report files with share tokens |
| 16 | `security_badges` | Earned security badges per domain |
| 17 | `ai_chat_sessions` | AI chat history per user/scan |
| 18 | `notifications` | In-app notification records |
| 19 | `audit_logs` | Enterprise audit trail of all user actions |
| 20 | `referrals` | Referral tracking and commission records |
| 21 | `ip_flags` | Abuse detection — flagged/blocked IP addresses |
| 22 | `changelogs` | Platform version release notes |
| 23 | `scan_usage` | Weekly scan usage tracking per user |

**Key Triggers:**
- `on_auth_user_created` — auto-creates a `profiles` row on new Supabase signup
- `on_profiles_updated`, `on_subscriptions_updated`, etc. — auto-updates `updated_at` timestamps

---

## 11. Authentication Flow

### Sign Up Flow
1. User fills `signup.html` → email/password or Google/GitHub OAuth
2. Supabase sends email verification link (`emailRedirectTo` → `auth-callback.html`)
3. `auth-callback.html` reads the URL hash, detects session, stores `pc_session` / `pc_user_id` / `pc_user_email` in `localStorage`
4. Redirects to `onboarding.html` (first login) or `dashboard.html`

### Login Flow
1. User fills `login.html` → email/password or social login
2. On success, Supabase returns session token
3. Session stored in `localStorage` as `pc_session`, `pc_user_id`, `pc_user_email`
4. Redirected to `dashboard.html`

### OAuth Callback URL
- Local dev: `http://127.0.0.1:5500/auth-callback.html`
- Override: `localStorage.setItem('pc_dev_url', 'http://127.0.0.1:5500')` for any port

### Session Check (All Dashboard Pages)
Every `dashboard-*.html` page:
1. Checks for `pc_session` in `localStorage`
2. If missing → redirects to `login.html?expired=1`
3. If present → populates user info in sidebar

### Password Reset
1. User submits `forgot-password.html` → Supabase sends reset email
2. Email links to `reset-password.html` with token in URL hash
3. User sets new password → redirected to `login.html`

---

## 12. Design System

### Color Palette (CSS Variables)

| Variable | Value | Usage |
|---|---|---|
| `--bg` | `#0a0a0f` | Page background (dark default) |
| `--surface` | `#111118` | Card / sidebar background |
| `--surface2` | `#1a1a24` | Input / secondary surface |
| `--border` | `#2a2a3a` | Borders |
| `--accent` | `#00e5ff` | Primary brand color (cyan) |
| `--accent2` | `#7c3aed` | Secondary accent (purple) |
| `--text` | `#e8e8f0` | Primary text |
| `--text2` | `#8888a0` | Secondary / muted text |
| `--success` | `#22c55e` | Success / Low severity |
| `--warning` | `#f59e0b` | Medium severity |
| `--danger` | `#ef4444` | Critical severity |
| `--high` | `#f97316` | High severity |

### Severity Colors
| Level | Color |
|---|---|
| Critical | `#ef4444` (red) |
| High | `#f97316` (orange) |
| Medium | `#f59e0b` (amber) |
| Low | `#22c55e` (green) |
| Info | `#3b82f6` (blue) |

### Typography
- **Primary Font:** `Inter` (Google Fonts) — used across all pages
- **Monospace:** `JetBrains Mono` — used in code snippets and evidence blocks

### Dark/Light Mode
- Default: **Dark mode**
- Toggle: `.light-theme` class on `<body>`
- Persisted in `localStorage` as `pencheckerTheme` (`'light'` or `'dark'`)
- Theme button uses `tBtn.innerHTML = ...` (NOT `.textContent`) for SVG icons

### Sidebar Navigation
Built dynamically by `dashboard-config.js` based on logged-in user's plan and role.

---

## 13. File Structure

```
pencheckers1/
├── index.html                    # Landing page
├── features.html                 # Features marketing page
├── pricing.html                  # Pricing plans page
├── about.html                    # About page
├── blog.html                     # Blog / security learning hub
├── contact.html                  # Contact page
├── terms.html                    # Terms of Service
├── privacy.html                  # Privacy Policy
├── acceptable-use.html           # Acceptable Use Policy
├── dmca.html                     # DMCA page
├── affiliates.html               # Affiliate / referral program page
├── changelog.html                # Product changelog
├── article.html                  # Blog article template
├── login.html                    # Login page
├── signup.html                   # Signup page
├── forgot-password.html          # Forgot password
├── reset-password.html           # Reset password
├── verify-email.html             # Email verification confirmation
├── setup-2fa.html                # 2FA setup page
├── onboarding.html               # First-login onboarding
├── auth-callback.html            # OAuth / email callback handler
├── dashboard.html                # Dashboard home
├── dashboard-scan.html           # New scan page
├── dashboard-report.html         # Scan report / results page
├── dashboard-history.html        # Scan history
├── dashboard-domains.html        # Domain management & verification
├── dashboard-monitoring.html     # Continuous monitoring
├── dashboard-reports.html        # All reports list
├── dashboard-badges.html         # Security badges
├── dashboard-ai.html             # AI assistant chat
├── dashboard-settings.html       # Account settings
├── dashboard-billing.html        # Billing & subscriptions
├── dashboard-team.html           # Team overview
├── dashboard-team-invite.html    # Team invite management
├── dashboard-team-scans.html     # Team scan results
├── dashboard-team-reports.html   # Team reports export
├── dashboard-config.js           # Global dashboard config (session, nav, theme)
├── penchecker-schema.sql         # Full Supabase database schema
├── update-global.sql             # Schema update patches
├── project.md                    # This file — full project documentation
├── README.md                     # Quick start guide
└── penchecker-dist/              # Packaged distribution build
```

---

## 14. Known Issues & Bug Log

| # | Issue | Status | Fix Applied |
|---|---|---|---|
| 1 | **SVG rendering as raw text** — `tBtn.textContent = '<svg...'` doesn't render HTML | Fixed | Changed to `tBtn.innerHTML = '<svg...'` across all dashboard pages |
| 2 | **Encoding artifacts** — Characters like `âšï¸`, `â†'`, `â€"` appear in login/signup pages | Fixed | Ran `clean_emojis.py` to strip mojibake and replace with proper HTML entities or SVGs |
| 3 | **Emojis rendering as unidentified characters** — Emojis in features.html, pricing.html, dashboard-scan.html appeared as boxes or garbled text in some browsers | Fixed | Replaced all emojis with inline SVG icons or English text via `clean_emojis.py` |
| 4 | **OAuth redirect fails on `file://` protocol** — Social login callback URL hardcoded | Fixed | Implemented dynamic origin detection with `pc_dev_url` localStorage override |
| 5 | **Email verification redirect hardcoded** — `emailRedirectTo` used fixed URL | Fixed | Updated to use dynamic origin detection in `signup.html` |
| 6 | **Dashboard files zeroed out** — Bulk script truncated some `dashboard-team-*.html` files to 0 bytes | Fixed | Restored from VS Code local history backup |
| 7 | **`file://` CORS errors** — Supabase JS library and fetch calls blocked on `file://` | Documented | Must always serve via HTTP (`python -m http.server 5500`) |
| 8 | **Session expired message garbled** — Icon before "Your session expired" showed as `âšï¸` | Fixed | Part of encoding cleanup |

---

## 15. Decisions & Notes Log

| Date | Decision / Note |
|---|---|
| Mar 2026 | Project plan finalized. 48 pages across 7 phases confirmed. |
| Mar 2026 | Chose Supabase as the backend (auth + database). No custom backend API needed for MVP. |
| Mar 2026 | Chose Paystack as payment gateway (NGN support, African market focus). |
| Mar 2026 | Decided on static, no-build architecture to avoid setup overhead in early stages. |
| Apr 2026 | Implemented `dashboard-config.js` as the global controller for all dashboard pages (session, nav, theme, toast). |
| Apr 2026 | Established CSS variable design system — dark mode default, `--accent: #00e5ff` (cyan) brand color. |
| Apr 2026 | Completed Phases 1, 2, 3 (all 25 pages). |
| Apr 2026 | Completed Phase 4 (Team Dashboard — 4 pages). |
| Apr 2026 | Fixed SVG `textContent` vs `innerHTML` bug across all dashboard pages. |
| Apr 2026 | Fixed all character encoding (mojibake) artifacts. All emojis replaced with professional SVG icons or English text. |
| Apr 2026 | `pc_dev_url` localStorage pattern established for local OAuth callback override. |
| Jun 2026 | Migrated codebase to `pencheckers1/` directory. `Main_penchecker/` contains React v4 source for future migration. |

---

## 16. Build Rules

1. **One page at a time** — no page is skipped or rushed
2. Each page must be **fully designed and functional** before moving to the next
3. Follow the **phase order** strictly (Phase 5 → 6 → 7 next)
4. Every page must be **mobile responsive**
5. Every page must follow the **consistent design system** (CSS variables defined above)
6. Security-critical flows (auth, scan submission, billing) require **extra review** before sign-off
7. **No `file://` protocol** — always serve via `python -m http.server 5500`
8. **No emojis** — all icons must be inline SVGs or text; no emoji characters allowed in any HTML file
9. **English only** — all text in the UI must be in English; no other languages or unidentified characters
10. **No bulk scripts without backup** — always back up the directory before running any find-and-replace script

---

## 17. Next Steps

### Immediate (Phase 5 — Enterprise Dashboard)
- [ ] Page 30: Enterprise Overview Page
- [ ] Page 31: Sub-Admin Management Page
- [ ] Page 32: Enterprise Audit Log Page
- [ ] Page 33: White-Label Report Page
- [ ] Page 34: Enterprise Billing Page

### Phase 6 — Owner Admin Dashboard
- [ ] Page 35: Owner Dashboard Home
- [ ] Page 36: User Management Page
- [ ] Page 37: Subscription Management Page
- [ ] Page 38: Revenue & Analytics Page
- [ ] Page 39: Scan Blacklist Management Page
- [ ] Page 40: Platform Settings Page
- [ ] Page 41: Abuse & Security Monitoring Page
- [ ] Page 42: Affiliate / Referral Management Page

### Phase 7 — Utility Pages (remaining)
- [ ] Page 43: Notifications Center
- [ ] Page 44: 404 Error Page
- [ ] Page 45: 500 Error Page
- [ ] Page 46: Maintenance Page

### Technical Backlog
- [ ] Integrate Paystack API (real billing)
- [ ] Connect AI Assistant to OpenAI/Claude API
- [ ] Implement real scan engine backend (Python/Node.js microservice)
- [ ] WhatsApp Business API for scan alerts
- [ ] Email system (SendGrid) for transactional emails
- [ ] Deploy to production (Vercel / Netlify)
- [ ] Set up Supabase Edge Functions for server-side logic
- [ ] Domain verification automation (DNS lookup + file check)
- [ ] PDF report generation (Puppeteer or WeasyPrint)

---

*Built by Samson Obaji | PenChecker — Securing Africa's Digital Frontier*
