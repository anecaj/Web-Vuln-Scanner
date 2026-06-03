# VulnScope — Web Vulnerability Scanner

An OWASP Top 10 aligned web vulnerability scanner that checks for 10+ vulnerability classes
and generates detailed findings with evidence and remediation guidance.

**Live demo:** `https://anecaj.github.io/Web-Vuln-Scanner/`
**Backend API:** `https://web-vuln-scanner-api.onrender.com`

> ⚠ Only scan websites you own or have explicit written permission to test.

---

## Vulnerability Checks

| Check | OWASP | Severity |
|-------|-------|----------|
| HTTPS / SSL configuration | A02 | HIGH |
| HTTP Strict Transport Security | A02 | HIGH |
| Content Security Policy | A03 | HIGH |
| X-Frame-Options (Clickjacking) | A05 | MEDIUM |
| X-Content-Type-Options | A05 | LOW |
| Referrer-Policy | A05 | LOW |
| Permissions-Policy | A05 | LOW |
| Server version disclosure | A05 | MEDIUM |
| X-Powered-By disclosure | A05 | MEDIUM |
| Debug information in response | A05 | HIGH |
| CORS misconfiguration | A05 | MEDIUM/CRITICAL |
| Cookie security flags | A07 | MEDIUM |
| Reflected XSS (potential) | A03 | HIGH |
| SQL injection indicators | A03 | CRITICAL |
| Open redirect | A01 | MEDIUM |
| Sensitive file/path exposure | A05 | CRITICAL-INFO |

---

## Stack

| Layer | Tech |
|-------|------|
| Backend | Python, Flask, requests, BeautifulSoup4 |
| Frontend | React, Vite, Recharts |
| Storage | SQLite (scan history) |
| Hosting | Render.com + GitHub Pages |

---

## Local Setup

### Backend
```bash
cd backend
pip install -r requirements.txt
python app.py   # port 5003
```

### Frontend
```bash
cd frontend
npm install
npm run dev     # port 5173
```

Test with `http://testphp.vulnweb.com` — a deliberately vulnerable PHP app.

---

## Deploy

### Backend → Render.com
- Root Directory: `backend`
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app --workers 1 --bind 0.0.0.0:$PORT --timeout 120 --preload`

### Frontend → GitHub Pages
- Settings → Pages → GitHub Actions
- Secret: `VITE_API_URL` = `https://your-render-url.onrender.com/api`
