# KavachNet v2.0 — Setup Guide

## How the Access System Works

```
Kavach Net Team (Super Admin)
    │  superadmin-login.html  →  superadmin.html
    │  Reviews institution requests, approves and issues institution codes
    ▼
Institution Admin
    │  institution-register.html  → submits request
    │  Receives institution code via email after approval
    │  register.html (role = Admin, enter institution code)
    │  admin-login.html → dashboard.html (Staff Management tab)
    │  Approves or rejects pending staff registrations
    ▼
Staff Members (max 2 per institution)
    │  register.html (role = Staff, enter institution code)
    │  Account is pending until admin approves
    └  staff-login.html → dashboard.html
```

**One institution = 1 Admin + 2 Staff = 3 members total**

---

## Backend Setup

### 1. Install dependencies
```bash
cd Backend
pip install -r requirements.txt
```

### 2. Create `.env` file in Backend/
```env
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here
JWT_ACCESS_TOKEN_EXPIRES=3600
EMAIL_ADDRESS=your-gmail@gmail.com
EMAIL_PASSWORD=your-app-password
GOOGLE_API_KEY=your-google-api-key
DB_NAME=kavachnet.db
SUPERADMIN_USERNAME=kavachnet_root
SUPERADMIN_PASSWORD=KN@SuperAdmin2026!
```

> Change SUPERADMIN_USERNAME and SUPERADMIN_PASSWORD before deploying!

### 3. Run the server
```bash
python app.py
```
Server runs on `http://localhost:5000`

---

## Frontend

Open `Frontened/landing.html` in your browser. All pages connect to `http://localhost:5000`.

---

## Full User Journey

### Step 1 — Institution registers (public)
- Go to `portal.html` → "Register a new institution"
- Fill in institution name, contact person, email

### Step 2 — You (Super Admin) approve
- Go to `superadmin-login.html`
- Username: `kavachnet_root` / Password: `KN@SuperAdmin2026!`
- Review the request → Approve → Copy the 8-character institution code
- Send the code to the institution's contact email

### Step 3 — Institution Admin registers
- Go to `register.html`
- Enter name, email, set password
- Enter the institution code → Validate → Select "Administrator"
- Account is instantly active (no approval needed for admin)

### Step 4 — Admin logs in
- Go to `portal.html` → Admin Login
- Enter credentials → Receive OTP → Enter OTP
- Access dashboard, click "Staff Management" in sidebar

### Step 5 — Staff members register
- Go to `register.html`
- Enter the same institution code → Validate → Select "Staff / Analyst"
- Account is pending admin approval

### Step 6 — Admin approves staff
- In dashboard → Staff Management
- Click "Approve" next to pending staff members

### Step 7 — Staff logs in
- Go to `portal.html` → Staff Login
- Enter credentials → OTP → Dashboard

---

## Debug Endpoints (development only)
- `GET /api/debug/otp/<username>` — retrieve OTP without email (remove in production)
- `GET /api/health` — health check
