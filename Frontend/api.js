// ═══════════════════════════════════════════════════════
//  KavachNet — API Helper v2.0
//  Change API_BASE if your backend runs on a different host
// ═══════════════════════════════════════════════════════

const API_BASE = 'https://kavachnet-backend.onrender.com';

// ── Token / session helpers ─────────────────────────────
function saveToken(token)   { localStorage.setItem('kn_token', token); }
function getToken()         { return localStorage.getItem('kn_token'); }
function clearToken()       { localStorage.removeItem('kn_token'); }

function saveSession(data) {
    localStorage.setItem('kn_session', JSON.stringify({
        username:         data.username || '',
        role:             data.role || 'staff',
        institution_code: data.institution_code || null
    }));
}
function getSession() {
    const s = localStorage.getItem('kn_session');
    return s ? JSON.parse(s) : null;
}
function clearSession() { localStorage.removeItem('kn_session'); }

// ── Auth guard ───────────────────────────────────────────
function requireAuth(allowedRoles) {
    if (!getToken()) { window.location.href = 'portal.html'; return; }
    if (allowedRoles) {
        const s = getSession();
        if (!s || !allowedRoles.includes(s.role)) {
            window.location.href = 'portal.html';
        }
    }
}

function requireSuperAdmin() {
    if (!getToken()) { window.location.href = 'superadmin-login.html'; return; }
    const s = getSession();
    if (!s || s.role !== 'superadmin') { window.location.href = 'superadmin-login.html'; }
}

// ── Logout ───────────────────────────────────────────────
function logout() {
    clearToken();
    clearSession();
    window.location.href = 'portal.html';
}
function logoutSuperAdmin() {
    clearToken();
    clearSession();
    window.location.href = 'superadmin-login.html';
}

// ── Fetch wrappers ───────────────────────────────────────
async function apiPost(endpoint, body, auth = false) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();
    const res = await fetch(API_BASE + endpoint, {
        method: 'POST', headers, body: JSON.stringify(body)
    });
    return res.json().then(data => ({ 
        ok: res.ok, 
        status: res.status, 
        data: { ...data, error: data.error || data.msg } 
    }));
}

async function apiGet(endpoint, auth = true) {
    const headers = {};
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();
    const res = await fetch(API_BASE + endpoint, { headers });
    return res.json().then(data => ({ 
        ok: res.ok, 
        status: res.status, 
        data: { ...data, error: data.error || data.msg } 
    }));
}

async function apiPatch(endpoint, body, auth = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();
    const res = await fetch(API_BASE + endpoint, {
        method: 'PATCH', headers, body: JSON.stringify(body)
    });
    return res.json().then(data => ({ 
        ok: res.ok, 
        status: res.status, 
        data: { ...data, error: data.error || data.msg } 
    }));
}
