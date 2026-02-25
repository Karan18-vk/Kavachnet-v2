// ═══════════════════════════════════════════════════════
//  KavachNet — API Helper v2.0
//  Change API_BASE if your backend runs on a different host
// ═══════════════════════════════════════════════════════

const API_BASE = 'http://localhost:5000';

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

// ── Fetch wrappers with Timeout and Robust Parsing ────────────────
async function apiPost(endpoint, body, auth = false) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000); // Increased to 60s for Render cold-starts

    const headers = { 'Content-Type': 'application/json' };
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();

    try {
        const res = await fetch(API_BASE + endpoint, {
            method: 'POST', 
            headers, 
            body: JSON.stringify(body),
            signal: controller.signal
        });
        clearTimeout(timeout);

        const contentType = res.headers.get("content-type");
        let data = {};
        if (contentType && contentType.includes("application/json")) {
            data = await res.json();
        } else {
            const text = await res.text();
            data = { msg: text || res.statusText };
        }

        if (res.status === 401 || res.status === 422) {
            const errText = data.error?.toLowerCase() || "";
            if (errText.includes("string") || errText.includes("token") || errText.includes("signature") || errText.includes("identity")) {
                throw new Error("AUTH_SESSION_INVALID");
            }
        }

        return { 
            ok: res.ok, 
            status: res.status, 
            data: { ...data, error: data.error || data.msg } 
        };
    } catch (err) {
        clearTimeout(timeout);
        if (err.message === "AUTH_SESSION_INVALID") throw err;
        if (err.name === 'AbortError') throw new Error("Request timed out (server slow to respond)");
        throw err;
    }
}

async function apiGet(endpoint, auth = true) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000); // Increased to 60s for Render cold-starts

    const headers = {};
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();

    try {
        const res = await fetch(API_BASE + endpoint, { 
            headers,
            signal: controller.signal 
        });
        clearTimeout(timeout);

        const contentType = res.headers.get("content-type");
        let data = {};
        if (contentType && contentType.includes("application/json")) {
            data = await res.json();
        } else {
            const text = await res.text();
            data = { msg: text || res.statusText };
        }

        if (res.status === 401 || res.status === 422) {
            const errText = data.error?.toLowerCase() || "";
            if (errText.includes("string") || errText.includes("token") || errText.includes("signature") || errText.includes("identity")) {
                throw new Error("AUTH_SESSION_INVALID");
            }
        }

        return { 
            ok: res.ok, 
            status: res.status, 
            data: { ...data, error: data.error || data.msg } 
        };
    } catch (err) {
        clearTimeout(timeout);
        if (err.message === "AUTH_SESSION_INVALID") throw err;
        if (err.name === 'AbortError') throw new Error("Request timed out (server slow to respond)");
        throw err;
    }
}

async function apiPatch(endpoint, body, auth = true) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000); // Increased to 60s for Render cold-starts

    const headers = { 'Content-Type': 'application/json' };
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();

    try {
        const res = await fetch(API_BASE + endpoint, {
            method: 'PATCH', 
            headers, 
            body: JSON.stringify(body),
            signal: controller.signal
        });
        clearTimeout(timeout);

        const contentType = res.headers.get("content-type");
        let data = {};
        if (contentType && contentType.includes("application/json")) {
            data = await res.json();
        } else {
            const text = await res.text();
            data = { msg: text || res.statusText };
        }

        if (res.status === 401 || res.status === 422) {
            const errText = data.error?.toLowerCase() || "";
            if (errText.includes("string") || errText.includes("token") || errText.includes("signature") || errText.includes("identity")) {
                throw new Error("AUTH_SESSION_INVALID");
            }
        }

        return { 
            ok: res.ok, 
            status: res.status, 
            data: { ...data, error: data.error || data.msg } 
        };
    } catch (err) {
        clearTimeout(timeout);
        if (err.message === "AUTH_SESSION_INVALID") throw err;
        if (err.name === 'AbortError') throw new Error("Request timed out (server slow to respond)");
        throw err;
    }
}

