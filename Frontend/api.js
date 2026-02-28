// ═══════════════════════════════════════════════════════
//  KavachNet — API Helper v4.0 (Production Hardened)
//  Clean Architecture & Dual-Token Rotation
// ═══════════════════════════════════════════════════════

const API_BASE = (() => {
    if (window.BACKEND_URL) return window.BACKEND_URL + '/api/v1';
    // Production safety: Disable localhost if not in dev mode
    const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    if (!isLocal && !window.BACKEND_URL) {
        console.error("[CRITICAL] Production Backend URL not configured. Security fallback engaged.");
        return 'https://api.kavachnet.io/api/v1'; // System fallback
    }
    return 'http://localhost:5000/api/v1';
})();

/**
 * Global Security Interceptor
 * Alerts the user to potential session hijacking or backend integrity failures.
 */
function handleSecurityAlert(errorType, message) {
    console.error(`[SECURITY ALERT] ${errorType}: ${message}`);
    if (errorType === 'INTEGRITY_FAILURE') {
        alert("CRITICAL: System integrity failure detected. Your session has been terminated for safety.");
        logout();
    }
}

// ── Token / session helpers (Ultra Hardening: sessionStorage) ──────
function saveToken(token)           { sessionStorage.setItem('kn_token', token); }
function getToken()                 { return sessionStorage.getItem('kn_token'); }
function clearToken()               { sessionStorage.removeItem('kn_token'); }

function saveRefreshToken(token)    { sessionStorage.setItem('kn_refresh', token); }
function getRefreshToken()          { return sessionStorage.getItem('kn_refresh'); }
function clearRefreshToken()        { sessionStorage.removeItem('kn_refresh'); }

function saveSession(data) {
    sessionStorage.setItem('kn_session', JSON.stringify({
        username:         data.username || '',
        role:             data.role || 'staff',
        institution_code: data.institution_code || null
    }));
}
function getSession() {
    const s = sessionStorage.getItem('kn_session');
    return s ? JSON.parse(s) : null;
}
function clearSession() { sessionStorage.removeItem('kn_session'); }

// ── Session Heartbeat & "Self-Destruct" Sequence ──
let heartbeatInterval = null;
function startSessionHeartbeat() {
    if (heartbeatInterval) return;
    heartbeatInterval = setInterval(async () => {
        if (!getToken()) return;
        try {
            // FIX: Use relative path — API_BASE already includes /api/v1
            const res = await apiGet('/auth/me');
            if (!res.ok) throw new Error("HEARTBEAT_FAILURE");
        } catch (err) {
            console.error("[SECURITY] Session heartbeat failed. Initiating self-destruct.");
            logout();
        }
    }, 300000); // Check every 5 minutes
}
function stopSessionHeartbeat() {
    if (heartbeatInterval) {
        clearInterval(heartbeatInterval);
        heartbeatInterval = null;
    }
}
if (getToken()) startSessionHeartbeat();

// ── World-Class Security: XSS Sanitization ─────────────────────
function sanitizeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ── Token Rotation ───────────────────────────────────────────
async function refreshToken() {
    const rf = getRefreshToken();
    if (!rf) return false;
    try {
        // FIX: Use relative path — API_BASE already includes /api/v1
        const res = await fetch(API_BASE + '/auth/refresh', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + rf }
        });
        if (res.ok) {
            const result = await res.json();
            // Handle standardized api_response format: {status, message, data}
            const accessToken = result.data ? result.data.access_token : result.access_token;
            if (accessToken) {
                saveToken(accessToken);
                return true;
            }
        }
    } catch (e) { console.error("Refresh failed", e); }
    return false;
}

// ── Logout ───────────────────────────────────────────────
function logout() {
    clearToken();
    clearRefreshToken();
    clearSession();
    stopSessionHeartbeat();
    window.location.href = 'portal.html';
}
function logoutSuperAdmin() {
    clearToken();
    clearRefreshToken();
    clearSession();
    stopSessionHeartbeat();
    window.location.href = 'superadmin-login.html';
}

// ── Auth Guards ──────────────────────────────────────────
function requireSuperAdmin() {
    const session = getSession();
    if (!getToken() || !session || session.role !== 'superadmin') {
        window.location.href = 'superadmin-login.html';
    }
}

function requireAuth(allowedRoles) {
    const session = getSession();
    if (!getToken() || !session) {
        window.location.href = 'portal.html';
        return;
    }
    if (allowedRoles && !allowedRoles.includes(session.role)) {
        window.location.href = 'portal.html';
    }
}

// ── Fetch wrappers with Automatic Refresh ────────────────
async function apiPost(endpoint, body, auth = false) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();

    let res = await fetch(API_BASE + endpoint, {
        method: 'POST', 
        headers, 
        body: JSON.stringify(body)
    });

    if (auth && res.status === 401) {
        if (await refreshToken()) {
            headers['Authorization'] = 'Bearer ' + getToken();
            res = await fetch(API_BASE + endpoint, {
                method: 'POST', 
                headers, 
                body: JSON.stringify(body)
            });
        } else {
            logout();
            throw new Error("AUTH_SESSION_INVALID");
        }
    }

    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}

async function apiGet(endpoint, auth = true) {
    const headers = {};
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();

    let res = await fetch(API_BASE + endpoint, { headers });

    if (auth && res.status === 401) {
        if (await refreshToken()) {
            headers['Authorization'] = 'Bearer ' + getToken();
            res = await fetch(API_BASE + endpoint, { headers });
        } else {
            logout();
            throw new Error("AUTH_SESSION_INVALID");
        }
    }

    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}

async function apiPatch(endpoint, body, auth = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();

    let res = await fetch(API_BASE + endpoint, {
        method: 'PATCH', 
        headers, 
        body: JSON.stringify(body)
    });

    if (auth && res.status === 401) {
        if (await refreshToken()) {
            headers['Authorization'] = 'Bearer ' + getToken();
            res = await fetch(API_BASE + endpoint, {
                method: 'PATCH', 
                headers, 
                body: JSON.stringify(body)
            });
        } else {
            logout();
            throw new Error("AUTH_SESSION_INVALID");
        }
    }

    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}
