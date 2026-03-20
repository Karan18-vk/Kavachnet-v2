// ═══════════════════════════════════════════════════════
//  KavachNet — API Helper v4.1 (Production Hardened)
//  Clean Architecture & Dual-Token Rotation
// ═══════════════════════════════════════════════════════

const API_BASE = (() => {
    // Priority 1: Explicit backend URL set via config.js or inline script
    if (window.BACKEND_URL) {
        // Strip trailing slash, ensure /api/v1 suffix is present exactly once
        const base = window.BACKEND_URL.replace(/\/+$/, '');
        return base.endsWith('/api/v1') ? base : base + '/api/v1';
    }

    // Priority 2: Local development fallback
    const isLocal = (
        window.location.hostname === 'localhost' ||
        window.location.hostname === '127.0.0.1' ||
        window.location.hostname === ''
    );
    if (isLocal) {
        return 'http://localhost:5000/api/v1';
    }

    // Priority 3: Production fallback — MUST include /v1 segment
    // FIX (Bug 5): was '/api' — missing /v1 caused all production API calls to 404
    const RENDER_URL = 'https://kavachnet-backend.onrender.com/api/v1';
    console.warn("[KavachNet] BACKEND_URL not set. Using default Render URL:", RENDER_URL);
    return RENDER_URL;
})();


console.log("[KavachNet] API Base:", API_BASE);

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

// ── Response Helper ──────────────────────────────────────
/**
 * Extracts data from standardized backend response format {status, message, data}
 * Usage: const payload = extractData(res); // gets res.data.data
 */
function extractData(res) {
    if (res.data && res.data.data !== undefined) return res.data.data;
    return res.data || {};
}

/**
 * Extracts error/message from standardized backend response
 * Usage: const msg = extractMessage(res); // gets res.data.message
 */
function extractMessage(res) {
    if (res.data && res.data.message) return res.data.message;
    if (res.data && res.data.error) return res.data.error; // Legacy fallback
    
    // Handle cases where the backend returned HTML (e.g. 502 Bad Gateway) and JSON parsing failed
    if (res.status === 502) return "Backend is currently waking up (502). Please wait 30 seconds and try again.";
    if (res.status === 503) return "Service temporarily unavailable (503).";
    if (res.status === 504) return "Gateway timeout (504). The server took too long to respond.";
    if (res.status === 500) return "Internal Server Error (500).";
    if (res.status === 404) return "API Endpoint not found (404). Check backend URL.";
    if (res.status === 0)   return "Network Error or CORS issue block.";
    
    return `An unknown error occurred (Status: ${res.status || 'unknown'}).`;
}

// ── Fetch wrappers with Automatic Refresh ────────────────
async function _apiFetch(method, endpoint, body, auth) {
    const url = API_BASE + endpoint;
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (auth) headers['Authorization'] = 'Bearer ' + getToken();

    const opts = { method, headers };
    if (body !== undefined) opts.body = JSON.stringify(body);

    let res;
    try {
        res = await fetch(url, opts);
    } catch (networkErr) {
        // Network-level failure (no connection, CORS preflight blocked, DNS failure)
        console.error(`[KavachNet] Network error on ${method} ${url}:`, networkErr);
        return { ok: false, status: 0, data: { error: 'Network error — cannot reach backend.', detail: networkErr.message } };
    }

    if (auth && res.status === 401) {
        if (await refreshToken()) {
            headers['Authorization'] = 'Bearer ' + getToken();
            try {
                res = await fetch(url, { ...opts, headers });
            } catch (retryErr) {
                console.error(`[KavachNet] Retry network error on ${method} ${url}:`, retryErr);
                return { ok: false, status: 0, data: { error: 'Network error on retry.' } };
            }
        } else {
            logout();
            throw new Error('AUTH_SESSION_INVALID');
        }
    }

    // Attempt JSON parse; fall through to empty object on non-JSON responses (e.g. 502 HTML page)
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}

async function apiPost(endpoint, body, auth = false) {
    return _apiFetch('POST', endpoint, body, auth);
}

async function apiGet(endpoint, auth = true) {
    return _apiFetch('GET', endpoint, undefined, auth);
}

async function apiPatch(endpoint, body, auth = true) {
    return _apiFetch('PATCH', endpoint, body, auth);
}

async function apiPut(endpoint, body, auth = true) {
    return _apiFetch('PUT', endpoint, body, auth);
}

async function apiDelete(endpoint, auth = true) {
    return _apiFetch('DELETE', endpoint, undefined, auth);
}
