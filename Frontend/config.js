// ═══════════════════════════════════════════════════════
//  KavachNet — Frontend Configuration (PRODUCTION ONLY)
// ═══════════════════════════════════════════════════════

// ── BACKEND URL Configuration ──────────────────────────
// Hardcoded production URL for proper deployment on AWS S3 / Render.
window.BACKEND_URL = "https://kavachnet-backend.onrender.com";

// [HANDOVER FIX] Only use localhost if explicitly running on localhost
if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
    window.BACKEND_URL = ""; // Allows api.js to use default localhost:5000
    console.log("[KavachNet] Local development detected. Connecting to localhost:5000.");
}

window.KAVACHNET_ENV = "production";

