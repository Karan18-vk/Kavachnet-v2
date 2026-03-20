// ═══════════════════════════════════════════════════════
//  KavachNet — Frontend Configuration
//  Edit BACKEND_URL here if you change the backend host.
// ═══════════════════════════════════════════════════════

// ── Local Development Override ──────────────────────────
// When served on localhost (e.g. VS Code Live Server / file://),
// api.js will automatically use http://localhost:5000/api/v1.
// Setting BACKEND_URL to "" tells api.js to use its localhost fallback.
if (
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === ""
) {
    window.BACKEND_URL = ""; // api.js falls back to http://localhost:5000/api/v1
    window.KAVACHNET_ENV = "development";
    console.log("[KavachNet] Local environment detected. Using localhost:5000.");
} else {
    // ── Production Backend URL ──────────────────────────
    // api.js will append /api/v1 automatically IF this URL does not already end with /api/v1.
    // DO NOT add a trailing slash.
    window.BACKEND_URL = "https://kavachnet-backend.onrender.com";
    window.KAVACHNET_ENV = "production";
}
