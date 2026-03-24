/**
 * KavachNet AI ML Integration Sample
 * This script demonstrates how to connect your dashboard frontend to the new ML-based scan endpoints.
 */

const API_BASE_URL = "http://127.0.0.1:5000/api/v1/ai-ml";

/**
 * Scans a single URL for phishing threats using the trained Random Forest model.
 * @param {string} url - The URL to analyze.
 * @param {string} token - JWT Access Token (optional but recommended for history saving).
 */
async function scanUrl(url, token = null) {
  try {
    const response = await fetch(`${API_BASE_URL}/predict-url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : ''
      },
      body: JSON.stringify({ url })
    });

    const result = await response.json();
    if (result.status === "success") {
      console.log("🛡️ Scan Result:", result.data);
      return result.data;
    } else {
      console.error("❌ Scan Failed:", result.message);
    }
  } catch (error) {
    console.error("🌐 Network Error:", error);
  }
}

/**
 * Scans block of text (email body, chat content) for embedded phishing links.
 * @param {string} content - The text content to analyze.
 * @param {string} token - JWT Access Token.
 */
async function scanContent(content, token = null) {
  try {
    const response = await fetch(`${API_BASE_URL}/predict-content`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : ''
      },
      body: JSON.stringify({ content })
    });

    const result = await response.json();
    return result.data;
  } catch (error) {
    console.error("🌐 Network Error:", error);
  }
}

// --- EXAMPLE USAGE ---
/*
const myToken = localStorage.getItem('access_token');

// 1. Scan a suspicious URL
scanUrl("http://secure-login-wellsfargo.com", myToken).then(data => {
  if (data.verdict === "Malicious") {
    alert(`DANGER! Risk Level: ${data.risk_level}\nReasons: ${data.reasons.join(', ')}`);
  }
});

// 2. Scan an email body
const emailBody = "Dear user, please update your account at http://verify-bank.xyz immediately.";
scanContent(emailBody, myToken).then(data => {
  console.log(`Content scan verdict: ${data.verdict} (${data.confidence}% confidence)`);
});
*/
