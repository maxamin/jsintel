// Vulnerable SPA source (minified before shipping; secrets survive only in the .map)
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc0000example";
const API_BASE = "https://api.internal.reactlab/api/v3";
async function loadUser(id) {
  const r = await fetch(`${API_BASE}/users/${id}/profile`, { headers: { Authorization: "Bearer " + localStorage.token } });
  return r.json();
}
async function adminReset() { return fetch(API_BASE + "/admin/reset-all", { method: "POST" }); }
window.__app = { loadUser, adminReset, key: AWS_ACCESS_KEY_ID, stripe: STRIPE_KEY };
