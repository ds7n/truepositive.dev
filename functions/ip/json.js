// /ip/json — the JSON view of the /ip echo. Same handlers as /ip; wantsHtml()
// detects the /json path and forces the JSON response.
export { onRequestGet, onRequestHead, onRequest } from '../ip.js';
