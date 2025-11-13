// Backend base URL
const API_BASE = "https://backend-myvote.onrender.com";
let token = localStorage.getItem("token") || null;

function qs(id){return document.getElementById(id);}
function showResult(id,msg){
  const el = qs(id);
  if(el) el.innerText = typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2);
}

// Reusable fetch helper
async function apiFetch(path, opts = {}) {
  opts.headers = opts.headers || {};
  if (token) opts.headers["Authorization"] = "Bearer " + token;
  if (opts.body && typeof opts.body === "object") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  try {
    const res = await fetch(API_BASE + path, opts);
    const text = await res.text();
    try { return JSON.parse(text); } catch { return text; }
  } catch (err) {
    return { error: "Network error: " + err.message };
  }
}

// Register new user
async function register(){
  const name = qs('name').value;
  const email = qs('email').value;
  const phone = qs('phone').value;
  const password = qs('password').value;
  showResult('registerResult', 'Sending...');
  const data = await apiFetch('/api/register', { 
    method: 'POST', 
    body: { name, email, phone, password } 
  });
  showResult('registerResult', data);
}

// Request OTP
async function requestOtp(){
  const email = qs('otpEmail').value;
  const phone = qs('otpPhone').value;
  showResult('otpResult', 'Requesting OTP...');
  const data = await apiFetch('/api/otp/request', { 
    method: 'POST', 
    body: { email, phone } 
  });
  showResult('otpResult', data);
}

// ✅ Verify OTP (fixed)
async function verifyOtp(){
  const email = qs('otpEmail').value;
  const phone = qs('otpPhone').value;
  const otp = qs('otpCode').value;
  showResult('otpResult', 'Verifying...');
  
  const data = await apiFetch('/api/otp/verify', { 
    method: 'POST', 
    body: { email, phone, otp } 
  });
  
  if (data && data.token) {
    token = data.token;
    localStorage.setItem('token', token);
    showResult('otpResult', 'Authenticated. Token saved locally.');
  } else {
    showResult('otpResult', data);
  }
}

// Load elections list
async function loadElections(){
  const data = await apiFetch('/api/elections');
  const list = qs('electionList');
  if (!list) return;
  list.innerHTML = '';
  if (data && data.elections && Array.isArray(data.elections)) {
    data.elections.forEach(e=>{
      const li = document.createElement('li');
      li.innerHTML = `<strong>${escapeHtml(e.name)}</strong><br><small>${new Date(e.start_ts).toLocaleString()} - ${new Date(e.end_ts).toLocaleString()}</small>`;
      list.appendChild(li);
    });
  } else {
    list.innerHTML = `<li>${escapeHtml(JSON.stringify(data))}</li>`;
  }
}

// Escape HTML safely
function escapeHtml(str){
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, s => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[s]));
}
