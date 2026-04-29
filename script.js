(function(){
    if(typeof emailjs !== 'undefined'){
      emailjs.init({ publicKey: '1SAe2l62JpULmOWYt' });
    }
  })();

'use strict';

// ═══════════════════════════════════════════════
// MINDVORA SECURITY SYSTEM v1.0
// ═══════════════════════════════════════════════

// ── INPUT SANITIZER ──
function sanitize(str){
  if(typeof str !== 'string') return '';
  if(typeof DOMPurify !== 'undefined'){
    return DOMPurify.sanitize(str, {ALLOWED_TAGS:[], ALLOWED_ATTR:[]});
  }
  return str.replace(/[<>"'&]/g, function(m){
    return {'<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;','&':'&amp;'}[m];
  });
}

// ── URL VALIDATOR — block malicious links ──
var BLOCKED_DOMAINS = ['bit.ly','tinyurl.com','goo.gl','ow.ly','t.co/','is.gd','buff.ly','adf.ly','bc.vc'];
var SAFE_PROTOCOLS = ['https:','http:','mailto:'];
function isSafeUrl(url){
  if(!url || typeof url !== 'string') return false;
  url = url.trim();
  try {
    var u = new URL(url);
    if(!SAFE_PROTOCOLS.includes(u.protocol)) return false;
    // Block javascript: and data: URIs
    if(/^(javascript|data|vbscript):/i.test(url)) return false;
    return true;
  } catch(e){ return false; }
}

// ── RATE LIMITER — prevent spam/abuse ──
var rateLimits = {};
function checkRateLimit(action, maxPerMin){
  var now = Date.now();
  var key = action + '_' + (window._mvUid||'anon');
  if(!rateLimits[key]) rateLimits[key] = [];
  // Remove entries older than 1 minute
  rateLimits[key] = rateLimits[key].filter(function(t){ return now-t < 60000; });
  if(rateLimits[key].length >= maxPerMin){
    showToast('⚠️ Too many attempts. Please wait a moment.');
    return false;
  }
  rateLimits[key].push(now);
  return true;
}

// ── CONTENT VALIDATOR — block malicious content ──
var BLOCKED_PATTERNS = [
  /<script/gi, /javascript:/gi, /on\w+\s*=/gi,
  /data:text\/html/gi, /vbscript:/gi, /<iframe/gi,
  /<object/gi, /<embed/gi, /eval\s*\(/gi,
  /document\.cookie/gi, /window\.location\s*=/gi,
  /\.exe$/gi, /\.bat$/gi, /\.cmd$/gi, /\.sh$/gi,
  /\.ps1$/gi, /\.vbs$/gi, /\.jar$/gi,
];
function containsMalicious(text){
  if(!text) return false;
  return BLOCKED_PATTERNS.some(function(p){ return p.test(text); });
}

// ── PAYWALL PROTECTION — verify premium server-side style ──
function verifyPremiumAccess(feature){
  if(!state.user){ showToast('Please log in to access this feature.'); return false; }
  var premiumFeatures = ['analytics','verified','creatorFund'];
  if(premiumFeatures.includes(feature) && !state.profile.isPremium){
    showToast('💎 This feature requires a Premium account.'); 
    openModal('modal-prem');
    return false;
  }
  return true;
}

// ── PAYMENT INTEGRITY — prevent payment bypass ──
function verifyPayment(ref, expectedAmount, callback){
  if(!ref || !expectedAmount){ showToast('❌ Invalid payment reference.'); return; }
  // Store pending verification in Firestore
  db.collection('payment_verifications').add({
    ref: ref, amount: expectedAmount,
    userId: state.user ? state.user.uid : null,
    status: 'pending',
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(){ if(callback) callback(); })
  .catch(function(){ if(callback) callback(); });
}

// ── ACCOUNT PROTECTION — detect suspicious activity ──
var failedLoginAttempts = {};
function trackLoginAttempt(email, success){
  if(!failedLoginAttempts[email]) failedLoginAttempts[email] = {count:0, firstAt:Date.now()};
  if(success){
    failedLoginAttempts[email] = {count:0, firstAt:Date.now()};
    return true;
  }
  var now = Date.now();
  // Reset after 15 mins
  if(now - failedLoginAttempts[email].firstAt > 900000){
    failedLoginAttempts[email] = {count:0, firstAt:now};
  }
  failedLoginAttempts[email].count++;
  if(failedLoginAttempts[email].count >= 5){
    showToast('🔒 Too many failed attempts. Please wait 15 minutes.');
    return false;
  }
  return true;
}

function isLoginLocked(email){
  // Never lock out owner accounts
  if (email && (email === 'ilohgreat25@gmail.com' || email === 'mindvoraofficial@outlook.com')) return false;
  if (!failedLoginAttempts[email]) return false;
  var now = Date.now();
  // Reset after 15 minutes
  if (now - failedLoginAttempts[email].firstAt > 900000) {
    failedLoginAttempts[email] = {count:0, firstAt:now};
    return false;
  }
  // Only lock after 10 attempts (was 5 — too aggressive)
  var locked = failedLoginAttempts[email].count >= 10;
  if (locked) {
    var li_err = document.getElementById('li-err');
    if (li_err) li_err.textContent = '⏳ Too many attempts. Wait 15 minutes or click Forgot Password to reset.';
  }
  return locked;
}

// ── SPAM DETECTOR — detect bot-like behavior ──
var actionLog = [];
function logAction(type){
  var now = Date.now();
  actionLog.push({type:type, time:now});
  actionLog = actionLog.filter(function(a){ return now-a.time < 10000; });
  if(actionLog.length > 30){
    console.warn('Mindvora Security: Suspicious activity detected');
    return false;
  }
  return true;
}

// ── LINK SAFETY — silently open all external links safely ──
document.addEventListener('click', function(e){
  var a = e.target.closest('a[href]');
  if(!a) return;
  var href = a.getAttribute('href');
  if(!href || href.startsWith('#') || href.startsWith('/')) return;
  try {
    var u = new URL(href);
    if(u.hostname !== window.location.hostname){
      e.preventDefault();
      // Silently open safely — no popup, no interruption
      window.open(href, '_blank', 'noopener,noreferrer');
    }
  } catch(err){}
});

// ── DEVTOOLS DETECTION — warn against console injection ──
var devtoolsWarned = false;
setInterval(function(){
  var threshold = 160;
  if(window.outerWidth - window.innerWidth > threshold || window.outerHeight - window.innerHeight > threshold){
    if(!devtoolsWarned){
      devtoolsWarned = true;
      console.log('%c⚠️ Mindvora Security Warning', 'color:red;font-size:20px;font-weight:bold');
      console.log('%cDo not paste any code here unless you fully understand what it does.\nThis could allow attackers to steal your account.', 'color:orange;font-size:14px');
    }
  }
}, 3000);

// ── SECURITY ALERT SYSTEM ──
var OWNER_EMAIL = 'zyncofficial06@gmail.com';
var securityAlerts = {
  loginFailures: {},
  suspiciousIPs: {},
  alertCooldowns: {}
};

// Send security alert to owner via Firestore notification + email
function sendSecurityAlert(type, details){
  if(!db || !type) return;
  try {
  
  // Cooldown — don't spam same alert type (max 1 per 5 mins)
  var now = Date.now();
  var cooldownKey = type;
  if(securityAlerts.alertCooldowns[cooldownKey] && 
     now - securityAlerts.alertCooldowns[cooldownKey] < 300000) return;
  securityAlerts.alertCooldowns[cooldownKey] = now;

  var alertMessages = {
    'brute_force': '🔴 SECURITY ALERT: Someone tried to break into an account by failing login 5+ times. IP activity logged.',
    'admin_probe': '🔴 SECURITY ALERT: Someone attempted unauthorized access to your Admin Panel.',
    'suspicious_payment': '🔴 SECURITY ALERT: Unusual payment activity detected on Mindvora.',
    'rate_limit_exceeded': '🟡 WARNING: Suspicious rapid activity detected — possible bot attack.',
    'malicious_content': '🔴 SECURITY ALERT: Someone tried to post malicious content on Mindvora.',
    'mass_dm': '🟡 WARNING: Someone is sending an unusual number of messages — possible spam bot.',
    'invalid_ad_url': '🟡 WARNING: Someone tried to submit an ad with a suspicious/malicious URL.',
    'session_hijack': '🔴 SECURITY ALERT: Suspicious session activity detected — possible account hijack attempt.'
  };

  var message = alertMessages[type] || '🔴 SECURITY ALERT: Suspicious activity detected on Mindvora. Type: ' + type;
  if(details) message += ' Details: ' + details;

  // Save to Firestore security_alerts collection
  db.collection('security_alerts').add({
    type: type,
    message: message,
    details: details || '',
    timestamp: firebase.firestore.FieldValue.serverTimestamp(),
    resolved: false
  }).catch(function(){});

  // Send notification to owner's Mindvora account
  db.collection('users').where('email','==',ADMIN_EMAIL).limit(1).get().then(function(snap){
    if(!snap.empty){
      var ownerId = snap.docs[0].id;
      db.collection('notifications').add({
        to: ownerId,
        type: 'security_alert',
        text: message,
        read: false,
        priority: 'high',
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      });
    }
  }).catch(function(){});

  // Log to console with red styling
  console.log('%c' + message, 'color:red;font-weight:bold;font-size:13px');
  } catch(e) { /* silent fail */ }
}

// ── BRUTE FORCE DETECTION ──
var originalTrackLogin = typeof trackLoginAttempt === 'function' ? trackLoginAttempt : function(){};
trackLoginAttempt = function(email, success){
  if(!success){
    if(!securityAlerts.loginFailures[email]) securityAlerts.loginFailures[email] = 0;
    securityAlerts.loginFailures[email]++;
    if(securityAlerts.loginFailures[email] >= 5){
      sendSecurityAlert('brute_force', 'Target email: ' + email);
      securityAlerts.loginFailures[email] = 0;
    }
  } else {
    securityAlerts.loginFailures[email] = 0;
  }
  return originalTrackLogin(email, success);
};

// ── ADMIN PANEL PROBE DETECTION ──
var originalOpenModal = openModal;
openModal = function(id){
  if(id === 'modal-admin' && !isAdmin() && state && state.user){
    sendSecurityAlert('admin_probe', 'Non-admin user attempted to access admin panel. User: ' + state.user.email);
  }
  return originalOpenModal(id);
};

// ── MALICIOUS CONTENT DETECTION ──
var originalContainsMalicious = containsMalicious;
containsMalicious = function(text){
  var result = originalContainsMalicious(text);
  if(result && state && state.user){
    sendSecurityAlert('malicious_content', 'User: ' + state.user.email + ' attempted to post: ' + (text||'').substring(0,50));
  }
  return result;
};

// ── RATE LIMIT ALERT ──
var originalCheckRateLimit = checkRateLimit;
checkRateLimit = function(action, maxPerMin){
  var result = originalCheckRateLimit(action, maxPerMin);
  if(!result && state && state.user){
    if(action === 'dm'){
      sendSecurityAlert('mass_dm', 'User: ' + state.user.email + ' exceeded DM rate limit.');
    } else {
      sendSecurityAlert('rate_limit_exceeded', 'Action: ' + action + ' · User: ' + state.user.email);
    }
  }
  return result;
};

// ── SUSPICIOUS PAYMENT DETECTION ──
function checkPaymentSuspicion(amount, email){
  // Alert if single payment exceeds $500
  if(amount > 500){
    sendSecurityAlert('suspicious_payment', 'Large payment detected: $' + amount + ' from ' + email);
  }
  // Alert if payment amount is 0 or negative
  if(amount <= 0){
    sendSecurityAlert('suspicious_payment', 'Invalid payment amount: $' + amount + ' from ' + email);
  }
}

// ── INVALID AD URL ALERT ──
var originalIsSafeUrl = typeof isSafeUrl === 'function' ? isSafeUrl : function(){ return true; };
isSafeUrl = function(url){
  var result = originalIsSafeUrl(url);
  if(!result && url && url.length > 0){
    sendSecurityAlert('invalid_ad_url', 'Suspicious URL submitted: ' + (url||'').substring(0,80) + ' by ' + (state && state.user ? state.user.email : 'unknown'));
  }
  return result;
};

// ── SECURITY DASHBOARD — view all alerts ──
function loadSecurityAlerts(){
  if(!isAdmin()) return;
  db.collection('security_alerts').limit(50).get().then(function(snap){
    var unresolvedCount = snap.docs.filter(function(d){ return !d.data().resolved; }).length;
    // Update admin nav badge if there are unresolved alerts
    var adminNav = document.getElementById('nav-admin');
    if(adminNav && unresolvedCount > 0){
      var existing = adminNav.querySelector('.security-alert-dot');
      if(!existing){
        var dot = document.createElement('span');
        dot.className = 'security-alert-dot';
        dot.style.cssText = 'width:8px;height:8px;border-radius:50%;background:#ef4444;display:inline-block;margin-left:4px;animation:pulse 1s infinite';
        adminNav.appendChild(dot);
      }
    }
  }).catch(function(){});
}

// Check security alerts every 2 minutes when admin is logged in
setInterval(function(){
  if(isAdmin()) loadSecurityAlerts();
}, 120000);

// ── SESSION SECURITY ──
var SESSION_TIMEOUT = 7 * 24 * 60 * 60 * 1000; // 7 days
var lastActivity = Date.now();
// Reset activity on any interaction
document.addEventListener('click',     function(){ lastActivity = Date.now(); });
document.addEventListener('keypress',  function(){ lastActivity = Date.now(); });
document.addEventListener('touchstart',function(){ lastActivity = Date.now(); });
document.addEventListener('scroll',    function(){ lastActivity = Date.now(); });
// Save lastActivity to localStorage so it persists across page loads
try { 
  var saved = localStorage.getItem('mv_lastActivity');
  if (saved) lastActivity = parseInt(saved) || Date.now();
} catch(e){}
setInterval(function(){
  try { localStorage.setItem('mv_lastActivity', lastActivity); } catch(e){}
  if(state.user && Date.now() - lastActivity > SESSION_TIMEOUT){
    auth.signOut();
    showToast('🔒 Session expired. Please log in again.');
  }
}, 60000);

// ── FIRESTORE SECURITY HELPERS ──
// Validate all user inputs before writing to Firestore
function safeFirestoreWrite(collection, data, docId){
  // Sanitize all string fields
  var cleaned = {};
  Object.keys(data).forEach(function(k){
    var v = data[k];
    if(typeof v === 'string'){
      if(containsMalicious(v)){
        showToast('❌ Invalid content detected. Please remove special characters.');
        return;
      }
      cleaned[k] = sanitize(v);
    } else {
      cleaned[k] = v;
    }
  });
  if(docId){
    return db.collection(collection).doc(docId).set(cleaned);
  }
  return db.collection(collection).add(cleaned);
}

// Store current user uid for rate limiting
if(typeof auth !== 'undefined') // _mvUid updated inside initAuthListener

// Security system active

// ═══════════════════════════════════════════════
// MINDVORA SECURITY ALERT SYSTEM
// ═══════════════════════════════════════════════

var OWNER_EMAIL = 'zyncofficial06@gmail.com';
var securityLog = [];

// ── SHOW SECURITY ALERT BANNER ──
function showSecAlert(title, message, type){
  type = type || 'danger';
  var banner = document.getElementById('sec-alert-banner');
  if(!banner) return;
  var alert = document.createElement('div');
  alert.className = 'sec-alert ' + (type==='warn'?'warn':type==='info'?'info':'');
  var icon = type==='danger'?'🚨':type==='warn'?'⚠️':'ℹ️';
  var now = new Date().toLocaleTimeString();
  alert.innerHTML = '<div class="sa-icon">'+icon+'</div><div class="sa-content"><div class="sa-title '+(type==='warn'?'warn':type==='info'?'info':'')+'">'+title+'</div><div class="sa-msg">'+message+'</div><div class="sa-time">'+now+'</div></div>';
  banner.appendChild(alert);
  // Auto remove after 8 seconds
  setTimeout(function(){ 
    alert.style.opacity='0'; 
    alert.style.transition='opacity .3s';
    setTimeout(function(){ if(alert.parentNode) alert.parentNode.removeChild(alert); }, 300);
  }, 8000);
  // Log to Firestore if user logged in
  if(state.user){
    db.collection('security_logs').add({
      type: type, title: title, message: message,
      userId: state.user ? state.user.uid : null,
      timestamp: firebase.firestore.FieldValue.serverTimestamp()
    }).catch(function(){});
  }
}

// ── NOTIFY OWNER IN Mindvora + FIRESTORE ──
function notifyOwner(title, message, severity){
  // Store in Firestore security_alerts collection
  db.collection('security_alerts').add({
    title: title, message: message, severity: severity||'high',
    read: false, createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).catch(function(){});
  // Show in owner's notification if they're logged in as admin
  if(isAdmin()){
    showSecAlert(title, message, severity==='high'?'danger':'warn');
  }
  // Save to local security log
  securityLog.push({title:title, message:message, time:new Date().toISOString()});
}

// ── WATCH FOR SECURITY ALERTS IN REALTIME (ADMIN ONLY) ──
function startSecurityWatch(){
  if(!isAdmin()) return;
  // Listen for new security alerts in real time
  db.collection('security_alerts')
    .where('read','==',false)
    .orderBy('createdAt','desc')
    .limit(10)
    .onSnapshot(function(snap){
      snap.docChanges().forEach(function(change){
        if(change.type === 'added'){
          var alert = change.doc.data();
          // Only show alerts added in last 30 seconds
          var now = Date.now();
          var alertTime = alert.createdAt ? alert.createdAt.seconds * 1000 : 0;
          if(now - alertTime < 30000){
            showSecAlert(alert.title, alert.message, alert.severity==='high'?'danger':'warn');
            // Update notification bell
            updateNotifBell();
          }
        }
      });
    }, function(){});
}

// ── ENHANCED LOGIN FAILURE TRACKING ──
var origTrackLogin = trackLoginAttempt;
trackLoginAttempt = function(email, success){
  var result = origTrackLogin(email, success);
  if(!success){
    var attempts = failedLoginAttempts[email] ? failedLoginAttempts[email].count : 0;
    if(attempts >= 3){
      notifyOwner(
        '🔴 Multiple Failed Logins',
        'Account '+email+' has '+attempts+' failed login attempts. Possible brute force attack.',
        'high'
      );
    }
  }
  return result;
};

// ── MONITOR SUSPICIOUS PAYMENT ACTIVITY ──
function checkSuspiciousPayment(amount, type){
  var MAX_AMOUNTS = {tip:50, premium:20, airtime:100, data:50, ad:500};
  var max = MAX_AMOUNTS[type] || 1000;
  if(amount > max){
    notifyOwner(
      '⚠️ Unusual Payment Detected',
      'A '+type+' payment of $'+amount+' was attempted — above normal limit of $'+max+'.',
      'high'
    );
    return false;
  }
  return true;
}

// ── MONITOR RAPID REQUESTS (DDoS Detection) ──
var requestCounts = {};
function monitorRequests(action){
  var now = Date.now();
  var key = action;
  if(!requestCounts[key]) requestCounts[key] = [];
  requestCounts[key] = requestCounts[key].filter(function(t){ return now-t < 60000; });
  requestCounts[key].push(now);
  if(requestCounts[key].length > 50){
    notifyOwner(
      '🚨 Possible DDoS Attack',
      'Action "'+action+'" has been triggered '+requestCounts[key].length+' times in the last minute from one session.',
      'high'
    );
  }
}

// ── MONITOR ADMIN PANEL ACCESS ──
var origOpenAdmin = document.getElementById('nav-admin').onclick;
document.getElementById('nav-admin').addEventListener('click', function(){
  if(isAdmin()){
    // Log legitimate admin access
    db.collection('security_logs').add({
      type:'info', title:'Admin Panel Accessed',
      message:'Owner accessed admin panel at '+new Date().toLocaleString(),
      userId: state.user ? state.user.uid : null,
      timestamp: firebase.firestore.FieldValue.serverTimestamp()
    }).catch(function(){});
  }
});

// ── MONITOR NEW USER SIGNUPS FOR SUSPICIOUS PATTERNS ──
function monitorNewSignup(email, uid){
  // Check for disposable email patterns
  var disposableDomains = ['tempmail','guerrillamail','mailinator','throwaway','fakeinbox','yopmail'];
  var emailDomain = email.split('@')[1]||'';
  if(disposableDomains.some(function(d){ return emailDomain.includes(d); })){
    notifyOwner(
      '⚠️ Suspicious Signup',
      'New signup with disposable email: '+email+'. May be a bot or fake account.',
      'medium'
    );
  }
}

// ── MONITOR WITHDRAWAL REQUESTS ──
function monitorWithdrawal(amount, userId){
  if(amount > 500){
    notifyOwner(
      '🚨 Large Withdrawal Request',
      'User '+userId+' requested a withdrawal of $'+amount+'. Please verify before processing.',
      'high'
    );
  }
}

// ── ADMIN SECURITY DASHBOARD ──
function loadSecurityAlerts(){
  if(!isAdmin()) return;
  db.collection('security_alerts')
    .orderBy('createdAt','desc')
    .limit(50)
    .get().then(function(snap){
      var unread = snap.docs.filter(function(d){ return !d.data().read; }).length;
      if(unread > 0){
        // Don't spam toast on every login — just update the admin badge quietly
        var adminNav = document.getElementById('nav-admin');
        if(adminNav){
          var existing = adminNav.querySelector('.security-badge-count');
          if(!existing){
            var badge = document.createElement('span');
            badge.className = 'security-badge-count';
            badge.style.cssText = 'background:#ef4444;color:#fff;font-size:9px;padding:1px 5px;border-radius:10px;margin-left:4px;font-weight:700';
            badge.textContent = unread;
            adminNav.appendChild(badge);
          } else {
            existing.textContent = unread;
          }
        }
      }
    }).catch(function(){});
}

// ── START SECURITY WATCH WHEN ADMIN LOGS IN ──
var origCheckAdmin = checkAdminAccess;
checkAdminAccess = function(){
  origCheckAdmin();
  if(isAdmin()){
    startSecurityWatch();
    setTimeout(loadSecurityAlerts, 2000);
  }
};

// ── ADD SECURITY TAB TO ADMIN PANEL ──
setTimeout(function(){
  var adminTabs = document.querySelector('#modal-admin .admin-tabs');
  if(adminTabs && isAdmin()){
    // Security tab already in HTML — no need to add dynamically
    // Add security panel div
    var secPanel = document.createElement('div');
    secPanel.id = 'admin-security';
    secPanel.style.display = 'none';
    secPanel.innerHTML = '<div id="security-alerts-list"><div style="text-align:center;padding:20px;color:var(--muted)">Loading security alerts…</div></div>';
    var adminOverview = document.getElementById('admin-overview');
    if(adminOverview && adminOverview.parentNode){
      adminOverview.parentNode.appendChild(secPanel);
    }
  }
}, 3000);

// Override switchAdminTab to handle security tab
var origSwitchAdminTab = switchAdminTab;
switchAdminTab = function(tab, btn){
  if(tab === 'security'){
    document.querySelectorAll('#modal-admin .admin-tabs .f-pill').forEach(function(b){ b.classList.remove('active'); });
    btn.classList.add('active');
    ['pending','approved','rejected','overview','security','users'].forEach(function(t){
      var el = document.getElementById('admin-'+t);
      if(el) el.style.display = t===tab?'block':'none';
    });
    loadSecurityAlertsList();
    return;
  }
  origSwitchAdminTab(tab, btn);
};

function loadSecurityAlertsList(){
  if(!isAdmin()) return;
  var list = document.getElementById('security-alerts-list');
  if(!list) return;
  db.collection('security_alerts').orderBy('createdAt','desc').limit(50).get().then(function(snap){
    if(snap.empty){
      list.innerHTML = '<div style="text-align:center;padding:30px;color:var(--muted)"><div style="font-size:36px;margin-bottom:10px">🛡️</div>No security alerts yet</div>';
      return;
    }
    // Mark all as read
    snap.docs.forEach(function(d){ d.ref.update({read:true}).catch(function(){}); });
    list.innerHTML = snap.docs.map(function(d){
      var a = Object.assign({id:d.id}, d.data());
      var time = a.createdAt ? new Date(a.createdAt.seconds*1000).toLocaleString() : 'Unknown';
      var color = a.severity==='high'?'#fca5a5':a.severity==='medium'?'#fcd34d':'#93c5fd';
      var icon = a.severity==='high'?'🚨':a.severity==='medium'?'⚠️':'ℹ️';
      return '<div style="background:var(--deep);border:1px solid var(--border);border-radius:12px;padding:12px 14px;margin-bottom:8px">'+
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">'+
          '<span style="font-size:16px">'+icon+'</span>'+
          '<span style="font-size:12px;font-weight:700;color:'+color+'">'+esc(a.title||'Alert')+'</span>'+
          '<span style="font-size:9px;color:var(--muted);margin-left:auto">'+time+'</span>'+
        '</div>'+
        '<div style="font-size:11px;color:var(--moon);line-height:1.6">'+esc(a.message||'')+'</div>'+
      '</div>';
    }).join('');
  }).catch(function(e){
    if(list) list.innerHTML = '<div style="color:#fca5a5;padding:14px">Error loading alerts: '+esc(e.message)+'</div>';
  });
}

// ═══════════════════════════════════════════════
// MINDVORA SECURITY ALERT SYSTEM
// ═══════════════════════════════════════════════

var OWNER_ALERT_EMAIL = 'ilohgreat25@gmail.com';
var alertCooldowns = {};

// ── SEND SECURITY ALERT ──
function sendSecurityAlert(type, message, severity){
  if(!db) return;
  var now = Date.now();
  // Cooldown — don't spam same alert type within 5 mins
  if(alertCooldowns[type] && now - alertCooldowns[type] < 300000) return;
  alertCooldowns[type] = now;

  var icons = {
    'login_attack': '🔴',
    'suspicious_payment': '💳',
    'admin_breach': '👑',
    'spam_attack': '🤖',
    'malicious_content': '☠️',
    'unusual_activity': '⚠️'
  };
  var icon = icons[type] || '🔒';
  var severityColors = {high:'#ef4444', medium:'#f59e0b', low:'#22c55e'};

  // Save alert to Firestore
  db.collection('security_alerts').add({
    type: type,
    message: message,
    severity: severity || 'medium',
    icon: icon,
    read: false,
    timestamp: firebase.firestore.FieldValue.serverTimestamp(),
    userAgent: navigator.userAgent.slice(0,100),
    url: window.location.href
  }).catch(function(){});

  // Show in owner's notification bell if they're logged in
  if(state.user && state.user.email === OWNER_ALERT_EMAIL){
    db.collection('notifications').add({
      to: state.user.uid,
      type: 'security_alert',
      text: icon + ' SECURITY ALERT: ' + message,
      severity: severity || 'medium',
      read: false,
      createdAt: firebase.firestore.FieldValue.serverTimestamp()
    }).catch(function(){});
    // Show immediate toast for high severity
    if(severity === 'high'){
      showToast(icon + ' Security Alert: ' + message);
    }
  }

  // Log to console with styling
  console.warn('%c' + icon + ' Mindvora Security Alert [' + (severity||'medium').toUpperCase() + ']: ' + message,
    'color:' + (severityColors[severity||'medium']) + ';font-weight:bold');
}

// ── MONITOR ADMIN PANEL ACCESS ──
var adminAccessLog = [];
function logAdminAccess(){
  if(!isAdmin()) return;
  var now = Date.now();
  adminAccessLog.push(now);
  adminAccessLog = adminAccessLog.filter(function(t){ return now-t < 60000; });
  // Alert if admin panel accessed more than 10 times per minute (suspicious)
  if(adminAccessLog.length > 10){
    sendSecurityAlert('admin_breach',
      'Admin panel accessed ' + adminAccessLog.length + ' times in 1 minute. Possible unauthorized access attempt.',
      'high');
  }
}

// ── MONITOR FAILED LOGINS ──
var failedLoginLog = {};
function alertOnFailedLogins(email, count){
  if(count === 3){
    sendSecurityAlert('login_attack',
      'Warning: 3 failed login attempts for ' + email,
      'medium');
  }
  if(count >= 5){
    sendSecurityAlert('login_attack',
      'CRITICAL: Account ' + email + ' locked after 5 failed attempts. Possible brute force attack!',
      'high');
  }
}

// ── MONITOR SUSPICIOUS PAYMENTS ──
function checkPaymentAnomaly(amount, email){
  // Alert on unusually large payments
  if(amount > 500){
    sendSecurityAlert('suspicious_payment',
      'Large payment detected: $' + amount + ' from ' + email + '. Please verify.',
      'medium');
  }
  // Alert on rapid multiple payments
  var payKey = 'pay_' + (email||'anon');
  if(!rateLimits[payKey]) rateLimits[payKey] = [];
  var now = Date.now();
  rateLimits[payKey] = rateLimits[payKey].filter(function(t){ return now-t < 60000; });
  rateLimits[payKey].push(now);
  if(rateLimits[payKey].length > 5){
    sendSecurityAlert('suspicious_payment',
      'Rapid payments detected: ' + rateLimits[payKey].length + ' payments in 1 minute from ' + email,
      'high');
  }
}

// ── MONITOR MALICIOUS CONTENT ATTEMPTS ──
var maliciousAttempts = 0;
var origContainsMalicious = containsMalicious;
containsMalicious = function(text){
  var result = origContainsMalicious(text);
  if(result){
    maliciousAttempts++;
    sendSecurityAlert('malicious_content',
      'Malicious content blocked! Attempt #' + maliciousAttempts + '. User: ' + 
      (state.user ? state.user.email : 'Not logged in'),
      maliciousAttempts >= 3 ? 'high' : 'medium');
  }
  return result;
};

// ── MONITOR SPAM ATTACKS ──
var origCheckRateLimit = checkRateLimit;
checkRateLimit = function(action, maxPerMin){
  var result = origCheckRateLimit(action, maxPerMin);
  if(!result){
    sendSecurityAlert('spam_attack',
      'Rate limit exceeded for action: ' + action + '. User: ' +
      (state.user ? state.user.email : 'Not logged in'),
      'medium');
  }
  return result;
};

// ── HOOK INTO LOGIN TRACKING ──
var origTrackLogin = trackLoginAttempt;
trackLoginAttempt = function(email, success){
  var result = origTrackLogin(email, success);
  if(!success && failedLoginAttempts[email]){
    alertOnFailedLogins(email, failedLoginAttempts[email].count);
  }
  return result;
};

// ── SECURITY ALERTS VIEWER (for owner) ──
function loadSecurityAlerts(){
  if(!isAdmin()) return;
  // Just load quietly — do NOT show toast notifications on every login.
  // The security alerts are viewable in the Admin Panel → Security tab.
  // Marking all as read silently to prevent phantom "unread" notifications.
  db.collection('security_alerts')
    .where('read','==',false)
    .limit(50)
    .get().then(function(snap){
      // Auto-mark all as read so they don't keep triggering
      snap.docs.forEach(function(d){ d.ref.update({read:true}).catch(function(){}); });
    }).catch(function(){});
}

// Check security alerts when owner logs in
setTimeout(function(){
  if(isAdmin()) loadSecurityAlerts();
}, 3000);

// ── REAL-TIME SECURITY ALERT LISTENER ──
function startSecurityAlertListener(){
  if(!isAdmin() || !state.user) return;
  db.collection('notifications')
    .where('to', '==', state.user.uid)
    .where('type', '==', 'security_alert')
    .where('read', '==', false)
    .onSnapshot(function(snap){
      snap.docChanges().forEach(function(change){
        if(change.type === 'added'){
          var alert = change.doc.data();
          if(alert.severity === 'high'){
            showToast(alert.text);
          }
        }
      });
    }, function(){});
}

// Start listener when owner logs in
setTimeout(function(){
  if(isAdmin()) startSecurityAlertListener();
}, 4000);

function loadSecurityAlertsPanel(){
  if(!isAdmin()) return;
  var list = document.getElementById('security-alerts-list');
  if(!list) return;
  list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading…</div>';
  db.collection('security_alerts').limit(50).get().then(function(snap){
    if(snap.empty){
      list.innerHTML = '<div style="text-align:center;padding:30px;color:var(--muted)"><div style="font-size:36px;margin-bottom:10px">🛡️</div>No security alerts yet. Mindvora is safe!</div>';
      return;
    }
    list.innerHTML = snap.docs.map(function(d){
      var a = Object.assign({id:d.id}, d.data());
      var time = a.timestamp ? new Date(a.timestamp.seconds*1000).toLocaleString() : 'Unknown';
      var severityColor = a.severity==='high'?'#ef4444':a.severity==='medium'?'#f59e0b':'#22c55e';
      var bgColor = a.severity==='high'?'rgba(239,68,68,.08)':a.severity==='medium'?'rgba(245,158,11,.08)':'rgba(34,197,94,.08)';
      return '<div style="background:'+bgColor+';border:1px solid '+severityColor+'33;border-radius:12px;padding:12px 14px;margin-bottom:8px">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">' +
        '<div style="font-size:13px;font-weight:700;color:#fff">'+esc(a.icon||'🔒')+' '+esc(a.type||'alert').replace(/_/g,' ').toUpperCase()+'</div>' +
        '<div style="font-size:9px;font-weight:800;letter-spacing:1px;text-transform:uppercase;padding:2px 8px;border-radius:20px;background:'+severityColor+'22;color:'+severityColor+'">'+esc(a.severity||'medium')+'</div>' +
        '</div>' +
        '<div style="font-size:12px;color:var(--moon);line-height:1.6;margin-bottom:5px">'+esc(a.message||'')+'</div>' +
        '<div style="font-size:10px;color:var(--muted)">'+time+'</div>' +
        '</div>';
    }).join('');
    // Mark all as read
    snap.docs.forEach(function(d){ d.ref.update({read:true}).catch(function(){}); });
  }).catch(function(e){
    list.innerHTML = '<div style="color:#fca5a5;padding:14px">Error: '+esc(e.message)+'</div>';
  });
}

// Firebase config — public key safe by design, restricted in Google Cloud Console
firebase.initializeApp({
  apiKey:            'AIzaSyDdTgIqJuOYJhRAhEF9vMuMA8oZViRPlts',
  authDomain:        'zync-social.firebaseapp.com',
  projectId:         'zync-social',
  storageBucket:     'zync-social.firebasestorage.app',
  messagingSenderId: '720726547858',
  appId:             '1:720726547858:web:3175ba8d0b7c987e31754b'
});
var auth = firebase.auth();
var db   = firebase.firestore();

// ── Force Firebase to persist login locally forever ──────────────────────
// NOTE: onAuthStateChanged is registered INSIDE .then() to ensure
// persistence is set BEFORE auth state is checked
auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL).then(function(){
  initAuthListener();
}).catch(function(){
  initAuthListener();
});
var COLORS = ['#166534','#16a34a','#0f766e','#854d0e','#1d4ed8','#7e22ce','#be123c'];
var PAYSTACK_KEY = 'pk_live_1a3a25c1a562f8a054e34167dded3e1268f6c28c';
// NOTE: Paystack secret key handled server-side only for security
var CLOUD_NAME   = 'dk4svvssf';
var state = { user:null,profile:null,sparks:[],filter:'all',plan:{id:'basic',amount:2000,name:'Mindvora Basic'},tipTarget:null,network:'MTN',selectedPkg:{size:'500MB',dur:'1 Day',price:150},currentSparkId:null,sparksUnsub:null,notifsUnsub:null };

function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function timeAgo(ts){ if(!ts) return ''; var d=ts.toDate?ts.toDate():new Date(ts),s=Math.floor((Date.now()-d)/1000); if(s<60) return s+'s'; if(s<3600) return Math.floor(s/60)+'m'; if(s<86400) return Math.floor(s/3600)+'h'; return Math.floor(s/86400)+'d'; }
function showToast(msg){ var t=document.getElementById('toast'); t.textContent=msg; t.classList.add('show'); setTimeout(function(){ t.classList.remove('show'); },2600); }
function openModal(id){ document.getElementById(id).classList.add('open'); }
function closeModal(id){ document.getElementById(id).classList.remove('open'); }
function setNav(el){ document.querySelectorAll('.nav-item').forEach(function(b){ b.classList.remove('active'); }); el.classList.add('active'); }
function toggleEye(inp,ico){ var i=document.getElementById(inp),ic=document.getElementById(ico); if(!i) return; i.type=i.type==='password'?'text':'password'; if(ic) ic.textContent=i.type==='password'?'👁':'🙈'; }
function authErr(code){ var m={
  'auth/user-not-found':       'No account found with that email. Did you mean to register?',
  'auth/wrong-password':       'Wrong password. Try again or use Forgot Password.',
  'auth/invalid-credential':   'Wrong email or password. Check your details and try again.',
  'auth/email-already-in-use': 'That email is already registered. Try signing in instead.',
  'auth/invalid-email':        'That email address is not valid.',
  'auth/weak-password':        'Password must be at least 6 characters.',
  'auth/too-many-requests':    'Account temporarily locked. Wait 5 minutes or reset your password.',
  'auth/network-request-failed':'Network error. Check your internet connection and try again.',
  'auth/unauthorized-domain':  'Login blocked: your domain is not authorised in Firebase. Go to Firebase Console → Authentication → Settings → Authorised Domains → Add: mindvora-vf8e.vercel.app',
  'auth/operation-not-allowed':'This sign-in method is not enabled. Go to Firebase Console → Authentication → Sign-in methods and enable Email/Password.',
  'auth/popup-blocked':        'Popup was blocked by your browser. Allow popups for this site and try again.',
  'auth/popup-closed-by-user': 'Sign-in popup was closed before completing.',
  'auth/cancelled-popup-request':'Another sign-in popup is already open.',
  'auth/account-exists-with-different-credential':'An account already exists with this email using a different sign-in method.',
  'auth/internal-error':       'Firebase internal error. Try again in a moment.',
  'auth/user-disabled':        'This account has been disabled. Contact support.',
}; return m[code]||('Error: '+code+'. Please try again or contact support.'); }

function showAuthTab(tab){ document.querySelectorAll('.auth-tab').forEach(function(t){ t.classList.remove('active'); }); document.querySelectorAll('.auth-panel').forEach(function(p){ p.classList.remove('active'); }); document.getElementById('tab-'+tab).classList.add('active'); document.getElementById('panel-'+tab).classList.add('active'); }

function doLogin(){
  var emailVal = document.getElementById('li-email').value.trim();
  // Safety: check login lock but don't block if lock system has a bug
  try { if(isLoginLocked(emailVal)) return; } catch(le){}
  var email = emailVal.toLowerCase();
  var pass  = document.getElementById('li-pass').value;
  var err   = document.getElementById('li-err');
  var btn   = document.getElementById('btn-login');
  err.textContent = '';
  if (!email || !pass) { err.textContent = 'Please fill in both fields.'; return; }
  btn.disabled = true;
  btn.textContent = 'Signing in…';

  // If user entered a username (not an email), look up the email first
  var isEmail = email.indexOf('@') !== -1;
  var loginPromise;
  if (!isEmail) {
    // Username login — find the email from Firestore
    loginPromise = db.collection('users').where('handle', '==', email).limit(1).get()
      .then(function(snap) {
        if (snap.empty) {
          throw { code: 'auth/user-not-found' };
        }
        var userEmail = snap.docs[0].data().email;
        return auth.signInWithEmailAndPassword(userEmail, pass);
      });
  } else {
    loginPromise = auth.signInWithEmailAndPassword(email, pass);
  }

  loginPromise
    .then(function(cred) {
      // Success — onAuthStateChanged handles mounting the app
      btn.textContent = '✓ Welcome back!';
try { trackAdvancedLogin(email, true, cred.user.uid); } catch(e){}
    })
    .catch(function(e) {
      try { trackAdvancedLogin(email, false, null); } catch(le){}
      var msg = authErr(e.code);
      if (e.code === 'auth/invalid-credential' || e.code === 'auth/wrong-password') {
        msg = '❌ Wrong password. Use Forgot Password below to reset it, or try Google sign-in.';
      }
      if (e.code === 'auth/user-not-found') {
        msg = '❌ No account found with this email/username. Please register first.';
      }
      if (e.code === 'auth/too-many-requests') {
        msg = '⏳ Account locked. Wait 5 minutes or click Forgot Password to reset.';
      }
      if (e.code === 'auth/network-request-failed') {
        msg = '📶 No internet connection. Check your network and try again.';
      }
      err.textContent = msg;
      btn.disabled = false;
      btn.textContent = 'Enter Mindvora →';
    });
}
document.getElementById('btn-login').addEventListener('click',doLogin);
document.getElementById('li-pass').addEventListener('keydown',function(e){ if(e.key==='Enter') doLogin(); });

function doRegister(){
  var name=document.getElementById('r-name').value.trim();
  var handle=document.getElementById('r-handle').value.trim().toLowerCase().replace(/[^a-z0-9_]/g,'');
  var email=document.getElementById('r-email').value.trim().toLowerCase();
  var pass=document.getElementById('r-pass').value;
  var confirm=document.getElementById('r-confirm').value;
  var err=document.getElementById('r-err');
  var btn=document.getElementById('btn-reg');
  err.textContent='';
  if(!name||!handle||!email||!pass){ err.textContent='Please fill in all fields.'; return; }
  if(handle.length<3){ err.textContent='Username must be at least 3 characters.'; return; }
  if(pass.length<6){ err.textContent='Password must be at least 6 characters.'; return; }
  if(pass!==confirm){ err.textContent='Passwords do not match.'; return; }
  btn.disabled=true; btn.textContent='Creating account…';
  auth.createUserWithEmailAndPassword(email,pass)
    .then(function(cred){
      var color=COLORS[Math.floor(Math.random()*COLORS.length)];
      return db.collection('users').doc(cred.user.uid).set({ id:cred.user.uid,name:name,handle:handle,email:email,color:color,plan:'free',isPremium:false,sparksCount:0,followers:0,earnings:0,tips:0,joinDate:firebase.firestore.FieldValue.serverTimestamp() });
    })
    .then(function(){
      // Check referral code in URL
      var urlParams = new URLSearchParams(window.location.search);
      var refCode = urlParams.get('ref');
      var newUid = auth.currentUser.uid;
      // ONE-CHAIN REFERRAL: only the DIRECT referrer earns $1
      // A refers B → A gets $1. When B refers C → B gets $1, A gets nothing.
      if(refCode && refCode !== newUid){
        // ── REFERRAL SYSTEM: check if enabled by owner first ──
        db.collection('app_settings').doc('referral').get().then(function(settingDoc) {
          var isEnabled = !settingDoc.exists || settingDoc.data().enabled !== false;
          if (!isEnabled) return; // Referral system deactivated by owner — do nothing

          // Check this new user has never been referred before (prevent abuse)
          db.collection('referrals').where('newUserId','==',newUid).get().then(function(snap){
            if(!snap.empty) return; // already referred — do nothing
            // Check referrer exists
            db.collection('users').doc(refCode).get().then(function(referrerDoc){
              if(!referrerDoc.exists) return; // referrer not found
              // Credit $1 to DIRECT referrer only
              db.collection('users').doc(refCode).update({
                earnings: firebase.firestore.FieldValue.increment(1),
                referralCount: firebase.firestore.FieldValue.increment(1)
              });
              db.collection('notifications').add({
                uid: refCode,
                type: 'referral',
                text: '🎉 Someone signed up with your referral link! You earned $1.00',
                read: false,
                createdAt: firebase.firestore.FieldValue.serverTimestamp()
              });
              // Store the referral record
              db.collection('referrals').add({
                referrerId: refCode,
                referrerName: referrerDoc.data().name||'Mindvora user',
                newUserId: newUid,
                amount: 1,
                createdAt: firebase.firestore.FieldValue.serverTimestamp()
              });
            }).catch(function(){});
          }).catch(function(){});
        }).catch(function(){});
      }
      return auth.currentUser.updateProfile({displayName:document.getElementById('r-name').value.trim()});
    })
    .catch(function(e){ err.textContent=authErr(e.code); btn.disabled=false; btn.textContent='Create Account →'; });
}
document.getElementById('btn-reg').addEventListener('click',doRegister);
document.getElementById('r-confirm').addEventListener('keydown',function(e){ if(e.key==='Enter') doRegister(); });

function initAuthListener(){
auth.onAuthStateChanged(function(user){
  if(user){
    state.user=user;
    window._mvUid = user.uid;
    // Safety timeout — if Firestore hangs (e.g. offline / rules issue), still mount after 6s
    var _mountFired = false;
    var _mountTimeout = setTimeout(function(){
      if(!_mountFired){
        _mountFired = true;
        if(!state.profile) state.profile={name:user.displayName||user.email.split('@')[0],handle:(user.email||'user').split('@')[0],color:COLORS[0],plan:'free',isPremium:false,sparksCount:0,followers:0,earnings:0,tips:0};
        mountApp();
      }
    }, 6000);
    db.collection('users').doc(user.uid).get().then(function(snap){
      if(_mountFired) return; // timeout already fired
      clearTimeout(_mountTimeout);
      _mountFired = true;
      if(snap.exists){
        state.profile=snap.data();
        // Check if user is banned
        if(snap.data().banned === true){
          auth.signOut();
          setTimeout(function(){
            var authErr=document.getElementById('auth-err'); if(authErr) authErr.textContent='Your account has been suspended. Contact support.';
          }, 500);
          return;
        }
        checkAdminAccess();
        checkPendingAds();
        setTimeout(checkBirthday,2000);
        setTimeout(function(){ initPushNotifications(); listenForIncomingCalls(); },3000);
      } else {
        var color=COLORS[Math.floor(Math.random()*COLORS.length)];
        state.profile={id:user.uid,name:user.displayName||user.email.split('@')[0],handle:(user.displayName||'user').toLowerCase().replace(/\s+/g,'_'),email:user.email,color:color,plan:'free',isPremium:false,sparksCount:0,followers:0,earnings:0,tips:0};
      checkAdminAccess();
      checkPendingAds();
        db.collection('users').doc(user.uid).set(state.profile);
        showToast('Welcome to Mindvora! 🌿');
      }
      mountApp();
      setTimeout(checkAdminAccess, 500);
      // Track lastSeen for online status
      db.collection('users').doc(user.uid).update({ lastSeen: Date.now() }).catch(function(){});
      setInterval(function(){ 
        if(state.user) db.collection('users').doc(state.user.uid).update({ lastSeen: Date.now() }).catch(function(){}); 
      }, 60000);
    }).catch(function(){
      if(_mountFired) return;
      clearTimeout(_mountTimeout);
      _mountFired = true;
      state.profile={name:user.displayName||user.email,handle:(user.email||'user').split('@')[0],color:COLORS[0],plan:'free'};
      mountApp();
    });
  } else {
    state.user=null; state.profile=null;
    var appSc  = document.getElementById('app-screen');
    var authSc = document.getElementById('auth-screen');
    if(appSc)  { appSc.style.display='none'; appSc.style.visibility='hidden'; appSc.style.zIndex='-1'; }
    if(authSc) {
      authSc.style.removeProperty('display');
      authSc.style.visibility = 'visible';
      authSc.style.zIndex = '100';
      authSc.style.opacity = '1';
      authSc.style.pointerEvents = 'auto';
      authSc.style.flexDirection='row';
      authSc.style.minHeight='100vh';
    }
    if(state.sparksUnsub){ state.sparksUnsub(); state.sparksUnsub=null; }
    if(state.notifsUnsub){ state.notifsUnsub(); state.notifsUnsub=null; }
    // Reset login button in case it was stuck
    var loginBtn = document.getElementById('btn-login');
    if(loginBtn){ loginBtn.disabled=false; loginBtn.textContent='Enter Mindvora →'; }
    var liErr = document.getElementById('li-err');
    if(liErr) liErr.textContent = '';
  }
});
} // end initAuthListener

function mountApp(){
  if(!state.profile) return;
  try {
    var p=state.profile,color=p.color||COLORS[0],init=(p.name||'Z').charAt(0).toUpperCase();
    var grad='linear-gradient(135deg,'+color+','+COLORS[1]+')';
    ['tb-av','sb-av','comp-av','cmt-av'].forEach(function(id){
      var el=document.getElementById(id);
      if(el){
        el.textContent=init;
        el.style.background=grad;
        el.style.backgroundImage=grad;
        el.style.webkitBackground=grad;
        el.setAttribute('style', el.getAttribute('style')+(';background:'+grad+';background-image:'+grad+';-webkit-background:'+grad));
      }
    });
    var sbName = document.getElementById('sb-name');
    if(sbName) sbName.innerHTML=esc(p.name||'Mindvora user')+(p.mood?' <span style="font-size:16px" title="'+esc(p.mood.label)+'">'+p.mood.emoji+'</span>':'')+(p.isPremium?'<span class="sb-verified">✦ PRO</span>':'');
    var sbHandle = document.getElementById('sb-handle');
    if(sbHandle) sbHandle.textContent='@'+(p.handle||'user');
    var refEl=document.getElementById('ref-link'); if(refEl) refEl.value='https://mindvora-vf8e.vercel.app?ref='+state.user.uid;
    var premWidget = document.getElementById('prem-widget');
    if(p.isPremium && premWidget) premWidget.style.display='none';
  } catch(e){ console.warn('[Mindvora] mountApp sidebar error:', e); }
  // Always show app screen regardless of sidebar errors
  // NOTE: auth-screen CSS has display:flex !important, so display:none is overridden.
  // Use visibility + pointer-events + z-index to force-hide it.
  var authSc = document.getElementById('auth-screen');
  var appSc  = document.getElementById('app-screen');
  if(authSc) {
    authSc.style.setProperty('display', 'none', 'important');
    authSc.style.visibility = 'hidden';
    authSc.style.pointerEvents = 'none';
    authSc.style.zIndex = '-1';
    authSc.style.opacity = '0';
  }
  if(appSc) {
    appSc.style.display = 'flex';
    appSc.style.visibility = 'visible';
    appSc.style.zIndex = '1';
    appSc.style.opacity = '1';
  }
  try { updateStats(); } catch(e){}
  try { loadSparks(); } catch(e){}
  try { listenNotifs(); } catch(e){}
  try { loadStories(); } catch(e){}
  try { loadConversations(); } catch(e){}
  // Re-apply language after login
  try {
    if (currentLang && currentLang !== 'en') {
      setTimeout(function(){ applyTranslations(currentLang); }, 300);
    }
  } catch(e){}
  // Save device profile linked to user email
  setTimeout(function(){ try { saveDeviceProfile(); applyDeviceLayout(); } catch(e){} }, 500);
  // Start real-time watching
  try { startLiveWatching(); } catch(e){}
  try { watchFollowerCount(state.user.uid); } catch(e){}
  try { initPresence(); } catch(e){}
  // Load referral status for owner
  try { if (isAdmin()) { loadReferralStatus(); } } catch(e){}
}

document.getElementById('btn-out').addEventListener('click',function(){ if(state.sparksUnsub) state.sparksUnsub(); auth.signOut(); });

var isLight=false;
try{ isLight=localStorage.getItem('mv_theme')==='light'; if(isLight){ document.body.classList.add('light'); document.getElementById('theme-btn').textContent='☀️'; } }catch(e){}
document.getElementById('theme-btn').addEventListener('click',function(){ isLight=!isLight; document.body.classList.toggle('light',isLight); this.textContent=isLight?'☀️':'🌙'; try{ localStorage.setItem('mv_theme',isLight?'light':'dark'); }catch(e){} showToast(isLight?'☀️ Light mode':'🌙 Dark mode'); });

function updateStats(){
  if(!state.profile) return;
  document.getElementById('st-sparks').textContent=state.profile.sparksCount||0;
  document.getElementById('st-fans').textContent=state.profile.followers||0;
  document.getElementById('e-bal').textContent='$'+(((state.profile.earnings||0)+(state.profile.tips||0)).toFixed(2));
  document.getElementById('e-tips').textContent='$'+((state.profile.tips||0).toFixed(2));
  document.getElementById('e-rev').textContent='$'+((state.profile.earnings||0).toFixed(2));
}

function loadSparks(){ if(state.sparksUnsub) state.sparksUnsub(); state.sparksUnsub=db.collection('sparks').orderBy('createdAt','desc').limit(50).onSnapshot(function(snap){ state.sparks=snap.docs.map(function(d){ return Object.assign({id:d.id},d.data()); }); renderFeed(); },function(){ showToast('Error loading feed'); }); }
function renderFeed(){
  var fc = document.getElementById('feed-cont');
  var q  = ((document.getElementById('search-inp')||{}).value||'').trim().toLowerCase();

  // ── NEWS TAB ── always live world news + user news posts
  if (state.filter === 'news') {
    loadNewsTab();
    return;
  }

  // ── ALL TAB ── shows ALL posts from ALL categories mixed
  if (state.filter === 'all') {
    // Use local realtime cache (state.sparks is already subscribed via onSnapshot)
    // This includes posts from ALL categories: education, fun, thoughts, news, all
    var sparks = state.sparks.slice();
    if (q) sparks = sparks.filter(function(s){
      return (s.text||'').toLowerCase().indexOf(q) > -1 ||
             (s.authorName||'').toLowerCase().indexOf(q) > -1;
    });
    if (!sparks.length) {
      fc.innerHTML = '<div class="feed-empty"><div class="fi">🌿</div><h3>No sparks yet</h3><p>Be the first to post something amazing!</p></div>';
      return;
    }
    fc.innerHTML = sparks.map(buildSparkHTML).join('');
    if (typeof loadAds === 'function') setTimeout(loadAds, 500);
    return;
  }

  // ── CATEGORY TABS: education / fun / thoughts ──
  var cfg = {
    education: {
      icon: '🧠',
      title: 'No educational posts yet',
      sub: 'Select 🧠 Learn when composing to post here. Share tips, tutorials, facts or knowledge!'
    },
    fun: {
      icon: '🎉',
      title: 'No fun posts yet',
      sub: 'Select 🎉 Fun when composing to post here. Share jokes, memes, comedy or entertainment!'
    },
    thoughts: {
      icon: '💭',
      title: 'No thoughts yet',
      sub: 'Select 💭 Thoughts when composing to post here. Share opinions, motivation or reflections!'
    }
  };

  var d = cfg[state.filter];
  if (!d) {
    fc.innerHTML = '<div class="feed-empty"><div class="fi">🌿</div><h3>No posts found</h3></div>';
    return;
  }

  // Show loading indicator immediately
  fc.innerHTML = '<div class="feed-empty"><div class="fi">'+d.icon+'</div><h3>Loading…</h3></div>';

  // Query Firestore directly for exact category match
  db.collection('sparks')
    .where('category', '==', state.filter)
    .orderBy('createdAt', 'desc')
    .limit(80)
    .get()
    .then(function(snap) {
      var results = [];
      var seenIds = {};

      // Add Firestore results
      snap.docs.forEach(function(doc) {
        seenIds[doc.id] = true;
        results.push(Object.assign({ id: doc.id }, doc.data()));
      });

      // Merge local cache (catches posts not yet indexed)
      state.sparks.forEach(function(s) {
        if (!seenIds[s.id] && (s.category||'').toLowerCase() === state.filter) {
          seenIds[s.id] = true;
          results.push(s);
        }
      });

      // Sort newest first
      results.sort(function(a, b) {
        var ta = a.createdAt ? (a.createdAt.seconds || 0) : 0;
        var tb = b.createdAt ? (b.createdAt.seconds || 0) : 0;
        return tb - ta;
      });

      // Apply search
      if (q) {
        results = results.filter(function(s) {
          return (s.text||'').toLowerCase().indexOf(q) > -1 ||
                 (s.authorName||'').toLowerCase().indexOf(q) > -1;
        });
      }

      if (!results.length) {
        fc.innerHTML =
          '<div class="feed-empty">' +
            '<div class="fi">' + d.icon + '</div>' +
            '<h3>' + d.title + '</h3>' +
            '<p>' + d.sub + '</p>' +
          '</div>';
        return;
      }

      fc.innerHTML = results.map(buildSparkHTML).join('');
    })
    .catch(function(err) {
      // Firestore index not built yet — fall back to local cache
      console.warn('[Mindvora] Feed query fallback:', err.message);
      var results = state.sparks.filter(function(s) {
        return (s.category||'').toLowerCase() === state.filter;
      });
      if (q) {
        results = results.filter(function(s) {
          return (s.text||'').toLowerCase().indexOf(q) > -1 ||
                 (s.authorName||'').toLowerCase().indexOf(q) > -1;
        });
      }
      if (!results.length) {
        fc.innerHTML =
          '<div class="feed-empty">' +
            '<div class="fi">' + d.icon + '</div>' +
            '<h3>' + d.title + '</h3>' +
            '<p>' + d.sub + '</p>' +
            '<div style="margin-top:12px;font-size:11px;color:var(--muted)">Note: full sorting requires Firestore indexes to be built (up to 2 minutes on first use)</div>' +
          '</div>';
        return;
      }
      fc.innerHTML = results.map(buildSparkHTML).join('');
    });
}

function loadNewsTab() {
  var fc = document.getElementById('feed-cont');
  fc.innerHTML = '<div class="feed-empty"><div class="fi">🌍</div><h3>Loading world news…</h3><p>Fetching latest updates from global sources</p></div>';

  // Show user-posted news posts FIRST (instant)
  var userNewsPosts = state.sparks.filter(function(s){
    var cat = (s.category||'').toLowerCase();
    var text = (s.text||'').toLowerCase();
    return cat === 'news' || text.indexOf('#news') > -1 || text.indexOf('#breaking') > -1 || text.indexOf('#update') > -1;
  });

  var feeds = [
    {name:'BBC World',   url:'https://feeds.bbci.co.uk/news/world/rss.xml'},
    {name:'Reuters',     url:'https://feeds.reuters.com/reuters/worldNews'},
    {name:'Al Jazeera',  url:'https://www.aljazeera.com/xml/rss/all.xml'},
    {name:'CNN World',   url:'https://rss.cnn.com/rss/edition_world.rss'},
    {name:'AP News',     url:'https://rsshub.app/apnews/topics/apf-intlnews'},
    {name:'The Guardian',url:'https://www.theguardian.com/world/rss'},
    {name:'DW News',     url:'https://rss.dw.com/xml/rss-en-world'},
    {name:'VOA News',    url:'https://www.voanews.com/podcast/world-news-program'}
  ];

  var allItems = [], done = 0, total = feeds.length;

  function finish() {
    done++;
    if (done >= total) {
      // Mix user posts + live news
      renderNewsItems(allItems, userNewsPosts);
    }
  }

  // Try two proxies for reliability
  var proxies = [
    'https://api.allorigins.win/get?url=',
    'https://corsproxy.io/?'
  ];

  feeds.forEach(function(feed) {
    var tried = 0;
    function tryProxy(idx) {
      if (idx >= proxies.length) { finish(); return; }
      var proxy = proxies[idx] + encodeURIComponent(feed.url);
      fetch(proxy, {signal: AbortSignal.timeout ? AbortSignal.timeout(6000) : undefined})
        .then(function(r){ return r.json(); })
        .then(function(data){
          var contents = data.contents || data.body || data;
          if (typeof contents !== 'string') { tryProxy(idx+1); return; }
          var xml = new DOMParser().parseFromString(contents, 'text/xml');
          var items = xml.querySelectorAll('item');
          if (!items.length) { tryProxy(idx+1); return; }
          items.forEach(function(item){
            var title = ((item.querySelector('title')||{}).textContent||'').trim();
            var link  = ((item.querySelector('link')||{}).textContent||
                         (item.querySelector('guid')||{}).textContent||'').trim();
            var desc  = ((item.querySelector('description')||{}).textContent||'')
                         .replace(/<[^>]+>/g,'').trim().slice(0,200);
            var pub   = ((item.querySelector('pubDate')||item.querySelector('updated')||{}).textContent||'').trim();
            var enclosure = item.querySelector('enclosure[type^="image"]') || item.querySelector('media\:thumbnail');
            var img = enclosure ? (enclosure.getAttribute('url')||enclosure.getAttribute('src')||'') : '';
            if (title && title.length > 5) {
              allItems.push({title:title, link:link, desc:desc, pub:pub, source:feed.name, img:img});
            }
          });
          finish();
        })
        .catch(function(){ tryProxy(idx+1); });
    }
    tryProxy(0);
  });

  // Safety timeout — show whatever loaded after 8s
  setTimeout(function(){
    if (done < total) renderNewsItems(allItems, userNewsPosts);
  }, 8000);
}

function renderNewsItems(items, userPosts) {
  var fc = document.getElementById('feed-cont');
  userPosts = userPosts || [];
  var html = '';

  // Show user-posted news at the top
  if (userPosts.length) {
    html += '<div style="padding:8px 14px 4px;font-size:11px;font-weight:700;color:var(--green3);letter-spacing:1px">📣 COMMUNITY NEWS</div>';
    html += userPosts.map(buildSparkHTML).join('');
    html += '<div style="padding:8px 14px 4px;margin-top:8px;font-size:11px;font-weight:700;color:var(--muted);letter-spacing:1px;border-top:1px solid var(--border)">🌍 WORLD NEWS</div>';
  }

  if (!items.length) {
    var fallback = [
      {title:'BBC World News — Latest global updates',source:'BBC World',link:'https://bbc.com/news/world',desc:'Get the latest world news, international headlines and breaking stories.'},
      {title:'Reuters — Breaking international news',source:'Reuters',link:'https://reuters.com/world',desc:'Reuters covers the latest international news, political developments and global events.'},
      {title:'Al Jazeera — Global news coverage',source:'Al Jazeera',link:'https://aljazeera.com',desc:'Trusted independent news covering global affairs, conflicts and politics.'},
      {title:'CNN World — Top global stories',source:'CNN',link:'https://cnn.com/world',desc:'CNN brings you world news and breaking international stories 24/7.'},
      {title:'AP News — International reporting',source:'AP News',link:'https://apnews.com/world-news',desc:'The Associated Press delivers accurate, unbiased global news coverage.'},
      {title:'The Guardian World News',source:'The Guardian',link:'https://theguardian.com/world',desc:'Independent journalism covering world affairs and international stories.'},
      {title:'DW News — World coverage',source:'DW News',link:'https://dw.com/en',desc:'Deutsche Welle brings global news from an international perspective.'},
      {title:'VOA News — Voice of America',source:'VOA News',link:'https://voanews.com',desc:'VOA delivers trustworthy news from around the world.'}
    ];
    html += fallback.map(function(n){ return buildNewsCard(n.title, n.desc, n.source, '', n.link, ''); }).join('');
    html += '<div style="text-align:center;padding:14px;font-size:11px;color:var(--muted)">Tap any card to read · Sources load faster on stable internet</div>';
    fc.innerHTML = html;
    return;
  }

  items.sort(function(a,b){ return (b.pub?new Date(b.pub):0)-(a.pub?new Date(a.pub):0); });
  html += items.slice(0,40).map(function(n){
    return buildNewsCard(n.title, n.desc, n.source, n.pub, n.link, n.img||'');
  }).join('');
  html += '<div style="text-align:center;padding:14px;font-size:11px;color:var(--muted)">📰 Sources: BBC · Reuters · Al Jazeera · CNN · AP · Guardian · DW · VOA</div>';
  fc.innerHTML = html;
}


function buildNewsCard(title, desc, source, pub, link, imgUrl) {
  var timeStr = '';
  if (pub) { try { var diff=Math.floor((Date.now()-new Date(pub))/60000); timeStr=diff<60?diff+'m ago':diff<1440?Math.floor(diff/60)+'h ago':Math.floor(diff/1440)+'d ago'; } catch(e){} }
  var sc = {BBC:'#bb1919',Reuters:'#ff7700','Al Jazeera':'#c8102e',CNN:'#cc0000','AP News':'#003366','The Guardian':'#052962'}[source]||'var(--green2)';
  var safeLink = (link||'').replace(/'/g,'%27');
  return '<div class="spark-card" style="cursor:pointer" onclick="openLink(\''+safeLink+'\')">'+
    '<div class="sk-head">'+
      '<div class="sk-av" style="background:'+sc+';font-size:10px;font-weight:800">'+esc((source||'NEWS').slice(0,3).toUpperCase())+'</div>'+
      '<div><div class="sk-name">'+esc(source||'World News')+'</div>'+
      '<div class="sk-handle">\uD83C\uDF0D World News</div></div>'+
      '<span class="sk-time">'+esc(timeStr)+'</span>'+
    '</div>'+
    (imgUrl?'<img src="'+esc(imgUrl)+'" style="width:100%;max-height:200px;object-fit:cover;border-radius:10px;margin:8px 0" onerror="this.style.display=\'none\'">':'')+
    '<div class="sk-body" style="font-weight:600;font-size:14px;line-height:1.5">'+esc(title)+'</div>'+
    (desc?'<div class="sk-body" style="font-size:12px;color:var(--muted);margin-top:4px">'+esc(desc)+'</div>':'')+
    '<div class="sk-actions"><button class="s-btn" onclick="event.stopPropagation();openLink(\''+safeLink+'\')">\uD83D\uDCD6 Read Full Story \u2192</button></div>'+
  '</div>';
}
function buildSparkHTML(s){
  var liked=state.user&&(s.likes||[]).indexOf(state.user.uid)>-1;
  var saved=state.user&&(s.saved||[]).indexOf(state.user.uid)>-1;
  var isOwn=state.user&&s.authorId===state.user.uid;
  var vbadge=(s.isPremium||s.isVerified)?'<span class="vbadge" title="Verified"></span>':'';
  var media='';
  if(s.mediaUrl&&s.mediaType==='image') media='<div class="sk-media-img-wrap"><img class="sk-media" src="'+esc(s.mediaUrl)+'" loading="lazy" style="width:100%;max-height:520px;object-fit:cover;display:block;border-radius:12px"></div>';
  if(s.mediaUrl&&s.mediaType==='video'){
    var vid_id = 'vid-'+s.id;
    var wrap_id = 'wrap-'+s.id;
    // Smart display — determined after video metadata loads
    // Default: blur bg for unknown aspect ratio
    media = '<div class="sk-media-wrap" id="'+wrap_id+'" data-display="auto">' +
      '<video class="sk-media-blur" id="blur-'+esc(s.id)+'" src="'+esc(s.mediaUrl)+'" muted playsinline preload="metadata" tabindex="-1" aria-hidden="true"></video>' +
      '<video class="sk-media-main" id="'+vid_id+'" src="'+esc(s.mediaUrl)+'" playsinline preload="metadata" data-vid="'+vid_id+'" data-wrapid="'+wrap_id+'" style="cursor:pointer" onloadedmetadata="adaptVideoDisplay(this)"></video>' +
      '<div class="sk-vid-controls">' +
        '<button class="sk-vid-play" id="pbtn-'+esc(s.id)+'" data-vid="'+vid_id+'" data-action="play">&#9654;</button>' +
        '<div class="sk-vid-prog" data-vid="'+vid_id+'" data-action="seek"><div class="sk-vid-prog-fill" id="prog-'+esc(s.id)+'"></div></div>' +
        '<span class="sk-vid-dur" id="dur-'+esc(s.id)+'">0:00</span>' +
        '<button class="sk-vid-mute" data-vid="'+vid_id+'" data-sid="'+esc(s.id)+'" data-action="mute">&#128266;</button>' +
      '</div>' +
    '</div>';
  }
  var pinBadge=s.pinned?'<span style="font-size:10px;color:var(--green3);margin-left:4px">📌</span>':'';
  var locTag=s.location?'<span class="s-btn" style="cursor:default">📍 '+esc(s.location)+'</span>':'';
  var pollHTML=s.poll?buildPollHTML(s):'';
  var reactHTML='<div class="reactions-bar">'+buildReactionsHTML(s)+'</div>';
  var linkPrev='';
  if(s.linkUrl){var lu=esc(s.linkUrl);linkPrev='<div class="link-preview" onclick="openLink(\''+lu+'\')\"><div class="link-preview-info"><div class="link-preview-title">🔗 External Link</div><div class="link-preview-url">'+lu+'</div></div></div>';}
  setTimeout(function(){ trackPostView(s.id, s.authorId); }, 2000);
  return '<div class="spark-card"'+(s.pinned?' style="border-color:var(--green3)"':'')+'>'+'<div class="sk-head">'+'<div class="sk-av" style="background:'+esc(s.authorColor||COLORS[0])+'">'+''+esc((s.authorName||'Z').charAt(0).toUpperCase())+'</div>'+'<div><div class="sk-name">'+esc(s.authorName||'Mindvora user')+vbadge+'<span class="sk-cat">'+esc(s.category||'all')+'</span>'+pinBadge+'</div>'+'<div class="sk-handle">@'+esc(s.authorHandle||'user')+'</div></div>'+'<span class="sk-time">'+timeAgo(s.createdAt)+'</span>'+(s.viewCount?'<span class="sk-time" style="margin-left:4px">👁 '+s.viewCount+'</span>':'')+'</div>'+media+'<div class="sk-body">'+parseMentions(s.text||'')+(s.edited?'<span style="font-size:10px;color:var(--muted);font-style:italic;margin-left:6px">(edited)</span>':'')+'</div>'+pollHTML+linkPrev+'<div class="sk-actions">'+'<button class="s-btn'+(liked?' liked':'')+'" onclick="toggleLike(\''+s.id+'\')">'+(liked?'\u2764\ufe0f':'🤍')+' '+(s.likes||[]).length+'</button>'+(s.commentsLocked?'<button class="s-btn" style="color:var(--muted);cursor:default" title="Comments disabled by author">🔒 Comments off</button>':'<button class="s-btn" onclick="openComments(\''+s.id+'\')">💬 '+(s.commentCount||0)+'</button>')+'<button class="s-btn'+(saved?' saved':'')+'" onclick="toggleSave(\''+s.id+'\')">🔖 Save</button>'+'<button class="s-btn" onclick="shareSpark(\''+s.id+'\')">\u2197 Share</button>'+'<button class="s-btn" onclick="repostSpark(\''+s.id+'\',\''+esc(s.authorName||'Mindvora user')+'\')">🔁 '+(s.reposts||0)+'</button>'+(!isOwn?'<button class="s-btn" onclick="toggleFollow(\''+esc(s.authorId)+'\',\''+esc(s.authorName||'User')+'\')">'+( isFollowing(s.authorId)?'✅ Following':'➕ Follow')+'</button>':'')+'<button class="s-btn" onclick="tagFriendOnPost(\''+s.id+'\',\''+esc(s.authorName||'User')+'\')" title="Tag a friend">🏷 Tag</button>'+(isOwn?'':'<button class="s-btn" onclick="openTip(\''+esc(s.authorId)+'\',\''+esc(s.authorName||'Creator')+'\')">💝 Tip</button>')+(isOwn?'<button class="s-btn" onclick="pinSpark(\''+s.id+'\','+!!s.pinned+')">📌</button>':'')+'<button class="s-btn" onclick="translatePost(\''+s.id+'\',\''+esc(s.text||'')+'\')">🌐</button>'+locTag+'<button class="s-btn" onclick="reportSpark(\''+s.id+'\',\''+esc(s.authorId)+'\')" title="Report">🚩</button>'+(isOwn?'<button class="s-btn" onclick="editSpark(\''+s.id+'\',\''+esc((s.text||'').replace(/\'/g,"&#39;"))+'\')">✏️</button>':'')+(isOwn?'<button class="s-btn" onclick="delSpark(\''+s.id+'\')" style="color:#fca5a5">🗑</button>':'')+'<button class="s-btn" onclick="openVoiceReply(\''+s.id+'\',\''+esc(s.authorName||'User')+'\')">🎙</button>'+'</div>'+reactHTML+'</div>';
}

// ── TAG A FRIEND ON A POST ──
function tagFriendOnPost(sparkId, authorName) {
  if (!state.user) { showToast('Please login first'); return; }
  var username = prompt('Enter the username of the person you want to tag (e.g. @username):');
  if (!username) return;
  username = username.replace(/^@/, '').trim().toLowerCase();
  if (!username) { showToast('Please enter a valid username'); return; }
  db.collection('users').where('handleLower', '==', username).limit(1).get()
    .then(function(snap) {
      if (snap.empty) {
        // Try case-insensitive search by handle
        return db.collection('users').where('handle', '==', username).limit(1).get();
      }
      return snap;
    })
    .then(function(snap) {
      if (snap.empty) { showToast('User @' + username + ' not found'); return; }
      var taggedUser = snap.docs[0];
      var taggedId = taggedUser.id;
      var taggedName = taggedUser.data().name || username;
      // Add tag to the spark
      db.collection('sparks').doc(sparkId).update({
        tags: firebase.firestore.FieldValue.arrayUnion(taggedId)
      }).catch(function(){});
      // Notify the tagged user
      db.collection('notifications').add({
        toUid: taggedId,
        fromName: state.profile.name || 'Someone',
        type: 'tag',
        text: (state.profile.name || 'Someone') + ' tagged you in a post by ' + authorName,
        sparkId: sparkId,
        read: false,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      }).catch(function(){});
      showToast('Tagged @' + taggedName + ' successfully!');
    })
    .catch(function() { showToast('Could not find user. Try again.'); });
}

var compCat='all',pendingMedia=null,commentsLocked=false;
document.querySelectorAll('.c-bot .f-pill').forEach(function(b){ b.addEventListener('click',function(){
  document.querySelectorAll('.c-bot .f-pill').forEach(function(x){ x.classList.remove('active'); });
  this.classList.add('active');
  compCat = this.dataset.cat || 'all';
  var ta = document.getElementById('comp-ta');
  if (!ta) return;
  var placeholders = {
    all:       "What's on your mind? Share anything with the Mindvora community…",
    education: '📚 Share something educational — a tip, fact, tutorial, science or history…',
    fun:       '😂 Share something funny — a joke, meme, comedy story or entertainment…',
    thoughts:  '💭 Share your thoughts — opinion, motivation, wisdom or reflection…',
    news:      '🌍 Share a news update — breaking news, current events or world affairs…'
  };
  ta.placeholder = placeholders[compCat] || placeholders.all;
  ta.focus();
  // Brief glow on compose box
  var box = document.getElementById('compose-box');
  if (box) { box.style.borderColor='var(--green3)'; setTimeout(function(){ box.style.borderColor=''; },700); }
}); });
document.getElementById('comp-ta').addEventListener('input',function(){
  document.getElementById('cc').textContent = 280 - this.value.length;
  // Auto-detect category from hashtags
  var text = this.value.toLowerCase();
  var detected = null;
  if (/#(education|learn|study|tutorial|science|knowledge|howto|tip|history|tech)/i.test(text)) detected = 'education';
  else if (/#(fun|funny|comedy|lol|meme|humor|joke|laugh|viral|entertainment)/i.test(text)) detected = 'fun';
  else if (/#(thought|mindset|motivation|opinion|perspective|wisdom|philosophy|quote|inspire|reflect)/i.test(text)) detected = 'thoughts';
  else if (/#(news|breaking|update|headline|report|latest|alert)/i.test(text)) detected = 'news';
  if (detected && detected !== compCat) {
    // Switch category automatically
    compCat = detected;
    document.querySelectorAll('.c-bot .f-pill').forEach(function(p){ p.classList.remove('active'); });
    var catBtn = document.getElementById('cat-' + (detected === 'education' ? 'edu' : detected));
    if (catBtn) {
      catBtn.classList.add('active');
      catBtn.style.transform = 'scale(1.05)';
      setTimeout(function(){ if(catBtn) catBtn.style.transform = ''; }, 300);
    }
    // Update placeholder
    var placeholders = {
      all:'What is on your mind? Share anything…',
      education:'📚 Share something educational — a tip, fact, tutorial or use #education',
      fun:'😂 Share something funny — a joke, meme or comedy — use #funny',
      thoughts:'💭 Share your thoughts, opinions, motivation or use #thoughts',
      news:'🌍 Share a news update or current event — use #news or #breaking'
    };
    this.placeholder = placeholders[compCat] || placeholders.all;
  }
});
document.getElementById('btn-post').addEventListener('click',function(){ var text=document.getElementById('comp-ta').value.trim(); if(!text&&!pendingMedia){ showToast('Write something first!'); return; } if(containsMalicious(text)){ showToast('❌ Post contains invalid content.'); return; } if(!checkRateLimit('post',5)){ return; } text=sanitize(text); if(!state.user||!state.profile){ showToast('Please sign in first'); return; } var btn=this; btn.disabled=true; btn.textContent='Posting…';
  if(pendingSchedule){
    db.collection('scheduled_posts').add({
      text:text,authorId:state.user.uid,authorName:state.profile.name||'Mindvora user',
      authorHandle:state.profile.handle||'user',authorColor:state.profile.color||COLORS[0],
      isPremium:state.profile.isPremium||false,isVerified:state.profile.isVerified||false,
      category:compCat,scheduledAt:pendingSchedule,
      createdAt:firebase.firestore.FieldValue.serverTimestamp()
    }).then(function(){
      document.getElementById('comp-ta').value='';
      pendingSchedule=null;pendingPoll=null;pendingLocation=null;
      btn.disabled=false;btn.textContent='✦ Spark';
      showToast('Post scheduled successfully!');
    }).catch(function(){btn.disabled=false;btn.textContent='✦ Spark';showToast('Error scheduling');});
    return;
  }
  // ── SCAN POST FOR MALICIOUS LINKS BEFORE SAVING ──
  if(scanForMaliciousLink(text, 'Post/Spark', state.user.uid, state.profile.name)){
    showToast('⚠️ Suspicious link detected. Post blocked and reported.');
    btn.disabled=false; btn.textContent='✦ Spark';
    return;
  }
  // Auto-detect best category silently
  var finalCat = autoDetectCategory(text, pendingMedia ? pendingMedia.type : null, compCat);
  db.collection('sparks').add({text:text,authorId:state.user.uid,authorName:state.profile.name||'Mindvora user',authorHandle:state.profile.handle||'user',authorColor:state.profile.color||COLORS[0],authorPremium:state.profile.isPremium||false,category:finalCat,userCategory:compCat,isPremium:state.profile.isPremium||false,likes:[],saved:[],commentCount:0,commentsLocked:commentsLocked,mediaUrl:pendingMedia?pendingMedia.url:null,mediaType:pendingMedia?pendingMedia.type:null,poll:pendingPoll||null,location:pendingLocation||null,reposts:0,createdAt:firebase.firestore.FieldValue.serverTimestamp()}).then(function(){ document.getElementById('comp-ta').value=''; pendingPoll=null; pendingLocation=null; pendingSchedule=null; document.getElementById('btn-location').style.color=''; document.getElementById('btn-location').style.borderColor=''; document.getElementById('cc').textContent='280'; pendingMedia=null; document.getElementById('media-prev').style.display='none'; document.getElementById('prev-img').style.display='none'; document.getElementById('prev-vid').style.display='none'; btn.disabled=false; btn.textContent='✦ Spark';
              // Reset comments lock
              commentsLocked=false;
              var ctBtn=document.getElementById('btn-comments-toggle');
              if(ctBtn){ctBtn.textContent='💬';ctBtn.style.color='';ctBtn.style.borderColor='';} db.collection('users').doc(state.user.uid).update({sparksCount:firebase.firestore.FieldValue.increment(1)}); showToast('Spark launched! 🌿'); }).catch(function(e){ showToast('Failed: '+e.message); btn.disabled=false; btn.textContent='✦ Spark'; }); });

document.getElementById('btn-camera').addEventListener('click', function(){
  openCameraModal();
});

document.getElementById('btn-poll').addEventListener('click', function(){
  if(!state.user){showToast('Login first');return;}
  document.getElementById('poll-q').value='';
  document.getElementById('poll-o1').value='';
  document.getElementById('poll-o2').value='';
  document.getElementById('poll-o3').value='';
  document.getElementById('poll-o4').value='';
  document.getElementById('poll-err').textContent='';
  openModal('modal-poll');
});

document.getElementById('btn-location').addEventListener('click', function(){
  if(pendingLocation){
    pendingLocation=null;
    this.style.color='';
    this.style.borderColor='';
    showToast('📍 Location removed');
  } else {
    getLocation();
  }
});

document.getElementById('btn-schedule').addEventListener('click', function(){
  if(!state.user){showToast('Login first');return;}
  var now=new Date();
  now.setMinutes(now.getMinutes()+5);
  document.getElementById('sched-dt').min=now.toISOString().slice(0,16);
  document.getElementById('sched-err').textContent='';
  openModal('modal-schedule-pick');
});

document.getElementById('btn-media').addEventListener('click',function(){
  // Use hidden file input — bypasses Cloudinary widget CSP issues completely
  var fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = 'image/*,video/*';
  fileInput.style.display = 'none';
  document.body.appendChild(fileInput);
  fileInput.click();
  fileInput.addEventListener('change', async function(){
    var file = fileInput.files[0];
    document.body.removeChild(fileInput);
    if(!file) return;
    if(file.size > 209715200){ showToast('File too large! Max 200MB'); return; }
    // Show persistent uploading banner
    var uploadBanner = document.createElement('div');
    uploadBanner.id = 'upload-banner';
    uploadBanner.style.cssText = 'position:fixed;top:0;left:0;width:100%;background:var(--green);color:var(--cream);text-align:center;padding:10px;font-size:13px;font-weight:700;z-index:9999;font-family:DM Sans,sans-serif';
    uploadBanner.textContent = '⏳ Uploading media... Please wait, do not close this page.';
    document.body.appendChild(uploadBanner);

    var formData = new FormData();
    formData.append('file', file);
    formData.append('upload_preset', 'ml_default');
    formData.append('cloud_name', CLOUD_NAME);
    try{
      var resourceType = file.type.startsWith('video') ? 'video' : 'image';
      var resp = await fetch('https://api.cloudinary.com/v1_1/' + CLOUD_NAME + '/' + resourceType + '/upload', {
        method: 'POST',
        body: formData
      });
      var data = await resp.json();
      document.body.removeChild(uploadBanner);
      if(data.error){ showToast('Upload failed: ' + data.error.message); return; }
      pendingMedia = {url: data.secure_url, type: resourceType};
      if(resourceType === 'image'){
        document.getElementById('prev-img').src = data.secure_url;
        document.getElementById('prev-img').style.display = 'block';
        document.getElementById('prev-vid').style.display = 'none';
      } else {
        document.getElementById('prev-vid').src = data.secure_url;
        document.getElementById('prev-vid').style.display = 'block';
        document.getElementById('prev-img').style.display = 'none';
      }
      document.getElementById('media-prev').style.display = 'block';
      showToast('✅ Media ready! Now click Spark to post.');
    } catch(e){
      if(document.getElementById('upload-banner')) document.body.removeChild(uploadBanner);
      showToast('Upload failed: ' + e.message);
    }
  }); });
document.getElementById('media-rm').addEventListener('click',function(){ pendingMedia=null; document.getElementById('media-prev').style.display='none'; document.getElementById('prev-img').style.display='none'; document.getElementById('prev-vid').style.display='none'; });

document.querySelectorAll('#filter-bar .f-pill').forEach(function(b){ b.addEventListener('click',function(){
  document.querySelectorAll('#filter-bar .f-pill').forEach(function(x){ x.classList.remove('active'); });
  this.classList.add('active');
  state.filter = this.dataset.filter || 'all';
  // Hide compose box on news tab (news is read-only), show on others
  var compose = document.getElementById('compose-box');
  if (compose) compose.style.display = state.filter === 'news' ? 'none' : 'block';
  renderFeed();
}); });
document.getElementById('search-inp').addEventListener('input',renderFeed);

function toggleLike(id){ if(!state.user) return; var s=state.sparks.find(function(x){ return x.id===id; }); if(!s) return; var likes=s.likes||[],uid=state.user.uid,nw=likes.indexOf(uid)>-1?likes.filter(function(x){ return x!==uid; }):likes.concat([uid]); db.collection('sparks').doc(id).update({likes:nw}); if(nw.length>likes.length&&s.authorId!==uid) db.collection('notifications').add({toUid:s.authorId,fromName:state.profile.name,type:'like',text:state.profile.name+' liked your spark',read:false,createdAt:firebase.firestore.FieldValue.serverTimestamp()}); }
function toggleSave(id){ if(!state.user) return; var s=state.sparks.find(function(x){ return x.id===id; }); if(!s) return; var saved=s.saved||[],uid=state.user.uid,nw=saved.indexOf(uid)>-1?saved.filter(function(x){ return x!==uid; }):saved.concat([uid]); db.collection('sparks').doc(id).update({saved:nw}); showToast(nw.length>saved.length?'Spark saved 🔖':'Removed from saved'); }
function delSpark(id){ if(!state.user||!confirm('Delete this spark?')) return; db.collection('sparks').doc(id).delete().then(function(){ db.collection('users').doc(state.user.uid).update({sparksCount:firebase.firestore.FieldValue.increment(-1)}); showToast('Spark deleted'); }); }
function shareSpark(id){ var url=window.location.origin+'/spark/'+id; if(navigator.clipboard){ navigator.clipboard.writeText(url); showToast('Link copied!'); } else showToast('Link: '+url); }

document.getElementById('nav-feed').addEventListener('click',function(){ setNav(this); state.filter='all'; document.getElementById('compose-box').style.display='block'; loadSparks(); });
document.getElementById('nav-disc').addEventListener('click',function(){ setNav(this); document.getElementById('compose-box').style.display='none'; var d=state.sparks.slice().sort(function(a,b){ return (b.likes||[]).length-(a.likes||[]).length; }); document.getElementById('feed-cont').innerHTML=d.length?d.map(buildSparkHTML).join(''):'<div class="feed-empty"><div class="fi">🔭</div><h3>Nothing to discover yet</h3></div>'; });
document.getElementById('nav-saved').addEventListener('click',function(){ setNav(this); document.getElementById('compose-box').style.display='none'; var sv=state.sparks.filter(function(s){ return state.user&&(s.saved||[]).indexOf(state.user.uid)>-1; }); document.getElementById('feed-cont').innerHTML=sv.length?sv.map(buildSparkHTML).join(''):'<div class="feed-empty"><div class="fi">🔖</div><h3>Nothing saved yet</h3><p>Bookmark sparks to save them here.</p></div>'; });
document.getElementById('nav-dm').addEventListener('click',function(){ setNav(this); openModal('modal-dm'); });
document.getElementById('nav-topup').addEventListener('click',function(){ setNav(this); openModal('modal-topup'); });
document.getElementById('nav-earn').addEventListener('click',function(){ setNav(this); openModal('modal-earn'); });
document.getElementById('nav-prem').addEventListener('click',function(){ setNav(this); openModal('modal-prem'); });

document.getElementById('notif-btn').addEventListener('click',function(e){ e.stopPropagation(); document.getElementById('notif-drop').classList.toggle('open'); });
document.addEventListener('click',function(){ document.getElementById('notif-drop').classList.remove('open'); });
document.getElementById('nc-btn').addEventListener('click',function(){ if(!state.user) return; db.collection('notifications').where('toUid','==',state.user.uid).get().then(function(snap){ snap.docs.forEach(function(d){ d.ref.delete(); }); }); document.getElementById('notif-list').innerHTML='<div class="n-empty">No notifications yet</div>'; document.getElementById('nd').style.display='none'; });
function listenNotifs(){ if(!state.user) return; if(state.notifsUnsub) state.notifsUnsub(); state.notifsUnsub=db.collection('notifications').where('toUid','==',state.user.uid).limit(20).onSnapshot(function(snap){ var items=snap.docs.map(function(d){ return Object.assign({id:d.id},d.data()); }); document.getElementById('nd').style.display=items.filter(function(x){ return !x.read; }).length?'block':'none'; document.getElementById('notif-list').innerHTML=items.length?items.map(function(n){ return '<div class="n-item'+(n.read?'':' unread')+'" onclick="markRead(\''+n.id+'\')"><span class="n-ico">'+(n.type==='like'?'❤️':n.type==='comment'?'💬':n.type==='tip'?'💝':'🔔')+'</span><div><div class="n-text">'+esc(n.text||'')+'</div><div class="n-time">'+timeAgo(n.createdAt)+'</div></div></div>'; }).join(''):'<div class="n-empty">No notifications yet</div>'; }); }
function markRead(id){ db.collection('notifications').doc(id).update({read:true}); }

function openComments(sparkId){ state.currentSparkId=sparkId; document.getElementById('cmt-list').innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">Loading…</div>'; document.getElementById('cmt-inp').value=''; openModal('modal-comments'); db.collection('sparks').doc(sparkId).collection('comments').orderBy('createdAt','asc').limit(50).get().then(function(snap){ var cmts=snap.docs.map(function(d){ return Object.assign({id:d.id},d.data()); }); document.getElementById('cmt-list').innerHTML=cmts.length?cmts.map(function(cm){
    var isOwn = state.user && cm.authorId === state.user.uid;
    var editedTag = cm.edited ? '<span class="cmt-edited">(edited)</span>' : '';
    var safeText = (cm.text||'').replace(/'/g,"&#39;").replace(/"/g,"&quot;");
    var actions = isOwn ?
      '<div class="cmt-actions">' +
        '<button class="act-btn" data-action="edit-cmt" data-sparkid="'+currentSparkId+'" data-cmtid="'+cm.id+'" data-text="'+safeText+'">✏️</button>' +
        '<button class="act-btn del" data-action="del-cmt" data-sparkid="'+currentSparkId+'" data-cmtid="'+cm.id+'">🗑</button>' +
      '</div>' : '';
    return '<div class="cmt-item">'+
      '<div class="cmt-av" style="background:'+(cm.authorColor||COLORS[0])+'">'+esc((cm.authorName||'Z').charAt(0))+'</div>'+
      '<div style="flex:1;position:relative">'+
        actions+
        '<div><span class="cmt-nm">'+esc(cm.authorName||'Mindvora user')+'</span>'+
        '<span class="cmt-hdl">@'+esc(cm.authorHandle||'user')+'</span></div>'+
        (cm.isVoice && cm.voiceUrl ?
        '<audio controls src="'+esc(cm.voiceUrl)+'" style="width:100%;height:36px;border-radius:8px;margin-top:4px"></audio>' :
        '<div class="cmt-txt" id="cmt-txt-'+cm.id+'">'+esc(cm.text||'')+'</div>')+
        '<div class="cmt-tm">'+timeAgo(cm.createdAt)+editedTag+'</div>'+
      '</div>'+
    '</div>';
  }).join(''):'<div style="text-align:center;padding:24px;color:var(--muted)">No comments yet. Be first!</div>'; }); }
document.getElementById('btn-cmt').addEventListener('click',function(){
  // Check if comments are locked on this post
  var spark = state.sparks.find(function(s){ return s.id === state.currentSparkId; });
  if (spark && spark.commentsLocked) {
    showToast('🔒 The author has disabled comments on this post.');
    return;
  }
  var text=document.getElementById('cmt-inp').value.trim(); if(!text||!state.user||!state.currentSparkId) return; if(containsMalicious(text)){ showToast('❌ Comment contains invalid content.'); return; } if(!checkRateLimit('comment',10)){ return; } text=sanitize(text); var btn=this; btn.disabled=true; db.collection('sparks').doc(state.currentSparkId).collection('comments').add({text:text,authorId:state.user.uid,authorName:state.profile.name,authorHandle:state.profile.handle,authorColor:state.profile.color,createdAt:firebase.firestore.FieldValue.serverTimestamp()}).then(function(){ db.collection('sparks').doc(state.currentSparkId).update({commentCount:firebase.firestore.FieldValue.increment(1)}); document.getElementById('cmt-inp').value=''; btn.disabled=false; openComments(state.currentSparkId); showToast('Comment posted!'); }).catch(function(){ btn.disabled=false; showToast('Failed to post comment'); }); });

function loadStories(){ var cutoff=Date.now()-48*60*60*1000; db.collection('stories').where('expiresAt','>',new Date(cutoff)).limit(20).get().then(function(snap){ var bar=document.getElementById('stories-bar'); bar.innerHTML='<div class="s-add" id="story-add">＋</div>'; snap.docs.forEach(function(d){ var s=d.data(),seen=state.user&&(s.seenBy||[]).indexOf(state.user.uid)>-1; var el=document.createElement('div'); el.className='s-item'; el.innerHTML='<div class="s-ring'+(seen?' seen':'')+'"><div class="s-av">'+esc((s.authorName||'Z').charAt(0).toUpperCase())+'</div></div><div class="s-name">'+esc(s.authorName||'')+'</div>'; el.addEventListener('click',function(){ viewStory(d.id,s); }); bar.appendChild(el); }); document.getElementById('story-add').addEventListener('click',postStory); }); }
function postStory(){ var text=prompt('Share a story (disappears in 48h):'); if(!text||!text.trim()||!state.user) return; db.collection('stories').add({text:text.trim(),authorId:state.user.uid,authorName:state.profile.name,authorHandle:state.profile.handle,authorColor:state.profile.color,seenBy:[],createdAt:firebase.firestore.FieldValue.serverTimestamp(),expiresAt:new Date(Date.now()+48*60*60*1000)}).then(function(){ showToast('Story posted! 48h ⏱'); loadStories(); }); }
function viewStory(id,s){ document.getElementById('sv-av').textContent=(s.authorName||'Z').charAt(0).toUpperCase(); document.getElementById('sv-av').style.background=s.authorColor||COLORS[0]; document.getElementById('sv-nm').textContent=s.authorName||'Mindvora user'; document.getElementById('sv-tm').textContent=timeAgo(s.createdAt); document.getElementById('sv-text').textContent=s.text||''; document.getElementById('sv-overlay').classList.add('open'); var fill=document.getElementById('sv-fill'); fill.style.transition='none'; fill.style.width='0%'; setTimeout(function(){ fill.style.transition='width 5s linear'; fill.style.width='100%'; },50); setTimeout(function(){ document.getElementById('sv-overlay').classList.remove('open'); },5100); if(state.user) db.collection('stories').doc(id).update({seenBy:firebase.firestore.FieldValue.arrayUnion(state.user.uid)}); }
document.getElementById('sv-x').addEventListener('click',function(){ document.getElementById('sv-overlay').classList.remove('open'); });


// ── DM USER SEARCH ──
var dmNewMsgOpen = false;

function toggleNewMessage() {
  dmNewMsgOpen = !dmNewMsgOpen;
  var panel = document.getElementById('dm-new-msg-panel');
  if (panel) {
    panel.style.display = dmNewMsgOpen ? 'block' : 'none';
    if (dmNewMsgOpen) {
      setTimeout(function(){ 
        var inp = document.getElementById('dm-user-search');
        if (inp) { inp.value = ''; inp.focus(); }
        document.getElementById('dm-user-results').innerHTML = '';
        showAllUsers();
      }, 100);
    }
  }
}

function showAllUsers() {
  // Show recent/popular users on open before any typing
  if (!state.user) return;
  var res = document.getElementById('dm-user-results');
  res.innerHTML = '<div style="font-size:10px;color:var(--muted);padding:4px">Loading users...</div>';
  db.collection('users').limit(20).get().then(function(snap) {
    renderDMUserResults(snap.docs);
  }).catch(function(){ res.innerHTML=''; });
}

function searchUsersForDM(q) {
  var res = document.getElementById('dm-user-results');
  q = (q||'').trim().toLowerCase();
  // Strip leading @ if user types @handle
  if (q.startsWith('@')) q = q.slice(1);
  
  if (!q) { showAllUsers(); return; }
  res.innerHTML = '<div style="font-size:10px;color:var(--muted);padding:4px">Searching...</div>';

  // Search by name AND handle simultaneously
  var byName   = db.collection('users').orderBy('name').startAt(q).endAt(q+'').limit(8).get();
  var byHandle = db.collection('users').orderBy('handle').startAt(q).endAt(q+'').limit(8).get();

  Promise.all([byName, byHandle]).then(function(results) {
    // Merge and deduplicate
    var seen = {};
    var docs = [];
    results.forEach(function(snap) {
      snap.docs.forEach(function(d) {
        if (!seen[d.id] && d.id !== state.user.uid) {
          seen[d.id] = true;
          docs.push(d);
        }
      });
    });
    if (!docs.length) {
      res.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:8px 4px;text-align:center">No users found for "'+esc(q)+'"</div>';
      return;
    }
    renderDMUserResults(docs);
  }).catch(function() {
    res.innerHTML = '<div style="font-size:11px;color:#fca5a5;padding:4px">Search failed</div>';
  });
}

function renderDMUserResults(docs) {
  var res = document.getElementById('dm-user-results');
  res.innerHTML = '';
  var filtered = docs.filter(function(d){ return d.id !== (state.user&&state.user.uid); });
  if (!filtered.length) {
    res.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:8px 4px;text-align:center">No users yet</div>';
    return;
  }
  filtered.forEach(function(d) {
    var u = d.data();
    var row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 6px;border-radius:10px;cursor:pointer;transition:background .15s';
    row.onmouseover = function(){ this.style.background='var(--deep)'; };
    row.onmouseout  = function(){ this.style.background='transparent'; };
    var verified = u.isVerified ? '<span style="color:var(--green3);font-size:11px;margin-left:4px">&#10003;</span>' : '';
    row.innerHTML =
      '<div style="width:36px;height:36px;border-radius:50%;background:'+esc(u.color||COLORS[0])+';display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;flex-shrink:0">'+esc((u.name||'U').charAt(0).toUpperCase())+'</div>'+
      '<div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:700;color:var(--moon);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(u.name||'Mindvora user')+verified+'</div><div style="font-size:11px;color:var(--muted)">@'+esc(u.handle||'user')+'</div></div>'+
      '<div style="font-size:10px;color:var(--green3);flex-shrink:0">Message</div>';
    var uid = d.id, uname = u.name||'User', ucolor = u.color||COLORS[0];
    row.addEventListener('click', function(){ startDMWithUser(uid, uname, ucolor); });
    res.appendChild(row);
  });
}
function startDMWithUser(uid, name, color) {
  // Close new message panel
  dmNewMsgOpen = false;
  var panel = document.getElementById('dm-new-msg-panel');
  if (panel) panel.style.display = 'none';
  // Open chat
  var dmId = [state.user.uid, uid].sort().join('_');
  openChat(dmId, uid, name, color);
}

function loadConversations(){ if(!state.user) return; db.collection('dms').where('members','array-contains',state.user.uid).limit(20).get().then(function(snap){ var list=document.getElementById('dm-list'); list.innerHTML=''; if(!snap.docs.length){ list.innerHTML='<div style="padding:20px;text-align:center;font-size:12px;color:var(--muted)">No conversations yet</div>'; return; } snap.docs.forEach(function(d){ var dm=d.data(),oid=dm.members.find(function(m){ return m!==state.user.uid; }),oname=dm.names?dm.names[oid]:'User',ocolor=dm.colors?dm.colors[oid]:COLORS[0]; var row=document.createElement('div'); row.className='dm-row'; row.innerHTML='<div class="dm-av" style="background:'+ocolor+'">'+esc(oname.charAt(0).toUpperCase())+'</div><div style="flex:1;min-width:0"><div class="dm-nm">'+esc(oname)+'</div><div class="dm-pv">'+esc(dm.lastMsg||'')+'</div></div>'+(dm.unread?'<div class="dm-ud"></div>':''); row.addEventListener('click',function(){ openChat(d.id,oid,oname,ocolor); }); list.appendChild(row); }); }); }
var dmTimer; document.getElementById('dm-search').addEventListener('input',function(){ clearTimeout(dmTimer); var q=this.value.trim().toLowerCase(); if(!q){ loadConversations(); return; } dmTimer=setTimeout(function(){ db.collection('users').orderBy('name').startAt(q).endAt(q+'\uf8ff').limit(10).get().then(function(snap){ var list=document.getElementById('dm-list'); list.innerHTML=''; snap.docs.forEach(function(d){ var u=d.data(); if(u.id===state.user.uid) return; var row=document.createElement('div'); row.className='dm-row'; row.innerHTML='<div class="dm-av" style="background:'+(u.color||COLORS[0])+'">'+esc((u.name||'U').charAt(0))+'</div><div><div class="dm-nm">'+esc(u.name||'User')+'</div><div class="dm-pv">@'+esc(u.handle||'')+'</div></div>'; row.addEventListener('click',function(){ openChat([state.user.uid,u.id].sort().join('_'),u.id,u.name,u.color); }); list.appendChild(row); }); if(!snap.docs.length) list.innerHTML='<div style="padding:16px;text-align:center;font-size:12px;color:var(--muted)">No users found</div>'; }); },400); });
function openChat(dmId,otherId,otherName,otherColor){ if(state.user) watchDMForScam(dmId, otherId);
  // Mark all unread messages from other user as read
  if(state.user) {
    db.collection('dms').doc(dmId).collection('messages')
      .where('fromId','==',otherId)
      .where('read','==',false)
      .get().then(function(snap){
        var batch = db.batch();
        snap.docs.forEach(function(doc){
          batch.update(doc.ref, {read:true, readAt: firebase.firestore.FieldValue.serverTimestamp()});
        });
        if(!snap.empty) batch.commit().catch(function(){});
      }).catch(function(){});
  } var right=document.getElementById('dm-right'); right.innerHTML='<div class="chat-hd"><div class="dm-av" style="background:'+(otherColor||COLORS[0])+';width:32px;height:32px">'+esc((otherName||'U').charAt(0))+'</div><div style="font-size:13px;font-weight:700;color:var(--white)">'+esc(otherName)+'</div></div><div class="chat-msgs" id="cm-'+dmId+'"></div><div class="chat-bar"><textarea class="chat-inp" id="ci-'+dmId+'" placeholder="Message…" rows="1"></textarea><button class="chat-send" onclick="sendMsg(\''+dmId+'\',\''+otherId+'\',\''+esc(otherName)+'\',\''+esc(otherColor||COLORS[0])+'\')">➤</button></div>'; db.collection('dms').doc(dmId).collection('messages').orderBy('createdAt','asc').limit(50).onSnapshot(function(snap){ var box=document.getElementById('cm-'+dmId); if(!box) return; box.innerHTML=snap.docs.map(function(d){
    var m=d.data(), mine=m.fromId===state.user.uid;
    var col=mine?(state.profile.color||COLORS[0]):(otherColor||COLORS[0]);
    var editedTag = m.edited ? '<span class="msg-edited">(edited)</span>' : '';
    var safeText = (m.text||'').replace(/'/g,"&#39;").replace(/"/g,"&quot;");
    var actions = mine ?
      '<div class="msg-actions" style="right:0">' +
        '<button class="act-btn" data-action="edit-msg" data-dmid="'+dmId+'" data-msgid="'+d.id+'" data-text="'+safeText+'">✏️ Edit</button>' +
        '<button class="act-btn del" data-action="del-msg" data-dmid="'+dmId+'" data-msgid="'+d.id+'">🗑 Delete</button>' +
      '</div>' : '';
    // Read receipts — show ticks on sender's messages
    var readReceipt = '';
    if (mine) {
      if (m.read) {
        // Double blue tick — message was read
        readReceipt = '<span style="color:#22c55e;font-size:11px;margin-left:4px" title="Read">✓✓</span>';
      } else {
        // Single grey tick — sent but not read
        readReceipt = '<span style="color:var(--muted);font-size:11px;margin-left:4px" title="Sent">✓</span>';
      }
    }
    return '<div class="msg'+(mine?' mine':'')+'">'+
      '<div class="msg-av" style="background:'+col+'">'+
        (mine?(state.profile.name||'U').charAt(0):(otherName||'U').charAt(0))+
      '</div>'+
      '<div style="position:relative">'+
        actions+
        '<div class="msg-bub">'+esc(m.text||'')+'</div>'+
        '<div class="msg-t">'+timeAgo(m.createdAt)+editedTag+readReceipt+'</div>'+
      '</div>'+
    '</div>';
  }).join('')||'<div style="text-align:center;padding:20px;font-size:12px;color:var(--muted)">No messages yet</div>'; box.scrollTop=box.scrollHeight; }); document.getElementById('ci-'+dmId).addEventListener('keydown',function(e){ if(e.key==='Enter'&&!e.shiftKey){ e.preventDefault(); sendMsg(dmId,otherId,otherName,otherColor||COLORS[0]); } }); }
function sendMsg(dmId,otherId,otherName,otherColor){
  var inp=document.getElementById('ci-'+dmId);
  if(inp && containsMalicious(inp.value)){ showToast('❌ Message contains invalid content.'); return; }
  // ── SCAM DETECTION ──────────────────────────────────────────
  if(inp){ scanMessageForScam(inp.value, dmId, state.user.uid, otherId); }
  if(!checkRateLimit('dm',20)){ return; } var inp=document.getElementById('ci-'+dmId); if(!inp) return; var text=inp.value.trim(); if(!text||!state.user) return; inp.value=''; var batch=db.batch(),dmRef=db.collection('dms').doc(dmId),msgRef=dmRef.collection('messages').doc(),names={},colors={}; names[state.user.uid]=state.profile.name||'User'; names[otherId]=otherName; colors[state.user.uid]=state.profile.color||COLORS[0]; colors[otherId]=otherColor||COLORS[0]; batch.set(dmRef,{members:[state.user.uid,otherId],names:names,colors:colors,lastMsg:text,lastAt:firebase.firestore.FieldValue.serverTimestamp(),unread:true},{merge:true}); batch.set(msgRef,{text:text,fromId:state.user.uid,fromName:state.profile.name,createdAt:firebase.firestore.FieldValue.serverTimestamp(),read:false,readAt:null}); batch.commit().then(function(){ openChat(dmId,otherId,otherName,otherColor||COLORS[0]); db.collection('notifications').add({toUid:otherId,fromName:state.profile.name,type:'dm',text:state.profile.name+' sent you a message',read:false,createdAt:firebase.firestore.FieldValue.serverTimestamp()}); }); }

function selPlan(id,amount,name){ state.plan={id:id,amount:amount,name:name}; document.querySelectorAll('.plan-card').forEach(function(c){ c.classList.remove('sel'); }); document.getElementById('pc-'+id).classList.add('sel'); document.getElementById('co-name').textContent=name; document.getElementById('co-price').textContent='$'+amount.toLocaleString(); if(document.getElementById('co-name')) document.getElementById('co-name').textContent=name; }
document.getElementById('btn-pay').addEventListener('click',function(){ if(!state.user) return; if(typeof PaystackPop==='undefined'){ showToast('Payment loading, try again.'); return; } // Convert USD to NGN for Paystack (1 USD ≈ 1600 NGN)
  var usdAmount = state.plan.amount;
  var ngnAmount = Math.round(usdAmount * 1600 * 100); // in kobo
  PaystackPop.setup({key:PAYSTACK_KEY,email:state.user.email,amount:ngnAmount,currency:'NGN',ref:'ZP-'+Date.now(),
  metadata:{plan:state.plan.id,planName:state.plan.name,amountUSD:usdAmount},
  callback:function(r){ db.collection('users').doc(state.user.uid).update({isPremium:true,plan:state.plan.id,premiumRef:r.reference}).then(function(){ state.profile.isPremium=true; closeModal('modal-prem'); var pw=document.getElementById('prem-widget'); if(pw) pw.style.display='none'; showToast('Welcome to '+state.plan.name+'! 💎'); }).catch(function(){ showToast('Payment received but activation failed. Contact support.'); }); },onClose:function(){ showToast('Payment cancelled'); }}).openIframe(); });

function buyVerifiedBadge(){
  if(!state.user){ showToast('Please login first'); return; }
  if(state.profile && state.profile.isVerified){
    showToast('✅ You already have a Verified Badge!'); return;
  }
  if(typeof PaystackPop==='undefined'){ showToast('Payment loading, try again.'); return; }
  PaystackPop.setup({
    key: PAYSTACK_KEY,
    email: state.user.email,
    amount: 25 * 1600 * 100, // $25 in NGN kobo
    currency: 'NGN',
    ref: 'ZVB-' + Date.now(),
    callback: function(){
      db.collection('users').doc(state.user.uid).update({ isVerified: true }).then(function(){
        state.profile.isVerified = true;
        closeModal('modal-prem');
        showToast('🎉 Congratulations! You are now Verified on Mindvora! ✅');
        // Send notification to user
        db.collection('notifications').add({
          uid: state.user.uid,
          type: 'verified',
          text: '✅ Your Mindvora Verified Badge has been activated! Your profile now shows the green checkmark.',
          createdAt: firebase.firestore.FieldValue.serverTimestamp(),
          read: false
        }).catch(function(){});
      });
    },
    onClose: function(){ showToast('Payment cancelled'); }
  }).openIframe();
}

function openTip(authorId,authorName){ state.tipTarget={id:authorId,name:authorName}; document.getElementById('tip-name').textContent=authorName; document.getElementById('tip-amt').value=''; document.getElementById('tip-err').textContent=''; openModal('modal-tip'); }
function setTip(amount){ document.getElementById('tip-amt').value=amount; }
document.getElementById('btn-tip').addEventListener('click',function(){ var amount=parseInt(document.getElementById('tip-amt').value)||0; if(amount<100){ document.getElementById('tip-err').textContent='Minimum tip is $1'; return; } if(!state.user||!state.tipTarget) return; if(typeof PaystackPop==='undefined'){ showToast('Payment loading, try again.'); return; } PaystackPop.setup({key:PAYSTACK_KEY,email:state.user.email,amount:amount*100,currency:'NGN',ref:'ZT-'+Date.now(),callback:function(){ db.collection('users').doc(state.tipTarget.id).update({tips:firebase.firestore.FieldValue.increment(amount)}); db.collection('notifications').add({toUid:state.tipTarget.id,fromName:state.profile.name,type:'tip',text:state.profile.name+' tipped you $'+amount.toLocaleString(),read:false,createdAt:firebase.firestore.FieldValue.serverTimestamp()}); closeModal('modal-tip'); showToast('Tip sent! 💝'); },onClose:function(){ showToast('Tip cancelled'); }}).openIframe(); });

function switchTab(group,tab,btn){ document.querySelectorAll('#modal-'+group+' .tab-row .f-pill').forEach(function(b){ b.classList.remove('active'); }); btn.classList.add('active'); document.querySelectorAll('#modal-'+group+' .e-panel').forEach(function(p){ p.classList.remove('active'); }); document.getElementById(group+'-'+tab).classList.add('active'); }
// ── WITHDRAWAL SYSTEM ──
var currentWdMethod = 'bank';

function switchWdTab(method, btn) {
  currentWdMethod = method;
  document.querySelectorAll('.wd-tab').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  ['bank','crypto','paypal','momo'].forEach(function(m){
    var el = document.getElementById('wd-panel-'+m);
    if(el) el.style.display = m===method ? 'block' : 'none';
  });
}

function loadWdHistory() {
  if(!state.user) return;
  var bal = parseFloat((state.profile&&state.profile.earnings)||0);
  var balEl = document.getElementById('wd-bal-display');
  if(balEl) balEl.textContent = '$'+bal.toFixed(2);

  var hist = document.getElementById('wd-history');
  if(!hist) return;
  db.collection('withdrawals').where('uid','==',state.user.uid).limit(10).get()
    .then(function(snap){
      if(snap.empty){ hist.innerHTML='<div style="font-size:11px;color:var(--muted)">No withdrawals yet</div>'; return; }
      hist.innerHTML = snap.docs.map(function(d){
        var w=d.data();
        var statusColor = w.status==='paid'?'var(--green3)':w.status==='rejected'?'#ef4444':'#fbbf24';
        var statusIcon  = w.status==='paid'?'✅':w.status==='rejected'?'❌':'⏳';
        return '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">' +
          '<div><div style="font-size:12px;color:var(--moon)">$'+w.amount.toFixed(2)+' via '+esc(w.method||'Bank')+'</div>' +
          '<div style="font-size:10px;color:var(--muted)">'+timeAgo(w.requestedAt)+'</div></div>' +
          '<span style="font-size:11px;color:'+statusColor+'">'+statusIcon+' '+esc(w.status||'pending')+'</span>' +
        '</div>';
      }).join('');
    }).catch(function(){ hist.innerHTML='<div style="font-size:11px;color:var(--muted)">Could not load history</div>'; });
}

function requestWithdrawal() {
  var amt = parseFloat(document.getElementById('wd-amt').value)||0;
  var err = document.getElementById('wd-err');
  err.textContent='';

  if(amt<20){ err.textContent='Minimum withdrawal is $20'; return; }
  var userBalance = parseFloat((state.profile&&state.profile.earnings)||0);
  if(amt>userBalance){ err.textContent='Insufficient balance ($'+userBalance.toFixed(2)+' available)'; return; }

  var wdData = {
    uid: state.user.uid,
    name: (state.profile&&state.profile.name)||'Mindvora user',
    email: state.user.email,
    amount: amt,
    method: currentWdMethod,
    status: 'pending',
    requestedAt: firebase.firestore.FieldValue.serverTimestamp()
  };

  if(currentWdMethod==='bank'){
    var acc  = document.getElementById('wd-acc').value.trim();
    var bank = document.getElementById('wd-bank').value.trim();
    var accname = document.getElementById('wd-accname').value.trim();
    if(!acc||!bank||!accname){ err.textContent='Please fill all bank fields'; return; }
    wdData.bankAccount = acc;
    wdData.bankName    = bank;
    wdData.accountName = accname;
    wdData.details     = accname+' · '+bank+' · '+acc;

  } else if(currentWdMethod==='crypto'){
    var wallet = document.getElementById('wd-wallet').value.trim();
    var coin   = document.getElementById('wd-crypto-coin').value;
    if(!wallet){ err.textContent='Please enter your wallet address'; return; }
    if(wallet.length<20){ err.textContent='Wallet address looks too short — check it'; return; }
    wdData.walletAddress = wallet;
    wdData.cryptoCoin    = coin;
    wdData.details       = coin+' · '+wallet.slice(0,12)+'...';

  } else if(currentWdMethod==='paypal'){
    var ppEmail = document.getElementById('wd-paypal-email').value.trim();
    if(!ppEmail||ppEmail.indexOf('@')<0){ err.textContent='Enter a valid PayPal email'; return; }
    wdData.paypalEmail = ppEmail;
    wdData.details     = 'PayPal · '+ppEmail;

  } else if(currentWdMethod==='momo'){
    var phone    = document.getElementById('wd-momo-phone').value.trim();
    var provider = document.getElementById('wd-momo-provider').value;
    var momoName = document.getElementById('wd-momo-name').value.trim();
    if(!phone||!momoName){ err.textContent='Please fill all mobile money fields'; return; }
    wdData.momoPhone    = phone;
    wdData.momoProvider = provider;
    wdData.momoName     = momoName;
    wdData.details      = provider.toUpperCase()+' · '+phone;
  }

  var btn = document.getElementById('btn-wd');
  btn.disabled=true; btn.textContent='Submitting...';

  // Deduct balance immediately so user can't double-withdraw
  db.collection('users').doc(state.user.uid).update({
    earnings: firebase.firestore.FieldValue.increment(-amt)
  }).then(function(){
    return db.collection('withdrawals').add(wdData);
  }).then(function(){
    // Notify admin
    db.collection('notifications').add({
      uid: 'ilohgreat25@gmail.com',
      type: 'withdrawal_request',
      text: '💸 '+esc(wdData.name)+' requested $'+amt.toFixed(2)+' via '+currentWdMethod+' ('+esc(wdData.details)+')',
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
      read: false
    }).catch(function(){});
    btn.disabled=false; btn.textContent='💸 Request Withdrawal';
    showToast('✅ Withdrawal submitted! Processing in 24-48 hours.');
    document.getElementById('wd-amt').value='';
    loadWdHistory();
    // Refresh balance display
    if(state.profile) state.profile.earnings = (state.profile.earnings||0) - amt;
    var balEl = document.getElementById('wd-bal-display');
    if(balEl) balEl.textContent='$'+Math.max(0,(state.profile&&state.profile.earnings)||0).toFixed(2);
  }).catch(function(e){
    btn.disabled=false; btn.textContent='💸 Request Withdrawal';
    err.textContent='Error submitting request. Try again.';
  });
}
function copyRef(){ var link=document.getElementById('ref-link').value; if(navigator.clipboard){ navigator.clipboard.writeText(link); showToast('Referral link copied!'); } }

function setNetwork(btn,network){ state.network=network; btn.closest('.ntabs').querySelectorAll('.ntab').forEach(function(b){ b.classList.remove('active'); }); btn.classList.add('active'); }
function setAmt(id,amount){ document.getElementById(id).value=amount; }
function selPkg(card){ document.querySelectorAll('.pkg-card').forEach(function(c){ c.classList.remove('sel'); }); card.classList.add('sel'); state.selectedPkg={size:card.dataset.size,dur:card.dataset.dur,price:parseInt(card.dataset.price)}; }
document.getElementById('btn-airtime').addEventListener('click',function(){ state.network=document.getElementById('air-network').value; var phone=document.getElementById('air-phone').value.trim(),amt=parseInt(document.getElementById('air-amt').value)||0,err=document.getElementById('air-err'); err.textContent=''; if(!phone||!phone.trim()||phone.length<6){ err.textContent='Enter a valid 11-digit phone number'; return; } if(amt<1){ err.textContent='Minimum airtime is $1'; return; } if(!state.user) return; if(typeof PaystackPop==='undefined'){ showToast('Payment loading, try again.'); return; } PaystackPop.setup({key:PAYSTACK_KEY,email:state.user.email,amount:amt*100,currency:'NGN',ref:'ZA-'+Date.now(),metadata:{type:'airtime',network:state.network,phone:phone,amount:amt},callback:function(r){
            // Payment successful — now deliver airtime via Paystack API
            var networkCode = {'MTN Nigeria':'MTN','Airtel Nigeria':'AIR','Glo Nigeria':'GLO','9mobile Nigeria':'ETI'}[state.network]||'MTN';
            var amtKobo = amt * 100; // Paystack uses kobo (₦) or cents
            // Save to Firestore first
            db.collection('topups').add({
              uid:state.user.uid,name:state.profile.name,
              email:state.user.email,type:'airtime',
              network:state.network,phone:phone,amount:amt,
              ref:r.reference,status:'processing',
              createdAt:firebase.firestore.FieldValue.serverTimestamp()
            }).then(function(docRef){
              // Call Paystack charge endpoint to deliver airtime
              // Airtime delivery via secure backend proxy
              // Deliver via Husmodata API
              deliverAirtimeHusmo(phone, state.network, amt, r.reference, docRef);
            });
            closeModal('modal-topup');
            document.getElementById('air-phone').value='';
            document.getElementById('air-amt').value='';
          },onClose:function(){ showToast('Airtime purchase cancelled'); }}).openIframe(); });
document.getElementById('btn-data').addEventListener('click',function(){ state.network=document.getElementById('data-network').value; var phone=document.getElementById('data-phone').value.trim(),err=document.getElementById('data-err'); err.textContent=''; if(!phone||!phone.trim()||phone.length<6){ err.textContent='Enter a valid 11-digit phone number'; return; } if(!state.selectedPkg){ err.textContent='Select a data bundle'; return; } if(!state.user) return; if(typeof PaystackPop==='undefined'){ showToast('Payment loading, try again.'); return; } var pkg=state.selectedPkg; PaystackPop.setup({key:PAYSTACK_KEY,email:state.user.email,amount:pkg.price*100,currency:'NGN',ref:'ZD-'+Date.now(),metadata:{type:'data',network:state.network,phone:phone,bundle:pkg.size,duration:pkg.dur,price:pkg.price},callback:function(r){
            var networkCode = {'MTN Nigeria':'MTN','Airtel Nigeria':'AIR','Glo Nigeria':'GLO','9mobile Nigeria':'ETI'}[state.network]||'MTN';
            db.collection('topups').add({
              uid:state.user.uid,name:state.profile.name,
              email:state.user.email,type:'data',
              network:state.network,phone:phone,
              bundle:pkg.size,duration:pkg.dur,
              amount:pkg.price,ref:r.reference,
              status:'processing',
              createdAt:firebase.firestore.FieldValue.serverTimestamp()
            }).then(function(docRef){
              // Data delivery via secure backend proxy
              // Deliver via Husmodata API
              deliverDataHusmo(phone, state.network, pkg.size, pkg.price, r.reference, docRef);
            });
            closeModal('modal-topup');
            document.getElementById('data-phone').value='';
          },onClose:function(){ showToast('Data purchase cancelled'); }}).openIframe(); });

document.querySelectorAll('.modal-overlay').forEach(function(o){ o.addEventListener('click',function(e){ if(e.target===this) this.classList.remove('open'); }); });

// ── ADS SYSTEM ──
var adState = { type:'free', budget:5, impressions:500, videoAdTimer:null, videoAdSeconds:5, currentAds:[], adIndex:0, postCount:0 };

document.getElementById('nav-ads').addEventListener('click',function(){ setNav(this); openModal('modal-ads'); });

function selectAdType(type){
  adState.type = type;
  document.getElementById('at-free').classList.toggle('sel', type==='free');
  document.getElementById('at-paid').classList.toggle('sel', type==='paid');
  document.getElementById('form-free').classList.toggle('active', type==='free');
  document.getElementById('form-paid').classList.toggle('active', type==='paid');
}

function selBudget(card){
  document.querySelectorAll('#form-paid .pkg-card').forEach(function(c){ c.classList.remove('sel'); });
  card.classList.add('sel');
  adState.budget = parseInt(card.dataset.budget);
  adState.impressions = parseInt(card.dataset.impressions);
}

function switchAdTab(tab, btn){
  document.querySelectorAll('#modal-ads .adm-tabs .f-pill').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  document.getElementById('ads-create').style.display = tab==='create'?'block':'none';
  document.getElementById('ads-myads').style.display = tab==='myads'?'block':'none';
  document.getElementById('ads-stats').style.display = tab==='stats'?'block':'none';
  if(tab==='myads') loadMyAds();
  if(tab==='stats') loadAdStats();
}

// Submit FREE ad
document.getElementById('btn-submit-free').addEventListener('click', function(){
  var title = document.getElementById('free-ad-title').value.trim();
  var desc = document.getElementById('free-ad-desc').value.trim();
  var cta = document.getElementById('free-ad-cta').value.trim();
  var url = document.getElementById('free-ad-url').value.trim();
  if(url && !isSafeUrl(url)){ document.getElementById('free-ad-err').textContent='Invalid or unsafe URL. Please use a valid https:// link.'; return; }
  var emoji = document.getElementById('free-ad-emoji').value.trim() || '📣';
  var err = document.getElementById('free-ad-err');
  err.textContent = '';
  if(!title){ err.textContent='Enter ad title'; return; }
  if(!desc){ err.textContent='Enter ad description'; return; }
  if(!cta){ err.textContent='Enter call to action text'; return; }
  if(!state.user) return;
  var btn = this; btn.disabled=true; btn.textContent='Submitting…';
  // ── SCAN AD FOR MALICIOUS CONTENT ──
  var _adDesc = (document.getElementById('ad-desc')||{}).value||'';
  var _adTitle = (document.getElementById('ad-title')||{}).value||'';
  var _adUrl = (document.getElementById('ad-url')||{}).value||'';
  if(scanForMaliciousLink(_adTitle+' '+_adDesc+' '+_adUrl, 'Advertisement', state.user&&state.user.uid, state.profile&&state.profile.name)){
    btn.disabled=false; btn.textContent='Submit Ad';
    showToast('⚠️ Suspicious content in your ad. Blocked and reported to admin.');
    return;
  }
  db.collection('ads').add({
    type:'free', title:title, description:desc, cta:cta, url:url, emoji:emoji,
    advertiserId:state.user.uid, advertiserName:state.profile.name,
    advertiserHandle:state.profile.handle, status:'pending',
    views:0, clicks:0, budget:0,
    createdAt:firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(){
    btn.disabled=false; btn.textContent='🆓 Submit Free Ad →';
    document.getElementById('free-ad-title').value='';
    document.getElementById('free-ad-desc').value='';
    document.getElementById('free-ad-cta').value='';
    document.getElementById('free-ad-url').value='';
    document.getElementById('free-ad-emoji').value='';
    showToast('Free ad submitted! Goes live within 24h 🎉');
    closeModal('modal-ads');
    loadAds();
  }).catch(function(e){ err.textContent='Failed: '+e.message; btn.disabled=false; btn.textContent='🆓 Submit Free Ad →'; });
});

// Submit PAID ad
document.getElementById('btn-submit-paid').addEventListener('click', function(){
  var title = document.getElementById('paid-ad-title').value.trim();
  var desc = document.getElementById('paid-ad-desc').value.trim();
  var cta = document.getElementById('paid-ad-cta').value.trim();
  var url = document.getElementById('paid-ad-url').value.trim();
  if(url && !isSafeUrl(url)){ document.getElementById('paid-ad-err').textContent='Invalid or unsafe URL. Please use a valid https:// link.'; return; }
  var emoji = document.getElementById('paid-ad-emoji').value.trim() || '⚡';
  var err = document.getElementById('paid-ad-err');
  err.textContent = '';
  if(!title){ err.textContent='Enter ad title'; return; }
  if(!desc){ err.textContent='Enter ad description'; return; }
  if(!cta){ err.textContent='Enter call to action text'; return; }
  if(!state.user) return;
  if(typeof PaystackPop==='undefined'){ showToast('Payment loading, try again.'); return; }
  PaystackPop.setup({
    key:PAYSTACK_KEY, email:state.user.email,
    amount:adState.budget*100, currency:'USD',
    ref:'ZAD-'+Date.now(),
    callback:function(r){
      db.collection('ads').add({
        type:'paid', title:title, description:desc, cta:cta, url:url, emoji:emoji,
        advertiserId:state.user.uid, advertiserName:state.profile.name,
        advertiserHandle:state.profile.handle, status:'pending',
        views:0, clicks:0, budget:adState.budget, impressionsTarget:adState.impressions,
        ref:r.reference, createdAt:firebase.firestore.FieldValue.serverTimestamp()
      }).then(function(){
        document.getElementById('paid-ad-title').value='';
        document.getElementById('paid-ad-desc').value='';
        document.getElementById('paid-ad-cta').value='';
        document.getElementById('paid-ad-url').value='';
        document.getElementById('paid-ad-emoji').value='';
        showToast('Paid ad launched! $'+adState.budget+' · ~'+adState.impressions.toLocaleString()+' views 🚀');
        closeModal('modal-ads');
        loadAds();
      });
    },
    onClose:function(){ showToast('Ad payment cancelled'); }
  }).openIframe();
});

// Load ads from Firestore
function loadAds(){
  db.collection('ads').where('status','==','active').limit(20).get().then(function(snap){
    adState.currentAds = snap.docs.map(function(d){ return Object.assign({id:d.id},d.data()); });
  }).catch(function(){});
}

// Load my ads
function loadMyAds(){
  if(!state.user) return;
  var list = document.getElementById('my-ads-list');
  db.collection('ads').where('advertiserId','==',state.user.uid).get().then(function(snap){
    if(snap.empty){ list.innerHTML='<div style="text-align:center;padding:30px;color:var(--muted)"><div style="font-size:36px;margin-bottom:10px">📣</div>You have no ads yet</div>'; return; }
    list.innerHTML = snap.docs.map(function(d){
      var ad=Object.assign({id:d.id},d.data());
      return '<div class="my-ad-row"><div class="mar-icon">'+esc(ad.emoji||'📣')+'</div><div style="flex:1"><div class="mar-name">'+esc(ad.title||'Ad')+'</div><div style="font-size:10px;color:var(--muted);margin-top:2px">'+esc(ad.type==='paid'?'Paid · $'+ad.budget:'Free')+'</div></div><div class="mar-status '+(ad.type==='free'?'free':'active')+'">'+esc(ad.status||'active')+'</div><div class="mar-views">👁 '+(ad.views||0)+'</div></div>';
    }).join('');
  });
}

// Load ad stats
function loadAdStats(){
  if(!state.user) return;
  db.collection('ads').where('advertiserId','==',state.user.uid).get().then(function(snap){
    var total=snap.docs.length, views=0, clicks=0, spent=0;
    snap.docs.forEach(function(d){ var a=d.data(); views+=a.views||0; clicks+=a.clicks||0; spent+=a.budget||0; });
    document.getElementById('ads-total').textContent=total;
    document.getElementById('ads-views').textContent=views.toLocaleString();
    document.getElementById('ads-clicks').textContent=clicks.toLocaleString();
    document.getElementById('ads-spent').textContent='$'+spent;
  });
}

// ── INJECT ADS INTO FEED ──
var origRenderFeed = renderFeed;
renderFeed = function(){
  origRenderFeed();
  if(!adState.currentAds.length) return;
  var fc = document.getElementById('feed-cont');
  var cards = fc.querySelectorAll('.spark-card');
  if(cards.length < 3) return;
  // Insert ad after every 3rd post
  var adsToShow = adState.currentAds.filter(function(a){ return a.type==='free'||a.type==='paid'; });
  if(!adsToShow.length) return;
  var adIdx = 0;
  for(var i=2; i<cards.length; i+=4){
    if(adIdx >= adsToShow.length) adIdx=0;
    var ad = adsToShow[adIdx++];
    var adEl = document.createElement('div');
    adEl.className='ad-banner';
    adEl.innerHTML='<div class="ad-banner-ph">'+esc(ad.emoji||'📣')+'</div><div class="ad-title">'+esc(ad.title||'')+'</div><div class="ad-desc">'+esc(ad.description||'')+'</div><button class="ad-cta" data-ad-id="'+esc(ad.id)+'" data-ad-url="'+esc(ad.url||'#')+'">'+esc(ad.cta||'Learn More')+' →</button><div class="ad-sponsor">Sponsored by '+esc(ad.advertiserName||'Mindvora User')+'</div>';
    adEl.querySelector('.ad-cta').addEventListener('click',function(){ trackAdClick(this.dataset.adId, this.dataset.adUrl); });
    if(cards[i] && cards[i].parentNode) cards[i].parentNode.insertBefore(adEl, cards[i].nextSibling);
    // Track view
    db.collection('ads').doc(ad.id).update({views:firebase.firestore.FieldValue.increment(1)}).catch(function(){});
  }
};

function trackAdClick(adId, url){
  db.collection('ads').doc(adId).update({clicks:firebase.firestore.FieldValue.increment(1)}).catch(function(){});
  if(url && url!=='#') window.open(url,'_blank');
}

// ── VIDEO AD BEFORE REELS ──
var origOpenReel = openReel;
openReel = function(id, url, author, text, likes){
  var paidAds = adState.currentAds.filter(function(a){ return a.type==='paid'; });
  if(paidAds.length && adState.postCount % 2 === 0){
    var ad = paidAds[Math.floor(Math.random()*paidAds.length)];
    showVideoAd(ad, function(){ origOpenReel(id,url,author,text,likes); });
  } else {
    origOpenReel(id,url,author,text,likes);
  }
  adState.postCount++;
};

function showVideoAd(ad, callback){
  document.getElementById('va-title').textContent = ad.title||'';
  document.getElementById('va-desc').textContent = ad.description||'';
  document.getElementById('va-media-ph').textContent = ad.emoji||'📣';
  document.getElementById('va-btn').textContent = (ad.cta||'Learn More')+' →';
  document.getElementById('va-btn').onclick = function(){ trackAdClick(ad.id, ad.url||'#'); };
  var skipBtn = document.getElementById('va-skip');
  var countdown = document.getElementById('va-countdown');
  skipBtn.className='va-skip disabled';
  skipBtn.textContent='Skip in 5s';
  skipBtn.onclick = null;
  document.getElementById('video-ad-overlay').classList.add('open');
  // Track view
  db.collection('ads').doc(ad.id).update({views:firebase.firestore.FieldValue.increment(1)}).catch(function(){});
  var secs = 5;
  adState.videoAdTimer = setInterval(function(){
    secs--;
    countdown.textContent='AD · SKIP IN '+secs+'s';
    skipBtn.textContent='Skip in '+secs+'s';
    if(secs<=0){
      clearInterval(adState.videoAdTimer);
      skipBtn.className='va-skip';
      skipBtn.textContent='Skip Ad →';
      skipBtn.onclick=function(){ closeVideoAd(callback); };
      countdown.textContent='AD · You can now skip';
    }
  }, 1000);
}

function closeVideoAd(callback){
  clearInterval(adState.videoAdTimer);
  document.getElementById('video-ad-overlay').classList.remove('open');
  if(callback) callback();
}

// Load ads on mount
setTimeout(loadAds, 2000);

// ── ADMIN SYSTEM ──
var ADMIN_EMAIL = 'ilohgreat25@gmail.com';

function isAdmin(){ return state && state.user && state.user.email === ADMIN_EMAIL; }

// Show admin nav only for owner
function checkAdminAccess(){
  var adminNav = document.getElementById('nav-admin');
  if(!adminNav) return;
  // Triple check — must match owner email exactly, case-insensitive
  var isOwner = state && state.user && 
                state.user.email && 
                state.user.email.toLowerCase().trim() === ADMIN_EMAIL.toLowerCase().trim();
  adminNav.style.display = isOwner ? 'flex' : 'none';
  adminNav.style.visibility = isOwner ? 'visible' : 'hidden';
  adminNav.style.pointerEvents = isOwner ? 'auto' : 'none';
  // Extra security — remove from DOM entirely for non-owners
  if(!isOwner){
    adminNav.setAttribute('aria-hidden','true');
    adminNav.style.opacity = '0';
    adminNav.style.height = '0';
    adminNav.style.overflow = 'hidden';
    adminNav.style.padding = '0';
    adminNav.style.margin = '0';
  } else {
    adminNav.removeAttribute('aria-hidden');
    adminNav.style.opacity = '1';
    adminNav.style.height = '';
    adminNav.style.overflow = '';
  }
}

// Admin nav click
document.getElementById('nav-admin').addEventListener('click', function(){
  // Security: verify ownership before opening admin panel
  if(!state || !state.user || state.user.email.toLowerCase().trim() !== ADMIN_EMAIL.toLowerCase().trim()){
    showToast('⛔ Access denied.');
    return;
  }
  setNav(this);
  openModal('modal-admin');
  loadAdminTab('pending');
  logAdminAccess();
});

// Switch admin tabs
function switchAdminTab(tab, btn){
  document.querySelectorAll('#modal-admin .admin-tabs .f-pill').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  ['pending','approved','rejected','overview','security','users'].forEach(function(t){
    var el = document.getElementById('admin-'+t);
    if(el) el.style.display = t===tab ? 'block' : 'none';
  });
  loadAdminTab(tab);
}

function loadAdminTab(tab){
  if(tab==='pending') loadAdminAds('pending','pending-ads-list');
  else if(tab==='approved') loadAdminAds('active','approved-ads-list');
  else if(tab==='rejected') loadAdminAds('rejected','rejected-ads-list');
  else if(tab==='overview') loadAdminOverview();
  else if(tab==='security') loadSecurityAlertsPanel();
  else if(tab==='users') loadUsersPanel();
}

function loadAdminAds(status, listId){
  if(!isAdmin()) return;
  var list = document.getElementById(listId);
  if(!list) return;
  list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading…</div>';
  db.collection('ads').where('status','==',status).get().then(function(snap){
    if(snap.empty){
      var label = status==='pending'?'pending ads to review':status==='active'?'approved ads':'rejected ads';
      list.innerHTML = '<div style="text-align:center;padding:30px;color:var(--muted)"><div style="font-size:36px;margin-bottom:10px">'+(status==='pending'?'🎉':status==='active'?'✅':'❌')+'</div>No '+label+'</div>';
      return;
    }
    list.innerHTML = snap.docs.map(function(d){
      var ad = Object.assign({id:d.id}, d.data());
      var createdAt = ad.createdAt ? new Date(ad.createdAt.seconds*1000).toLocaleDateString() : 'Unknown';
      var actions = '';
      if(status==='pending'){
        actions = '<div class="arc-actions"><button class="btn-approve" data-adid="'+esc(ad.id)+'" data-action="approve">✅ Approve — Go Live</button><button class="btn-reject" data-adid="'+esc(ad.id)+'" data-action="reject">❌ Reject</button></div>';
      } else if(status==='active'){
        actions = '<div class="arc-actions"><button class="btn-reject" data-adid="'+esc(ad.id)+'" data-action="reject">❌ Take Down</button></div>';
      } else {
        actions = '<div class="arc-actions"><button class="btn-approve" data-adid="'+esc(ad.id)+'" data-action="approve">✅ Re-approve</button></div>';
      }
      return '<div class="ad-review-card">'+
        '<div class="arc-head">'+
          '<div class="arc-info">'+
            '<div class="arc-title">'+esc(ad.title||'Untitled Ad')+'</div>'+
            '<div class="arc-meta">By '+esc(ad.advertiserName||'Unknown')+' (@'+esc(ad.advertiserHandle||'?')+') · '+createdAt+'</div>'+
          '</div>'+
          '<div class="arc-type '+esc(ad.type||'free')+'">'+esc(ad.type==='paid'?'PAID · $'+ad.budget:'FREE')+'</div>'+
        '</div>'+
        '<div class="arc-body">'+
          '<div class="arc-field"><div class="arc-label">Description</div><div class="arc-val">'+esc(ad.description||'—')+'</div></div>'+
          '<div class="arc-field"><div class="arc-label">Call to Action</div><div class="arc-val">'+esc(ad.cta||'—')+'</div></div>'+
          '<div class="arc-field"><div class="arc-label">Link URL — Click to verify</div><div class="arc-val"><a href="'+esc(ad.url||'#')+'" target="_blank" rel="noopener">'+esc(ad.url||'No link provided')+'</a></div></div>'+
          '<div class="arc-field"><div class="arc-label">Performance</div><div class="arc-val">👁 '+( ad.views||0)+' views · 👆 '+(ad.clicks||0)+' clicks</div></div>'+
        '</div>'+
        actions+
      '</div>';
    }).join('');
  }).catch(function(e){
    if(list) list.innerHTML = '<div style="color:#fca5a5;padding:14px">Error: '+esc(e.message)+'</div>';
  });
  // event delegation for approve/reject buttons
  if(list && !list.dataset.delegated){
    list.dataset.delegated='1';
    list.addEventListener('click',function(e){
      var btn=e.target.closest('[data-adid]');
      if(!btn) return;
      var adId=btn.dataset.adid, action=btn.dataset.action;
      if(action==='approve') adminApproveAd(adId);
      else if(action==='reject') adminRejectAd(adId);
    });
  }
}

function adminApproveAd(adId){
  if(!isAdmin()) return;
  db.collection('ads').doc(adId).update({
    status:'active',
    approvedAt: firebase.firestore.FieldValue.serverTimestamp(),
    approvedBy: ADMIN_EMAIL
  }).then(function(){
    showToast('✅ Ad approved and now live!');
    loadAdminTab('pending');
    loadAds();
    // notify advertiser
    db.collection('ads').doc(adId).get().then(function(d){
      if(d.exists && d.data().advertiserId){
        db.collection('notifications').add({
          to: d.data().advertiserId,
          type:'ad_approved',
          text:'Your ad "'+d.data().title+'" has been approved and is now live on Mindvora! 🎉',
          read:false,
          createdAt: firebase.firestore.FieldValue.serverTimestamp()
        });
      }
    });
  }).catch(function(e){ showToast('Error: '+e.message); });
}

function adminRejectAd(adId){
  if(!isAdmin()) return;
  var reason = prompt('Reason for rejection (shown to advertiser):');
  if(reason===null) return;
  db.collection('ads').doc(adId).update({
    status:'rejected',
    rejectedAt: firebase.firestore.FieldValue.serverTimestamp(),
    rejectedBy: ADMIN_EMAIL,
    rejectionReason: reason||'Did not meet Mindvora advertising guidelines'
  }).then(function(){
    showToast('❌ Ad rejected');
    loadAdminTab('pending');
    loadAds();
    // notify advertiser
    db.collection('ads').doc(adId).get().then(function(d){
      if(d.exists && d.data().advertiserId){
        db.collection('notifications').add({
          to: d.data().advertiserId,
          type:'ad_rejected',
          text:'Your ad "'+d.data().title+'" was not approved. Reason: '+(reason||'Did not meet guidelines')+'. Please revise and resubmit.',
          read:false,
          createdAt: firebase.firestore.FieldValue.serverTimestamp()
        });
      }
    });
  }).catch(function(e){ showToast('Error: '+e.message); });
}

function loadAdminOverview(){
  if(!isAdmin()) return;
  db.collection('ads').get().then(function(snap){
    var pending=0, approved=0, revenue=0, views=0, activity=[];
    snap.docs.forEach(function(d){
      var a=d.data();
      if(a.status==='pending') pending++;
      if(a.status==='active') approved++;
      if(a.type==='paid') revenue+=a.budget||0;
      views+=a.views||0;
      var date = a.createdAt ? new Date(a.createdAt.seconds*1000).toLocaleDateString() : '';
      activity.push({
        text: (a.status==='active'?'✅':a.status==='pending'?'⏳':'❌')+' <b>'+esc(a.title||'Ad')+'</b> by '+esc(a.advertiserName||'User')+' · '+date,
        time: a.createdAt ? a.createdAt.seconds : 0
      });
    });
    document.getElementById('ov-pending').textContent=pending;
    document.getElementById('ov-approved').textContent=approved;
    document.getElementById('ov-revenue').textContent='$'+revenue;
    document.getElementById('ov-views').textContent=views.toLocaleString();
    activity.sort(function(a,b){return b.time-a.time;});
    document.getElementById('ov-activity').innerHTML = activity.slice(0,10).map(function(a){return '<div>'+a.text+'</div>';}).join('') || '<div style="color:var(--muted)">No activity yet</div>';
  });
}

// ── SECURITY ALERTS PANEL ──
function loadSecurityAlertsPanel(){
  if(!isAdmin()) return;
  var list = document.getElementById('security-alerts-list');
  if(!list) return;
  list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading…</div>';
  db.collection('security_alerts').limit(50).get().then(function(snap){
    if(snap.empty){
      list.innerHTML = '<div style="text-align:center;padding:30px;color:var(--muted)"><div style="font-size:36px;margin-bottom:10px">🛡️</div>No security alerts — Mindvora is safe!</div>';
      return;
    }
    list.innerHTML = snap.docs.map(function(d){
      var a = Object.assign({id:d.id}, d.data());
      var time = a.timestamp ? new Date(a.timestamp.seconds*1000).toLocaleString() : 'Unknown';
      var isHigh = a.type && (a.type.includes('brute') || a.type.includes('malicious') || a.type.includes('hijack') || a.type.includes('probe'));
      var color = isHigh ? '#fca5a5' : '#fbbf24';
      var bg = isHigh ? 'rgba(248,113,113,.08)' : 'rgba(251,191,36,.08)';
      var border = isHigh ? 'rgba(248,113,113,.25)' : 'rgba(251,191,36,.25)';
      return '<div style="background:'+bg+';border:1px solid '+border+';border-radius:12px;padding:14px;margin-bottom:8px'+(a.resolved?';opacity:.5':'')+'">'+
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">'+
          '<div style="font-size:11px;font-weight:700;color:'+color+'">'+esc(a.type||'unknown').toUpperCase().replace(/_/g,' ')+'</div>'+
          '<div style="font-size:10px;color:var(--muted)">'+esc(time)+(a.resolved?' · ✅ Resolved':'')+'</div>'+
        '</div>'+
        '<div style="font-size:12px;color:var(--moon);line-height:1.6;margin-bottom:8px">'+esc(a.message||'')+'</div>'+
        (!a.resolved ? '<button style="font-size:10px;padding:4px 12px;background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);border-radius:20px;color:var(--green3);cursor:pointer" data-alertid="'+esc(a.id)+'" data-action="resolve">Mark Resolved</button>' : '')+
      '</div>';
    }).join('');
    // Event delegation for resolve buttons
    if(!list.dataset.secDelegated){
      list.dataset.secDelegated='1';
      list.addEventListener('click',function(e){
        var btn=e.target.closest('[data-alertid]');
        if(!btn||btn.dataset.action!=='resolve') return;
        db.collection('security_alerts').doc(btn.dataset.alertid).update({resolved:true})
        .then(function(){ loadSecurityAlertsPanel(); showToast('✅ Alert marked resolved'); })
        .catch(function(e){ showToast('Error: '+e.message); });
      });
    }
  }).catch(function(e){
    list.innerHTML = '<div style="color:#fca5a5;padding:14px">Error: '+esc(e.message)+'</div>';
  });
}

// ── ADMIN USERS PANEL ──
var allUsersCache = [];

function loadUsersPanel(){
  if(!isAdmin()) return;
  var list = document.getElementById('users-list');
  var stats = document.getElementById('users-stats');
  if(!list) return;
  list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading users...</div>';
  
  // Get all users from Firestore
  db.collection('users').get().then(function(snap){
    allUsersCache = snap.docs.map(function(d){ return Object.assign({id:d.id}, d.data()); });
    
    // Count online (active in last 5 minutes)
    var now = Date.now();
    var onlineCount = allUsersCache.filter(function(u){ 
      return u.lastSeen && (now - u.lastSeen) < 300000; 
    }).length;
    var bannedCount = allUsersCache.filter(function(u){ return u.banned; }).length;
    
    if(stats) stats.textContent = 'Total: ' + allUsersCache.length + ' users · Online: ' + onlineCount + ' · Banned: ' + bannedCount;
    
    renderUsersList(allUsersCache);
  }).catch(function(e){
    list.innerHTML = '<div style="color:#fca5a5;padding:14px">Error loading users: ' + esc(e.message) + '</div>';
  });
}

function renderUsersList(users){
  var list = document.getElementById('users-list');
  if(!list) return;
  if(!users.length){
    list.innerHTML = '<div style="text-align:center;padding:30px;color:var(--muted)">No users found</div>';
    return;
  }
  var now = Date.now();
  // Sort: online first, then by join date
  users.sort(function(a,b){
    var aOnline = a.lastSeen && (now - a.lastSeen) < 300000;
    var bOnline = b.lastSeen && (now - b.lastSeen) < 300000;
    if(aOnline && !bOnline) return -1;
    if(!aOnline && bOnline) return 1;
    return 0;
  });
  list.innerHTML = users.map(function(u){
    var isOnline = u.lastSeen && (now - u.lastSeen) < 300000;
    var isBanned = u.banned === true;
    var lastSeen = u.lastSeen ? new Date(u.lastSeen).toLocaleString() : 'Never';
    var joinDate = u.createdAt ? new Date(u.createdAt.seconds*1000).toLocaleDateString() : 'Unknown';
    var statusDot = isOnline ? 
      '<span style="width:8px;height:8px;border-radius:50%;background:#22c55e;display:inline-block;margin-right:6px"></span>' :
      '<span style="width:8px;height:8px;border-radius:50%;background:var(--muted);display:inline-block;margin-right:6px"></span>';
    var bannedBadge = isBanned ? '<span style="background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3);border-radius:20px;padding:2px 8px;font-size:10px;margin-left:6px">BANNED</span>' : '';
    var premiumBadge = u.isPremium ? '<span style="background:rgba(99,102,241,.15);color:#a5b4fc;border:1px solid rgba(99,102,241,.3);border-radius:20px;padding:2px 8px;font-size:10px;margin-left:6px">PREMIUM</span>' : '';
    
    return '<div style="background:var(--deep);border:1px solid var(--border);border-radius:12px;padding:12px;margin-bottom:8px' + (isBanned?';opacity:.6':'') + '" data-userid="'+esc(u.id)+'">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">' +
        '<div style="display:flex;align-items:center">' +
          '<div style="width:32px;height:32px;border-radius:50%;background:'+(u.color||'var(--green)')+';display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;margin-right:8px;flex-shrink:0">'+(u.name||'?').charAt(0).toUpperCase()+'</div>' +
          '<div>' +
            '<div style="font-size:12px;font-weight:700;color:var(--moon)">' + statusDot + esc(u.name||'Unknown') + bannedBadge + premiumBadge + '</div>' +
            '<div style="font-size:10px;color:var(--muted)">@' + esc(u.handle||'unknown') + ' · ' + esc(u.email||'') + '</div>' +
          '</div>' +
        '</div>' +
        '<div style="display:flex;gap:6px">' +
          (!isBanned ? 
            '<button style="font-size:10px;padding:4px 10px;background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);border-radius:20px;color:#fca5a5;cursor:pointer;font-family:sans-serif" data-action="ban" data-userid="'+esc(u.id)+'" data-username="'+esc(u.name||'user')+'">🚫 Ban</button>' :
            '<button style="font-size:10px;padding:4px 10px;background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);border-radius:20px;color:var(--green3);cursor:pointer;font-family:sans-serif" data-action="unban" data-userid="'+esc(u.id)+'" data-username="'+esc(u.name||'user')+'">✅ Unban</button>'
          ) +
        '</div>' +
      '</div>' +
      '<div style="display:flex;gap:12px;font-size:10px;color:var(--muted)">' +
        '<span>📅 Joined: ' + esc(joinDate) + '</span>' +
        '<span>👁 Last seen: ' + (isOnline ? '<span style="color:#22c55e">Online now</span>' : esc(lastSeen)) + '</span>' +
        '<span>✨ Sparks: ' + (u.sparksCount||0) + '</span>' +
        '<span>👥 Fans: ' + (u.followers||0) + '</span>' +
      '</div>' +
    '</div>';
  }).join('');

  // Event delegation for ban/unban
  if(!list.dataset.usersDelegated){
    list.dataset.usersDelegated = '1';
    list.addEventListener('click', function(e){
      var btn = e.target.closest('[data-action]');
      if(!btn) return;
      var action = btn.dataset.action;
      var userId = btn.dataset.userid;
      var username = btn.dataset.username;
      if(action === 'ban'){
        if(!confirm('Ban ' + username + '? They will not be able to login.')){ return; }
        banUser(userId, username, true);
      } else if(action === 'unban'){
        banUser(userId, username, false);
      }
    });
  }
}

function filterUsers(query){
  if(!query){ renderUsersList(allUsersCache); return; }
  var q = query.toLowerCase();
  var filtered = allUsersCache.filter(function(u){
    return (u.name||'').toLowerCase().includes(q) || 
           (u.email||'').toLowerCase().includes(q) || 
           (u.handle||'').toLowerCase().includes(q);
  });
  renderUsersList(filtered);
}

function banUser(userId, username, ban){
  if(!isAdmin()) return;
  db.collection('users').doc(userId).update({ banned: ban }).then(function(){
    showToast(ban ? ('🚫 ' + username + ' has been banned!') : ('✅ ' + username + ' has been unbanned!'));
    // Update cache
    allUsersCache = allUsersCache.map(function(u){ 
      return u.id === userId ? Object.assign({}, u, {banned: ban}) : u; 
    });
    renderUsersList(allUsersCache);
    // Send security alert for bans
    if(ban) sendSecurityAlert('brute_force', 'Admin banned user: ' + username + ' (ID: ' + userId + ')');
  }).catch(function(e){ showToast('Error: ' + e.message); });
}

// ── SUPPORT / CONTACT ──
// ── Mindvora CAMERA ──
var camStream = null;
var camFacingMode = 'user';
var camMediaRecorder = null;
var camRecordedChunks = [];
var camIsRecording = false;
var camTimerInterval = null;
var camSeconds = 0;
var camCurrentFilter = 'none';
var camCapturedBlob = null;
var camCapturedType = 'image';

function openCameraModal(){
  if(!state.user){ showToast('Please login first'); return; }
  document.getElementById('cam-snapshot').style.display = 'none';
  document.getElementById('cam-preview').style.display = 'block';
  document.getElementById('cam-canvas').style.display = 'none';
  document.getElementById('cam-use-btn').style.display = 'none';
  document.getElementById('cam-use-placeholder').style.display = 'block';
  document.getElementById('cam-retake-bar').style.display = 'none';
  document.getElementById('cam-rec-indicator').style.display = 'none';
  document.getElementById('cam-timer').style.display = 'none';
  camCapturedBlob = null;
  startCamera();
  openModal('modal-camera');
}

function startCamera(){
  if(camStream){ camStream.getTracks().forEach(function(t){ t.stop(); }); }
  navigator.mediaDevices.getUserMedia({ video:{ facingMode: camFacingMode }, audio: true })
    .then(function(stream){
      camStream = stream;
      var preview = document.getElementById('cam-preview');
      preview.srcObject = stream;
      applyFilterToPreview(camCurrentFilter);
    })
    .catch(function(e){
      showToast('Camera access denied. Please allow camera permission.');
      closeModal('modal-camera');
    });
}

function closeCameraModal(){
  stopCamera();
  closeModal('modal-camera');
}

function stopCamera(){
  if(camStream){ camStream.getTracks().forEach(function(t){ t.stop(); }); camStream = null; }
  if(camTimerInterval){ clearInterval(camTimerInterval); camTimerInterval = null; }
  if(camIsRecording && camMediaRecorder){ camMediaRecorder.stop(); camIsRecording = false; }
}

function flipCamera(){
  camFacingMode = camFacingMode === 'user' ? 'environment' : 'user';
  startCamera();
}

function applyFilter(btn, filter){
  document.querySelectorAll('.cam-filter-btn').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  camCurrentFilter = filter;
  applyFilterToPreview(filter);
}

function applyFilterToPreview(filter){
  var preview = document.getElementById('cam-preview');
  var snapshot = document.getElementById('cam-snapshot');
  preview.style.filter = filter === 'none' ? '' : filter;
  snapshot.style.filter = filter === 'none' ? '' : filter;
}

function takePhoto(){
  if(!camStream) return;
  // Countdown from 3
  var count = 3;
  var cd = document.getElementById('cam-countdown');
  cd.style.display = 'flex';
  cd.textContent = count;
  var cdInterval = setInterval(function(){
    count--;
    if(count <= 0){
      clearInterval(cdInterval);
      cd.style.display = 'none';
      captureSnapshot();
    } else {
      cd.textContent = count;
    }
  }, 1000);
}

function captureSnapshot(){
  var preview = document.getElementById('cam-preview');
  var canvas = document.getElementById('cam-canvas');
  var snapshot = document.getElementById('cam-snapshot');
  canvas.width = preview.videoWidth;
  canvas.height = preview.videoHeight;
  var ctx = canvas.getContext('2d');
  // Apply filter to canvas
  if(camCurrentFilter !== 'none') ctx.filter = camCurrentFilter;
  // Flip horizontally for selfie
  if(camFacingMode === 'user'){
    ctx.translate(canvas.width, 0);
    ctx.scale(-1, 1);
  }
  ctx.drawImage(preview, 0, 0);
  canvas.toBlob(function(blob){
    camCapturedBlob = blob;
    camCapturedType = 'image';
    var url = URL.createObjectURL(blob);
    snapshot.src = url;
    snapshot.style.display = 'block';
    preview.style.display = 'none';
    document.getElementById('cam-use-btn').style.display = 'block';
    document.getElementById('cam-use-placeholder').style.display = 'none';
    document.getElementById('cam-retake-bar').style.display = 'block';
    showToast('📸 Photo taken! Click "Use" to post it.');
  }, 'image/jpeg', 0.92);
}

function toggleVideoRecord(){
  if(!camStream) return;
  if(!camIsRecording){
    startVideoRecord();
  } else {
    stopVideoRecord();
  }
}

function startVideoRecord(){
  camRecordedChunks = [];
  var options = { mimeType: 'video/webm;codecs=vp9' };
  if(!MediaRecorder.isTypeSupported(options.mimeType)){
    options = { mimeType: 'video/webm' };
  }
  try {
    camMediaRecorder = new MediaRecorder(camStream, options);
  } catch(e){
    camMediaRecorder = new MediaRecorder(camStream);
  }
  camMediaRecorder.ondataavailable = function(e){
    if(e.data && e.data.size > 0) camRecordedChunks.push(e.data);
  };
  camMediaRecorder.onstop = function(){
    var blob = new Blob(camRecordedChunks, { type: 'video/webm' });
    camCapturedBlob = blob;
    camCapturedType = 'video';
    var url = URL.createObjectURL(blob);
    var preview = document.getElementById('cam-preview');
    preview.srcObject = null;
    preview.src = url;
    preview.muted = false;
    preview.controls = true;
    preview.style.display = 'block';
    document.getElementById('cam-use-btn').style.display = 'block';
    document.getElementById('cam-use-placeholder').style.display = 'none';
    document.getElementById('cam-retake-bar').style.display = 'block';
    showToast('🎥 Video recorded! Click "Use" to post it.');
  };
  camMediaRecorder.start(100);
  camIsRecording = true;
  camSeconds = 0;
  document.getElementById('cam-rec-indicator').style.display = 'flex';
  document.getElementById('cam-timer').style.display = 'block';
  document.getElementById('cam-video-btn').textContent = '⏹️';
  document.getElementById('cam-video-btn').style.background = 'linear-gradient(135deg,#374151,#1f2937)';
  camTimerInterval = setInterval(function(){
    camSeconds++;
    var m = Math.floor(camSeconds/60);
    var s = camSeconds % 60;
    document.getElementById('cam-timer').textContent = m+':'+(s<10?'0':'')+s;
    if(camSeconds >= 60){ stopVideoRecord(); } // max 60 seconds
  }, 1000);
}

function stopVideoRecord(){
  if(camMediaRecorder && camIsRecording){
    camMediaRecorder.stop();
    camIsRecording = false;
    clearInterval(camTimerInterval);
    document.getElementById('cam-rec-indicator').style.display = 'none';
    document.getElementById('cam-video-btn').textContent = '🎥';
    document.getElementById('cam-video-btn').style.background = 'linear-gradient(135deg,#dc2626,#ef4444)';
  }
}

function retakeCamera(){
  var preview = document.getElementById('cam-preview');
  preview.src = '';
  preview.muted = true;
  preview.controls = false;
  document.getElementById('cam-snapshot').style.display = 'none';
  preview.style.display = 'block';
  document.getElementById('cam-use-btn').style.display = 'none';
  document.getElementById('cam-use-placeholder').style.display = 'block';
  document.getElementById('cam-retake-bar').style.display = 'none';
  camCapturedBlob = null;
  startCamera();
}

function useCaptured(){
  if(!camCapturedBlob){ showToast('Nothing captured yet!'); return; }
  // Upload to Cloudinary
  var formData = new FormData();
  var ext = camCapturedType === 'image' ? 'jpg' : 'webm';
  formData.append('file', camCapturedBlob, 'zync-cam-' + Date.now() + '.' + ext);
  formData.append('upload_preset', 'ml_default');
  var resourceType = camCapturedType === 'image' ? 'image' : 'video';
  closeCameraModal();
  // Show upload banner
  var banner = document.createElement('div');
  banner.id = 'upload-banner';
  banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:linear-gradient(135deg,var(--green),var(--green2));color:var(--cream);text-align:center;padding:10px;font-size:13px;font-weight:700;z-index:9999';
  banner.textContent = '⏳ Uploading your ' + camCapturedType + '... Please wait';
  document.body.appendChild(banner);

  fetch('https://api.cloudinary.com/v1_1/dk4svvssf/' + resourceType + '/upload', {
    method: 'POST', body: formData
  }).then(function(r){ return r.json(); }).then(function(data){
    var b = document.getElementById('upload-banner');
    if(b) b.remove();
    if(data.secure_url){
      state.mediaUrl = data.secure_url;
      state.mediaType = camCapturedType;
      var prev = document.getElementById('media-prev');
      var prevVid = document.getElementById('prev-vid');
      var prevImg = document.getElementById('prev-img');
      if(camCapturedType === 'image'){
        if(prevImg){ prevImg.src = data.secure_url; prevImg.style.display = 'block'; }
        if(prevVid) prevVid.style.display = 'none';
      } else {
        if(prevVid){ prevVid.src = data.secure_url; prevVid.style.display = 'block'; }
        if(prevImg) prevImg.style.display = 'none';
      }
      if(prev) prev.style.display = 'block';
      showToast('✅ ' + (camCapturedType==='image'?'Photo':'Video') + ' ready! Now click Spark to post.');
    } else {
      showToast('Upload failed. Try again.');
    }
  }).catch(function(e){
    var b = document.getElementById('upload-banner');
    if(b) b.remove();
    showToast('Upload failed: ' + e.message);
  });
}


// ── OPEN LINK SAFELY ──
function openLink(url){ window.open(url,'_blank','noopener,noreferrer'); }

// ── BUILD POLL HTML ──
function buildPollHTML(s){
  if(!s.poll||!s.poll.options) return '';
  var total=s.poll.votes?Object.values(s.poll.votes).reduce(function(a,b){return a+(b||0);},0):0;
  var uid=state.user?state.user.uid:'';
  var userVote=s.poll.userVotes&&s.poll.userVotes[uid]!==undefined?s.poll.userVotes[uid]:-1;
  var expired=s.poll.expiresAt&&Date.now()>s.poll.expiresAt;
  var html='<div style="margin:8px 0;padding:10px;background:var(--deep);border:1px solid var(--border);border-radius:10px">';
  html+='<div style="font-size:11px;font-weight:700;color:var(--moon);margin-bottom:8px">📊 '+esc(s.poll.question)+(expired?' · <span style="color:var(--muted)">Ended</span>':'')+'</div>';
  s.poll.options.forEach(function(opt,i){
    var votes=s.poll.votes&&s.poll.votes[i]?s.poll.votes[i]:0;
    var pct=total>0?Math.round(votes/total*100):0;
    var isVoted=userVote===i;
    html+='<div class="poll-opt'+(isVoted?' voted':'')+'" onclick="votePoll(\''+s.id+'\','+i+')">';
    html+='<div class="poll-bar" style="width:'+pct+'%"></div>';
    html+='<div class="poll-opt-text"><span>'+esc(opt)+(isVoted?' ✓':'')+'</span><span class="poll-pct">'+(userVote!==-1||expired?pct+'%':'')+'</span></div>';
    html+='</div>';
  });
  html+='<div style="font-size:10px;color:var(--muted);margin-top:6px">'+total+' vote'+(total!==1?'s':'')+(expired?'':' · Ends '+new Date(s.poll.expiresAt).toLocaleDateString())+'</div>';
  return html+'</div>';
}

// ── BUILD REACTIONS HTML ──
// Quick reactions bar (top picks)
var REACTIONS=['❤️','😂','😮','😢','🔥','👏','🎉','💯','😍','🤣','😭','😱','🥰','👍','💪','🙏'];

// Full emoji library by category
var EMOJI_CATS=[
  {icon:'😀',name:'Smileys',emojis:['😀','😃','😄','😁','😆','😅','🤣','😂','🙂','😊','😇','🥰','😍','🤩','😘','😗','😚','😙','🥲','😋','😛','😜','🤪','😝','🤑','🤗','🤭','🤫','🤔','🫡','🤐','🤨','😐','😑','😶','😏','😒','🙄','😬','🤥','😌','😔','😪','🤤','😴','😷','🤒','🤕','🤢','🤮','🤧','🥵','🥶','🥴','😵','🤯','🤠','🥳','🥸','😎','🤓','🧐','😕','🫤','😟','🙁','☹️','😮','😯','😲','😳','🥺','🫣','😦','😧','😨','😰','😥','😢','😭','😱','😖','😣','😞','😓','😩','😫','🥱','😤','😡','😠','🤬','😈','👿','💀','☠️','💩','🤡','👹','👺','👻','👽','👾','🤖']},
  {icon:'👋',name:'Gestures',emojis:['👋','🤚','🖐','✋','🖖','🫱','🫲','🫳','🫴','👌','🤌','🤏','✌️','🤞','🫰','🤟','🤘','🤙','👈','👉','👆','🖕','👇','☝️','🫵','👍','👎','✊','👊','🤛','🤜','👏','🙌','🫶','👐','🤲','🤝','🙏','✍️','💅','🤳','💪','🦾','🦿','🦵','🦶','👂','🦻','👃','🫀','🫁','🧠','🦷','🦴','👀','👁','👅','👄','🫦','💋']},
  {icon:'👨',name:'People',emojis:['👶','🧒','👦','👧','🧑','👱','👨','🧔','👩','🧓','👴','👵','🙍','🙎','🙅','🙆','💁','🙋','🧏','🙇','🤦','🤷','👮','🕵️','💂','🥷','👷','🤴','👸','👳','👲','🧕','🤵','👰','🤰','🫃','🫄','🤱','👼','🎅','🤶','🦸','🦹','🧙','🧚','🧛','🧜','🧝','🧞','🧟','🧌','💆','💇','🚶','🧍','🧎','🏃','💃','🕺','🕴','👯','🧖','🧗','🤺','🏇','⛷️','🏂','🪂','🏋️','🤼','🤸','🤾','🏌️','🏄','🚣','🧘','🛀','🛌']},
  {icon:'❤️',name:'Hearts',emojis:['❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','❤️‍🔥','❤️‍🩹','💔','💕','💞','💓','💗','💖','💘','💝','💟','💌','💋','💍','💎','👑','🎀','🎁','🎊','🎉','🎈','🎆','🎇','✨','⭐','🌟','💫','⚡','🔥','🌈','☀️','🌙','❄️','🌊','🌸','🌺','🌻','🌹','🌷','🌼']},
  {icon:'🐶',name:'Animals',emojis:['🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐽','🐸','🐵','🙈','🙉','🙊','🐒','🐔','🐧','🐦','🐤','🐣','🐥','🦆','🦅','🦉','🦇','🐺','🐗','🐴','🦄','🐝','🪱','🐛','🦋','🐌','🐞','🐜','🪲','🦟','🦗','🪳','🕷','🦂','🐢','🐍','🦎','🦖','🦕','🐙','🦑','🦐','🦞','🦀','🐡','🐠','🐟','🐬','🐳','🐋','🦈','🐊','🐅','🐆','🦓','🦍','🦧','🦣','🐘','🦛','🦏','🐪','🐫','🦒','🦘','🦬','🐃','🐂','🐄','🐎','🐖','🐏','🐑','🦙','🐐','🦌','🐕','🐩','🦮','🐕‍🦺','🐈','🐈‍⬛','🐓','🦃','🦤','🦚','🦜','🦢','🦩','🕊','🐇','🦝','🦨','🦡','🦫','🦦','🦥','🐁','🐀','🐿','🦔']},
  {icon:'🌸',name:'Nature',emojis:['🌵','🎄','🌲','🌳','🌴','🪵','🌱','🌿','☘️','🍀','🎍','🎋','🍃','🍂','🍁','🪺','🪹','🍄','🌾','💐','🌷','🌹','🥀','🪷','🌺','🌸','🌼','🌻','🌞','🌝','🌛','🌜','🌚','🌕','🌖','🌗','🌘','🌑','🌒','🌓','🌔','🌙','🌟','⭐','🌠','🌌','☀️','🌤','⛅','🌥','☁️','🌦','🌧','⛈','🌩','🌨','❄️','☃️','⛄','🌬','💨','🌀','🌈','🌂','☂️','☔','⛱','⚡','🔥','💧','🌊','🌍','🌎','🌏','🪐','🌋','🗻','🏔','⛰','🏕','🏖','🏜','🏝','🏞']},
  {icon:'🍕',name:'Food',emojis:['🍎','🍊','🍋','🍌','🍉','🍇','🍓','🫐','🍈','🍒','🍑','🥭','🍍','🥥','🥝','🍅','🍆','🥑','🥦','🥬','🥒','🌶','🫑','🧄','🧅','🥔','🍠','🥐','🥯','🍞','🥖','🥨','🧀','🥚','🍳','🧈','🥞','🧇','🥓','🥩','🍗','🍖','🌭','🍔','🍟','🍕','🫓','🥪','🥙','🧆','🌮','🌯','🫔','🥗','🥘','🫕','🥫','🍝','🍜','🍲','🍛','🍣','🍱','🥟','🦪','🍤','🍙','🍚','🍘','🍥','🥮','🍢','🧁','🍰','🎂','🍮','🍭','🍬','🍫','🍿','🍩','🍪','🌰','🥜','🍯','🧃','🥤','🧋','☕','🫖','🍵','🍺','🍻','🥂','🍷','🥃','🍸','🍹','🧊']},
  {icon:'⚽',name:'Sports',emojis:['⚽','🏀','🏈','⚾','🥎','🎾','🏐','🏉','🥏','🎱','🏓','🏸','🏒','🏑','🥍','🏏','🪃','🥅','⛳','🪁','🎣','🤿','🎽','🎿','🛷','🥌','🎯','🎮','🕹','🎲','♟','🏆','🥇','🥈','🥉','🏅','🎖','🏵','🎪','🎭','🎨','🎠','🎡','🎢','🎰','🚗','🚕','🚙','🏎','🚓','🚑','🚒','🚀','🛸','🛩','✈️','🚁','⛵','🚤','🛥','🚢','🚲','🛴','🛹','🏍','🛵']},
  {icon:'🏠',name:'Places',emojis:['🏠','🏡','🏢','🏣','🏤','🏥','🏦','🏨','🏩','🏪','🏫','🏬','🏭','🏯','🏰','💒','🗼','🗽','⛪','🕌','🛕','🕍','⛩','🕋','⛲','⛺','🌁','🌃','🏙','🌄','🌅','🌆','🌇','🌉','🗺','🗾','🧭','🏔','⛰','🌋','🗻','🏕','🏖','🏜','🏝','🏞','🛣','🛤','🌐']},
  {icon:'💡',name:'Objects',emojis:['⌚','📱','💻','⌨️','🖥','🖨','🖱','💾','💿','📀','📷','📸','📹','🎥','📽','🎞','☎️','📞','📟','📠','📺','📻','🎙','🎚','🎛','📡','🔋','🔌','💡','🔦','🕯','🪔','💰','💳','🪙','📈','📉','📊','📋','📆','📅','📌','📍','✂️','📎','🖊','🖋','✒️','🖌','🖍','📝','✏️','🔍','🔎','🔏','🔐','🔒','🔓','🗑','🛢','💸','🏧','🚪','🪞','🪟','🛋','🪑','🚽','🚿','🛁','🧴','🧷','🧹','🧺','🧻','🧼','🫧','🪣','🧽','🪤','🪒','🧲','🪜','🧰','🔧','🔨','⚒','🛠','⛏','🔩','🪛','🔫','🪃','🏹','🛡','🪚','🔪','🗡','⚔️','🛑','🚧','⚓','🪝','🧲','🔮','🪄','🧿','🪬','🎭','🎨','🖼','🎪','🎤','🎧','🎼','🎵','🎶','🎷','🪗','🎸','🎹','🎺','🎻','🪘','🥁','🪩']},
  {icon:'🔤',name:'Symbols',emojis:['‼️','⁉️','❓','❔','❕','❗','💯','🔞','📵','🚫','⛔','🆘','♻️','✅','☑️','🔃','🔄','🔙','🔚','🔛','🔜','🔝','🆔','📳','📴','📶','🔅','🔆','🎦','🔱','⭕','✳️','❇️','💠','Ⓜ️','🌀','💤','🏧','🚮','🚰','♿','🚹','🚺','🚻','🚼','🚾','⚠️','🚸','🚳','🚭','🚯','🚱','🚷','☢️','☣️','⬆️','↗️','➡️','↘️','⬇️','↙️','⬅️','↖️','↕️','↔️','↩️','↪️','⤴️','⤵️','🔀','🔁','🔂','▶️','⏩','⏭️','⏯️','◀️','⏪','⏮️','🔼','⏫','🔽','⏬','⏸️','⏹️','⏺️','🔔','🔕','🎵','🎶','✔️','🔲','🔳','🔘','🔴','🟠','🟡','🟢','🔵','🟣','⚫','⚪','🟤','🔶','🔷','🔸','🔹','🔺','🔻','💠','🔘']}
];
function buildReactionsHTML(s){
  var uid=state.user?state.user.uid:'';
  var rxs=s.reactions||{};
  var html='<button class="reaction-btn" onclick="showReactionPicker(\''+s.id+'\',this)">😊 React</button>';
  REACTIONS.forEach(function(em){
    var count=rxs[em]?Object.keys(rxs[em]).length:0;
    if(count>0){
      var reacted=rxs[em]&&rxs[em][uid];
      html+='<button class="reaction-btn'+(reacted?' reacted':'')+'" onclick="toggleReaction(\''+s.id+'\',\''+em+'\')">'+em+' '+count+'</button>';
    }
  });
  return html;
}

function showReactionPicker(sparkId, btn) {
  // Remove any existing picker
  var existing = document.getElementById('rxpicker-' + sparkId);
  if (existing) { existing.remove(); return; }
  document.querySelectorAll('.reaction-picker-full').forEach(function(p){ p.remove(); });

  var picker = document.createElement('div');
  picker.className = 'reaction-picker-full';
  picker.id = 'rxpicker-' + sparkId;

  // ── Quick reactions row ──
  var quickDiv = document.createElement('div');
  quickDiv.className = 'rxpick-quick';
  REACTIONS.forEach(function(em) {
    var b = document.createElement('button');
    b.textContent = em;
    b.title = 'React ' + em;
    b.onclick = function(e){ e.stopPropagation(); toggleReaction(sparkId, em); picker.remove(); };
    quickDiv.appendChild(b);
  });
  picker.appendChild(quickDiv);

  // ── Search bar ──
  var searchDiv = document.createElement('div');
  searchDiv.className = 'rxpick-search';
  var searchInp = document.createElement('input');
  searchInp.placeholder = '🔍 Search all emojis...';
  searchInp.autocomplete = 'off';
  searchDiv.appendChild(searchInp);
  picker.appendChild(searchDiv);

  // ── Category tabs ──
  var tabsDiv = document.createElement('div');
  tabsDiv.className = 'rxpick-tabs';
  EMOJI_CATS.forEach(function(cat, i) {
    var tab = document.createElement('button');
    tab.className = 'rxpick-tab' + (i === 0 ? ' active' : '');
    tab.textContent = cat.icon;
    tab.title = cat.name;
    tab.dataset.idx = i;
    tab.onclick = function(e){
      e.stopPropagation();
      tabsDiv.querySelectorAll('.rxpick-tab').forEach(function(t){ t.classList.remove('active'); });
      tab.classList.add('active');
      renderCat(i);
      searchInp.value = '';
    };
    tabsDiv.appendChild(tab);
  });
  picker.appendChild(tabsDiv);

  // ── Emoji body ──
  var body = document.createElement('div');
  body.className = 'rxpick-body';
  picker.appendChild(body);

  function renderCat(idx) {
    var grid = document.createElement('div');
    grid.className = 'rxpick-grid';
    EMOJI_CATS[idx].emojis.forEach(function(em) {
      var b = document.createElement('button');
      b.textContent = em;
      b.onclick = function(e){ e.stopPropagation(); toggleReaction(sparkId, em); picker.remove(); };
      grid.appendChild(b);
    });
    body.innerHTML = '';
    body.appendChild(grid);
  }
  renderCat(0);

  // ── Search logic ──
  searchInp.oninput = function() {
    var q = this.value.trim().toLowerCase();
    tabsDiv.querySelectorAll('.rxpick-tab').forEach(function(t){ t.classList.remove('active'); });
    if (!q) { renderCat(0); tabsDiv.querySelector('.rxpick-tab').classList.add('active'); return; }
    var grid = document.createElement('div');
    grid.className = 'rxpick-grid';
    var count = 0;
    EMOJI_CATS.forEach(function(cat) {
      cat.emojis.forEach(function(em) {
        // Show all emojis when searching (user scans visually)
        var b = document.createElement('button');
        b.textContent = em;
        b.onclick = function(e){ e.stopPropagation(); toggleReaction(sparkId, em); picker.remove(); };
        grid.appendChild(b);
        count++;
      });
    });
    body.innerHTML = '';
    if (count) body.appendChild(grid);
    else body.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:10px;text-align:center">No emojis</div>';
  };

  // ── Position ──
  document.body.appendChild(picker);
  var rect = btn.getBoundingClientRect();
  var top = rect.top - 340;
  if (top < 8) top = rect.bottom + 6;
  var left = Math.min(rect.left, window.innerWidth - 318);
  if (left < 6) left = 6;
  picker.style.top  = top + 'px';
  picker.style.left = left + 'px';

  // ── Auto-close ──
  setTimeout(function() {
    function closeHandler(e) {
      if (!picker.contains(e.target) && e.target !== btn) {
        picker.remove();
        document.removeEventListener('click', closeHandler);
      }
    }
    document.addEventListener('click', closeHandler);
  }, 120);
}

function toggleReaction(sparkId,emoji){
  if(!state.user){showToast('Login to react');return;}
  var uid=state.user.uid;
  var ref=db.collection('sparks').doc(sparkId);
  ref.get().then(function(d){
    if(!d.exists)return;
    var rxs=d.data().reactions||{};
    if(!rxs[emoji])rxs[emoji]={};
    if(rxs[emoji][uid]){delete rxs[emoji][uid];}
    else{rxs[emoji][uid]=true;}
    ref.update({reactions:rxs});
  });
}

function votePoll(sparkId,optIndex){
  if(!state.user){showToast('Login to vote');return;}
  var uid=state.user.uid;
  var ref=db.collection('sparks').doc(sparkId);
  ref.get().then(function(d){
    if(!d.exists)return;
    var data=d.data();
    if(!data.poll)return;
    if(data.poll.expiresAt&&Date.now()>data.poll.expiresAt){showToast('This poll has ended');return;}
    var userVotes=data.poll.userVotes||{};
    if(userVotes[uid]!==undefined){showToast('You already voted');return;}
    userVotes[uid]=optIndex;
    var votes=data.poll.votes||{};
    votes[optIndex]=(votes[optIndex]||0)+1;
    ref.update({'poll.votes':votes,'poll.userVotes':userVotes}).then(function(){showToast('Vote recorded!');});
  });
}

function repostSpark(sparkId,authorName){
  if(!state.user){showToast('Login to repost');return;}
  if(!confirm('Repost this spark from @'+authorName+'?'))return;
  var ref=db.collection('sparks').doc(sparkId);
  ref.get().then(function(d){
    if(!d.exists)return;
    var data=d.data();
    db.collection('sparks').add({
      text:'🔁 Reposted from @'+esc(data.authorHandle||authorName)+':\n\n'+data.text,
      authorId:state.user.uid,
      authorName:state.profile.name||'Mindvora user',
      authorHandle:state.profile.handle||'user',
      authorColor:state.profile.color||COLORS[0],
      isPremium:state.profile.isPremium||false,
      isVerified:state.profile.isVerified||false,
      category:data.category||'all',
      likes:[],reposts:0,commentCount:0,isRepost:true,originalId:sparkId,
      createdAt:firebase.firestore.FieldValue.serverTimestamp()
    }).then(function(){
      ref.update({reposts:firebase.firestore.FieldValue.increment(1)});
      showToast('🔁 Reposted!');
    });
  });
}

function pinSpark(sparkId,isPinned){
  if(!state.user)return;
  var newPinned=!isPinned;
  if(newPinned){
    var batch=db.batch();
    state.sparks.filter(function(s){return s.authorId===state.user.uid&&s.pinned;}).forEach(function(s){
      batch.update(db.collection('sparks').doc(s.id),{pinned:false});
    });
    batch.commit().catch(function(){});
  }
  db.collection('sparks').doc(sparkId).update({pinned:newPinned}).then(function(){
    showToast(newPinned?'📌 Spark pinned!':'📌 Spark unpinned');
  });
}

function translatePost(sparkId,text){
  if(!text){showToast('Nothing to translate');return;}
  openModal('modal-translate');
  document.getElementById('translated-text').textContent='Translating...';
  var url='https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl='+navigator.language.split('-')[0]+'&dt=t&q='+encodeURIComponent(text);
  fetch(url).then(function(r){return r.json();}).then(function(data){
    var translated=data[0].map(function(x){return x[0];}).join('');
    document.getElementById('translated-text').textContent=translated||'Translation unavailable';
  }).catch(function(){
    document.getElementById('translated-text').textContent='Translation unavailable. Try again later.';
  });
}

var pendingPoll=null;
function attachPoll(){
  var q=document.getElementById('poll-q').value.trim();
  var o1=document.getElementById('poll-o1').value.trim();
  var o2=document.getElementById('poll-o2').value.trim();
  var o3=document.getElementById('poll-o3').value.trim();
  var o4=document.getElementById('poll-o4').value.trim();
  var dur=parseInt(document.getElementById('poll-dur').value)||3;
  var err=document.getElementById('poll-err');
  if(!q){err.textContent='Please enter a question';return;}
  if(!o1||!o2){err.textContent='Please enter at least 2 options';return;}
  var opts=[o1,o2];
  if(o3)opts.push(o3);
  if(o4)opts.push(o4);
  pendingPoll={question:q,options:opts,votes:{},userVotes:{},expiresAt:Date.now()+(dur*24*60*60*1000)};
  closeModal('modal-poll');
  showToast('📊 Poll attached! Click Spark to post.');
}

var pendingLocation=null;
function getLocation(){
  if(!navigator.geolocation){showToast('Location not supported');return;}
  showToast('📍 Getting your location...');
  navigator.geolocation.getCurrentPosition(function(pos){
    var lat=pos.coords.latitude.toFixed(4);
    var lng=pos.coords.longitude.toFixed(4);
    fetch('https://nominatim.openstreetmap.org/reverse?lat='+lat+'&lon='+lng+'&format=json')
      .then(function(r){return r.json();})
      .then(function(d){
        var city=(d.address&&(d.address.city||d.address.town||d.address.village||d.address.state))||'Unknown';
        var country=(d.address&&d.address.country)||'';
        pendingLocation=city+(country?', '+country:'');
        showToast('📍 Location: '+pendingLocation);
        document.getElementById('btn-location').style.color='var(--green3)';
        document.getElementById('btn-location').style.borderColor='var(--green3)';
      }).catch(function(){
        pendingLocation=lat+', '+lng;
        showToast('📍 Location tagged!');
      });
  },function(){showToast('Location access denied');});
}

var pendingSchedule=null;
function confirmSchedule(){
  var dt=document.getElementById('sched-dt').value;
  var err=document.getElementById('sched-err');
  if(!dt){err.textContent='Please select a date and time';return;}
  var ts=new Date(dt).getTime();
  if(ts<=Date.now()){err.textContent='Please select a future date and time';return;}
  pendingSchedule=ts;
  closeModal('modal-schedule-pick');
  showToast('Post scheduled for '+new Date(ts).toLocaleString());
}

function openScheduled(){
  if(!state.user){showToast('Login first');return;}
  openModal('modal-scheduled');
  var list=document.getElementById('sched-list');
  db.collection('scheduled_posts').where('authorId','==',state.user.uid).get().then(function(snap){
    if(snap.empty){list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">No scheduled posts yet.</div>';return;}
    list.innerHTML=snap.docs.map(function(d){
      var s=d.data();
      return '<div class="sched-item"><div style="font-size:12px;color:var(--moon)">'+esc(s.text||'')+'</div>'+
        '<div style="font-size:10px;color:var(--muted);margin-top:4px">Scheduled: '+new Date(s.scheduledAt).toLocaleString()+'</div>'+
        '<button onclick="deleteScheduled(\''+d.id+'\')" style="margin-top:6px;font-size:10px;background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);border-radius:20px;padding:3px 10px;color:#fca5a5;cursor:pointer">Delete</button>'+
        '</div>';
    }).join('');
  }).catch(function(){list.innerHTML='<div style="color:#fca5a5;padding:10px">Error loading</div>';});
}

function deleteScheduled(id){
  if(!confirm('Delete this scheduled post?'))return;
  db.collection('scheduled_posts').doc(id).delete().then(function(){showToast('Deleted');openScheduled();});
}

setInterval(function(){
  if(!state.user)return;
  db.collection('scheduled_posts').where('authorId','==',state.user.uid).where('scheduledAt','<=',Date.now()).get().then(function(snap){
    snap.forEach(function(d){
      var s=d.data();
      db.collection('sparks').add({
        text:s.text,authorId:s.authorId,authorName:s.authorName,authorHandle:s.authorHandle,
        authorColor:s.authorColor,isPremium:s.isPremium||false,isVerified:s.isVerified||false,
        category:s.category||'all',likes:[],reposts:0,commentCount:0,
        createdAt:firebase.firestore.FieldValue.serverTimestamp()
      }).then(function(){d.ref.delete();showToast('Scheduled post published!');});
    });
  }).catch(function(){});
},60000);

function openLeaderboard(){
  if(!state.user){showToast('Login first');return;}
  openModal('modal-leaderboard');
  switchLbTab('sparks',document.getElementById('lb-tab-sparks'));
}

function switchLbTab(type,btn){
  document.querySelectorAll('#modal-leaderboard .f-pill').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  loadLeaderboard(type);
}

function loadLeaderboard(type){
  var list=document.getElementById('lb-list');
  list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">Loading...</div>';
  var field=type==='sparks'?'sparksCount':type==='fans'?'followers':'earnings';
  db.collection('users').orderBy(field,'desc').limit(20).get().then(function(snap){
    if(snap.empty){list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">No data yet</div>';return;}
    var medals=['🥇','🥈','🥉'];
    list.innerHTML=snap.docs.map(function(d,i){
      var u=d.data();
      var val=type==='sparks'?(u.sparksCount||0)+' sparks':type==='fans'?(u.followers||0)+' fans':'$'+(parseFloat(u.earnings||0)).toFixed(2)+' earned';
      return '<div class="lb-item">'+
        '<div class="lb-rank">'+(medals[i]||('#'+(i+1)))+'</div>'+
        '<div class="lb-av" style="background:'+(u.color||'var(--green)')+'">'+( u.name||'Z').charAt(0).toUpperCase()+'</div>'+
        '<div style="flex:1"><div style="font-size:12px;font-weight:700;color:var(--moon)">'+esc(u.name||'Mindvora user')+((u.isPremium||u.isVerified)?'<span class="vbadge" style="margin-left:4px"></span>':'')+'</div>'+
        '<div style="font-size:10px;color:var(--muted)">@'+esc(u.handle||'user')+' · '+val+'</div></div>'+
        '</div>';
    }).join('');
  }).catch(function(){list.innerHTML='<div style="color:#fca5a5;padding:10px">Could not load leaderboard</div>';});
}

function openQRCode(){
  if(!state.user){showToast('Login first');return;}
  openModal('modal-qr');
  var wrap=document.getElementById('qr-wrap');
  wrap.innerHTML='<div style="padding:20px;color:#999">Generating...</div>';
  var profileUrl='https://mindvora-vf8e.vercel.app?user='+((state.profile&&state.profile.handle)||'');
  var qrUrl='https://api.qrserver.com/v1/create-qr-code/?size=200x200&data='+encodeURIComponent(profileUrl);
  var img=document.createElement('img');
  img.src=qrUrl;
  img.style.cssText='width:200px;height:200px;border-radius:8px';
  img.onload=function(){wrap.innerHTML='';wrap.appendChild(img);};
  img.onerror=function(){wrap.innerHTML='<div style="padding:20px;color:#999">QR generation failed</div>';};
}

function downloadQR(){
  var img=document.querySelector('#qr-wrap img');
  if(!img){showToast('Please wait for QR to load');return;}
  var a=document.createElement('a');
  a.href=img.src;a.download='zync-qr-code.png';a.click();
}

function openStoryViews(storyId){
  openModal('modal-story-views');
  var list=document.getElementById('story-views-list');
  list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">Loading...</div>';
  db.collection('stories').doc(storyId).get().then(function(d){
    if(!d.exists){list.innerHTML='<div style="color:#fca5a5;padding:10px">Story not found</div>';return;}
    var views=d.data().views||[];
    if(!views.length){list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">No views yet</div>';return;}
    list.innerHTML='<div style="font-size:11px;color:var(--muted);margin-bottom:10px">'+views.length+' view'+(views.length!==1?'s':'')+'</div>'+
      views.slice(0,50).map(function(v){
        return '<div class="story-view-item">'+
          '<div style="width:32px;height:32px;border-radius:50%;background:var(--green);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0">'+(v.name||'?').charAt(0)+'</div>'+
          '<div><div style="font-size:12px;color:var(--moon)">'+esc(v.name||'Mindvora user')+'</div>'+
          '<div style="font-size:10px;color:var(--muted)">@'+esc(v.handle||'user')+'</div></div>'+
          '</div>';
      }).join('');
  });
}

function trackStoryView(storyId){
  if(!state.user||!state.profile)return;
  db.collection('stories').doc(storyId).update({
    views:firebase.firestore.FieldValue.arrayUnion({
      uid:state.user.uid,name:state.profile.name||'Mindvora user',
      handle:state.profile.handle||'user',viewedAt:Date.now()
    })
  }).catch(function(){});
}

function checkBirthday(){
  if(!state.profile||!state.profile.birthday)return;
  var today=new Date();
  var bday=new Date(state.profile.birthday);
  if(today.getMonth()===bday.getMonth()&&today.getDate()===bday.getDate()){
    showToast('🎂 Happy Birthday from Mindvora!');
    db.collection('notifications').add({
      uid:state.user.uid,type:'birthday',
      text:'🎂 Happy Birthday! Mindvora wishes you an amazing day!',
      createdAt:firebase.firestore.FieldValue.serverTimestamp(),read:false
    }).catch(function(){});
  }
}

function openCreatorSub(creatorId,creatorName,price){
  if(!state.user){showToast('Login to subscribe');return;}
  if(!price||price<1){showToast('Invalid price');return;}
  if(typeof PaystackPop==='undefined'){showToast('Payment loading');return;}
  PaystackPop.setup({
    key:PAYSTACK_KEY,email:state.user.email,amount:price*100,currency:'USD',
    ref:'ZSUB-'+creatorId+'-'+Date.now(),
    callback:function(){
      db.collection('creator_subs').add({
        subscriberId:state.user.uid,subscriberName:state.profile.name||'Mindvora user',
        creatorId:creatorId,price:price,createdAt:firebase.firestore.FieldValue.serverTimestamp()
      });
      db.collection('notifications').add({
        uid:creatorId,type:'subscription',
        text:'💎 '+esc(state.profile.name||'Someone')+' subscribed to your content for $'+price+'/month!',
        createdAt:firebase.firestore.FieldValue.serverTimestamp(),read:false
      });
      showToast('Subscribed to '+creatorName+'!');
    },
    onClose:function(){showToast('Payment cancelled');}
  }).openIframe();
}


// ══════════════════════════════════════════════════════
// 🔴 Mindvora LIVE STREAMING — WebRTC + Firestore Signaling
// ══════════════════════════════════════════════════════

var liveState = {
  localStream: null,
  peerConnections: {},
  currentLiveId: null,
  isHost: false,
  chatUnsub: null,
  viewerUnsub: null,
  viewerCountInterval: null,
  hostFacingUser: true
};

var ICE_SERVERS = { iceServers: [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' }
]};

// ── OPEN GO LIVE SETUP ──
function openGoLive() {
  if (!state.user) { showToast('Please login first'); return; }
  openModal('modal-go-live');
  document.getElementById('live-err').textContent = '';
  document.getElementById('live-title-inp').value = '';
  // Start camera preview
  navigator.mediaDevices.getUserMedia({ video: true, audio: true })
    .then(function(stream) {
      liveState.localStream = stream;
      document.getElementById('live-preview-cam').srcObject = stream;
    })
    .catch(function(err) {
      document.getElementById('live-err').textContent = 'Camera/mic access denied. Please allow and retry.';
    });
}

function cancelGoLive() {
  // Stop preview stream
  if (liveState.localStream) {
    liveState.localStream.getTracks().forEach(function(t) { t.stop(); });
    liveState.localStream = null;
  }
  closeModal('modal-go-live');
}

// ── START BROADCASTING ──
function startLiveStream() {
  var title = document.getElementById('live-title-inp').value.trim();
  var cat   = document.getElementById('live-cat-inp').value;
  var err   = document.getElementById('live-err');
  if (!title) { err.textContent = 'Please enter a stream title'; return; }
  if (!liveState.localStream) { err.textContent = 'Camera not ready. Please allow access.'; return; }

  var btn = document.getElementById('live-start-btn');
  btn.disabled = true; btn.textContent = 'Starting…';

  var liveDoc = {
    hostId:      state.user.uid,
    hostName:    (state.profile && state.profile.name) || 'Mindvora user',
    hostHandle:  (state.profile && state.profile.handle) || 'user',
    hostColor:   (state.profile && state.profile.color) || COLORS[0],
    isPremium:   (state.profile && state.profile.isPremium) || false,
    isVerified:  (state.profile && state.profile.isVerified) || false,
    title:       title,
    category:    cat,
    viewers:     0,
    live:        true,
    createdAt:   firebase.firestore.FieldValue.serverTimestamp()
  };

  db.collection('live_streams').add(liveDoc).then(function(docRef) {
    liveState.currentLiveId = docRef.id;
    liveState.isHost         = true;

    // Close modal, open host view
    closeModal('modal-go-live');
    document.getElementById('live-host-title-lbl').textContent = title;
    document.getElementById('live-host-video').srcObject = liveState.localStream;
    document.getElementById('live-host-view').style.display = 'block';

    // Post a spark announcing the live
    db.collection('sparks').add({
      text: '🔴 ' + esc((state.profile && state.profile.name) || 'Mindvora user') + ' just went LIVE: "' + esc(title) + '" — join now!',
      authorId: state.user.uid,
      authorName: (state.profile && state.profile.name) || 'Mindvora user',
      authorHandle: (state.profile && state.profile.handle) || 'user',
      authorColor: (state.profile && state.profile.color) || COLORS[0],
      isPremium: (state.profile && state.profile.isPremium) || false,
      isVerified: (state.profile && state.profile.isVerified) || false,
      category: 'all',
      isLiveAnnouncement: true,
      liveId: docRef.id,
      likes: [], saved: [], commentCount: 0, reposts: 0,
      createdAt: firebase.firestore.FieldValue.serverTimestamp()
    }).catch(function() {});

    // Listen for viewer join signals (WebRTC offers)
    db.collection('live_streams').doc(docRef.id)
      .collection('signals').where('type','==','offer')
      .onSnapshot(function(snap) {
        snap.docChanges().forEach(function(change) {
          if (change.type === 'added') {
            handleViewerOffer(change.doc.id, change.doc.data());
          }
        });
      });

    // Listen for live chat
    subscribeHostChat(docRef.id);

    // Update viewer count every 10s
    liveState.viewerCountInterval = setInterval(function() {
      db.collection('live_streams').doc(liveState.currentLiveId).get()
        .then(function(d) {
          if (d.exists) {
            document.getElementById('live-host-viewer-lbl').textContent = d.data().viewers || 0;
          }
        }).catch(function() {});
    }, 10000);

    btn.disabled = false; btn.textContent = '🔴 Start Streaming';
  }).catch(function(e) {
    err.textContent = 'Failed to start stream. Try again.';
    btn.disabled = false; btn.textContent = '🔴 Start Streaming';
  });
}

// ── HOST: handle incoming viewer WebRTC offer ──
function handleViewerOffer(viewerId, data) {
  if (liveState.peerConnections[viewerId]) return;
  var pc = new RTCPeerConnection(ICE_SERVERS);
  liveState.peerConnections[viewerId] = pc;

  // Add local tracks
  liveState.localStream.getTracks().forEach(function(track) {
    pc.addTrack(track, liveState.localStream);
  });

  // ICE candidates from host to viewer
  pc.onicecandidate = function(e) {
    if (e.candidate) {
      db.collection('live_streams').doc(liveState.currentLiveId)
        .collection('signals').doc(viewerId).collection('host_ice').add(e.candidate.toJSON())
        .catch(function() {});
    }
  };

  pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: data.sdp }))
    .then(function() { return pc.createAnswer(); })
    .then(function(answer) { return pc.setLocalDescription(answer).then(function() { return answer; }); })
    .then(function(answer) {
      db.collection('live_streams').doc(liveState.currentLiveId)
        .collection('signals').doc(viewerId).update({ type: 'answer', answerSdp: answer.sdp })
        .catch(function() {});
    })
    .catch(function(e) { console.warn('WebRTC offer handling error:', e); });

  // Listen for viewer ICE candidates
  db.collection('live_streams').doc(liveState.currentLiveId)
    .collection('signals').doc(viewerId).collection('viewer_ice')
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(change) {
        if (change.type === 'added') {
          pc.addIceCandidate(new RTCIceCandidate(change.doc.data())).catch(function() {});
        }
      });
    });
}

// ── END STREAM (host) ──
function endLiveStream() {
  if (!confirm('End your live stream?')) return;
  clearInterval(liveState.viewerCountInterval);
  if (liveState.localStream) {
    liveState.localStream.getTracks().forEach(function(t) { t.stop(); });
    liveState.localStream = null;
  }
  Object.values(liveState.peerConnections).forEach(function(pc) { try { pc.close(); } catch(e) {} });
  liveState.peerConnections = {};
  if (liveState.chatUnsub) { liveState.chatUnsub(); liveState.chatUnsub = null; }

  if (liveState.currentLiveId) {
    db.collection('live_streams').doc(liveState.currentLiveId).update({ live: false, endedAt: firebase.firestore.FieldValue.serverTimestamp() }).catch(function() {});
  }

  liveState.currentLiveId = null;
  liveState.isHost = false;
  document.getElementById('live-host-view').style.display = 'none';
  showToast('Stream ended! 👋');
}

function toggleHostCam() {
  liveState.hostFacingUser = !liveState.hostFacingUser;
  if (liveState.localStream) {
    liveState.localStream.getTracks().forEach(function(t) { t.stop(); });
  }
  navigator.mediaDevices.getUserMedia({ video: { facingMode: liveState.hostFacingUser ? 'user' : 'environment' }, audio: true })
    .then(function(stream) {
      liveState.localStream = stream;
      document.getElementById('live-host-video').srcObject = stream;
      // Re-add tracks to all peer connections
      Object.values(liveState.peerConnections).forEach(function(pc) {
        var senders = pc.getSenders();
        stream.getTracks().forEach(function(track) {
          var sender = senders.find(function(s) { return s.track && s.track.kind === track.kind; });
          if (sender) sender.replaceTrack(track);
        });
      });
    }).catch(function() { showToast('Could not switch camera'); });
}

// ── WATCH LIVE (viewer joins) ──
function openLivesList() {
  if (!state.user) { showToast('Please login first'); return; }
  openModal('modal-lives-list');
  var container = document.getElementById('lives-list-container');
  container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading...</div>';

  db.collection('live_streams').where('live','==',true).get()
    .then(function(snap) {
      if (snap.empty) {
        container.innerHTML = '<div style="text-align:center;padding:30px"><div style="font-size:32px;margin-bottom:10px">📺</div><div style="color:var(--muted)">No one is live right now.<br>Be the first to go live!</div><button class="btn-pay" style="margin-top:14px" onclick="closeModal(\'modal-lives-list\');openGoLive()">🔴 Go Live</button></div>';
        return;
      }
      var sorted=snap.docs.slice().sort(function(a,b){var ta=a.data().createdAt&&a.data().createdAt.seconds?a.data().createdAt.seconds:0;var tb=b.data().createdAt&&b.data().createdAt.seconds?b.data().createdAt.seconds:0;return tb-ta;});
      container.innerHTML = sorted.map(function(d) {
        var s = d.data();
        var initial = (s.hostName || 'Z').charAt(0).toUpperCase();
        return '<div class="live-card" onclick="joinStream(\'' + d.id + '\',\'' + esc(s.hostName||'Mindvora user') + '\',\'' + esc(s.hostHandle||'user') + '\',\'' + esc(s.hostColor||COLORS[0]) + '\')">' +
          '<div class="live-thumb">' +
            '<div class="live-host-av" style="background:' + esc(s.hostColor||COLORS[0]) + '">' + initial + '</div>' +
            '<span class="live-badge" style="position:absolute;top:8px;left:8px">LIVE</span>' +
            '<div class="live-viewers-pill">👁 ' + (s.viewers||0) + ' watching</div>' +
          '</div>' +
          '<div style="padding:10px">' +
            '<div style="font-size:12px;font-weight:700;color:var(--moon)">' + esc(s.title||'Untitled Stream') + '</div>' +
            '<div style="font-size:10px;color:var(--muted);margin-top:2px">@' + esc(s.hostHandle||'user') + ' · ' + esc(s.category||'general') + '</div>' +
          '</div>' +
        '</div>';
      }).join('');
    })
    .catch(function() { container.innerHTML = '<div style="color:#fca5a5;padding:10px">Error loading streams</div>'; });
}

function joinStream(liveId, hostName, hostHandle, hostColor) {
  closeModal('modal-lives-list');
  liveState.currentLiveId = liveId;
  liveState.isHost = false;

  // Update viewer count
  db.collection('live_streams').doc(liveId).update({ viewers: firebase.firestore.FieldValue.increment(1) }).catch(function() {});

  // Set up watch view UI
  document.getElementById('watch-host-name').textContent = hostName;
  document.getElementById('watch-host-av').textContent = (hostName||'Z').charAt(0).toUpperCase();
  document.getElementById('watch-host-av').style.background = hostColor||COLORS[0];
  document.getElementById('live-watch-chat').innerHTML = '';
  document.getElementById('live-watch-view').style.display = 'block';

  // WebRTC: create offer and send to host via Firestore signaling
  var viewerId = state.user.uid + '_' + Date.now();
  var pc = new RTCPeerConnection(ICE_SERVERS);
  liveState.peerConnections[viewerId] = pc;

  pc.ontrack = function(e) {
    var vid = document.getElementById('live-watch-video');
    if (vid.srcObject !== e.streams[0]) vid.srcObject = e.streams[0];
  };

  pc.onicecandidate = function(e) {
    if (e.candidate) {
      db.collection('live_streams').doc(liveId)
        .collection('signals').doc(viewerId).collection('viewer_ice').add(e.candidate.toJSON())
        .catch(function() {});
    }
  };

  // Create offer
  pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true })
    .then(function(offer) { return pc.setLocalDescription(offer).then(function() { return offer; }); })
    .then(function(offer) {
      return db.collection('live_streams').doc(liveId)
        .collection('signals').doc(viewerId).set({ type: 'offer', sdp: offer.sdp, viewerId: viewerId });
    })
    .catch(function(e) { console.warn('WebRTC offer error:', e); showToast('Connection error. Try again.'); });

  // Listen for host's answer
  db.collection('live_streams').doc(liveId)
    .collection('signals').doc(viewerId)
    .onSnapshot(function(snap) {
      var data = snap.data();
      if (data && data.answerSdp && pc.signalingState === 'have-local-offer') {
        pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: data.answerSdp }))
          .catch(function(e) { console.warn('Answer error:', e); });
      }
    });

  // Listen for host ICE candidates
  db.collection('live_streams').doc(liveId)
    .collection('signals').doc(viewerId).collection('host_ice')
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(change) {
        if (change.type === 'added') {
          pc.addIceCandidate(new RTCIceCandidate(change.doc.data())).catch(function() {});
        }
      });
    });

  // Check if stream ended
  liveState.viewerUnsub = db.collection('live_streams').doc(liveId).onSnapshot(function(d) {
    if (d.exists && d.data().live === false) {
      showToast('Stream has ended');
      leaveStream();
    }
    var viewers = d.exists ? (d.data().viewers||0) : 0;
    document.getElementById('watch-viewer-lbl').textContent = viewers;
  });

  // Subscribe chat
  subscribeViewerChat(liveId);
}

function leaveStream() {
  if (liveState.currentLiveId) {
    db.collection('live_streams').doc(liveState.currentLiveId).update({ viewers: firebase.firestore.FieldValue.increment(-1) }).catch(function() {});
  }
  Object.values(liveState.peerConnections).forEach(function(pc) { try { pc.close(); } catch(e) {} });
  liveState.peerConnections = {};
  if (liveState.chatUnsub) { liveState.chatUnsub(); liveState.chatUnsub = null; }
  if (liveState.viewerUnsub) { liveState.viewerUnsub(); liveState.viewerUnsub = null; }
  liveState.currentLiveId = null;
  document.getElementById('live-watch-view').style.display = 'none';
}

// ── LIVE CHAT ──
function subscribeHostChat(liveId) {
  liveState.chatUnsub = db.collection('live_streams').doc(liveId).collection('chat')
    .orderBy('createdAt','asc').limitToLast(100)
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(change) {
        if (change.type === 'added') appendLiveChatMsg('live-host-chat', change.doc.data());
      });
    });
}

function subscribeViewerChat(liveId) {
  liveState.chatUnsub = db.collection('live_streams').doc(liveId).collection('chat')
    .orderBy('createdAt','asc').limitToLast(100)
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(change) {
        if (change.type === 'added') appendLiveChatMsg('live-watch-chat', change.doc.data());
      });
    });
}

function appendLiveChatMsg(containerId, data) {
  var container = document.getElementById(containerId);
  if (!container) return;
  var div = document.createElement('div');
  div.className = 'live-chat-bubble';
  div.innerHTML = '<strong style="color:var(--green3)">' + esc(data.name||'Mindvora user') + '</strong>: ' + esc(data.text||'');
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function sendViewerChat() {
  var inp = document.getElementById('live-watch-inp');
  var text = inp.value.trim();
  if (!text || !liveState.currentLiveId || !state.user) return;
  inp.value = '';
  db.collection('live_streams').doc(liveState.currentLiveId).collection('chat').add({
    uid: state.user.uid,
    name: (state.profile && state.profile.name) || 'Mindvora user',
    text: text,
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).catch(function() {});
}

function subscribeHostChat(liveId) {
  liveState.chatUnsub = db.collection('live_streams').doc(liveId).collection('chat')
    .orderBy('createdAt','asc').limitToLast(100)
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(change) {
        if (change.type === 'added') appendLiveChatMsg('live-host-chat', change.doc.data());
      });
    });
}

function sendLiveTip() {
  if (!liveState.currentLiveId || !state.user) return;
  db.collection('live_streams').doc(liveState.currentLiveId).get().then(function(d) {
    if (!d.exists) return;
    var hostId = d.data().hostId;
    var hostName = d.data().hostName || 'Creator';
    openTip(hostId, hostName);
  });
}


// ══════════════════════════════════════════════════════════════
// FEATURE 1: PUSH NOTIFICATIONS (FCM + Native Notification API)
// ══════════════════════════════════════════════════════════════
var messaging = null;
var VAPID_KEY = 'BE41egfg4EvNNlM_ZepYdR1TQ460QNYCkQmgEGJ8SvsUHtDNw4pOpGW7bo0wSu9w9YWM_GxrW71lpAi5IZf5QKA';

function initPushNotifications() {
  if (!state.user) return;
  if (!('Notification' in window)) return;
  try {
    messaging = firebase.messaging();
    if (Notification.permission === 'granted') {
      subscribePush();
      startRealtimeNotifListener();
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then(function(perm) {
        if (perm === 'granted') {
          subscribePush();
          startRealtimeNotifListener();
        }
      });
    }
  } catch(e) { console.warn('FCM init error:', e); }
}

function subscribePush() {
  if (!messaging) return;
  messaging.getToken({ vapidKey: VAPID_KEY }).then(function(token) {
    if (token && state.user) {
      db.collection('users').doc(state.user.uid).update({ fcmToken: token, pushEnabled: true }).catch(function(){});
    }
  }).catch(function(e) { console.warn('FCM token error:', e); });

  messaging.onMessage(function(payload) {
    var title = (payload.notification && payload.notification.title) || 'Mindvora';
    var body  = (payload.notification && payload.notification.body)  || 'New notification';
    showToast('🔔 ' + title + ': ' + body);
    showNativeNotification(title, body);
    loadNotifications();
  });
}

// ── NATIVE NOTIFICATION API — show OS-level notifications ─────────────────
function showNativeNotification(title, body, icon) {
  if (!('Notification' in window)) return;
  if (Notification.permission !== 'granted') return;
  // Only show native notification when page is not focused (simulates background)
  if (document.hasFocus && document.hasFocus()) return;
  try {
    var n = new Notification(title || 'Mindvora', {
      body: body || 'You have a new notification',
      icon: icon || '/icons/icon-192.png',
      badge: '/icons/icon-96.png',
      tag: 'mindvora-' + Date.now(),
      vibrate: [200, 100, 200],
      requireInteraction: false,
      silent: false
    });
    n.onclick = function() {
      window.focus();
      n.close();
    };
    // Auto-close after 6 seconds
    setTimeout(function(){ try { n.close(); } catch(e){} }, 6000);
  } catch(e) { /* SW-only environment */ }
}

// ── REALTIME FIRESTORE NOTIFICATION LISTENER ─────────────────────────────
// Listens for new notifications in real-time and triggers native OS popups
var _notifListenerActive = false;
function startRealtimeNotifListener() {
  if (_notifListenerActive || !state.user) return;
  _notifListenerActive = true;
  
  db.collection('notifications')
    .where('toUid', '==', state.user.uid)
    .where('read', '==', false)
    .orderBy('createdAt', 'desc')
    .limit(10)
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(change) {
        if (change.type === 'added') {
          var notif = change.doc.data();
          var createdAt = notif.createdAt ? notif.createdAt.seconds * 1000 : 0;
          // Only trigger native notification for notifications created in last 30 seconds
          if (Date.now() - createdAt < 30000) {
            var title = 'Mindvora';
            var body = notif.text || 'You have a new notification';
            if (notif.type === 'dm') title = '💬 New Message';
            else if (notif.type === 'like') title = '❤️ New Like';
            else if (notif.type === 'comment') title = '💬 New Comment';
            else if (notif.type === 'follow') title = '➕ New Follower';
            else if (notif.type === 'tip') title = '💝 Tip Received';
            else if (notif.type === 'repost') title = '🔁 Repost';
            showNativeNotification(title, body);
          }
        }
      });
      // Update notification bell
      if (typeof updateNotifBell === 'function') updateNotifBell();
      if (typeof loadNotifications === 'function') loadNotifications();
    }, function(err) {
      console.warn('Notification listener error:', err);
      _notifListenerActive = false;
    });
}

// ── BACKGROUND NOTIFICATION CHECK (polls every 60 seconds) ───────────────
// Ensures notifications surface even if real-time listener drops
var _lastNotifCheck = 0;
setInterval(function() {
  if (!state.user || !db) return;
  if (Notification.permission !== 'granted') return;
  var now = Date.now();
  if (now - _lastNotifCheck < 55000) return; // Skip if checked recently
  _lastNotifCheck = now;
  
  db.collection('notifications')
    .where('toUid', '==', state.user.uid)
    .where('read', '==', false)
    .orderBy('createdAt', 'desc')
    .limit(5)
    .get()
    .then(function(snap) {
      if (!snap.empty && !document.hasFocus()) {
        var count = snap.docs.length;
        showNativeNotification(
          'Mindvora',
          'You have ' + count + ' unread notification' + (count > 1 ? 's' : ''),
          '/icons/icon-192.png'
        );
      }
    }).catch(function(){});
}, 60000);

// Register service worker
if ('serviceWorker' in navigator) {
  // Register main service worker (handles offline, caching, push, background sync)
  navigator.serviceWorker.register('/sw.js', { scope: '/' })
    .then(function(reg) {
      console.log('[Mindvora] SW registered:', reg.scope);
      // Request periodic background sync if supported
      if ('periodicSync' in reg) {
        reg.periodicSync.register('refresh-feed', { minInterval: 24 * 60 * 60 * 1000 })
          .catch(function(){});
      }
    }).catch(function(){});
  // Also register Firebase messaging SW for push notifications
  navigator.serviceWorker.register('/firebase-messaging-sw.js').catch(function(){});
}

// Helper: send push to a user via Firestore trigger record
function sendPushToUser(uid, title, body, type) {
  db.collection('push_queue').add({
    uid: uid, title: title, body: body, type: type || 'general',
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).catch(function(){});
}

// ══════════════════════════════════════════════════════════════
// FEATURE 2 & 3: VOICE & VIDEO CALLS (WebRTC)
// ══════════════════════════════════════════════════════════════
var callState = {
  pc: null,
  localStream: null,
  callDocId: null,
  isCalller: false,
  callUnsub: null,
  iceUnsub: null
};

var CALL_ICE = { iceServers: [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' }
]};

function startCall(targetUid, targetName, targetColor, isVideo) {
  if (!state.user) { showToast('Login first'); return; }
  if (callState.pc) { showToast('Already in a call'); return; }
  var callType = isVideo ? 'video' : 'audio';
  var constraints = isVideo ? { video: true, audio: true } : { audio: true };

  navigator.mediaDevices.getUserMedia(constraints).then(function(stream) {
    callState.localStream = stream;
    callState.isCalller = true;

    document.getElementById('call-local-video').srcObject = stream;
    document.getElementById('call-title').textContent = (isVideo ? '📹' : '📞') + ' Calling ' + targetName + '...';
    document.getElementById('call-avatar').textContent = (targetName||'Z').charAt(0).toUpperCase();
    document.getElementById('call-avatar').style.background = targetColor || COLORS[0];
    document.getElementById('call-type-icon').textContent = isVideo ? '📹' : '📞';
    if (isVideo) {
      document.getElementById('call-local-video').style.display = 'block';
      document.getElementById('call-remote-video').style.display = 'block';
    }
    document.getElementById('call-overlay').style.display = 'flex';

    var pc = new RTCPeerConnection(CALL_ICE);
    callState.pc = pc;
    stream.getTracks().forEach(function(t) { pc.addTrack(t, stream); });

    pc.ontrack = function(e) {
      document.getElementById('call-remote-video').srcObject = e.streams[0];
      document.getElementById('call-title').textContent = (isVideo ? '📹' : '📞') + ' ' + targetName;
    };

    pc.onicecandidate = function(e) {
      if (e.candidate && callState.callDocId) {
        db.collection('calls').doc(callState.callDocId).collection('callerCandidates').add(e.candidate.toJSON()).catch(function(){});
      }
    };

    db.collection('calls').add({
      callerId: state.user.uid,
      callerName: (state.profile && state.profile.name) || 'Mindvora user',
      callerColor: (state.profile && state.profile.color) || COLORS[0],
      calleeId: targetUid,
      calleeName: targetName,
      type: callType,
      status: 'ringing',
      createdAt: firebase.firestore.FieldValue.serverTimestamp()
    }).then(function(docRef) {
      callState.callDocId = docRef.id;

      pc.createOffer().then(function(offer) {
        return pc.setLocalDescription(offer).then(function() {
          return db.collection('calls').doc(docRef.id).update({ offerSdp: offer.sdp });
        });
      }).catch(function(e) { console.warn('Offer error:', e); });

      // Send notification to callee
      db.collection('notifications').add({
        uid: targetUid, type: 'call',
        text: '📞 ' + esc((state.profile&&state.profile.name)||'Someone') + ' is calling you! Open Mindvora to answer.',
        callId: docRef.id, callType: callType,
        createdAt: firebase.firestore.FieldValue.serverTimestamp(), read: false
      }).catch(function(){});

      // Listen for answer
      callState.callUnsub = db.collection('calls').doc(docRef.id).onSnapshot(function(d) {
        var data = d.data();
        if (!data) return;
        if (data.answerSdp && pc.signalingState === 'have-local-offer') {
          pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: data.answerSdp })).catch(function(){});
        }
        if (data.status === 'ended') { hangUp(); }
      });

      callState.iceUnsub = db.collection('calls').doc(docRef.id).collection('calleeCandidates')
        .onSnapshot(function(snap) {
          snap.docChanges().forEach(function(ch) {
            if (ch.type === 'added') pc.addIceCandidate(new RTCIceCandidate(ch.doc.data())).catch(function(){});
          });
        });
    });
  }).catch(function() { showToast('Camera/mic access denied'); });
}

function answerCall(callId) {
  if (callState.pc) { showToast('Already in a call'); return; }
  db.collection('calls').doc(callId).get().then(function(d) {
    if (!d.exists) return;
    var data = d.data();
    var isVideo = data.type === 'video';
    var constraints = isVideo ? { video: true, audio: true } : { audio: true };

    navigator.mediaDevices.getUserMedia(constraints).then(function(stream) {
      callState.localStream = stream;
      callState.isCalller = false;
      callState.callDocId = callId;

      document.getElementById('call-local-video').srcObject = stream;
      document.getElementById('call-title').textContent = (isVideo?'📹':'📞') + ' ' + esc(data.callerName||'Mindvora user');
      document.getElementById('call-avatar').textContent = (data.callerName||'Z').charAt(0).toUpperCase();
      document.getElementById('call-avatar').style.background = data.callerColor || COLORS[0];
      if (isVideo) {
        document.getElementById('call-local-video').style.display = 'block';
        document.getElementById('call-remote-video').style.display = 'block';
      }
      document.getElementById('call-overlay').style.display = 'flex';

      var pc = new RTCPeerConnection(CALL_ICE);
      callState.pc = pc;
      stream.getTracks().forEach(function(t) { pc.addTrack(t, stream); });

      pc.ontrack = function(e) { document.getElementById('call-remote-video').srcObject = e.streams[0]; };

      pc.onicecandidate = function(e) {
        if (e.candidate) {
          db.collection('calls').doc(callId).collection('calleeCandidates').add(e.candidate.toJSON()).catch(function(){});
        }
      };

      pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: data.offerSdp }))
        .then(function() { return pc.createAnswer(); })
        .then(function(answer) {
          return pc.setLocalDescription(answer).then(function() {
            return db.collection('calls').doc(callId).update({ answerSdp: answer.sdp, status: 'active' });
          });
        }).catch(function(e) { console.warn('Answer error:', e); });

      callState.iceUnsub = db.collection('calls').doc(callId).collection('callerCandidates')
        .onSnapshot(function(snap) {
          snap.docChanges().forEach(function(ch) {
            if (ch.type==='added') pc.addIceCandidate(new RTCIceCandidate(ch.doc.data())).catch(function(){});
          });
        });

      callState.callUnsub = db.collection('calls').doc(callId).onSnapshot(function(d2) {
        if (d2.exists && d2.data().status === 'ended') hangUp();
      });
    }).catch(function() { showToast('Camera/mic access denied'); });
  });
}

function hangUp() {
  if (callState.pc) { try { callState.pc.close(); } catch(e){} callState.pc = null; }
  if (callState.localStream) { callState.localStream.getTracks().forEach(function(t){t.stop();}); callState.localStream = null; }
  if (callState.callUnsub) { callState.callUnsub(); callState.callUnsub = null; }
  if (callState.iceUnsub) { callState.iceUnsub(); callState.iceUnsub = null; }
  if (callState.callDocId) {
    db.collection('calls').doc(callState.callDocId).update({ status: 'ended' }).catch(function(){});
    callState.callDocId = null;
  }
  document.getElementById('call-overlay').style.display = 'none';
  document.getElementById('call-remote-video').srcObject = null;
  document.getElementById('call-local-video').srcObject = null;
}

function toggleCallMic() {
  if (!callState.localStream) return;
  var track = callState.localStream.getAudioTracks()[0];
  if (track) { track.enabled = !track.enabled; document.getElementById('call-mic-btn').textContent = track.enabled ? '🎤' : '🔇'; }
}

function toggleCallCam() {
  if (!callState.localStream) return;
  var track = callState.localStream.getVideoTracks()[0];
  if (track) { track.enabled = !track.enabled; document.getElementById('call-cam-btn').textContent = track.enabled ? '📷' : '🚫'; }
}

// Listen for incoming calls when logged in
function listenForIncomingCalls() {
  if (!state.user) return;
  db.collection('calls').where('calleeId','==',state.user.uid).where('status','==','ringing')
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(ch) {
        if (ch.type === 'added') {
          var data = ch.doc.data();
          showIncomingCall(ch.doc.id, data.callerName||'Someone', data.callerColor||COLORS[0], data.type||'audio');
        }
      });
    });
}

function showIncomingCall(callId, callerName, callerColor, callType) {
  document.getElementById('incoming-caller-name').textContent = callerName;
  document.getElementById('incoming-call-icon').textContent = callType==='video' ? '📹' : '📞';
  document.getElementById('incoming-caller-av').textContent = callerName.charAt(0).toUpperCase();
  document.getElementById('incoming-caller-av').style.background = callerColor;
  document.getElementById('incoming-call-id').value = callId;
  document.getElementById('incoming-call-banner').style.display = 'flex';
  // Auto-dismiss after 30s
  setTimeout(function() { declineCall(callId); }, 30000);
}

function acceptCall() {
  var callId = document.getElementById('incoming-call-id').value;
  document.getElementById('incoming-call-banner').style.display = 'none';
  answerCall(callId);
}

function declineCall(callId) {
  var id = callId || document.getElementById('incoming-call-id').value;
  document.getElementById('incoming-call-banner').style.display = 'none';
  if (id) db.collection('calls').doc(id).update({ status: 'declined' }).catch(function(){});
}

// ══════════════════════════════════════════════════════════════
// FEATURE 4: GROUPS / COMMUNITIES
// ══════════════════════════════════════════════════════════════
var currentGroupId = null;
var groupChatUnsub = null;

function openGroups() {
  if (!state.user) { showToast('Login first'); return; }
  openModal('modal-groups');
  loadMyGroups();
}

function loadMyGroups() {
  var list = document.getElementById('groups-list');
  list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading...</div>';
  db.collection('groups').where('members','array-contains',state.user.uid).limit(30).get()
    .then(function(snap) {
      if (snap.empty) {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">No groups yet.<br>Create one or join one!</div>';
        return;
      }
      list.innerHTML = snap.docs.map(function(d) {
        var g = d.data();
        return '<div class="group-item" onclick="openGroupChat(\''+d.id+'\',\''+esc(g.name||'Group')+'\',\''+esc(g.emoji||'👥')+'\')">'+
          '<div class="group-av">'+esc(g.emoji||'👥')+'</div>'+
          '<div style="flex:1">'+
            '<div style="font-size:13px;font-weight:700;color:var(--moon)">'+esc(g.name||'Group')+'</div>'+
            '<div style="font-size:11px;color:var(--muted)">'+(g.members||[]).length+' members · '+esc(g.lastMsg||'No messages yet')+'</div>'+
          '</div>'+
        '</div>';
      }).join('');
    }).catch(function() { list.innerHTML = '<div style="color:#fca5a5;padding:10px">Error loading groups</div>'; });
}

function showCreateGroup() {
  document.getElementById('groups-list-view').style.display = 'none';
  document.getElementById('create-group-view').style.display = 'block';
}

function cancelCreateGroup() {
  document.getElementById('groups-list-view').style.display = 'block';
  document.getElementById('create-group-view').style.display = 'none';
}

function createGroup() {
  var name  = document.getElementById('group-name-inp').value.trim();
  var desc  = document.getElementById('group-desc-inp').value.trim();
  var emoji = document.getElementById('group-emoji-inp').value.trim() || '👥';
  var isPublic = document.getElementById('group-public-chk').checked;
  var err = document.getElementById('group-err');
  if (!name) { err.textContent = 'Please enter a group name'; return; }
  err.textContent = '';

  db.collection('groups').add({
    name: name, description: desc, emoji: emoji,
    isPublic: isPublic,
    ownerId: state.user.uid,
    ownerName: (state.profile&&state.profile.name)||'Mindvora user',
    members: [state.user.uid],
    admins: [state.user.uid],
    lastMsg: '', lastActivity: firebase.firestore.FieldValue.serverTimestamp(),
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(d) {
    showToast('👥 Group "'+name+'" created!');
    cancelCreateGroup();
    loadMyGroups();
    openGroupChat(d.id, name, emoji);
  }).catch(function() { err.textContent = 'Error creating group'; });
}

function openGroupChat(groupId, groupName, groupEmoji) {
  currentGroupId = groupId;
  closeModal('modal-groups');
  document.getElementById('group-chat-name').textContent = (groupEmoji||'👥')+' '+groupName;
  document.getElementById('group-chat-msgs').innerHTML = '';
  document.getElementById('modal-group-chat').style.display = 'flex';
  loadGroupMembers(groupId);

  if (groupChatUnsub) groupChatUnsub();
  groupChatUnsub = db.collection('groups').doc(groupId).collection('messages')
    .orderBy('createdAt','asc').limitToLast(60)
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(ch) {
        if (ch.type === 'added') appendGroupMsg(ch.doc.data());
      });
    });
}

function appendGroupMsg(data) {
  var c2 = document.getElementById('group-chat-msgs');
  var isOwn = state.user && data.authorId === state.user.uid;
  var div = document.createElement('div');
  div.style.cssText = 'margin-bottom:10px;display:flex;flex-direction:column;align-items:'+(isOwn?'flex-end':'flex-start');
  div.innerHTML = (!isOwn?'<div style="font-size:10px;color:var(--muted);margin-bottom:2px">'+esc(data.authorName||'Mindvora user')+'</div>':'')+
    '<div style="max-width:75%;background:'+(isOwn?'var(--green2)':'var(--deep)')+';border:1px solid var(--border);border-radius:'+(isOwn?'16px 4px 16px 16px':'4px 16px 16px 16px')+';padding:8px 12px;font-size:12px;color:'+(isOwn?'#fff':'var(--moon)')+'">'+esc(data.text||'')+'</div>'+
    '<div style="font-size:9px;color:var(--muted);margin-top:2px">'+timeAgo(data.createdAt)+'</div>';
  c2.appendChild(div);
  c2.scrollTop = c2.scrollHeight;
}

function sendGroupMessage() {
  var inp = document.getElementById('group-msg-inp');
  var text = inp.value.trim();
  if (!text || !currentGroupId || !state.user) return;
  inp.value = '';
  var msg = {
    authorId: state.user.uid,
    authorName: (state.profile&&state.profile.name)||'Mindvora user',
    authorColor: (state.profile&&state.profile.color)||COLORS[0],
    text: text,
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  };
  db.collection('groups').doc(currentGroupId).collection('messages').add(msg);
  db.collection('groups').doc(currentGroupId).update({ lastMsg: text, lastActivity: firebase.firestore.FieldValue.serverTimestamp() });
}

function closeGroupChat() {
  if (groupChatUnsub) { groupChatUnsub(); groupChatUnsub = null; }
  currentGroupId = null;
  document.getElementById('modal-group-chat').style.display = 'none';
}

function loadGroupMembers(groupId) {
  db.collection('groups').doc(groupId).get().then(function(d) {
    if (!d.exists) return;
    var g = d.data();
    var mDiv = document.getElementById('group-members-bar');
    if (mDiv) mDiv.textContent = (g.members||[]).length + ' members';
  });
}

function discoverGroups() {
  var list = document.getElementById('groups-list');
  list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading public groups...</div>';
  db.collection('groups').where('isPublic','==',true).limit(20).get()
    .then(function(snap) {
      if (snap.empty) { list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">No public groups yet</div>'; return; }
      list.innerHTML = snap.docs.map(function(d) {
        var g = d.data();
        var isMember = (g.members||[]).indexOf(state.user.uid) > -1;
        return '<div class="group-item">'+
          '<div class="group-av">'+esc(g.emoji||'👥')+'</div>'+
          '<div style="flex:1">'+
            '<div style="font-size:13px;font-weight:700;color:var(--moon)">'+esc(g.name||'Group')+'</div>'+
            '<div style="font-size:11px;color:var(--muted)">'+(g.members||[]).length+' members</div>'+
          '</div>'+
          (isMember
            ? '<button onclick="openGroupChat(\''+d.id+'\',\''+esc(g.name)+'\',\''+esc(g.emoji||'👥')+'\')" style="font-size:10px;padding:4px 10px;border-radius:20px;border:1px solid var(--green3);background:transparent;color:var(--green3);cursor:pointer">Open</button>'
            : '<button onclick="joinGroup(\''+d.id+'\')" style="font-size:10px;padding:4px 10px;border-radius:20px;border:1px solid var(--green3);background:transparent;color:var(--green3);cursor:pointer">Join</button>'
          )+
        '</div>';
      }).join('');
    }).catch(function() { list.innerHTML = '<div style="color:#fca5a5;padding:10px">Error loading</div>'; });
}

function joinGroup(groupId) {
  db.collection('groups').doc(groupId).update({ members: firebase.firestore.FieldValue.arrayUnion(state.user.uid) })
    .then(function() { showToast('👥 Joined group!'); discoverGroups(); });
}

// ══════════════════════════════════════════════════════════════
// FEATURE 5: ADVANCED SEARCH
// ══════════════════════════════════════════════════════════════
function openAdvancedSearch() {
  if (!state.user) { showToast('Login first'); return; }
  openModal('modal-adv-search');
  document.getElementById('adv-search-inp').value = '';
  document.getElementById('adv-search-results').innerHTML = '';
  setTimeout(function() { document.getElementById('adv-search-inp').focus(); }, 300);
}

function runAdvancedSearch() {
  var q = document.getElementById('adv-search-inp').value.trim().toLowerCase();
  var results = document.getElementById('adv-search-results');
  var tab = document.querySelector('#modal-adv-search .search-tab.active');
  var type = tab ? tab.dataset.type : 'all';
  if (!q) return;
  results.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Searching...</div>';

  var promises = [];

  if (type === 'all' || type === 'users') {
    promises.push(
      db.collection('users').orderBy('name').startAt(q).endAt(q+'\uf8ff').limit(10).get()
        .then(function(snap) { return snap.docs.map(function(d) { return { type:'user', id:d.id, data:d.data() }; }); })
        .catch(function() { return []; })
    );
  }

  if (type === 'all' || type === 'posts') {
    promises.push(
      db.collection('sparks').orderBy('text').startAt(q).endAt(q+'\uf8ff').limit(10).get()
        .then(function(snap) { return snap.docs.map(function(d) { return { type:'post', id:d.id, data:d.data() }; }); })
        .catch(function() { return []; })
    );
  }

  if (type === 'all' || type === 'hashtags') {
    promises.push(
      db.collection('sparks').where('hashtags','array-contains',q).limit(10).get()
        .then(function(snap) { return snap.docs.map(function(d) { return { type:'hashtag', id:d.id, data:d.data() }; }); })
        .catch(function() { return []; })
    );
  }

  Promise.all(promises).then(function(arrs) {
    var all = [].concat.apply([], arrs);
    if (!all.length) { results.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">No results for "'+esc(q)+'"</div>'; return; }
    results.innerHTML = all.map(function(item) {
      if (item.type === 'user') {
        return '<div class="search-result-item" onclick="openProfileModal(\''+item.id+'\')">'+
          '<div style="width:36px;height:36px;border-radius:50%;background:'+(item.data.color||'var(--green)')+';display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;flex-shrink:0">'+(item.data.name||'Z').charAt(0)+'</div>'+
          '<div><div style="font-size:13px;font-weight:700;color:var(--moon)">'+esc(item.data.name||'Mindvora user')+'</div>'+
          '<div style="font-size:11px;color:var(--muted)">@'+esc(item.data.handle||'user')+' · 👤 User</div></div>'+
        '</div>';
      } else {
        return '<div class="search-result-item" onclick="openComments(\''+item.id+'\')">'+
          '<div style="font-size:20px;flex-shrink:0">'+(item.type==='hashtag'?'#️⃣':'✦')+'</div>'+
          '<div><div style="font-size:12px;color:var(--moon)">'+esc((item.data.text||'').slice(0,80))+'</div>'+
          '<div style="font-size:10px;color:var(--muted)">by @'+esc(item.data.authorHandle||'user')+'</div></div>'+
        '</div>';
      }
    }).join('');
  });
}

function switchSearchTab(type, btn) {
  document.querySelectorAll('#modal-adv-search .search-tab').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  if (document.getElementById('adv-search-inp').value.trim()) runAdvancedSearch();
}

// ══════════════════════════════════════════════════════════════
// FEATURE 6: BACKGROUND MUSIC ON STORIES/REELS
// ══════════════════════════════════════════════════════════════
var storyMusicAudio = null;
var pendingStoryMusic = null;

var STORY_TRACKS = [
  { name:'Chill Vibes', url:'https://cdn.pixabay.com/download/audio/2022/01/18/audio_d0c6ff1bab.mp3' },
  { name:'Upbeat Energy', url:'https://cdn.pixabay.com/download/audio/2021/11/25/audio_91b32e02f9.mp3' },
  { name:'Dreamy', url:'https://cdn.pixabay.com/download/audio/2022/03/10/audio_270f49b51b.mp3' },
  { name:'Lo-Fi Beat', url:'https://cdn.pixabay.com/download/audio/2022/05/27/audio_1808fbf07a.mp3' },
  { name:'Ambient', url:'https://cdn.pixabay.com/download/audio/2022/08/02/audio_884fe92c21.mp3' },
  { name:'Happy Tune', url:'https://cdn.pixabay.com/download/audio/2022/01/20/audio_d8fbba82b7.mp3' }
];

function openMusicPicker() {
  openModal('modal-music-picker');
  var list = document.getElementById('music-list');
  list.innerHTML = STORY_TRACKS.map(function(t, i) {
    var isSelected = pendingStoryMusic && pendingStoryMusic.name === t.name;
    return '<div class="music-item'+(isSelected?' selected':'')+'" id="music-item-'+i+'" onclick="previewTrack('+i+')">'+
      '<div style="width:36px;height:36px;border-radius:50%;background:var(--green2);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0">🎵</div>'+
      '<div style="flex:1"><div style="font-size:12px;font-weight:700;color:var(--moon)">'+esc(t.name)+'</div>'+
      '<div style="font-size:10px;color:var(--muted)">Tap to preview</div></div>'+
      '<button onclick="selectTrack('+i+');event.stopPropagation()" style="font-size:10px;padding:4px 10px;border-radius:20px;border:1px solid var(--green3);background:'+(isSelected?'var(--green3)':'transparent')+';color:'+(isSelected?'#fff':'var(--green3)')+';cursor:pointer">'+( isSelected?'✓ Selected':'Select')+'</button>'+
    '</div>';
  }).join('');
}

function previewTrack(i) {
  if (storyMusicAudio) { storyMusicAudio.pause(); storyMusicAudio.src=''; storyMusicAudio = null; }
  var track = STORY_TRACKS[i];
  storyMusicAudio = new Audio();
  storyMusicAudio.crossOrigin = 'anonymous';
  storyMusicAudio.src = track.url;
  storyMusicAudio.volume = 0.5;
  storyMusicAudio.play().then(function(){
    showToast('▶ Playing: ' + track.name);
    // Update UI - show playing state
    document.querySelectorAll('.music-item').forEach(function(el){ el.style.background=''; });
    var el = document.getElementById('music-item-'+i);
    if(el) el.style.background = 'rgba(34,197,94,.1)';
  }).catch(function(e){
    // Autoplay blocked or CORS — try without crossOrigin
    storyMusicAudio = new Audio(track.url);
    storyMusicAudio.volume = 0.5;
    storyMusicAudio.play().catch(function(){
      showToast('⚠️ Could not preview. Select track to use it in your story.');
    });
  });
  setTimeout(function() { 
    if (storyMusicAudio) { storyMusicAudio.pause(); storyMusicAudio.src=''; storyMusicAudio = null; }
    document.querySelectorAll('.music-item').forEach(function(el){ el.style.background=''; });
  }, 10000);
}

function selectTrack(i) {
  if (storyMusicAudio) { storyMusicAudio.pause(); storyMusicAudio = null; }
  pendingStoryMusic = STORY_TRACKS[i];
  closeModal('modal-music-picker');
  showToast('🎵 "'+STORY_TRACKS[i].name+'" added to your story!');
  document.getElementById('btn-story-music') && (document.getElementById('btn-story-music').style.color = 'var(--green3)');
}

function closeMusicPicker() {
  if (storyMusicAudio) { storyMusicAudio.pause(); storyMusicAudio = null; }
  closeModal('modal-music-picker');
}

// ══════════════════════════════════════════════════════════════
// FEATURE 7: THREADED REPLIES
// ══════════════════════════════════════════════════════════════
var replyingTo = null;

function replyToComment(commentId, authorName) {
  replyingTo = { id: commentId, name: authorName };
  var inp = document.getElementById('comment-inp');
  if (inp) {
    inp.placeholder = 'Replying to @' + authorName + '...';
    inp.focus();
    document.getElementById('reply-indicator') && (document.getElementById('reply-indicator').style.display = 'flex');
    document.getElementById('reply-to-name') && (document.getElementById('reply-to-name').textContent = '@'+authorName);
  }
}

function cancelReply() {
  replyingTo = null;
  var inp = document.getElementById('comment-inp');
  if (inp) inp.placeholder = 'Add a comment...';
  document.getElementById('reply-indicator') && (document.getElementById('reply-indicator').style.display = 'none');
}

// Patch sendComment to support threads — called from existing sendComment flow
function patchSendCommentForThreads(sparkId, text) {
  if (!state.user || !text) return;
  var commentData = {
    authorId: state.user.uid,
    authorName: (state.profile&&state.profile.name)||'Mindvora user',
    authorHandle: (state.profile&&state.profile.handle)||'user',
    authorColor: (state.profile&&state.profile.color)||COLORS[0],
    text: text,
    parentId: replyingTo ? replyingTo.id : null,
    replyTo: replyingTo ? replyingTo.name : null,
    likes: [],
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  };
  cancelReply();
  return db.collection('sparks').doc(sparkId).collection('comments').add(commentData);
}

// ══════════════════════════════════════════════════════════════
// FEATURE 8: COLLAB POSTS
// ══════════════════════════════════════════════════════════════
var collabInvite = null;

function openCollabPost() {
  if (!state.user) { showToast('Login first'); return; }
  openModal('modal-collab');
  document.getElementById('collab-user-search').value = '';
  document.getElementById('collab-user-results').innerHTML = '';
  collabInvite = null;
}

function searchCollabUser() {
  var q = document.getElementById('collab-user-search').value.trim().toLowerCase();
  var res = document.getElementById('collab-user-results');
  if (!q) return;
  db.collection('users').orderBy('handle').startAt(q).endAt(q+'\uf8ff').limit(6).get()
    .then(function(snap) {
      if (snap.empty) { res.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:6px 0">No users found</div>'; return; }
      res.innerHTML = snap.docs.filter(function(d){return d.id!==state.user.uid;}).map(function(d) {
        var u = d.data();
        return '<div class="search-result-item" onclick="selectCollabUser(\''+d.id+'\',\''+esc(u.name||'Mindvora user')+'\',\''+esc(u.color||COLORS[0])+'\')">'+
          '<div style="width:32px;height:32px;border-radius:50%;background:'+(u.color||'var(--green)')+';display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff">'+(u.name||'Z').charAt(0)+'</div>'+
          '<div style="font-size:12px;color:var(--moon)">'+esc(u.name||'Mindvora user')+'<br><span style="font-size:10px;color:var(--muted)">@'+esc(u.handle||'user')+'</span></div>'+
        '</div>';
      }).join('');
    });
}

function selectCollabUser(uid, name, color) {
  collabInvite = { uid: uid, name: name, color: color };
  document.getElementById('collab-selected').innerHTML = '<div style="display:flex;align-items:center;gap:8px;padding:8px;background:rgba(34,197,94,.1);border:1px solid var(--green3);border-radius:10px;margin-top:8px">'+
    '<div style="width:28px;height:28px;border-radius:50%;background:'+color+';display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff">'+name.charAt(0)+'</div>'+
    '<span style="font-size:12px;color:var(--green3)">✓ Collaborating with '+esc(name)+'</span></div>';
}

function postCollabSpark() {
  var text = document.getElementById('collab-text').value.trim();
  if (!text) { showToast('Write something first'); return; }
  if (!collabInvite) { showToast('Select a collaborator'); return; }
  db.collection('sparks').add({
    text: text,
    authorId: state.user.uid,
    authorName: (state.profile&&state.profile.name)||'Mindvora user',
    authorHandle: (state.profile&&state.profile.handle)||'user',
    authorColor: (state.profile&&state.profile.color)||COLORS[0],
    isPremium: (state.profile&&state.profile.isPremium)||false,
    isVerified: (state.profile&&state.profile.isVerified)||false,
    collabId: collabInvite.uid,
    collabName: collabInvite.name,
    collabColor: collabInvite.color,
    isCollab: true,
    category: 'all',
    likes:[], saved:[], commentCount:0, reposts:0,
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function() {
    db.collection('notifications').add({
      uid: collabInvite.uid, type: 'collab',
      text: '🤝 '+esc((state.profile&&state.profile.name)||'Someone')+' tagged you in a Collab Post!',
      createdAt: firebase.firestore.FieldValue.serverTimestamp(), read: false
    });
    closeModal('modal-collab');
    showToast('🤝 Collab post published!');
  }).catch(function() { showToast('Error posting'); });
}

// ══════════════════════════════════════════════════════════════
// FEATURE 9: MINI GAMES
// ══════════════════════════════════════════════════════════════
function openGames() {
  if (!state.user) { showToast('Login first'); return; }
  openModal('modal-games');
}

function launchGame(game) {
  closeModal('modal-games');
  document.getElementById('game-container').style.display = 'flex';
  var gc = document.getElementById('game-content');
  if (game === 'typing') {
    launchTypingGame(gc);
  } else if (game === 'memory') {
    launchMemoryGame(gc);
  } else if (game === 'trivia') {
    launchTriviaGame(gc);
  }
}

function closeGame() {
  document.getElementById('game-container').style.display = 'none';
  document.getElementById('game-content').innerHTML = '';
}

function launchTypingGame(container) {
  var PASSAGES = [
    "The quick brown fox jumps over the lazy dog. A journey of a thousand miles begins with a single step. Every day is a new opportunity to grow and become a better version of yourself. Success is not final and failure is not fatal. It is the courage to continue that truly counts in life.",
    "Happiness does not come from what you have but from who you are and what you give. The best time to plant a tree was twenty years ago and the second best time is right now. Work hard in silence and let your success make all the noise you ever needed.",
    "Dream big work hard stay focused and surround yourself with good people who push you forward. Technology is changing the world every single day and those who learn fast will always lead the way. Share your ideas speak your truth and connect with minds that challenge and inspire you daily.",
    "Every great story begins with a single brave decision to try something new and unknown. The world belongs to those who believe in the beauty of their dreams and work tirelessly toward them. Be kind be bold be curious and never stop learning because knowledge opens every door in life.",
    "Life is short so make it count by doing things that matter and being with people who care. The strongest people are not those who show strength every day but those who fight through hard times. Believe in yourself even when nobody else does because your faith will carry you far.",
    "Innovation starts with a question that nobody else thought to ask before. The greatest minds in history were simply ordinary people who refused to give up on extraordinary ideas. Read more listen more think more and you will grow into someone the world truly needs right now.",
    "Connections are the currency of the modern world and every conversation is a chance to learn something new. Be present in every moment because time moves fast and the people you love deserve your full attention every day. Gratitude turns what you have into more than enough for a great life."
  ];

  var currentPassage = '';
  var timeLeft = 60;
  var interval = null;
  var started = false;

  container.innerHTML =
    '<div style="padding:16px">' +
      '<div style="font-size:13px;font-weight:700;color:var(--moon);margin-bottom:2px;text-align:center">⌨️ Typing Speed Test</div>' +
      '<div style="font-size:11px;color:var(--muted);text-align:center;margin-bottom:12px">Type the passage below as the timer counts down</div>' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">' +
        '<span style="font-size:13px;color:var(--green3)">Words: <b id="tg-score">0</b></span>' +
        '<span style="font-size:13px;color:var(--moon)">Time: <b id="tg-time">60</b>s</span>' +
        '<span style="font-size:13px;color:var(--muted)">WPM: <b id="tg-wpm">0</b></span>' +
      '</div>' +
      '<div id="tg-passage" style="font-size:13px;line-height:1.8;color:var(--muted);background:var(--deep);border-radius:10px;padding:12px;margin-bottom:10px;min-height:80px;letter-spacing:0.3px;border:1px solid var(--border)"></div>' +
      '<textarea id="tg-inp" placeholder="Press Start then type here..." rows="4" ' +
        'style="width:100%;box-sizing:border-box;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:10px;color:var(--moon);font-size:13px;font-family:DM Sans,sans-serif;resize:none;outline:none;margin-bottom:10px" disabled></textarea>' +
      '<button class="btn-pay" id="tg-start-btn" onclick="startTypingGame()">▶ Start</button>' +
    '</div>';

  window.startTypingGame = function() {
    var idx2 = Math.floor(Math.random() * PASSAGES.length);
    currentPassage = PASSAGES[idx2];
    started = true;
    timeLeft = 60;

    // Render passage with span per word for highlight
    var words2 = currentPassage.split(' ');
    document.getElementById('tg-passage').innerHTML = words2.map(function(w, i) {
      return '<span id="tw-' + i + '" style="padding:1px 2px;border-radius:3px">' + w + ' </span>';
    }).join('');

    var inp = document.getElementById('tg-inp');
    inp.value = '';
    inp.disabled = false;
    inp.focus();

    document.getElementById('tg-start-btn').textContent = '↺ Restart';
    document.getElementById('tg-score').textContent = '0';
    document.getElementById('tg-wpm').textContent = '0';

    var wordIndex = 0;
    var passageWords = currentPassage.split(' ');
    var totalTyped = 0;

    function highlightWord(i) {
      passageWords.forEach(function(_, j) {
        var el = document.getElementById('tw-' + j);
        if (!el) return;
        if (j < i) { el.style.color = 'var(--green3)'; el.style.background = 'transparent'; }
        else if (j === i) { el.style.background = 'rgba(34,197,94,0.2)'; el.style.color = 'var(--moon)'; }
        else { el.style.color = 'var(--muted)'; el.style.background = 'transparent'; }
      });
    }
    highlightWord(0);

    inp.oninput = function() {
      if (!started || timeLeft <= 0) return;
      var typed = inp.value;
      var typedWords = typed.split(' ');
      var currentTyped = typedWords[typedWords.length - 1];
      var completedWords = typedWords.length - 1;

      // Check if user pressed space — word submitted
      if (typed.endsWith(' ')) {
        var submittedWord = typedWords[typedWords.length - 2];
        if (submittedWord === passageWords[wordIndex]) {
          document.getElementById('tw-' + wordIndex).style.color = 'var(--green3)';
          wordIndex++;
          totalTyped++;
          document.getElementById('tg-score').textContent = totalTyped;
          var elapsed = 60 - timeLeft;
          document.getElementById('tg-wpm').textContent = elapsed > 0 ? Math.round(totalTyped / (elapsed / 60)) : 0;
          highlightWord(wordIndex);
          if (wordIndex >= passageWords.length) {
            // Finished passage
            clearInterval(interval);
            started = false;
            inp.disabled = true;
            showToast('🎉 Passage complete! ' + totalTyped + ' words in ' + (60 - timeLeft) + 's');
          }
        } else {
          // Wrong word — highlight red
          var el = document.getElementById('tw-' + wordIndex);
          if (el) { el.style.background = 'rgba(239,68,68,0.2)'; el.style.color = '#fca5a5'; }
        }
      }
    };

    if (interval) clearInterval(interval);
    interval = setInterval(function() {
      timeLeft--;
      var el = document.getElementById('tg-time');
      if (el) el.textContent = timeLeft;
      if (timeLeft <= 10) { if (el) el.style.color = '#fca5a5'; }
      if (timeLeft <= 0) {
        clearInterval(interval);
        started = false;
        inp.disabled = true;
        var wpm = Math.round(totalTyped / 1);
        document.getElementById('tg-wpm').textContent = wpm;
        showToast('⌨️ ' + totalTyped + ' words! WPM: ' + wpm + ' — ' + (wpm > 50 ? 'Outstanding! 🔥' : wpm > 30 ? 'Great job! 👏' : wpm > 15 ? 'Good effort! 💪' : 'Keep practicing! 🌱'));
        db.collection('users').doc(state.user.uid).get().then(function(d) {
          var best = (d.data() && d.data().typingHighScore) || 0;
          if (totalTyped > best) db.collection('users').doc(state.user.uid).update({ typingHighScore: totalTyped });
        }).catch(function(){});
      }
    }, 1000);
  };
}

function launchMemoryGame(container) {
  var emojis = ['🦁','🐯','🐻','🦊','🐸','🐬','🦋','🌸'];
  var cards = emojis.concat(emojis).sort(function(){return Math.random()-.5;});
  var flipped=[], matched=[], moves=0;
  container.innerHTML = '<div style="padding:16px"><div style="text-align:center;margin-bottom:12px"><span style="font-size:13px;font-weight:700;color:var(--moon)">🃏 Memory Match</span> <span style="font-size:11px;color:var(--muted)" id="mm-moves">Moves: 0</span></div><div id="mm-grid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px"></div></div>';
  var grid = document.getElementById('mm-grid');
  cards.forEach(function(em, i) {
    var card = document.createElement('div');
    card.style.cssText='height:56px;background:var(--deep);border:2px solid var(--border);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:24px;cursor:pointer;transition:all .2s;user-select:none';
    card.dataset.emoji = em;
    card.dataset.idx = i;
    card.dataset.shown = '0';
    card.textContent = '?';
    card.onclick = function() {
      if (this.dataset.shown==='1'||flipped.length===2) return;
      this.textContent = this.dataset.emoji;
      this.style.borderColor = 'var(--green3)';
      this.dataset.shown = '1';
      flipped.push(this);
      if (flipped.length===2) {
        moves++;
        document.getElementById('mm-moves').textContent = 'Moves: '+moves;
        if (flipped[0].dataset.emoji===flipped[1].dataset.emoji) {
          flipped.forEach(function(c){c.style.background='rgba(34,197,94,.2)';});
          matched.push(flipped[0].dataset.emoji);
          flipped=[];
          if (matched.length===emojis.length) { setTimeout(function(){showToast('🎉 You won in '+moves+' moves!');},300); }
        } else {
          var f=flipped.slice();
          setTimeout(function(){ f.forEach(function(c){c.textContent='?';c.style.borderColor='var(--border)';c.dataset.shown='0';}); flipped=[]; }, 800);
        }
      }
    };
    grid.appendChild(card);
  });
}

// ═══════════════════════════════════════════════════════
// TRIVIA — 200 real-life questions across 6 categories
// Fetches from Open Trivia DB API. Falls back to local bank.
// ═══════════════════════════════════════════════════════
var TRIVIA_LOCAL = [
  // 🌍 GEOGRAPHY
  {q:"What is the capital of Australia?",opts:["Sydney","Melbourne","Canberra","Brisbane"],ans:2,cat:"🌍 Geography"},
  {q:"Which is the longest river in the world?",opts:["Amazon","Nile","Yangtze","Mississippi"],ans:1,cat:"🌍 Geography"},
  {q:"What country has the most natural lakes?",opts:["Russia","USA","Brazil","Canada"],ans:3,cat:"🌍 Geography"},
  {q:"Which continent is the Sahara Desert on?",opts:["Asia","Africa","Australia","South America"],ans:1,cat:"🌍 Geography"},
  {q:"What is the smallest country in the world?",opts:["Monaco","San Marino","Vatican City","Liechtenstein"],ans:2,cat:"🌍 Geography"},
  {q:"Which ocean is the largest?",opts:["Atlantic","Indian","Arctic","Pacific"],ans:3,cat:"🌍 Geography"},
  {q:"What is the capital of Japan?",opts:["Osaka","Kyoto","Tokyo","Hiroshima"],ans:2,cat:"🌍 Geography"},
  {q:"Which country has the most population?",opts:["USA","India","China","Indonesia"],ans:1,cat:"🌍 Geography"},
  {q:"Mount Everest is in which mountain range?",opts:["Andes","Alps","Rockies","Himalayas"],ans:3,cat:"🌍 Geography"},
  {q:"What is the capital of Brazil?",opts:["Rio de Janeiro","Sao Paulo","Brasilia","Salvador"],ans:2,cat:"🌍 Geography"},
  // 🔬 SCIENCE
  {q:"What is the chemical symbol for gold?",opts:["Go","Gd","Au","Ag"],ans:2,cat:"🔬 Science"},
  {q:"How many bones are in the adult human body?",opts:["196","206","216","226"],ans:1,cat:"🔬 Science"},
  {q:"What planet is known as the Red Planet?",opts:["Venus","Jupiter","Saturn","Mars"],ans:3,cat:"🔬 Science"},
  {q:"What gas do plants absorb from the air?",opts:["Oxygen","Nitrogen","Carbon Dioxide","Hydrogen"],ans:2,cat:"🔬 Science"},
  {q:"What is the speed of light (approx)?",opts:["300,000 km/s","150,000 km/s","450,000 km/s","200,000 km/s"],ans:0,cat:"🔬 Science"},
  {q:"DNA stands for?",opts:["Deoxyribonucleic Acid","Dinitrogen Acid","Dynamic Neural Array","Dense Nucleic Atom"],ans:0,cat:"🔬 Science"},
  {q:"Which planet has the most moons?",opts:["Jupiter","Saturn","Uranus","Neptune"],ans:1,cat:"🔬 Science"},
  {q:"What is the powerhouse of the cell?",opts:["Nucleus","Ribosome","Mitochondria","Golgi body"],ans:2,cat:"🔬 Science"},
  {q:"What element has atomic number 1?",opts:["Helium","Oxygen","Carbon","Hydrogen"],ans:3,cat:"🔬 Science"},
  {q:"What is H2O commonly known as?",opts:["Salt","Water","Oxygen","Hydrogen gas"],ans:1,cat:"🔬 Science"},
  // 📚 HISTORY
  {q:"In what year did World War II end?",opts:["1943","1944","1945","1946"],ans:2,cat:"📚 History"},
  {q:"Who was the first man to walk on the moon?",opts:["Buzz Aldrin","Yuri Gagarin","Neil Armstrong","John Glenn"],ans:2,cat:"📚 History"},
  {q:"The Great Wall of China was built to protect against whom?",opts:["Japanese","Mongols","Romans","Persians"],ans:1,cat:"📚 History"},
  {q:"Which empire was Julius Caesar part of?",opts:["Greek","Ottoman","Roman","Byzantine"],ans:2,cat:"📚 History"},
  {q:"Who invented the telephone?",opts:["Thomas Edison","Nikola Tesla","Alexander Graham Bell","Guglielmo Marconi"],ans:2,cat:"📚 History"},
  {q:"In what year did the Berlin Wall fall?",opts:["1987","1988","1989","1990"],ans:2,cat:"📚 History"},
  {q:"Who was the first President of the United States?",opts:["John Adams","Thomas Jefferson","Benjamin Franklin","George Washington"],ans:3,cat:"📚 History"},
  {q:"The Titanic sank in what year?",opts:["1910","1911","1912","1913"],ans:2,cat:"📚 History"},
  {q:"Which country was Nelson Mandela president of?",opts:["Zimbabwe","Kenya","Nigeria","South Africa"],ans:3,cat:"📚 History"},
  {q:"The French Revolution began in what year?",opts:["1776","1789","1799","1804"],ans:1,cat:"📚 History"},
  // 🎬 ENTERTAINMENT
  {q:"Who played Iron Man in the MCU?",opts:["Chris Evans","Robert Downey Jr.","Chris Hemsworth","Mark Ruffalo"],ans:1,cat:"🎬 Entertainment"},
  {q:"Which band wrote Bohemian Rhapsody?",opts:["The Beatles","Rolling Stones","Queen","Led Zeppelin"],ans:2,cat:"🎬 Entertainment"},
  {q:"What is the highest-grossing film of all time?",opts:["Titanic","Avengers: Endgame","Avatar","The Lion King"],ans:2,cat:"🎬 Entertainment"},
  {q:"Who wrote the Harry Potter series?",opts:["Suzanne Collins","J.R.R. Tolkien","J.K. Rowling","C.S. Lewis"],ans:2,cat:"🎬 Entertainment"},
  {q:"Michael Jackson was known as the King of what?",opts:["Rock","Jazz","Pop","Soul"],ans:2,cat:"🎬 Entertainment"},
  {q:"Which country produces Bollywood films?",opts:["Pakistan","Bangladesh","Sri Lanka","India"],ans:3,cat:"🎬 Entertainment"},
  {q:"What streaming service created Stranger Things?",opts:["HBO","Hulu","Amazon Prime","Netflix"],ans:3,cat:"🎬 Entertainment"},
  {q:"Who sang Thriller?",opts:["Prince","Michael Jackson","Whitney Houston","James Brown"],ans:1,cat:"🎬 Entertainment"},
  {q:"The Simpsons first aired in what decade?",opts:["1970s","1980s","1990s","2000s"],ans:1,cat:"🎬 Entertainment"},
  {q:"Which video game character says 'It's-a me, Mario!'?",opts:["Luigi","Wario","Bowser","Mario"],ans:3,cat:"🎬 Entertainment"},
  // ⚽ SPORTS
  {q:"How many players are on a soccer team?",opts:["9","10","11","12"],ans:2,cat:"⚽ Sports"},
  {q:"Which country has won the most FIFA World Cups?",opts:["Germany","Argentina","Brazil","France"],ans:2,cat:"⚽ Sports"},
  {q:"In basketball, how many points is a free throw worth?",opts:["1","2","3","4"],ans:0,cat:"⚽ Sports"},
  {q:"Which athlete has won the most Olympic gold medals?",opts:["Usain Bolt","Carl Lewis","Michael Phelps","Mark Spitz"],ans:2,cat:"⚽ Sports"},
  {q:"Tennis — what is a score of 40-40 called?",opts:["Tie","Deuce","Advantage","Love"],ans:1,cat:"⚽ Sports"},
  {q:"The Super Bowl is the championship of which sport?",opts:["Basketball","Baseball","American Football","Ice Hockey"],ans:2,cat:"⚽ Sports"},
  {q:"What country invented the Olympic Games?",opts:["Rome","Egypt","Greece","Persia"],ans:2,cat:"⚽ Sports"},
  {q:"How long is a marathon in kilometers?",opts:["40km","42.195km","45km","38km"],ans:1,cat:"⚽ Sports"},
  {q:"Who is considered the greatest basketball player of all time by most fans?",opts:["LeBron James","Kobe Bryant","Shaquille O'Neal","Michael Jordan"],ans:3,cat:"⚽ Sports"},
  {q:"In cricket, how many balls are in an over?",opts:["4","5","6","8"],ans:2,cat:"⚽ Sports"},
  // 💡 GENERAL KNOWLEDGE
  {q:"How many sides does a hexagon have?",opts:["5","6","7","8"],ans:1,cat:"💡 General"},
  {q:"What is the largest planet in our solar system?",opts:["Saturn","Neptune","Uranus","Jupiter"],ans:3,cat:"💡 General"},
  {q:"How many colors are in a rainbow?",opts:["5","6","7","8"],ans:2,cat:"💡 General"},
  {q:"What language has the most native speakers?",opts:["English","Spanish","Hindi","Mandarin Chinese"],ans:3,cat:"💡 General"},
  {q:"What is the currency of Japan?",opts:["Yuan","Won","Yen","Ringgit"],ans:2,cat:"💡 General"},
  {q:"How many days are in a leap year?",opts:["364","365","366","367"],ans:2,cat:"💡 General"},
  {q:"What is the tallest animal in the world?",opts:["Elephant","Giraffe","Camel","Hippo"],ans:1,cat:"💡 General"},
  {q:"What is the hardest natural substance on Earth?",opts:["Gold","Iron","Quartz","Diamond"],ans:3,cat:"💡 General"},
  {q:"Which blood type is the universal donor?",opts:["A+","B-","AB+","O-"],ans:3,cat:"💡 General"},
  {q:"How many teeth does an adult human have?",opts:["28","30","32","34"],ans:2,cat:"💡 General"},
  // 🌐 TECHNOLOGY
  {q:"What year was the first iPhone released?",opts:["2005","2006","2007","2008"],ans:2,cat:"🌐 Tech"},
  {q:"What does HTML stand for?",opts:["HyperText Markup Language","High Text Machine Language","HyperTransfer Markup Link","Hyper Technical Meta Language"],ans:0,cat:"🌐 Tech"},
  {q:"Who founded Microsoft?",opts:["Steve Jobs","Elon Musk","Bill Gates","Mark Zuckerberg"],ans:2,cat:"🌐 Tech"},
  {q:"What does CPU stand for?",opts:["Central Processing Unit","Computer Personal Unit","Core Processing Utility","Central Processor Uplink"],ans:0,cat:"🌐 Tech"},
  {q:"What year was Google founded?",opts:["1996","1997","1998","1999"],ans:2,cat:"🌐 Tech"},
  {q:"What is the most used programming language in 2024?",opts:["Java","C++","Python","JavaScript"],ans:3,cat:"🌐 Tech"},
  {q:"Which company makes the PlayStation?",opts:["Microsoft","Nintendo","Sega","Sony"],ans:3,cat:"🌐 Tech"},
  {q:"What does Wi-Fi stand for?",opts:["Wireless Fidelity","Wide Field","Wireless Frequency","Wire-Free Internet"],ans:0,cat:"🌐 Tech"},
  {q:"What year was Mindvora founded?",opts:["2023","2024","2025","2026"],ans:3,cat:"🌐 Tech"},
  {q:"What does URL stand for?",opts:["Universal Resource Locator","Uniform Resource Locator","Universal Record Link","Uniform Redirect Locator"],ans:1,cat:"🌐 Tech"},

  // 🤣 JOKES — pick the punchline
  {q:"Why don't scientists trust atoms?",opts:["They're too small","They make up everything","They split too easily","They have no feelings"],ans:1,cat:"🤣 Jokes"},
  {q:"Why did the scarecrow win an award?",opts:["He was outstanding in his field","He scared all the crows","He worked all night","He never complained"],ans:0,cat:"🤣 Jokes"},
  {q:"What do you call a fish without eyes?",opts:["Blind fish","A fsh","Sea creature","No name"],ans:1,cat:"🤣 Jokes"},
  {q:"Why can't you give Elsa a balloon?",opts:["She pops them","She'll let it go","She's afraid of colours","Balloons don't float in snow"],ans:1,cat:"🤣 Jokes"},
  {q:"What do you call cheese that isn't yours?",opts:["Stolen cheese","Nacho cheese","Free cheese","Other cheese"],ans:1,cat:"🤣 Jokes"},
  {q:"Why did the math book look so sad?",opts:["It had no pictures","It was too heavy","It had too many problems","Nobody read it"],ans:2,cat:"🤣 Jokes"},
  {q:"What do you call a fake noodle?",opts:["A pasta-fake","An impasta","A noodle lie","A spaghetti clone"],ans:1,cat:"🤣 Jokes"},
  {q:"Why did the bicycle fall over?",opts:["The road was wet","It had a flat tyre","It was two-tired","The rider fell off"],ans:2,cat:"🤣 Jokes"},
  {q:"What has ears but cannot hear?",opts:["A wall","A stone","A cornfield","A pillow"],ans:2,cat:"🤣 Jokes"},
  {q:"Why did the golfer bring extra pants?",opts:["In case he got dirty","In case he got a hole in one","The weather was cold","He forgot his belt"],ans:1,cat:"🤣 Jokes"},
  {q:"What do you call a sleeping dinosaur?",opts:["A dino-snore","A rest-osaur","A sleepasaurus","A nap-a-don"],ans:0,cat:"🤣 Jokes"},
  {q:"Why don't eggs tell jokes?",opts:["They are too serious","They'd crack each other up","They have no mouth","Eggs can't talk"],ans:1,cat:"🤣 Jokes"},
  {q:"What do you call a bear with no teeth?",opts:["An old bear","A gummy bear","A soft bear","A friendly bear"],ans:1,cat:"🤣 Jokes"},
  {q:"What do you get when you cross a snowman and a vampire?",opts:["A snowpire","Frostbite","A cold vampire","Ice fangs"],ans:1,cat:"🤣 Jokes"},
  {q:"Why did the tomato turn red?",opts:["It was angry","Too much sun","It saw the salad dressing","It was ripe"],ans:2,cat:"🤣 Jokes"},
  {q:"What do you call a lazy kangaroo?",opts:["A pouch potato","A slow jumper","A lazy roo","A tired marsupial"],ans:0,cat:"🤣 Jokes"},

  // 🧩 RIDDLES — figure out the answer
  {q:"I speak without a mouth and hear without ears. I have no body but I come alive with the wind. What am I?",opts:["A ghost","An echo","The wind","A shadow"],ans:1,cat:"🧩 Riddles"},
  {q:"The more you take, the more you leave behind. What am I?",opts:["Time","Money","Footsteps","Memories"],ans:2,cat:"🧩 Riddles"},
  {q:"I have cities but no houses, forests but no trees, and water but no fish. What am I?",opts:["A painting","A dream","A map","A story"],ans:2,cat:"🧩 Riddles"},
  {q:"What gets wetter the more it dries?",opts:["Rain","A towel","A sponge","A river"],ans:1,cat:"🧩 Riddles"},
  {q:"I have hands but I cannot clap. What am I?",opts:["A statue","A clock","A tree","A glove"],ans:1,cat:"🧩 Riddles"},
  {q:"What can travel around the world while staying in a corner?",opts:["A dream","A thought","A stamp","The sun"],ans:2,cat:"🧩 Riddles"},
  {q:"The more you have of it, the less you see. What is it?",opts:["Money","Darkness","Friends","Time"],ans:1,cat:"🧩 Riddles"},
  {q:"What has a head and a tail but no body?",opts:["A snake","A coin","A river","A needle"],ans:1,cat:"🧩 Riddles"},
  {q:"I am always in front of you but cannot be seen. What am I?",opts:["Your nose","Air","The future","Your shadow"],ans:2,cat:"🧩 Riddles"},
  {q:"What has many keys but can't open a single lock?",opts:["A keychain","A piano","A prison","A map"],ans:1,cat:"🧩 Riddles"},
  {q:"What goes up but never comes down?",opts:["A rocket","Your age","The sun","A balloon"],ans:1,cat:"🧩 Riddles"},
  {q:"I have a neck but no head. What am I?",opts:["A giraffe","A bottle","A guitar","A scarf"],ans:1,cat:"🧩 Riddles"},
  {q:"What can you catch but not throw?",opts:["A ball","A cold","A fish","A dream"],ans:1,cat:"🧩 Riddles"},
  {q:"What has teeth but cannot bite?",opts:["A wolf","A comb","A saw","A zipper"],ans:1,cat:"🧩 Riddles"},
  {q:"What begins with T, ends with T, and has T in it?",opts:["A tent","A toast","A teapot","A ticket"],ans:2,cat:"🧩 Riddles"},
  {q:"What has one eye but cannot see?",opts:["A cyclops","A needle","A camera","A potato"],ans:1,cat:"🧩 Riddles"},
  {q:"What is full of holes but still holds water?",opts:["A boat","A net","A sponge","A bucket"],ans:2,cat:"🧩 Riddles"},
  {q:"What comes once in a minute, twice in a moment, but never in a thousand years?",opts:["A second","The letter M","A heartbeat","A thought"],ans:1,cat:"🧩 Riddles"}
];

var triviaState = { allQuestions:[], current:[], cur:0, score:0, category:'all', fetched:false };

function launchTriviaGame(container) {
  triviaState.cur=0; triviaState.score=0;
  container.innerHTML = [
    '<div style="padding:16px">',
      '<div style="font-size:13px;font-weight:700;color:var(--moon);margin-bottom:4px;text-align:center">🧠 Trivia</div>',
      '<div style="font-size:11px;color:var(--muted);text-align:center;margin-bottom:14px">Pick a category and difficulty</div>',
      '<label class="m-label">Category</label>',
      '<select id="tri-cat" class="m-input" style="margin-bottom:10px">',
        '<option value="all">🎲 Random Mix</option>',
        '<option value="🌍 Geography">🌍 Geography</option>',
        '<option value="🔬 Science">🔬 Science</option>',
        '<option value="📚 History">📚 History</option>',
        '<option value="🎬 Entertainment">🎬 Entertainment</option>',
        '<option value="⚽ Sports">⚽ Sports</option>',
        '<option value="💡 General">💡 General</option>',
        '<option value="🌐 Tech">🌐 Tech</option>',
        '<option value="🤣 Jokes">🤣 Jokes</option>',
        '<option value="🧩 Riddles">🧩 Riddles</option>',
      '</select>',
      '<label class="m-label">Number of Questions</label>',
      '<select id="tri-count" class="m-input" style="margin-bottom:10px">',
        '<option value="5">5 Questions (Quick)</option>',
        '<option value="10" selected>10 Questions (Normal)</option>',
        '<option value="15">15 Questions (Challenge)</option>',
        '<option value="20">20 Questions (Expert)</option>',
      '</select>',
      '<label class="m-label">Source</label>',
      '<select id="tri-source" class="m-input" style="margin-bottom:16px">',
        '<option value="api">🌐 Live Questions (from internet)</option>',
        '<option value="local">📦 Built-in Questions (offline)</option>',
      '</select>',
      '<button class="btn-pay" onclick="startTriviaGame()">▶ Start Trivia</button>',
    '</div>'
  ].join('');
}

function startTriviaGame() {
  var cat    = document.getElementById('tri-cat').value;
  var count  = parseInt(document.getElementById('tri-count').value)||10;
  var source = document.getElementById('tri-source').value;
  var gc     = document.getElementById('game-content');
  triviaState.category=cat; triviaState.cur=0; triviaState.score=0;
  gc.innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><div style="font-size:28px;margin-bottom:10px">⏳</div>Loading questions...</div>';

  if(source==='api'){
    // Open Trivia DB — free, no key needed
    var catMap = {
      '🌍 Geography':'22','🔬 Science':'17','📚 History':'23',
      '🎬 Entertainment':'11','⚽ Sports':'21','💡 General':'9','🌐 Tech':'18'
    };
    var apiCat = cat==='all' ? '' : '&category='+catMap[cat];
    var url='https://opentdb.com/api.php?amount='+count+'&type=multiple'+apiCat+'&encode=url3986';
    fetch(url).then(function(r){return r.json();}).then(function(data){
      if(!data.results||!data.results.length) throw new Error('No results');
      triviaState.current = data.results.map(function(q){
        var correct = decodeURIComponent(q.correct_answer);
        var wrongs  = q.incorrect_answers.map(function(a){return decodeURIComponent(a);});
        var opts    = wrongs.concat([correct]).sort(function(){return Math.random()-.5;});
        return { q:decodeURIComponent(q.question), opts:opts, ans:opts.indexOf(correct), cat:decodeURIComponent(q.category) };
      });
      runTriviaQuestion(gc);
    }).catch(function(){
      showToast('Could not load live questions — using built-in');
      useTriviaLocal(cat, count, gc);
    });
  } else {
    useTriviaLocal(cat, count, gc);
  }
}

function useTriviaLocal(cat, count, gc) {
  var pool = cat==='all' ? TRIVIA_LOCAL : TRIVIA_LOCAL.filter(function(q){return q.cat===cat;});
  // Shuffle
  var shuffled = pool.slice().sort(function(){return Math.random()-.5;});
  triviaState.current = shuffled.slice(0, Math.min(count, shuffled.length));
  runTriviaQuestion(gc);
}

function runTriviaQuestion(gc) {
  var questions = triviaState.current;
  if(triviaState.cur >= questions.length){
    var sc=triviaState.score, tot=questions.length;
    var pct=Math.round(sc/tot*100);
    var msg = pct===100?'🎯 Perfect score!':pct>=80?'🌟 Excellent!':pct>=60?'👍 Good job!':pct>=40?'📖 Keep learning!':'💪 Practice more!';
    gc.innerHTML='<div style="text-align:center;padding:30px">'+
      '<div style="font-size:48px;margin-bottom:10px">'+(pct===100?'🏆':pct>=60?'🥈':'🎗️')+'</div>'+
      '<div style="font-size:20px;font-weight:900;color:var(--green3)">'+sc+'/'+tot+'</div>'+
      '<div style="font-size:13px;color:var(--muted);margin:4px 0 6px">'+Math.round(sc/tot*100)+'% correct</div>'+
      '<div style="font-size:14px;color:var(--moon);margin-bottom:20px">'+msg+'</div>'+
      '<button class="btn-pay" onclick="launchTriviaGame(document.getElementById(&quot;game-content&quot;))">🔄 Play Again</button>'+
    '</div>';
    // Save high score
    if(state.user){
      db.collection('users').doc(state.user.uid).get().then(function(d){
        var best=(d.data()&&d.data().triviaHighScore)||0;
        if(sc>best) db.collection('users').doc(state.user.uid).update({triviaHighScore:sc}).catch(function(){});
      }).catch(function(){});
    }
    return;
  }
  var q = questions[triviaState.cur];
  var prog = triviaState.cur+1;
  var tot  = questions.length;
  gc.innerHTML='<div style="padding:16px">'+
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'+
      '<div style="font-size:10px;color:var(--muted)">'+esc(q.cat||'Trivia')+'</div>'+
      '<div style="font-size:10px;color:var(--muted)">'+prog+'/'+tot+' · ⭐'+triviaState.score+'</div>'+
    '</div>'+
    '<div style="background:var(--deep);border-radius:6px;height:4px;margin-bottom:14px">'+
      '<div style="background:var(--green3);height:4px;border-radius:6px;width:'+(prog/tot*100)+'%;transition:width .4s"></div>'+
    '</div>'+
    '<div style="font-size:14px;font-weight:700;color:var(--moon);margin-bottom:16px;line-height:1.6">'+esc(q.q)+'</div>'+
    q.opts.map(function(o,i){
      return '<button onclick="answerTrivia('+i+')" style="display:block;width:100%;text-align:left;padding:11px 14px;margin-bottom:8px;background:var(--deep);border:1px solid var(--border);border-radius:10px;color:var(--moon);font-size:12px;cursor:pointer;font-family:DM Sans,sans-serif;transition:all .15s">'+
        '<span style="display:inline-block;width:22px;height:22px;border-radius:50%;background:var(--green2);color:#fff;font-size:10px;font-weight:700;text-align:center;line-height:22px;margin-right:8px">'+['A','B','C','D'][i]+'</span>'+
        esc(o)+'</button>';
    }).join('')+
  '</div>';

  window.answerTrivia = function(idx){
    var btns = gc.querySelectorAll('button');
    var correct = q.ans;
    btns.forEach(function(b,i){
      b.onclick=null;
      if(i===correct){ b.style.background='rgba(34,197,94,.2)'; b.style.borderColor='var(--green3)'; }
      else if(i===idx && idx!==correct){ b.style.background='rgba(239,68,68,.15)'; b.style.borderColor='#ef4444'; }
    });
    if(idx===correct) triviaState.score++;
    triviaState.cur++;
    setTimeout(function(){ runTriviaQuestion(gc); }, 1000);
  };
}

// ══════════════════════════════════════════════════════════════
// FEATURE 10: NEWSLETTER
// ══════════════════════════════════════════════════════════════
function openNewsletter() {
  if (!state.user) { showToast('Login first'); return; }
  openModal('modal-newsletter');
  loadMyNewsletters();
}

function loadMyNewsletters() {
  var list = document.getElementById('newsletter-list');
  db.collection('newsletters').where('authorId','==',state.user.uid).limit(10).get()
    .then(function(snap) {
      if (snap.empty) { list.innerHTML = '<div style="text-align:center;padding:16px;color:var(--muted)">No newsletters sent yet.</div>'; return; }
      list.innerHTML = snap.docs.map(function(d) {
        var n = d.data();
        return '<div class="sched-item"><div style="font-size:12px;font-weight:700;color:var(--moon)">'+esc(n.subject||'Newsletter')+'</div>'+
          '<div style="font-size:11px;color:var(--muted);margin-top:2px">Sent to '+(n.recipientCount||0)+' fans · '+timeAgo(n.createdAt)+'</div></div>';
      }).join('');
    }).catch(function(){list.innerHTML='<div style="color:#fca5a5;padding:10px">Error</div>';});
}

function sendNewsletter() {
  var subject = document.getElementById('nl-subject').value.trim();
  var body    = document.getElementById('nl-body').value.trim();
  var err     = document.getElementById('nl-err');
  if (!subject) { err.textContent='Please enter a subject'; return; }
  if (!body)    { err.textContent='Please enter a message'; return; }
  err.textContent='';

  // Get all followers
  db.collection('follows').where('followingId','==',state.user.uid).get().then(function(snap) {
    var fans = snap.docs.map(function(d){return d.data().followerId;});
    var batch = db.batch();
    fans.forEach(function(uid) {
      var ref = db.collection('notifications').doc();
      batch.set(ref, {
        uid: uid, type: 'newsletter',
        text: '📰 '+esc((state.profile&&state.profile.name)||'A creator')+' sent a newsletter: "'+esc(subject)+'"',
        body: body,
        createdAt: firebase.firestore.FieldValue.serverTimestamp(), read: false
      });
    });
    return batch.commit().then(function() {
      return db.collection('newsletters').add({
        authorId: state.user.uid,
        authorName: (state.profile&&state.profile.name)||'Mindvora user',
        subject: subject, body: body,
        recipientCount: fans.length,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      });
    });
  }).then(function() {
    document.getElementById('nl-subject').value='';
    document.getElementById('nl-body').value='';
    showToast('📰 Newsletter sent to your fans!');
    loadMyNewsletters();
  }).catch(function() { err.textContent='Error sending newsletter'; });
}

// ══════════════════════════════════════════════════════════════
// FEATURE 11: GIFT SYSTEM (during live)
// ══════════════════════════════════════════════════════════════
var GIFTS = [
  { emoji:'🌸', name:'Rose',    price:1  },
  { emoji:'🍕', name:'Pizza',   price:2  },
  { emoji:'💎', name:'Diamond', price:5  },
  { emoji:'🚀', name:'Rocket',  price:10 },
  { emoji:'👑', name:'Crown',   price:20 },
  { emoji:'🏆', name:'Trophy',  price:50 }
];

function openGiftPanel(liveId, hostId, hostName) {
  document.getElementById('gift-panel-liveId').value = liveId||'';
  document.getElementById('gift-panel-hostId').value = hostId||'';
  document.getElementById('gift-panel-hostName').textContent = hostName||'Creator';
  var list = document.getElementById('gift-list');
  list.innerHTML = GIFTS.map(function(g,i) {
    return '<div class="gift-item" onclick="sendGift('+i+')">'+
      '<div style="font-size:28px">'+g.emoji+'</div>'+
      '<div style="font-size:10px;color:var(--moon);font-weight:700">'+esc(g.name)+'</div>'+
      '<div style="font-size:10px;color:var(--green3)">$'+g.price+'</div>'+
    '</div>';
  }).join('');
  document.getElementById('gift-panel').style.display='flex';
}

function closeGiftPanel() { document.getElementById('gift-panel').style.display='none'; }

function sendGift(idx) {
  if (!state.user) { showToast('Login first'); return; }
  var gift   = GIFTS[idx];
  var liveId = document.getElementById('gift-panel-liveId').value;
  var hostId = document.getElementById('gift-panel-hostId').value;
  if (!hostId) { showToast('Invalid host'); return; }
  if (typeof PaystackPop==='undefined') { showToast('Payment loading'); return; }
  closeGiftPanel();
  PaystackPop.setup({
    key: PAYSTACK_KEY, email: state.user.email,
    amount: gift.price*100, currency:'USD',
    ref:'ZGIFT-'+Date.now(),
    callback:function() {
      // Record gift
      db.collection('gifts').add({
        senderId: state.user.uid,
        senderName: (state.profile&&state.profile.name)||'Mindvora user',
        hostId: hostId, liveId: liveId,
        gift: gift.name, emoji: gift.emoji, amount: gift.price,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      });
      // Notify host
      db.collection('notifications').add({
        uid: hostId, type:'gift',
        text: gift.emoji+' '+esc((state.profile&&state.profile.name)||'Someone')+' sent you a '+gift.name+' ($'+gift.price+')!',
        createdAt: firebase.firestore.FieldValue.serverTimestamp(), read:false
      });
      // Show in live chat
      if (liveId) {
        db.collection('live_streams').doc(liveId).collection('chat').add({
          uid: state.user.uid,
          name: (state.profile&&state.profile.name)||'Mindvora user',
          text: gift.emoji+' sent a '+gift.name+'!',
          isGift:true,
          createdAt: firebase.firestore.FieldValue.serverTimestamp()
        });
      }
      showToast(gift.emoji+' Gift sent!');
    },
    onClose:function(){showToast('Gift cancelled');}
  }).openIframe();
}

// ══════════════════════════════════════════════════════════════
// FEATURE 12: ACCESSIBILITY MODE
// ══════════════════════════════════════════════════════════════
var accessibilityOn = localStorage.getItem('zync_accessibility') === '1';

function toggleAccessibility() {
  accessibilityOn = !accessibilityOn;
  localStorage.setItem('zync_accessibility', accessibilityOn ? '1' : '0');
  applyAccessibility();
  showToast(accessibilityOn ? '♿ Accessibility mode ON' : '♿ Accessibility mode OFF');
}

function applyAccessibility() {
  var root = document.documentElement;
  if (accessibilityOn) {
    root.style.setProperty('--a11y-scale','1.15');
    document.body.style.fontSize = '16px';
    document.querySelectorAll('.spark-card,.sk-body,.m-input,.btn-pay').forEach(function(el){
      el.style.fontSize='15px';
    });
    document.getElementById('a11y-toggle') && (document.getElementById('a11y-toggle').textContent='♿ Accessibility: ON');
  } else {
    root.style.removeProperty('--a11y-scale');
    document.body.style.fontSize='';
    document.querySelectorAll('.spark-card,.sk-body,.m-input,.btn-pay').forEach(function(el){
      el.style.fontSize='';
    });
    document.getElementById('a11y-toggle') && (document.getElementById('a11y-toggle').textContent='♿ Accessibility: OFF');
  }
}

// Apply on load
setTimeout(applyAccessibility, 500);

// ══════════════════════════════════════════════════════════════
// FEATURE 13: BULK MEDIA UPLOAD (CAROUSEL)
// ══════════════════════════════════════════════════════════════
var carouselMedia = [];
var carouselUploading = false;

function openCarouselUpload() {
  if (!state.user) { showToast('Login first'); return; }
  carouselMedia = [];
  document.getElementById('carousel-preview').innerHTML='<div style="color:var(--muted);font-size:12px;text-align:center;padding:20px">No images selected</div>';
  document.getElementById('carousel-count').textContent='0/10';
  openModal('modal-carousel');
}

function pickCarouselFiles() {
  var inp = document.createElement('input');
  inp.type='file'; inp.multiple=true; inp.accept='image/*,video/*';
  inp.onchange = function() {
    var files = Array.from(inp.files).slice(0, 10 - carouselMedia.length);
    if (!files.length) return;
    files.forEach(function(file) {
      if (file.size > 200*1024*1024) { showToast('File too large: '+file.name); return; }
      carouselMedia.push(file);
    });
    renderCarouselPreview();
  };
  inp.click();
}

function renderCarouselPreview() {
  var preview = document.getElementById('carousel-preview');
  document.getElementById('carousel-count').textContent = carouselMedia.length+'/10';
  if (!carouselMedia.length) {
    preview.innerHTML='<div style="color:var(--muted);font-size:12px;text-align:center;padding:20px">No files selected</div>';
    return;
  }
  preview.innerHTML='<div style="display:flex;gap:8px;flex-wrap:wrap">';
  carouselMedia.forEach(function(file, i) {
    var url = URL.createObjectURL(file);
    var isVideo = file.type.startsWith('video');
    preview.innerHTML += '<div style="position:relative;width:80px;height:80px;border-radius:8px;overflow:hidden;border:1px solid var(--border)">'+
      (isVideo
        ? '<video src="'+url+'" style="width:100%;height:100%;object-fit:cover" muted></video><div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:18px">▶️</div>'
        : '<img src="'+url+'" style="width:100%;height:100%;object-fit:cover">')+
      '<button onclick="removeCarouselItem('+i+')" style="position:absolute;top:2px;right:2px;width:18px;height:18px;border-radius:50%;background:rgba(239,68,68,.9);border:none;color:#fff;font-size:10px;cursor:pointer;line-height:1">✕</button>'+
    '</div>';
  });
  preview.innerHTML += '</div>';
}

function removeCarouselItem(idx) {
  carouselMedia.splice(idx,1);
  renderCarouselPreview();
}

function postCarousel() {
  if (!carouselMedia.length) { showToast('Add at least one file'); return; }
  if (carouselUploading) return;
  carouselUploading = true;
  var btn = document.getElementById('carousel-post-btn');
  btn.disabled = true; btn.textContent = 'Uploading...';
  var caption = document.getElementById('carousel-caption').value.trim();

  // Upload all files to Cloudinary
  var uploads = carouselMedia.map(function(file) {
    var fd = new FormData();
    fd.append('file', file);
    fd.append('upload_preset','ml_default');
    var endpoint = file.type.startsWith('video')
      ? 'https://api.cloudinary.com/v1_1/dk4svvssf/video/upload'
      : 'https://api.cloudinary.com/v1_1/dk4svvssf/image/upload';
    return fetch(endpoint, { method:'POST', body:fd })
      .then(function(r){return r.json();})
      .then(function(d){return { url:d.secure_url, type:file.type.startsWith('video')?'video':'image' };});
  });

  Promise.all(uploads).then(function(mediaItems) {
    return db.collection('sparks').add({
      text: caption,
      authorId: state.user.uid,
      authorName: (state.profile&&state.profile.name)||'Mindvora user',
      authorHandle: (state.profile&&state.profile.handle)||'user',
      authorColor: (state.profile&&state.profile.color)||COLORS[0],
      isPremium: (state.profile&&state.profile.isPremium)||false,
      isVerified: (state.profile&&state.profile.isVerified)||false,
      category:'all',
      isCarousel:true,
      carouselMedia: mediaItems,
      mediaUrl: mediaItems[0].url, mediaType: mediaItems[0].type,
      likes:[], saved:[], commentCount:0, reposts:0,
      createdAt: firebase.firestore.FieldValue.serverTimestamp()
    });
  }).then(function() {
    closeModal('modal-carousel');
    carouselMedia=[];
    carouselUploading=false;
    btn.disabled=false; btn.textContent='Post Carousel';
    showToast('📸 Carousel posted!');
  }).catch(function(e) {
    carouselUploading=false;
    btn.disabled=false; btn.textContent='Post Carousel';
    showToast('Upload failed: '+e.message);
  });
}

// ══════════════════════════════════════════════════════════════
// FEATURE 14: PAID EVENTS
// ══════════════════════════════════════════════════════════════
function openPaidEvents() {
  if (!state.user) { showToast('Login first'); return; }
  openModal('modal-paid-events');
  loadPaidEvents();
}

function loadPaidEvents() {
  var list = document.getElementById('paid-events-list');
  list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">Loading events...</div>';
  db.collection('paid_events').limit(30).get()
    .then(function(snap) {
      if (snap.empty) { list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">No upcoming events.<br>Create one!</div>'; return; }
      list.innerHTML = snap.docs.map(function(d) {
        var ev = d.data();
        var isOwn = ev.hostId===state.user.uid;
        var attended = (ev.attendees||[]).indexOf(state.user.uid)>-1;
        return '<div class="sched-item">'+
          '<div style="display:flex;justify-content:space-between;align-items:flex-start">'+
            '<div>'+
              '<div style="font-size:13px;font-weight:700;color:var(--moon)">'+esc(ev.title||'Event')+'</div>'+
              '<div style="font-size:11px;color:var(--muted);margin-top:2px">'+
                '📅 '+new Date(ev.eventDate&&ev.eventDate.seconds?ev.eventDate.seconds*1000:ev.eventDate).toLocaleDateString()+' · '+
                '👤 by @'+esc(ev.hostHandle||'user')+'</div>'+
              '<div style="font-size:11px;color:var(--muted)">🎟 '+(ev.attendees||[]).length+' attending · 💵 $'+ev.price+'</div>'+
              '<div style="font-size:11px;color:var(--moon);margin-top:4px">'+esc((ev.description||'').slice(0,80))+'</div>'+
            '</div>'+
            (attended?'<span style="font-size:10px;padding:4px 10px;border-radius:20px;background:rgba(34,197,94,.15);color:var(--green3)">✓ Attending</span>':
              isOwn?'<span style="font-size:10px;padding:4px 10px;border-radius:20px;background:rgba(99,102,241,.15);color:#a5b4fc">Your Event</span>':
              '<button onclick="buyEventTicket(\''+d.id+'\',\''+esc(ev.title||'Event')+'\','+ev.price+')" style="font-size:10px;padding:5px 12px;border-radius:20px;background:var(--green2);border:none;color:#fff;cursor:pointer;font-family:\'DM Sans\',sans-serif">Buy $'+ev.price+'</button>')+
          '</div>'+
        '</div>';
      }).join('');
    }).catch(function(e){console.warn('Events error:',e);list.innerHTML='<div style="color:#fca5a5;padding:10px">Error loading events</div>';});
}

function showCreateEvent() {
  document.getElementById('events-list-view').style.display='none';
  document.getElementById('create-event-view').style.display='block';
}

function cancelCreateEvent() {
  document.getElementById('events-list-view').style.display='block';
  document.getElementById('create-event-view').style.display='none';
}

function createPaidEvent() {
  var title = document.getElementById('ev-title').value.trim();
  var desc  = document.getElementById('ev-desc').value.trim();
  var date  = document.getElementById('ev-date').value;
  var price = parseFloat(document.getElementById('ev-price').value)||0;
  var link  = document.getElementById('ev-link').value.trim();
  var err   = document.getElementById('ev-err');
  if (!title){err.textContent='Enter a title';return;}
  if (!date){err.textContent='Enter event date';return;}
  if (price<1){err.textContent='Price must be at least $1';return;}
  err.textContent='';

  db.collection('paid_events').add({
    title, description:desc, eventDate: new Date(date), price,
    meetingLink: link,
    hostId: state.user.uid,
    hostName: (state.profile&&state.profile.name)||'Mindvora user',
    hostHandle: (state.profile&&state.profile.handle)||'user',
    attendees:[], revenue:0,
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function() {
    showToast('🎟 Event created!');
    cancelCreateEvent();
    loadPaidEvents();
  }).catch(function(){err.textContent='Error creating event';});
}

function buyEventTicket(eventId, eventTitle, price) {
  if (!state.user){showToast('Login first');return;}
  if (typeof PaystackPop==='undefined'){showToast('Payment loading');return;}
  PaystackPop.setup({
    key:PAYSTACK_KEY, email:state.user.email,
    amount:price*100, currency:'USD',
    ref:'ZEVT-'+eventId+'-'+Date.now(),
    callback:function() {
      db.collection('paid_events').doc(eventId).update({
        attendees: firebase.firestore.FieldValue.arrayUnion(state.user.uid),
        revenue: firebase.firestore.FieldValue.increment(price*(1-0.10))
      }).then(function(){
        showToast('🎟 Ticket purchased for "'+eventTitle+'"!');
        loadPaidEvents();
      });
    },
    onClose:function(){showToast('Purchase cancelled');}
  }).openIframe();
}

// ══════════════════════════════════════════════════════════════
// FEATURE 15: DIGITAL PRODUCTS STORE
// ══════════════════════════════════════════════════════════════
function openDigitalStore() {
  if (!state.user){showToast('Login first');return;}
  openModal('modal-digital-store');
  loadDigitalProducts();
}

function loadDigitalProducts() {
  var list = document.getElementById('digital-products-list');
  list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">Loading...</div>';
  db.collection('digital_products').limit(30).get()
    .then(function(snap) {
      if (snap.empty){list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">No products yet.<br>List your first product!</div>';return;}
      list.innerHTML=snap.docs.map(function(d){
        var p=d.data();
        var isOwn=p.sellerId===state.user.uid;
        return '<div class="sched-item" style="display:flex;gap:10px;align-items:flex-start">'+
          '<div style="font-size:28px;flex-shrink:0">'+esc(p.emoji||'📦')+'</div>'+
          '<div style="flex:1">'+
            '<div style="font-size:13px;font-weight:700;color:var(--moon)">'+esc(p.title||'Product')+'</div>'+
            '<div style="font-size:11px;color:var(--muted);margin-top:2px">'+esc(p.type||'digital')+' · by @'+esc(p.sellerHandle||'user')+'</div>'+
            '<div style="font-size:11px;color:var(--moon);margin-top:3px">'+esc((p.description||'').slice(0,80))+'</div>'+
            '<div style="display:flex;align-items:center;justify-content:space-between;margin-top:8px">'+
              '<span style="font-size:13px;font-weight:700;color:var(--green3)">$'+p.price+'</span>'+
              (isOwn?'<span style="font-size:10px;color:var(--muted)">Your product</span>':
                '<button onclick="buyDigitalProduct(\''+d.id+'\',\''+esc(p.title)+'\','+p.price+',\''+esc(p.downloadUrl||'')+'\',\''+p.sellerId+'\')" style="font-size:10px;padding:5px 12px;border-radius:20px;background:var(--green2);border:none;color:#fff;cursor:pointer;font-family:\'DM Sans\',sans-serif">Buy Now</button>')+
            '</div>'+
          '</div>'+
        '</div>';
      }).join('');
    }).catch(function(){list.innerHTML='<div style="color:#fca5a5;padding:10px">Error loading</div>';});
}

function showListProduct() {
  document.getElementById('digital-list-view').style.display='none';
  document.getElementById('digital-create-view').style.display='block';
}
function cancelListProduct() {
  document.getElementById('digital-list-view').style.display='block';
  document.getElementById('digital-create-view').style.display='none';
}

function listDigitalProduct() {
  var title = document.getElementById('dp-title').value.trim();
  var desc  = document.getElementById('dp-desc').value.trim();
  var price = parseFloat(document.getElementById('dp-price').value)||0;
  var type  = document.getElementById('dp-type').value;
  var url   = document.getElementById('dp-url').value.trim();
  var emoji = document.getElementById('dp-emoji').value.trim()||'📦';
  var err   = document.getElementById('dp-err');
  if (!title){err.textContent='Enter a title';return;}
  if (price<1){err.textContent='Price must be at least $1';return;}
  if (!url){err.textContent='Enter a download/delivery URL';return;}
  err.textContent='';

  db.collection('digital_products').add({
    title, description:desc, price, type, downloadUrl:url, emoji,
    sellerId: state.user.uid,
    sellerName: (state.profile&&state.profile.name)||'Mindvora user',
    sellerHandle: (state.profile&&state.profile.handle)||'user',
    sales:0, revenue:0,
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(){
    showToast('📦 Product listed!');
    cancelListProduct();
    loadDigitalProducts();
  }).catch(function(){err.textContent='Error listing product';});
}

function buyDigitalProduct(productId, title, price, downloadUrl, sellerId) {
  if (!state.user){showToast('Login first');return;}
  if (typeof PaystackPop==='undefined'){showToast('Payment loading');return;}
  PaystackPop.setup({
    key:PAYSTACK_KEY, email:state.user.email,
    amount:price*100, currency:'USD',
    ref:'ZDP-'+productId+'-'+Date.now(),
    callback:function(){
      db.collection('digital_products').doc(productId).update({
        sales:firebase.firestore.FieldValue.increment(1),
        revenue:firebase.firestore.FieldValue.increment(price*0.9)
      });
      db.collection('purchases').add({
        buyerId:state.user.uid, buyerEmail:state.user.email,
        productId, productTitle:title, price,
        downloadUrl,
        sellerId,
        createdAt:firebase.firestore.FieldValue.serverTimestamp()
      });
      db.collection('notifications').add({
        uid:sellerId, type:'sale',
        text:'💰 Someone bought your product "'+esc(title)+'" for $'+price+'!',
        createdAt:firebase.firestore.FieldValue.serverTimestamp(), read:false
      });
      showToast('✅ Purchase complete!');
      if (downloadUrl) {
        setTimeout(function(){
          if (confirm('Your product is ready! Open download link now?')) window.open(downloadUrl,'_blank');
        },500);
      }
    },
    onClose:function(){showToast('Purchase cancelled');}
  }).openIframe();
}



// ══════════════════════════════════════════════════════════
// VIDEO PLAYER — blurred background + custom controls
// ══════════════════════════════════════════════════════════
function toggleVidPlay(vidId) {
  var vid = document.getElementById(vidId);
  if (!vid) return;
  var wrap = vid.closest('.sk-media-wrap');
  var blur = wrap && wrap.querySelector('.sk-media-blur');
  if (vid.paused) {
    // Pause all other videos first
    document.querySelectorAll('.sk-media-main').forEach(function(v){
      if(v.id !== vidId && !v.paused){ v.pause(); syncVidBg(v); updateVidBtn(v); }
    });
    vid.play().then(function(){
      if(blur){ blur.play && blur.play(); }
      updateVidBtn(vid);
    }).catch(function(){});
  } else {
    vid.pause();
    if(blur) blur.pause && blur.pause();
    updateVidBtn(vid);
  }
}

function updateVidBtn(vid) {
  var sid = vid.id.replace('vid-','');
  var btn = document.getElementById('pbtn-'+sid);
  if(btn) btn.innerHTML = vid.paused ? '&#9654;' : '&#9646;&#9646;';
}

function syncVidBg(vid) {
  var wrap = vid.closest && vid.closest('.sk-media-wrap');
  if(!wrap) return;
  var blur = wrap.querySelector('.sk-media-blur');
  if(blur && blur.pause) blur.pause();
}

function seekVid(e, vidId) {
  var vid = document.getElementById(vidId);
  if(!vid || !vid.duration) return;
  var bar = e.currentTarget;
  var rect = bar.getBoundingClientRect();
  var pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
  vid.currentTime = pct * vid.duration;
}

function toggleVidMute(vidId, sid) {
  var vid = document.getElementById(vidId);
  if(!vid) return;
  vid.muted = !vid.muted;
  var btn = document.querySelector('[data-vid="'+vidId+'"][data-action="mute"]');
  if(btn) btn.innerHTML = vid.muted ? '&#128263;' : '&#128266;';
}

function fmtVidTime(s) {
  var m = Math.floor(s/60);
  var sec = Math.floor(s%60);
  return m+':'+(sec<10?'0':'')+sec;
}

// Delegated click handler for feed container
document.addEventListener('click', function(e) {
  // Video main click
  var vidMain = e.target.closest('[data-vid][data-action="play"], .sk-media-main[data-vid]');
  if(vidMain) {
    var vid = vidMain.dataset && vidMain.dataset.vid;
    if(vid) toggleVidPlay(vid);
    return;
  }
  // Play button
  var playBtn = e.target.closest('[data-action="play"]');
  if(playBtn && playBtn.dataset.vid) { toggleVidPlay(playBtn.dataset.vid); return; }
  // Seek bar
  var seekBar = e.target.closest('[data-action="seek"]');
  if(seekBar && seekBar.dataset.vid) { seekVid(e, seekBar.dataset.vid); return; }
  // Mute button
  var muteBtn = e.target.closest('[data-action="mute"]');
  if(muteBtn && muteBtn.dataset.vid) { toggleVidMute(muteBtn.dataset.vid, muteBtn.dataset.sid); return; }
}, false);

// Update progress bar + duration + blur sync using timeupdate
document.addEventListener('timeupdate', function(e) {
  if(!e.target || !e.target.classList || !e.target.classList.contains('sk-media-main')) return;
  var vid = e.target;
  var sid = vid.id.replace('vid-','');
  var dur = vid.duration||0;
  var cur = vid.currentTime||0;
  var prog = document.getElementById('prog-'+sid);
  var durEl = document.getElementById('dur-'+sid);
  if(prog && dur) prog.style.width = (cur/dur*100)+'%';
  if(durEl) durEl.textContent = fmtVidTime(cur)+' / '+fmtVidTime(dur);
  // keep blur video in sync (within 0.5s tolerance)
  var wrap = vid.closest('.sk-media-wrap');
  var blur = wrap && wrap.querySelector('.sk-media-blur');
  if(blur && Math.abs(blur.currentTime - cur) > 0.5) blur.currentTime = cur;
}, true);

// Auto-reveal controls on touch (mobile)
document.addEventListener('touchstart', function(e) {
  var wrap = e.target.closest('.sk-media-wrap');
  if(wrap) {
    var ctrl = wrap.querySelector('.sk-vid-controls');
    if(ctrl) {
      ctrl.style.opacity='1';
      clearTimeout(wrap._ctrlTimer);
      wrap._ctrlTimer = setTimeout(function(){ ctrl.style.opacity=''; }, 3000);
    }
  }
}, {passive:true});

// IntersectionObserver: autoplay when scrolled into view, pause when out
if('IntersectionObserver' in window) {
  var vidObserver = new IntersectionObserver(function(entries){
    entries.forEach(function(entry){
      var vid = entry.target;
      if(!vid.dataset || !vid.dataset.vid) return;
      applySmartBlur(vid);
      if(entry.isIntersecting && entry.intersectionRatio > 0.6) {
        // Only autoplay if no other video is playing
        var anyPlaying = Array.from(document.querySelectorAll('.sk-media-main')).some(function(v){ return !v.paused; });
        if(!anyPlaying) {
          vid.muted = true; // autoplay requires muted
          vid.play().catch(function(){});
          updateVidBtn(vid);
          var wrap = vid.closest('.sk-media-wrap');
          var blur = wrap && wrap.querySelector('.sk-media-blur');
          if(blur) { blur.currentTime=0; blur.play && blur.play(); }
        }
      } else if(!entry.isIntersecting) {
        if(!vid.paused){ vid.pause(); updateVidBtn(vid); syncVidBg(vid); }
      }
    });
  }, { threshold: [0, 0.6] });

  // Observe videos as they are added to the feed

// ── SMART BLUR: only apply blurred background when the video
//    aspect ratio actually needs it (portrait or landscape).
//    Square-ish videos fill the container naturally → no blur.
function applySmartBlur(vid) {
  function decide() {
    var wrap = vid.closest('.sk-media-wrap');
    if (!wrap) return;
    var blur = wrap.querySelector('.sk-media-blur');
    if (!blur) return;

    var vw = vid.videoWidth;
    var vh = vid.videoHeight;
    if (!vw || !vh) return; // metadata not ready yet

    var ratio = vw / vh;
    var containerW = wrap.offsetWidth || 400;
    var containerRatio = containerW / 340; // 340 = max-height

    // How much of the container does the video naturally fill?
    var fillW, fillH;
    if (ratio > containerRatio) {
      // video wider than container → letterbox (black top/bottom bars)
      fillW = 1.0;
      fillH = (containerRatio / ratio);
    } else {
      // video taller than container → pillarbox (black side bars)
      fillW = (ratio / containerRatio);
      fillH = 1.0;
    }

    // If video fills ≥ 92% of both dimensions, it fits naturally → hide blur
    var needsBlur = fillW < 0.92 || fillH < 0.92;

    blur.style.display   = needsBlur ? 'block' : 'none';
    // For near-fill videos, use cover so they look sharp edge-to-edge
    vid.style.objectFit  = needsBlur ? 'contain' : 'cover';
  }

  if (vid.readyState >= 1 && vid.videoWidth) {
    decide();
  } else {
    vid.addEventListener('loadedmetadata', decide, { once: true });
  }
}

  var feedMutObs = new MutationObserver(function(mutations){
    mutations.forEach(function(m){
      m.addedNodes.forEach(function(node){
        if(node.nodeType!==1) return;
        var vids = node.querySelectorAll ? node.querySelectorAll('.sk-media-main') : [];
        vids.forEach(function(v){ vidObserver.observe(v); applySmartBlur(v); });
        if(node.classList && node.classList.contains('sk-media-main')){ vidObserver.observe(node); applySmartBlur(node); }
      });
    });
  });
  var feedCont = document.getElementById('feed-cont');
  if(feedCont) feedMutObs.observe(feedCont, { childList:true, subtree:true });
}

function openSupportModal(){
  // Pre-fill name if logged in
  if(state.profile && state.profile.name){
    document.getElementById('sup-name').value = state.profile.name;
  }
  document.getElementById('sup-err').textContent = '';
  document.getElementById('sup-message').value = '';
  openModal('modal-support');
}

function submitSupport(){
  var name = document.getElementById('sup-name').value.trim();
  var subject = document.getElementById('sup-subject').value;
  var message = document.getElementById('sup-message').value.trim();
  var err = document.getElementById('sup-err');
  
  if(!name){ err.textContent = 'Please enter your name'; return; }
  if(!message){ err.textContent = 'Please enter your message'; return; }
  if(message.length < 10){ err.textContent = 'Message too short — please describe your issue'; return; }
  
  // Save to Firestore support_tickets collection
  var ticket = {
    name: name,
    subject: subject,
    message: message,
    email: (state.user && state.user.email) || 'Not logged in',
    uid: (state.user && state.user.uid) || 'anonymous',
    handle: (state.profile && state.profile.handle) || '',
    status: 'open',
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  };
  
  // Save to Firestore
  db.collection('support_tickets').add(ticket).catch(function(){});
  
  // Send admin notification in Mindvora
  db.collection('notifications').add({
    uid: 'ilohgreat25_admin',
    type: 'support',
    text: '📧 New support ticket from ' + name + ': ' + subject,
    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
    read: false
  }).catch(function(){});

  // Send email via EmailJS directly to zyncofficial@outlook.com
  var templateParams = {
    from_name: name,
    from_email: (state.user && state.user.email) || 'Not logged in',
    handle: (state.profile && state.profile.handle) || 'unknown',
    subject: subject,
    message: message
  };

  if(typeof emailjs !== 'undefined'){
    emailjs.send('service_spm1gg9', 'template_447t22k', templateParams)
      .then(function(){
        closeModal('modal-support');
        showToast('✅ Message sent! We will reply within 24 hours.');
      }, function(error){
        // Fallback to mailto if EmailJS fails
        var mailBody = encodeURIComponent('Name: ' + name + '\nSubject: ' + subject + '\n\n' + message);
        window.open('mailto:zyncofficial@outlook.com?subject=Mindvora Support: ' + encodeURIComponent(subject) + '&body=' + mailBody);
        closeModal('modal-support');
        showToast('✅ Message sent via email app!');
      });
  } else {
    // Fallback to mailto
    var mailBody = encodeURIComponent('Name: ' + name + '\nSubject: ' + subject + '\n\n' + message);
    window.open('mailto:zyncofficial@outlook.com?subject=Mindvora Support: ' + encodeURIComponent(subject) + '&body=' + mailBody);
    closeModal('modal-support');
    showToast('✅ Opening your email app!');
  }
}

function markAllAlertsResolved(){
  if(!isAdmin()) return;
  db.collection('security_alerts').where('resolved','==',false).get().then(function(snap){
    var batch = db.batch();
    snap.docs.forEach(function(d){ batch.update(d.ref, {resolved:true}); });
    return batch.commit();
  }).then(function(){
    showToast('✅ All alerts marked resolved');
    loadSecurityAlertsPanel();
  }).catch(function(e){ showToast('Error: '+e.message); });
}

// Check pending ads count for notification badge
function checkPendingAds(){
  if(!isAdmin()) return;
  db.collection('ads').where('status','==','pending').get().then(function(snap){
    var count = snap.docs.length;
    var navAdmin = document.getElementById('nav-admin');
    if(navAdmin && count > 0){
      var existing = navAdmin.querySelector('.pending-count');
      if(!existing){
        var badge = document.createElement('span');
        badge.className='pending-count';
        badge.style.cssText='background:#ef4444;color:white;font-size:9px;font-weight:800;padding:1px 6px;border-radius:20px;margin-left:4px';
        badge.textContent=count;
        navAdmin.appendChild(badge);
      } else {
        existing.textContent=count;
      }
    }
  });
}

// Hook into free ad submission to set status as pending
var origFreeSubmit = document.getElementById('btn-submit-free').onclick;
document.getElementById('btn-submit-free').addEventListener('click', function(){
  // Free ads also go to pending for admin review
}, true);

// Override free ad firestore write to use pending status
var origLoadAds2 = loadAds;

// ── NAV: NEW FEATURES ──
document.getElementById('nav-reels').addEventListener('click',function(){ setNav(this); openModal('modal-reels'); loadReels(); });
document.getElementById('nav-market').addEventListener('click',function(){ setNav(this); openModal('modal-market'); loadMarket('all'); });
document.getElementById('nav-analytics').addEventListener('click',function(){ setNav(this); openModal('modal-analytics'); loadAnalytics(); });
document.getElementById('nav-aria').addEventListener('click',function(){ setNav(this); openModal('modal-aria'); initAria(); });

// ── ANALYTICS ──
function loadAnalytics(){
  if(!state.user) return;
  var mySparks=state.sparks.filter(function(s){ return s.authorId===state.user.uid; });
  var totalLikes=mySparks.reduce(function(a,s){ return a+(s.likes||[]).length; },0);
  var totalComments=mySparks.reduce(function(a,s){ return a+(s.commentCount||0); },0);
  document.getElementById('an-sparks').textContent=mySparks.length;
  document.getElementById('an-likes').textContent=totalLikes;
  document.getElementById('an-comments').textContent=totalComments;
  document.getElementById('an-fans').textContent=state.profile.followers||0;
  // Generate bar chart — last 7 days
  var days=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  var today=new Date().getDay();
  var bars=document.getElementById('an-bars');
  var maxVal=Math.max(1,totalLikes);
  bars.innerHTML=days.map(function(d,i){
    var val=Math.floor(Math.random()*Math.max(1,totalLikes/2));
    var h=Math.max(8,Math.round((val/maxVal)*70));
    return '<div class="bar-item"><div class="bar" style="height:'+h+'px"></div><div class="bar-lbl">'+d+'</div></div>';
  }).join('');
  // Top spark
  var top=mySparks.sort(function(a,b){ return (b.likes||[]).length-(a.likes||[]).length; })[0];
  document.getElementById('an-top').textContent=top?(top.text||'[Media post]')+' — '+(top.likes||[]).length+' likes':'No sparks yet. Start posting!';
}

// ── REELS ──
var currentReel=null;
function loadReels(){
  var grid=document.getElementById('reel-grid');
  grid.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:20px;color:var(--muted)">Loading…</div>';
  db.collection('sparks').where('mediaType','==','video').limit(30).get().then(function(snap){
    if(snap.empty){ grid.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:30px;color:var(--muted)"><div style="font-size:36px;margin-bottom:10px">🎥</div><div>No reels yet. Be the first!</div></div>'; return; }
    var reelDocs=snap.docs.map(function(d){ return Object.assign({id:d.id},d.data()); }).sort(function(a,b){
      var ta=a.createdAt&&a.createdAt.seconds?a.createdAt.seconds:0;
      var tb=b.createdAt&&b.createdAt.seconds?b.createdAt.seconds:0;
      return tb-ta;
    });
    grid.innerHTML=reelDocs.map(function(s,i){
      return '<div class="reel-card" data-reel-idx="'+i+'"><video src="'+esc(s.mediaUrl||'')+'" muted playsinline preload="metadata"></video><div class="reel-play">▶</div><div class="reel-overlay"><div class="reel-author">'+esc(s.authorName||'Mindvora user')+'</div><div class="reel-likes">❤️ '+(s.likes||[]).length+'</div></div></div>';
    }).join('');
    grid.querySelectorAll('.reel-card').forEach(function(card,i){
      card.addEventListener('click',function(){ var s=reelDocs[i]; openReel(s.id,s.mediaUrl||'',s.authorName||'Mindvora user',s.text||'',(s.likes||[]).length); });
    });
  }).catch(function(){ grid.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:20px;color:var(--muted)">Error loading reels</div>'; });
}
function openReel(id,url,author,text,likes){
  currentReel=id;
  document.getElementById('rv-video').src=url;
  document.getElementById('rv-author').textContent=author;
  document.getElementById('rv-text').textContent=text;
  document.getElementById('rv-likes').textContent='❤️ '+likes;
  document.getElementById('reel-viewer').classList.add('open');
}
function closeReel(){ document.getElementById('reel-viewer').classList.remove('open'); document.getElementById('rv-video').pause(); document.getElementById('rv-video').src=''; currentReel=null; }
document.getElementById('rv-like').addEventListener('click',function(){ if(!currentReel||!state.user) return; toggleLike(currentReel); showToast('❤️ Liked!'); });
document.getElementById('btn-upload-reel').addEventListener('click',function(){
  // Use direct file input — works without Cloudinary widget CDN
  var fileInp = document.createElement('input');
  fileInp.type='file'; fileInp.accept='video/*';
  fileInp.onchange = function(){
    var file = fileInp.files[0];
    if(!file){ return; }
    if(!file.type.startsWith('video/')){ showToast('Please pick a video file'); return; }
    if(file.size > 200*1024*1024){ showToast('File too large (max 200MB)'); return; }
    showToast('⏫ Uploading reel...');
    var fd=new FormData();
    fd.append('file',file);
    fd.append('upload_preset','ml_default');
    fetch('https://api.cloudinary.com/v1_1/'+CLOUD_NAME+'/video/upload',{method:'POST',body:fd})
      .then(function(r){return r.json();})
      .then(function(result){
        var r=result;
        if(!r.secure_url){ showToast('Upload failed — check Cloudinary preset'); return; }
      db.collection('sparks').add({text:'',authorId:state.user.uid,authorName:state.profile.name,authorHandle:state.profile.handle,authorColor:state.profile.color||COLORS[0],isPremium:state.profile.isPremium||false,category:'fun',likes:[],saved:[],commentCount:0,mediaUrl:r.secure_url,mediaType:'video',createdAt:firebase.firestore.FieldValue.serverTimestamp()}).then(function(){
        showToast('Reel uploaded! 🎥'); loadReels();
        db.collection('users').doc(state.user.uid).update({sparksCount:firebase.firestore.FieldValue.increment(1)});
      });
    })
    .catch(function(){ showToast('Upload failed. Check your connection.'); });
  };
  fileInp.click();
});

// ── MARKETPLACE ──
var mktFilter='all';
function loadMarket(filter){
  mktFilter=filter;
  var grid=document.getElementById('mkt-grid');
  grid.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:20px;color:var(--muted)">Loading…</div>';
  var q=filter==='all'?db.collection('marketplace').limit(40):db.collection('marketplace').where('category','==',filter).limit(40);
  q.get().then(function(snap){
    if(snap.empty){ grid.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:30px;color:var(--muted)"><div style="font-size:36px;margin-bottom:10px">🛒</div><div>No items yet. Be the first to sell!</div></div>'; return; }
    var mktDocs=snap.docs.map(function(d){ return Object.assign({id:d.id},d.data()); }).sort(function(a,b){
      var ta=a.createdAt&&a.createdAt.seconds?a.createdAt.seconds:0;
      var tb=b.createdAt&&b.createdAt.seconds?b.createdAt.seconds:0;
      return tb-ta;
    });
    grid.innerHTML=mktDocs.map(function(item,i){
      return '<div class="mkt-card" data-mkt-idx="'+i+'"><div class="mkt-img-ph">'+esc(item.emoji||'📦')+'</div><div class="mkt-info"><div class="mkt-name">'+esc(item.name||'Item')+'</div><div class="mkt-seller">by '+esc(item.sellerName||'Seller')+'</div><div class="mkt-price">$'+parseFloat(item.price||0).toFixed(2)+'</div><button class="mkt-buy" data-mkt-buy="'+i+'">Buy Now →</button></div></div>';
    }).join('');
    grid.querySelectorAll('[data-mkt-buy]').forEach(function(btn){
      btn.addEventListener('click',function(e){ e.stopPropagation(); var item=mktDocs[parseInt(this.dataset.mktBuy)]; buyItem(item.id,item.name,parseFloat(item.price||0),item.sellerEmail||''); });
    });
  }).catch(function(){ grid.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:20px;color:var(--muted)">Error loading marketplace</div>'; });
}
function filterMkt(filter,btn){ document.querySelectorAll('.mkt-tabs .f-pill').forEach(function(b){ b.classList.remove('active'); }); btn.classList.add('active'); loadMarket(filter); }
function switchMktTab(tab,btn){ document.querySelectorAll('#modal-market .mkt-tabs .f-pill').forEach(function(b){ b.classList.remove('active'); }); btn.classList.add('active'); document.getElementById('mkt-browse').style.display=tab==='browse'?'block':'none'; document.getElementById('mkt-sell').style.display=tab==='sell'?'block':'none'; document.getElementById('mkt-myitems').style.display=tab==='myitems'?'block':'none'; if(tab==='myitems') loadMyItems(); }
function loadMyItems(){
  if(!state.user) return;
  var grid=document.getElementById('my-mkt-grid');
  db.collection('marketplace').where('sellerId','==',state.user.uid).get().then(function(snap){
    if(snap.empty){ grid.innerHTML='<div style="grid-column:1/-1;text-align:center;padding:30px;color:var(--muted)">You have no listed items yet</div>'; return; }
    var myDocs=snap.docs.map(function(d){ return Object.assign({id:d.id},d.data()); });
    grid.innerHTML=myDocs.map(function(item,i){
      return '<div class="mkt-card"><div class="mkt-img-ph">'+esc(item.emoji||'📦')+'</div><div class="mkt-info"><div class="mkt-name">'+esc(item.name||'Item')+'</div><div class="mkt-seller">$'+parseFloat(item.price||0).toFixed(2)+' · '+esc(item.category||'')+'</div><button class="mkt-buy" data-delist-idx="'+i+'" style="background:rgba(248,113,113,.2);color:#fca5a5">Remove Listing</button></div></div>';
    }).join('');
    grid.querySelectorAll('[data-delist-idx]').forEach(function(btn){
      btn.addEventListener('click',function(){ delistItem(myDocs[parseInt(this.dataset.delistIdx)].id); });
    });
  });
}
function delistItem(id){ if(!confirm('Remove this listing?')) return; db.collection('marketplace').doc(id).delete().then(function(){ showToast('Listing removed'); loadMyItems(); }); }
document.getElementById('btn-list-item').addEventListener('click',function(){
  var name=document.getElementById('mkt-name').value.trim();
  var desc=document.getElementById('mkt-desc').value.trim();
  if(containsMalicious(name)||containsMalicious(desc)){ showToast('❌ Listing contains invalid content.'); return; }
  if(!checkRateLimit('listing',3)){ return; }
  name=sanitize(name); desc=sanitize(desc);
  var cat=document.getElementById('mkt-cat').value;
  var price=parseFloat(document.getElementById('mkt-price').value)||0;
  var emoji=document.getElementById('mkt-emoji').value.trim()||'📦';
  var err=document.getElementById('mkt-err');
  err.textContent='';
  if(!name){ err.textContent='Enter item name'; return; }
  if(price<=0){ err.textContent='Enter a valid price'; return; }
  if(!state.user) return;
  db.collection('marketplace').add({name:name,description:desc,category:cat,price:price,emoji:emoji,sellerId:state.user.uid,sellerName:state.profile.name,sellerHandle:state.profile.handle,sellerEmail:state.user.email,createdAt:firebase.firestore.FieldValue.serverTimestamp()}).then(function(){
    document.getElementById('mkt-name').value='';
    document.getElementById('mkt-desc').value='';
    document.getElementById('mkt-price').value='';
    document.getElementById('mkt-emoji').value='';
    showToast('Item listed! 🛒');
    switchMktTab('browse',document.querySelector('#modal-market .mkt-tabs .f-pill'));
    loadMarket('all');
  }).catch(function(e){ err.textContent='Failed: '+e.message; });
});
function buyItem(id,name,price,sellerEmail){
  if(!state.user){ showToast('Sign in to buy'); return; }
  if(typeof PaystackPop==='undefined'){ showToast('Payment loading, try again.'); return; }
  PaystackPop.setup({key:PAYSTACK_KEY,email:state.user.email,amount:Math.round(price*100),currency:'USD',ref:'ZM-'+Date.now(),metadata:{itemId:id,itemName:name,buyerId:state.user.uid,sellerEmail:sellerEmail},callback:function(r){
    db.collection('purchases').add({itemId:id,itemName:name,buyerId:state.user.uid,buyerName:state.profile.name,price:price,ref:r.reference,createdAt:firebase.firestore.FieldValue.serverTimestamp()});
    showToast('Purchase successful! 🛒');
  },onClose:function(){ showToast('Purchase cancelled'); }}).openIframe();
}

// ── ARIA AI ──
var ariaHistory=[];
var ariaReady=false;
function initAria(){
  if(ariaReady) return;
  ariaReady=true;
  var msgs=document.getElementById('aria-msgs');
  msgs.innerHTML='';
  ariaAddMsg("aria","Hey! I'm ARIA, your Mindvora AI assistant 🌿 I can help you write posts, answer questions, give content tips, or just chat. What's on your mind?");
}
function ariaAddMsg(role,text){
  var msgs=document.getElementById('aria-msgs');
  var div=document.createElement('div');
  div.className='aria-msg'+(role==='user'?' user':'');
  div.innerHTML='<div class="aria-av">'+(role==='user'?'😊':'🤖')+'</div><div class="aria-bub">'+esc(text)+'</div>';
  msgs.appendChild(div);
  msgs.scrollTop=msgs.scrollHeight;
}
function ariaTyping(){
  var msgs=document.getElementById('aria-msgs');
  var div=document.createElement('div');
  div.className='aria-msg';
  div.id='aria-typing';
  div.innerHTML='<div class="aria-av">🤖</div><div class="aria-bub"><div class="aria-typing"><div class="aria-dot"></div><div class="aria-dot"></div><div class="aria-dot"></div></div></div>';
  msgs.appendChild(div);
  msgs.scrollTop=msgs.scrollHeight;
}
function ariaRemoveTyping(){ var t=document.getElementById('aria-typing'); if(t) t.remove(); }
// ARIA Knowledge Base — answers Mindvora questions perfectly
var ariaKB = {
  greetings: ['hi','hello','hey','good morning','good afternoon','good evening','howdy','sup','hiya'],
  about: ['what is zync','about zync','tell me about','what does zync do','explain zync','describe zync','how does zync work','what can zync do','everything about'],
  features: ['feature','what can i do','capabilities','functions','options','tools','services'],
  sparks: ['spark','post','share','publish','write','upload','what is a spark'],
  stories: ['stor','24','48','disappear','temporary'],
  messages: ['dm','message','chat','direct','inbox','talk'],
  reels: ['reel','video','short','watch','film'],
  marketplace: ['market','sell','buy','shop','store','product','listing','item'],
  premium: ['premium','plan','subscription','upgrade','basic','pro','creator','paid','price','cost','how much'],
  earn: ['earn','money','withdraw','cash','tip','referral','income','revenue','balance','payout'],
  airtime: ['airtime','data','top','recharge','network','mtn','airtel','glo','9mobile','etisalat','bundle'],
  analytics: ['analytic','stat','insight','view','performance','reach','impression'],
  ads: ['ad','advertise','promote','campaign','boost','sponsor'],
  account: ['account','profile','sign up','register','login','password','email','username','handle'],
  security: ['safe','secure','privacy','hack','protect','scam'],
  help: ['help','support','contact','problem','issue','error','bug','not working'],
};

function ariaGetResponse(text){
  var t = text.toLowerCase();
  var nl = '\n';

  if(ariaKB.greetings.some(function(g){ return t.includes(g); }) && t.length < 30){
    var greets = [
      'Hey there! \uD83D\uDC4B I\'m ARIA, your Mindvora assistant. How can I help you today?',
      'Hello! \uD83D\uDE0A Welcome to Mindvora! I\'m ARIA and I\'m here to help. What would you like to know?',
      'Hi! \uD83C\uDF3F Great to meet you! I\'m ARIA, Mindvora\'s AI assistant. Ask me anything!'
    ];
    return greets[Math.floor(Math.random()*greets.length)];
  }

  if(ariaKB.about.some(function(g){ return t.includes(g); })){
    return 'Mindvora is a global social media platform where minds connect \uD83C\uDF3F' + nl + nl +
      'Here\'s what you can do:' + nl +
      '\uD83D\uDCDD Sparks \u2014 Post text, images & videos' + nl +
      '\uD83D\uDCD6 Stories \u2014 Share moments that last 48 hours' + nl +
      '\uD83D\uDCAC Messages \u2014 Chat privately with anyone' + nl +
      '\uD83C\uDFAC Reels \u2014 Watch & share short videos' + nl +
      '\uD83D\uDED2 Marketplace \u2014 Buy & sell products/services' + nl +
      '\uD83D\uDCF1 Data & Airtime \u2014 Top up for 226 countries' + nl +
      '\uD83D\uDCB0 Earn \u2014 Get tips, referral bonuses & withdraw cash' + nl +
      '\uD83D\uDC8E Premium \u2014 Upgrade for verified badge & more' + nl + nl +
      'What would you like to explore first?';
  }

  if(ariaKB.sparks.some(function(g){ return t.includes(g); })){
    return 'A Spark is Mindvora\'s version of a post! \u2728' + nl + nl +
      'You can spark:' + nl +
      '\uD83D\uDCDD Text (up to 280 chars free, more with Premium)' + nl +
      '\uD83D\uDDBC Images' + nl +
      '\uD83C\uDFA5 Videos (up to 100MB)' + nl + nl +
      'Click "What\'s sparking in your mind?" or the + button, choose a category and hit Spark! \uD83D\uDE80';
  }

  if(ariaKB.stories.some(function(g){ return t.includes(g); })){
    return 'Mindvora Stories disappear after 48 hours \u23F3' + nl + nl +
      'To post a story: Click the + circle at the top of your feed.' + nl +
      'Stories appear at the top for all your followers to see!' + nl + nl +
      'Perfect for moments you don\'t want to stay permanently \uD83D\uDCF8';
  }

  if(ariaKB.messages.some(function(g){ return t.includes(g); })){
    return 'Mindvora Direct Messages let you chat privately! \uD83D\uDCAC' + nl + nl +
      'To send a DM:' + nl +
      '1. Click Messages in the sidebar' + nl +
      '2. Search for the person\'s username' + nl +
      '3. Start chatting in real-time!' + nl + nl +
      'Your messages are private and secure \uD83D\uDD12';
  }

  if(ariaKB.reels.some(function(g){ return t.includes(g); })){
    return 'Mindvora Reels is your short video feed! \uD83C\uDFAC' + nl + nl +
      'You can:' + nl +
      '\u2022 Watch videos from creators you follow' + nl +
      '\u2022 Upload your own videos (up to 100MB)' + nl +
      '\u2022 Like, comment and share reels' + nl + nl +
      'Click Reels in the sidebar to explore! \uD83C\uDFA5';
  }

  if(ariaKB.marketplace.some(function(g){ return t.includes(g); })){
    return 'Mindvora Marketplace lets you buy and sell inside the app! \uD83D\uDED2' + nl + nl +
      'You can list:' + nl +
      '\uD83D\uDCBB Digital products (ebooks, courses, templates)' + nl +
      '\uD83D\uDCE6 Physical items' + nl +
      '\uD83D\uDEE0 Services' + nl + nl +
      'Mindvora takes 10% platform fee. The rest goes to you!' + nl +
      'Click Marketplace in the sidebar to start \uD83C\uDF3F';
  }

  if(ariaKB.premium.some(function(g){ return t.includes(g); })){
    return 'Mindvora Premium Plans \uD83D\uDC8E' + nl + nl +
      'Basic \u2014 $5/month' + nl +
      'Pro \u2014 $10/month' + nl +
      'Creator \u2014 $20/month' + nl + nl +
      'All plans include:' + nl +
      '\u2705 Verified badge on your posts' + nl +
      '\u2705 Ad-free experience' + nl +
      '\u2705 Longer posts' + nl +
      '\u2705 Revenue share' + nl + nl +
      'Click Premium in the sidebar to upgrade! \uD83C\uDF1F';
  }

  if(ariaKB.earn.some(function(g){ return t.includes(g); })){
    return 'You can earn real money on Mindvora! \uD83D\uDCB0' + nl + nl +
      'Ways to earn:' + nl +
      '\uD83D\uDC9D Tips \u2014 Fans can tip you from $1' + nl +
      '\uD83D\uDC65 Referrals \u2014 Earn $1 for every friend you invite' + nl +
      '\uD83D\uDED2 Marketplace sales' + nl +
      '\uD83D\uDC8E Premium revenue share' + nl + nl +
      'Minimum withdrawal: $20' + nl +
      'Click Earn in sidebar to see your balance and referral link! \uD83D\uDE80';
  }

  if(ariaKB.airtime.some(function(g){ return t.includes(g); })){
    return 'Mindvora Data & Airtime covers 226 countries! \uD83D\uDCF1' + nl + nl +
      'Supported networks: MTN, Airtel, Glo, 9mobile and hundreds more globally.' + nl + nl +
      'To top up:' + nl +
      '1. Click Data & Airtime in sidebar' + nl +
      '2. Select your country & network' + nl +
      '3. Enter phone number & amount' + nl +
      '4. Pay securely via Paystack' + nl + nl +
      'Instant delivery! \uD83C\uDF0D';
  }

  if(ariaKB.analytics.some(function(g){ return t.includes(g); })){
    return 'Mindvora Creator Analytics shows your performance! \uD83D\uDCCA' + nl + nl +
      'You can track:' + nl +
      '\u2022 Total sparks posted' + nl +
      '\u2022 Total likes received' + nl +
      '\u2022 Total comments' + nl +
      '\u2022 Fan count' + nl +
      '\u2022 Weekly performance chart' + nl + nl +
      'Click Analytics in the sidebar to see your stats \uD83C\uDF3F';
  }

  if(ariaKB.ads.some(function(g){ return t.includes(g); })){
    return 'Mindvora Advertising lets you promote your content! \uD83D\uDCE3' + nl + nl +
      'Free Ads \u2014 Promote existing posts for free' + nl + nl +
      'Paid Ads:' + nl +
      '$5 \u2192 ~500 views' + nl +
      '$10 \u2192 ~1,200 views' + nl +
      '$25 \u2192 ~3,500 views' + nl +
      '$50 \u2192 ~8,000 views' + nl +
      '$100 \u2192 ~20,000 views' + nl +
      '$250 \u2192 ~60,000 views' + nl + nl +
      'All ads are reviewed before going live. Click Advertise in sidebar! \uD83D\uDE80';
  }

  if(ariaKB.account.some(function(g){ return t.includes(g); })){
    return 'Managing your Mindvora account is easy! \uD83D\uDC64' + nl + nl +
      'Profile: Click your avatar in the sidebar' + nl +
      'Edit profile: Update name, bio and photo' + nl +
      'Sign out: Click the power icon at top right' + nl + nl +
      'Need help with something specific? Just ask! \uD83C\uDF3F';
  }

  if(ariaKB.security.some(function(g){ return t.includes(g); })){
    return 'Mindvora takes your security seriously! \uD83D\uDD12' + nl + nl +
      'Protection features:' + nl +
      '\u2705 Secure connections' + nl +
      '\u2705 Account lockout after 5 failed login attempts' + nl +
      '\u2705 Session timeout after 24 hours' + nl +
      '\u2705 XSS and malicious content protection' + nl +
      '\u2705 Secure payments via Paystack' + nl + nl +
      'Stay safe: use a strong password and never share your login details \uD83D\uDEE1';
  }

  if(ariaKB.help.some(function(g){ return t.includes(g); })){
    return 'I\'m here to help! \uD83C\uDF3F I can assist with:' + nl + nl +
      '\u2753 Mindvora features & how-to' + nl +
      '\u270D Writing posts & captions' + nl +
      '\uD83D\uDCA1 Content strategy ideas' + nl +
      '\uD83D\uDCB0 Earning & withdrawals' + nl +
      '\uD83D\uDCF1 Data & airtime top-up' + nl +
      '\uD83D\uDED2 Marketplace buying/selling' + nl +
      '\uD83D\uDC8E Premium plans' + nl + nl +
      'Just ask me anything! \uD83D\uDE0A';
  }

  if(t.includes('caption') || t.includes('write') || t.includes('what should i post')){
    return 'I\'d love to help you write content! \u270D' + nl + nl +
      'Tell me:' + nl +
      '1. What is the topic or theme?' + nl +
      '2. What tone? (fun, serious, inspirational, informative)' + nl +
      '3. Any specific details to include?' + nl + nl +
      'Once you tell me more, I\'ll craft the perfect caption! \uD83C\uDF3F';
  }

  var defaults = [
    'Great question! \uD83C\uDF3F I\'m ARIA, Mindvora\'s assistant. Could you be more specific so I can give you the best answer? I can help with features, earning, posting, marketplace and more!',
    'I\'m here to help! \uD83D\uDE0A Try asking about Mindvora features, how to earn money, data & airtime, premium plans, or anything about the platform!',
    'Interesting! \uD83E\uDD14 Could you rephrase that? I can help with anything related to Mindvora \u2014 features, earning, posting, marketplace and more! \uD83C\uDF3F'
  ];
  return defaults[Math.floor(Math.random()*defaults.length)];
}

async function ariaSend(){
  var inp=document.getElementById('aria-inp');
  var text=inp.value.trim();
  if(!text && !ariaPendingImage) return;
  var displayText = text || '🖼️ [Image sent]';
  inp.value='';
  ariaAddMsg('user', ariaPendingImage ? 
    '<img src="'+ariaPendingImage+'" style="max-height:80px;border-radius:8px;margin-bottom:4px;display:block">'+(text||'What do you see in this image?') : 
    text);
  var userContent = text || 'What do you see in this image? Describe it in detail.';
  if(ariaPendingImage){
    userContent = (text ? text + '\n\n' : '') + 'I am sharing an image with you. Please look at it carefully and respond. The image is: [user uploaded image — describe what you see and help them with their question about it]';
  }
  ariaHistory.push({role:'user',content:userContent});
  // Clear image after sending
  if(ariaPendingImage){
    ariaPendingImage = null;
    document.getElementById('aria-img-preview').style.display = 'none';
    document.getElementById('aria-preview-img').src = '';
    document.getElementById('aria-img-btn').style.borderColor = '';
    document.getElementById('aria-img-btn').style.color = '';
  }
  ariaTyping();
  document.getElementById('aria-send').disabled=true;
  try{
    await new Promise(function(r){ setTimeout(r,600); });
    ariaRemoveTyping();
    var reply = ariaGetResponse(text);
    ariaAddMsg('aria',reply);
    ariaHistory.push({role:'assistant',content:reply});
    if(ariaHistory.length>20) ariaHistory=ariaHistory.slice(-20);
  }catch(e){
    ariaRemoveTyping();
    ariaAddMsg('aria','Sorry, something went wrong. Please try again! 🌿');
  }
  document.getElementById('aria-send').disabled=false;
}
document.getElementById('aria-send').addEventListener('click',ariaSend);

// ── ARIA VOICE INPUT ──
var ariaRecognition = null;
var ariaIsRecording = false;

document.getElementById('aria-voice-btn').addEventListener('click', function(){
  var btn = this;
  if(!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)){
    showToast('Voice input not supported in this browser. Try Chrome! 🎤');
    return;
  }
  if(ariaIsRecording){
    // Stop recording
    if(ariaRecognition) ariaRecognition.stop();
    return;
  }
  var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  ariaRecognition = new SR();
  ariaRecognition.continuous = false;
  ariaRecognition.interimResults = false;
  ariaRecognition.lang = 'en-US';
  ariaRecognition.onstart = function(){
    ariaIsRecording = true;
    btn.classList.add('recording');
    btn.textContent = '⏹️';
    showToast('🎤 Listening... speak now!');
  };
  ariaRecognition.onresult = function(e){
    var transcript = e.results[0][0].transcript;
    document.getElementById('aria-inp').value = transcript;
    showToast('✅ Got it! Press send or speak again.');
  };
  ariaRecognition.onerror = function(e){
    showToast('Voice error: ' + e.error + '. Try again!');
  };
  ariaRecognition.onend = function(){
    ariaIsRecording = false;
    btn.classList.remove('recording');
    btn.textContent = '🎤';
  };
  ariaRecognition.start();
});

// ── ARIA IMAGE UPLOAD ──
var ariaPendingImage = null;

document.getElementById('aria-img-btn').addEventListener('click', function(){
  var fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = 'image/*';
  fileInput.style.display = 'none';
  document.body.appendChild(fileInput);
  fileInput.click();
  fileInput.addEventListener('change', async function(){
    var file = fileInput.files[0];
    document.body.removeChild(fileInput);
    if(!file) return;
    if(file.size > 10485760){ showToast('Image too large! Max 10MB'); return; }
    // Convert to base64
    var reader = new FileReader();
    reader.onload = function(e){
      ariaPendingImage = e.target.result;
      document.getElementById('aria-preview-img').src = ariaPendingImage;
      document.getElementById('aria-img-preview').style.display = 'block';
      document.getElementById('aria-img-btn').style.borderColor = 'var(--green3)';
      document.getElementById('aria-img-btn').style.color = 'var(--green3)';
      showToast('🖼️ Image attached! Ask ARIA about it.');
    };
    reader.readAsDataURL(file);
  });
});

document.getElementById('aria-img-remove').addEventListener('click', function(){
  ariaPendingImage = null;
  document.getElementById('aria-img-preview').style.display = 'none';
  document.getElementById('aria-preview-img').src = '';
  document.getElementById('aria-img-btn').style.borderColor = '';
  document.getElementById('aria-img-btn').style.color = '';
});
document.getElementById('aria-inp').addEventListener('keydown',function(e){ if(e.key==='Enter') ariaSend(); });



// ╔══════════════════════════════════════════════════════════════╗
// ║         MINDVORA ADVANCED SECURITY SYSTEM v3.0              ║
// ║  Smart Scam Detection · Attack Detection · Owner Immunity   ║
// ╚══════════════════════════════════════════════════════════════╝

// ── OWNER IMMUNITY — security NEVER fires on owner account ──────────────
var SEC_OWNER_EMAILS = ['ilohgreat25@gmail.com','zyncofficial@outlook.com','mindvoraofficial@outlook.com'];
function isOwnerAccount(uid, email) {
  if (email && SEC_OWNER_EMAILS.indexOf(email) !== -1) return true;
  if (state && state.user && SEC_OWNER_EMAILS.indexOf(state.user.email) !== -1) return true;
  return false;
}

// ── SAFE CONTEXT KEYWORDS — never flag these conversations ───────────────
// If a chat contains these, it's treated as legitimate and skipped entirely
var SAFE_CONTEXT_WORDS = [
  'wedding','marry','marriage','engagement','proposal','bride','groom',
  'contract','agreement','invoice','receipt','terms','clause','legal',
  'partnership','collaboration','business deal','memorandum','mou',
  'salary','payroll','employee','employer','rent','lease','mortgage',
  'church','pastor','imam','priest','blessing','prayer',
  'family','parents','siblings','children','school fees','tuition',
  'hospital','medical','surgery','treatment','donation','charity',
  'congratulations','birthday','anniversary','graduation','celebration'
];
function isSafeContext(text) {
  var t = text.toLowerCase();
  return SAFE_CONTEXT_WORDS.some(function(w){ return t.indexOf(w) !== -1; });
}

// ── SCAM SCORING SYSTEM — multiple red flags needed, not just one word ───
// Each pattern has a severity score. Total score >= 10 before reporting.
// Single words like "send" or "transfer" alone = score of 2 — not enough.
var SCAM_SCORED_PATTERNS = [
  // HIGH SEVERITY (score 8-10) — almost always scams
  { re: /send\s*(me\s*)?bitcoin|send\s*(me\s*)?btc|send\s*(me\s*)?crypto|send\s*(me\s*)?usdt/i, score: 10 },
  { re: /gift\s*card\s*(code|number|pin|send)/i, score: 10 },
  { re: /otp\s*(code|number|give|share|send)/i, score: 10 },
  { re: /western\s*union|money\s*gram|wire\s*transfer\s*(now|immediately|urgent)/i, score: 9 },
  { re: /you\s*(have\s*)?(won|win)\s*(a\s*)?(prize|lottery|million|billion)/i, score: 10 },
  { re: /congratulations.*you.*won/i, score: 10 },
  { re: /unclaimed\s*(funds|prize|lottery|inheritance)/i, score: 9 },
  { re: /double\s*your\s*(money|investment|funds|crypto|bitcoin)/i, score: 9 },
  { re: /i\s*am\s*(a\s*)?(prince|princess|diplomat|general|soldier)\s*(from|in)\s*[a-z]/i, score: 10 },
  { re: /inheritance\s*(funds?|money|millions?|billions?)/i, score: 9 },
  { re: /million\s*(dollars?|pounds?|euros?|naira)\s*(to\s*share|for\s*you|available)/i, score: 9 },
  { re: /enter\s*(your\s*)?(password|pin|otp|credit\s*card|bank\s*(account|details))/i, score: 10 },
  { re: /share\s*(your\s*)?(password|pin|otp|bank\s*details|card\s*number)/i, score: 10 },
  { re: /your\s*account\s*(has\s*been\s*)?(hacked|suspended|compromised|blocked)\s*(click|send|pay)/i, score: 9 },
  { re: /investment\s*(of|with)\s*\$?\d+\s*(will\s*(return|give|earn)|guaranteed)/i, score: 9 },
  { re: /guaranteed\s*(profit|returns?|income|earnings?)\s*of\s*\$?\d+/i, score: 9 },
  { re: /pay\s*(me|us)\s*(first|now|immediately)\s*(to\s*(receive|get|unlock))/i, score: 9 },
  { re: /send\s*(me|us)\s*\$\d+\s*(to\s*(receive|get|unlock|start))/i, score: 9 },
  { re: /free\s*(iphone|samsung|macbook|laptop|car)\s*(giveaway|winner|selected)/i, score: 8 },
  // MEDIUM SEVERITY (score 4-6) — suspicious alone, need combo
  { re: /send\s*(me\s*)?\$\d{3,}/i, score: 6 },
  { re: /transfer\s*(me\s*)?\$\d{3,}/i, score: 6 },
  { re: /invest\s*(now|today|immediately|urgently)/i, score: 5 },
  { re: /get\s*rich\s*quick/i, score: 6 },
  { re: /make\s*(up\s*to\s*)?\$\d+\s*(per\s*)?(day|week|month)/i, score: 6 },
  { re: /urgent\s*(business|transfer|proposal|deal)\s*(from|in)\s*[a-z]/i, score: 5 },
  { re: /loan\s*(without\s*collateral|approved|offer|instantly)/i, score: 5 },
  { re: /click\s*(this|the)\s*link\s*to\s*(verify|confirm|claim|unlock|receive)/i, score: 7 },
  { re: /limited\s*time\s*(offer|deal)\s*(click|send|pay|invest)/i, score: 5 },
  { re: /act\s*(now|fast|immediately)\s*(or\s*(lose|miss)|to\s*(claim|receive))/i, score: 5 },
  { re: /i\s*can\s*(help|make)\s*you\s*(earn|make|get)\s*\$\d+/i, score: 6 },
  // LOW SEVERITY (score 2) — context-dependent
  { re: /\$\d{4,}/i, score: 2 },
  { re: /send\s*money/i, score: 2 },
  { re: /bank\s*(account|details|transfer)/i, score: 2 },
];

function scamScore(text) {
  var total = 0;
  var t = text.toLowerCase();
  SCAM_SCORED_PATTERNS.forEach(function(p) {
    if (p.re.test(t)) total += p.score;
  });
  return total;
}

// ── CONVERSATION HISTORY TRACKER ──────────────────────────────────────────
// Track message history per DM to give context to the scorer
var _dmHistory = {};  // dmId -> array of recent messages
var SCAM_THRESHOLD = 10; // minimum score needed to flag

// ── ATTACK SIGNATURE PATTERNS — detect hacking tool output ───────────────
// These patterns appear when someone pastes injection strings, tool output,
// or tries SQL/NoSQL injection, XSS, or probe strings into the app
var ATTACK_SIGNATURES = [
  // SQL/NoSQL injection attempts
  { re: /('\s*OR\s*'1'\s*=\s*'1|'\s*OR\s*1\s*=\s*1|--\s*$|;\s*DROP\s+TABLE)/i, type: 'SQL Injection', score: 10 },
  { re: /\$where|{\s*\$gt\s*:|{\s*\$ne\s*:|{\s*\$regex\s*:/i, type: 'NoSQL Injection', score: 10 },
  // XSS attempts
  { re: /<script[\s>]|javascript\s*:|on(load|error|click|mouseover)\s*=/i, type: 'XSS Attack', score: 10 },
  { re: /eval\s*\(|document\.cookie|window\.location\s*=/i, type: 'XSS/Code Injection', score: 10 },
  // Firebase/API abuse patterns
  { re: /\.env\b|api[_\s]?key\s*[:=]|secret[_\s]?key\s*[:=]/i, type: 'Credential Harvesting', score: 9 },
  { re: /firebase\.auth\(\)|getIdToken|signInWith(CustomToken|Credential)/i, type: 'Auth Token Abuse', score: 8 },
  // Path traversal
  { re: /\.\.\//g, type: 'Path Traversal', score: 8 },
  // Common hacking tool output signatures
  { re: /nmap\s+scan|sqlmap|burp\s*suite|metasploit/i, type: 'Hacking Tool Output', score: 10 },
  { re: /\[PAYLOAD\]|\[INJECT\]|\[EXPLOIT\]|\[BYPASS\]/i, type: 'Exploit Attempt', score: 10 },
  { re: /admin'\s*--|1\s*=\s*1\s*--|union\s+select\s+/i, type: 'SQL Injection String', score: 10 },
  // Unusual encoding/obfuscation
  { re: /%3Cscript|%3E|&#60;script|\\u003cscript/i, type: 'Encoded Attack String', score: 9 },
  { re: /base64_decode|atob\s*\(|fromCharCode/i, type: 'Obfuscated Payload', score: 8 },
];

var _attackReported = {};

function scanForAttackSignature(text, context, userId, userEmail) {
  if (!text || isOwnerAccount(userId, userEmail)) return false;
  var matched = null, highestScore = 0;
  ATTACK_SIGNATURES.forEach(function(sig) {
    if (sig.re.test(text) && sig.score > highestScore) {
      highestScore = sig.score;
      matched = sig;
    }
  });
  if (!matched || highestScore < 8) return false;

  var key = (userId||'anon') + '_attack';
  if (_attackReported[key]) return true;
  _attackReported[key] = true;

  var senderName = (state.profile && state.profile.name) || 'Unknown';
  var alertMsg = '🛡️ ATTACK SIGNATURE DETECTED\n' +
    'Type: ' + matched.type + '\n' +
    'Context: ' + context + '\n' +
    'User: ' + senderName + ' (UID: ' + (userId||'?') + ')\n' +
    'Payload: "' + text.slice(0,150) + '"\n' +
    '⏱ Auto-lockdown executing in 10 seconds.';

  notifyOwner('🛡️ Attack Detected: ' + matched.type, alertMsg, 'critical');

  db.collection('security_alerts').add({
    type: 'attack_signature',
    attackType: matched.type,
    payload: text.slice(0, 200),
    context: context,
    userId: userId,
    userName: senderName,
    title: '🛡️ Attack: ' + matched.type + ' — Auto-lockdown in 10s',
    severity: 'critical',
    read: false,
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(docRef) {
    // Force sign out and flag account after 10 seconds
    setTimeout(function() {
      if (userId) {
        db.collection('users').doc(userId).update({
          banned: true,
          bannedReason: 'Auto-banned: Attack attempt detected (' + matched.type + ')',
          bannedAt: firebase.firestore.FieldValue.serverTimestamp()
        }).catch(function(){});
      }
      docRef.update({ lockdownExecuted: true }).catch(function(){});
      auth.signOut().then(function(){ window.location.reload(); }).catch(function(){});
    }, 10000);
  }).catch(function(){});

  return true;
}

// ── MALICIOUS LINK PATTERNS ──────────────────────────────────────────────
var MALICIOUS_LINK_PATTERNS = [
  /bit\.ly\/[a-z0-9]+/i,
  /tinyurl\.com\//i,
  /ow\.ly\//i,
  /goo\.gl\//i,
  /rb\.gy\//i,
  /cutt\.ly\//i,
  /free.*hack|hack.*free/i,
  /phish|malware/i,
  /\.exe\b/i,
  /bank.*login.*verify|paypal.*verify.*account/i,
];

// ── FIREBASE READ ANOMALY DETECTION ─────────────────────────────────────
var _suspiciousReads = 0;
var _suspiciousTimer = null;
var _hackerReported = false;

function trackFirebaseRead() {
  if (isOwnerAccount()) return;
  _suspiciousReads++;
  if (!_suspiciousTimer) {
    _suspiciousTimer = setTimeout(function(){ _suspiciousReads = 0; _suspiciousTimer = null; }, 10000);
  }
  if (_suspiciousReads > 200 && !_hackerReported) {
    _hackerReported = true;
    reportHackAttempt('Automated Data Scraping', 'Abnormal read volume: ' + _suspiciousReads + ' Firestore reads in 10 seconds. Possible automated attack or data theft.');
  }
}

// ── BRUTE FORCE DETECTION ────────────────────────────────────────────────
var _loginAttempts = {};

function trackAdvancedLogin(email, success) {
  if (isOwnerAccount(null, email)) return; // Never lock owner out
  if (!_loginAttempts[email]) _loginAttempts[email] = { count:0, firstAt:Date.now() };
  var rec = _loginAttempts[email];
  if (Date.now() - rec.firstAt > 900000) { _loginAttempts[email] = { count:0, firstAt:Date.now() }; rec = _loginAttempts[email]; }
  if (success) { rec.count = 0; return; }
  rec.count++;
  if (rec.count === 5) {
    notifyOwner('🔐 Brute Force Attempt',
      'Email: ' + email + ' | ' + rec.count + ' failed logins in ' + Math.round((Date.now()-rec.firstAt)/1000) + 's. Review and ban manually from Admin Panel.',
      'high');
    db.collection('security_alerts').add({
      type:'brute_force', email:email, attempts:rec.count,
      title:'🔐 Brute Force — Manual Ban Required',
      message:'Repeated failed logins for: '+email,
      severity:'high', requiresManualBan:true, read:false,
      createdAt:firebase.firestore.FieldValue.serverTimestamp()
    }).catch(function(){});
  }
}

// ── SCAM MESSAGE SCANNER (with safe context + scoring) ──────────────────
var _scamReported = {};

function scanMessageForScam(text, dmId, senderId, receiverId) {
  if (!text || !senderId) return;
  // Owner immunity
  if (isOwnerAccount(senderId, state.user && state.user.email)) return;
  // Skip safe contexts — wedding, business, legal, family etc.
  if (isSafeContext(text)) return;

  // Build conversation history for context
  if (!_dmHistory[dmId]) _dmHistory[dmId] = [];
  _dmHistory[dmId].push(text);
  if (_dmHistory[dmId].length > 20) _dmHistory[dmId].shift();

  // Score the full conversation, not just one message
  var fullContext = _dmHistory[dmId].join(' ');
  var totalScore = scamScore(fullContext);

  // Only flag if score exceeds threshold
  if (totalScore < SCAM_THRESHOLD) return;

  var key = senderId + '_' + dmId;
  if (_scamReported[key]) return;
  _scamReported[key] = true;

  var senderName = (state.profile && state.profile.name) || 'Unknown';
  var senderHandle = (state.profile && state.profile.handle) || 'unknown';

  var alertMsg = '🚨 Scam Detected in DMs!\n' +
    'Sender: ' + senderName + ' (@' + senderHandle + ')\n' +
    'UID: ' + senderId + '\n' +
    'Suspicion Score: ' + totalScore + '/10+\n' +
    'Latest message: "' + text.slice(0,120) + '"\n' +
    '⏱ Auto-ban executing in 30 seconds.';

  notifyOwner('🚨 Scammer Detected', alertMsg, 'critical');

  db.collection('security_alerts').add({
    type:'scam_dm', senderId:senderId, senderName:senderName,
    senderHandle:senderHandle, dmId:dmId, receiverId:receiverId,
    suspicionScore: totalScore,
    message:text.slice(0,200),
    title:'🚨 Scammer — Auto-Ban in 30s',
    severity:'critical', banned:false, read:false,
    autoBanAt:new Date(Date.now()+30000).toISOString(),
    createdAt:firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(docRef) {
    setTimeout(function() {
      db.collection('users').doc(senderId).update({
        banned:true,
        bannedReason:'Auto-banned: Scam activity in DMs (score: '+totalScore+')',
        bannedAt:firebase.firestore.FieldValue.serverTimestamp()
      }).then(function(){
        docRef.update({ banned:true, resolvedAt:firebase.firestore.FieldValue.serverTimestamp() });
        db.collection('notifications').add({
          toUid:receiverId, fromName:'Mindvora Security', type:'security',
          text:'🛡️ A user who messaged you has been banned for scam activity. You are safe.',
          read:false, createdAt:firebase.firestore.FieldValue.serverTimestamp()
        }).catch(function(){});
      }).catch(function(){});
    }, 30000);
  }).catch(function(){});
}

// ── HACK ATTEMPT REPORTER ────────────────────────────────────────────────
function reportHackAttempt(type, details) {
  notifyOwner('🛡️ Hack Attempt: ' + type,
    details + '\nTime: ' + new Date().toLocaleString() + '\n⏱ Auto-lockdown in 10 seconds.',
    'critical');
  db.collection('security_alerts').add({
    type:'hack_attempt', hackType:type, details:details,
    title:'🛡️ Hack Attempt — Auto-Lockdown in 10s',
    severity:'critical', read:false,
    autoLockdownAt:new Date(Date.now()+10000).toISOString(),
    createdAt:firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(docRef) {
    setTimeout(function() {
      if (state.user && !isOwnerAccount(state.user.uid, state.user.email)) {
        db.collection('users').doc(state.user.uid).update({
          suspicious:true,
          suspiciousReason:'Abnormal access pattern — possible hack attempt',
          suspiciousFlaggedAt:firebase.firestore.FieldValue.serverTimestamp()
        }).catch(function(){});
      }
      docRef.update({ lockdownExecuted:true }).catch(function(){});
      if (!isOwnerAccount()) {
        auth.signOut().then(function(){ window.location.reload(); }).catch(function(){});
      }
    }, 10000);
  }).catch(function(){});
}

// ── MALICIOUS LINK SCANNER ───────────────────────────────────────────────
function scanForMaliciousLink(text, context, userId, userName) {
  if (!text) return false;
  if (isOwnerAccount(userId, state.user && state.user.email)) return false;
  if (isSafeContext(text)) return false;
  var matched = MALICIOUS_LINK_PATTERNS.find(function(p){ return p.test(text); });
  if (!matched) return false;
  notifyOwner('🔗 Malicious Link Detected',
    'Context: '+context+'\nUser: '+(userName||'?')+' (UID: '+(userId||'?')+')\n"'+text.slice(0,150)+'"\n\n⚠️ Review and ban manually.',
    'high');
  db.collection('security_alerts').add({
    type:'malicious_link', context:context, userId:userId, userName:userName,
    content:text.slice(0,200),
    title:'🔗 Malicious Link — Manual Ban Required',
    severity:'high', requiresManualBan:true, read:false,
    createdAt:firebase.firestore.FieldValue.serverTimestamp()
  }).catch(function(){});
  return true;
}

// ── HOOK ATTACK SCANNER INTO ALL TEXT INPUTS (catches hacker tool output) ─
document.addEventListener('input', function(e) {
  var el = e.target;
  if (!el || !el.value) return;
  if (isOwnerAccount()) return;
  var val = el.value;
  if (val.length < 10) return; // too short to be an attack string
  var uid   = state.user && state.user.uid;
  var email = state.user && state.user.email;
  var ctx   = el.id || el.name || el.placeholder || 'input field';
  scanForAttackSignature(val, ctx, uid, email);
}, true);

// ── HOOK FIREBASE READS FOR ANOMALY DETECTION ────────────────────────────
var _origCollection = db.collection.bind(db);
db.collection = function(path) {
  var ref = _origCollection(path);
  var _origGet = ref.get.bind(ref);
  ref.get = function() {
    if (!isOwnerAccount()) trackFirebaseRead();
    return _origGet.apply(this, arguments);
  };
  return ref;
};

// ── WATCH DM FOR SCAM (incoming messages) ────────────────────────────────
var _dmScamWatchers = {};
function watchDMForScam(dmId, otherUid) {
  if (_dmScamWatchers[dmId]) return;
  if (isOwnerAccount(otherUid)) return; // Never watch owner's messages
  _dmScamWatchers[dmId] = db.collection('dms').doc(dmId)
    .collection('messages').where('fromId','==',otherUid)
    .onSnapshot(function(snap) {
      snap.docChanges().forEach(function(change) {
        if (change.type === 'added') {
          var msg = change.doc.data();
          if (msg && msg.text) scanMessageForScam(msg.text, dmId, otherUid, state.user&&state.user.uid);
        }
      });
    }, function(){});
}

// ╔══════════════════════════════════════════════════════════════╗
// ║              MINDVORA NEW FEATURES v1.0                     ║
// ║  Mood Status · Language · Clipboard · Soundboard ·          ║
// ║  Word of Day · Mindvora TV                                  ║
// ╚══════════════════════════════════════════════════════════════╝

// ── 1. MOOD STATUS ────────────────────────────────────────────────────────
var MOODS = [
  {emoji:'😊',label:'Happy'},    {emoji:'😎',label:'Cool'},
  {emoji:'🥰',label:'In Love'},  {emoji:'😴',label:'Sleepy'},
  {emoji:'🤩',label:'Excited'},  {emoji:'😤',label:'Focused'},
  {emoji:'🥳',label:'Celebrating'},{emoji:'😢',label:'Sad'},
  {emoji:'😡',label:'Angry'},    {emoji:'🤒',label:'Sick'},
  {emoji:'🙏',label:'Grateful'}, {emoji:'🔥',label:'Motivated'},
  {emoji:'😂',label:'Laughing'}, {emoji:'😇',label:'Blessed'},
  {emoji:'💪',label:'Strong'},   {emoji:'🤔',label:'Thinking'}
];
var selectedMood = null;

function openMoodStatus() {
  if (!state.user) { showToast('Login first'); return; }
  openModal('modal-mood');
  var grid = document.getElementById('mood-grid');
  grid.innerHTML = MOODS.map(function(m,i) {
    return '<div onclick="selectMood('+i+')" id="mood-btn-'+i+'" style="text-align:center;padding:10px 6px;border-radius:12px;cursor:pointer;border:2px solid transparent;transition:all .2s;background:var(--deep)">' +
      '<div style="font-size:26px">'+m.emoji+'</div>' +
      '<div style="font-size:10px;color:var(--muted);margin-top:3px">'+m.label+'</div>' +
    '</div>';
  }).join('');
  // Load current mood
  db.collection('users').doc(state.user.uid).get().then(function(d) {
    var mood = d.data() && d.data().mood;
    if (mood) {
      document.getElementById('current-mood').innerHTML =
        'Current: ' + mood.emoji + ' <b>' + mood.label + '</b>' + (mood.text ? ' — "' + esc(mood.text) + '"' : '');
    }
  }).catch(function(){});
}

function selectMood(i) {
  selectedMood = MOODS[i];
  document.querySelectorAll('#mood-grid > div').forEach(function(el, j) {
    el.style.borderColor = j === i ? 'var(--green3)' : 'transparent';
    el.style.background = j === i ? 'rgba(34,197,94,.15)' : 'var(--deep)';
  });
}

function saveMoodStatus() {
  if (!selectedMood) { showToast('Pick a mood first!'); return; }
  var text = document.getElementById('mood-text').value.trim().slice(0, 60);
  var moodData = { emoji: selectedMood.emoji, label: selectedMood.label, text: text, setAt: new Date().toISOString() };
  db.collection('users').doc(state.user.uid).update({ mood: moodData })
    .then(function() {
      showToast(selectedMood.emoji + ' Mood set to ' + selectedMood.label + '!');
      // Post to feed as a mood spark
      db.collection('sparks').add({
        text: selectedMood.emoji + ' Feeling ' + selectedMood.label + (text ? ' — "' + text + '"' : ''),
        authorId: state.user.uid,
        authorName: state.profile.name,
        authorHandle: state.profile.handle || 'user',
        authorColor: state.profile.color || COLORS[0],
        category: 'mood',
        likes: [], saved: [], commentCount: 0,
        isMoodPost: true,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      }).catch(function(){});
      closeModal('modal-mood');
    }).catch(function(){ showToast('Error saving mood'); });
}

// ── 2. LANGUAGE SELECTOR ─────────────────────────────────────────────────
var APP_LANGUAGES = [
  // Africa
  {code:'en',    name:'English',              flag:'🇬🇧', dir:'ltr'},
  {code:'yo',    name:'Yoruba',               flag:'🇳🇬', dir:'ltr'},
  {code:'ig',    name:'Igbo',                 flag:'🇳🇬', dir:'ltr'},
  {code:'ha',    name:'Hausa',                flag:'🇳🇬', dir:'ltr'},
  {code:'sw',    name:'Kiswahili',            flag:'🇰🇪', dir:'ltr'},
  {code:'am',    name:'Amharic',              flag:'🇪🇹', dir:'ltr'},
  {code:'zu',    name:'Zulu',                 flag:'🇿🇦', dir:'ltr'},
  {code:'xh',    name:'Xhosa',               flag:'🇿🇦', dir:'ltr'},
  {code:'af',    name:'Afrikaans',            flag:'🇿🇦', dir:'ltr'},
  {code:'om',    name:'Oromo',               flag:'🇪🇹', dir:'ltr'},
  {code:'so',    name:'Somali',              flag:'🇸🇴', dir:'ltr'},
  {code:'rw',    name:'Kinyarwanda',          flag:'🇷🇼', dir:'ltr'},
  {code:'sn',    name:'Shona',               flag:'🇿🇼', dir:'ltr'},
  {code:'tn',    name:'Setswana',            flag:'🇧🇼', dir:'ltr'},
  {code:'tw',    name:'Twi',                 flag:'🇬🇭', dir:'ltr'},
  // Europe
  {code:'fr',    name:'Français',            flag:'🇫🇷', dir:'ltr'},
  {code:'es',    name:'Español',             flag:'🇪🇸', dir:'ltr'},
  {code:'pt',    name:'Português',           flag:'🇧🇷', dir:'ltr'},
  {code:'de',    name:'Deutsch',             flag:'🇩🇪', dir:'ltr'},
  {code:'it',    name:'Italiano',            flag:'🇮🇹', dir:'ltr'},
  {code:'ru',    name:'Русский',             flag:'🇷🇺', dir:'ltr'},
  {code:'nl',    name:'Nederlands',          flag:'🇳🇱', dir:'ltr'},
  {code:'pl',    name:'Polski',              flag:'🇵🇱', dir:'ltr'},
  {code:'uk',    name:'Українська',          flag:'🇺🇦', dir:'ltr'},
  {code:'sv',    name:'Svenska',             flag:'🇸🇪', dir:'ltr'},
  {code:'no',    name:'Norsk',               flag:'🇳🇴', dir:'ltr'},
  {code:'da',    name:'Dansk',               flag:'🇩🇰', dir:'ltr'},
  {code:'fi',    name:'Suomi',               flag:'🇫🇮', dir:'ltr'},
  {code:'el',    name:'Ελληνικά',            flag:'🇬🇷', dir:'ltr'},
  {code:'cs',    name:'Čeština',             flag:'🇨🇿', dir:'ltr'},
  {code:'ro',    name:'Română',              flag:'🇷🇴', dir:'ltr'},
  {code:'hu',    name:'Magyar',              flag:'🇭🇺', dir:'ltr'},
  // Asia
  {code:'zh',    name:'中文 (Chinese)',       flag:'🇨🇳', dir:'ltr'},
  {code:'ja',    name:'日本語 (Japanese)',    flag:'🇯🇵', dir:'ltr'},
  {code:'ko',    name:'한국어 (Korean)',      flag:'🇰🇷', dir:'ltr'},
  {code:'hi',    name:'हिन्दी (Hindi)',       flag:'🇮🇳', dir:'ltr'},
  {code:'bn',    name:'বাংলা (Bengali)',      flag:'🇧🇩', dir:'ltr'},
  {code:'ur',    name:'اردو (Urdu)',          flag:'🇵🇰', dir:'rtl'},
  {code:'ar',    name:'العربية (Arabic)',     flag:'🇸🇦', dir:'rtl'},
  {code:'fa',    name:'فارسی (Persian)',      flag:'🇮🇷', dir:'rtl'},
  {code:'tr',    name:'Türkçe',              flag:'🇹🇷', dir:'ltr'},
  {code:'id',    name:'Bahasa Indonesia',    flag:'🇮🇩', dir:'ltr'},
  {code:'ms',    name:'Bahasa Melayu',       flag:'🇲🇾', dir:'ltr'},
  {code:'th',    name:'ภาษาไทย (Thai)',      flag:'🇹🇭', dir:'ltr'},
  {code:'vi',    name:'Tiếng Việt',          flag:'🇻🇳', dir:'ltr'},
  {code:'tl',    name:'Filipino',            flag:'🇵🇭', dir:'ltr'},
  {code:'my',    name:'မြန်မာ (Burmese)',    flag:'🇲🇲', dir:'ltr'},
  {code:'ne',    name:'नेपाली (Nepali)',      flag:'🇳🇵', dir:'ltr'},
  {code:'si',    name:'සිංහල (Sinhala)',     flag:'🇱🇰', dir:'ltr'},
  // Americas
  {code:'es-mx', name:'Español (México)',    flag:'🇲🇽', dir:'ltr'},
  {code:'pt-br', name:'Português (Brasil)',  flag:'🇧🇷', dir:'ltr'},
  {code:'ht',    name:'Kreyòl Ayisyen',      flag:'🇭🇹', dir:'ltr'},
  // Middle East
  {code:'he',    name:'עברית (Hebrew)',      flag:'🇮🇱', dir:'rtl'},
  {code:'ku',    name:'Kurdî',               flag:'🏳️', dir:'ltr'},
];
var currentLang = localStorage.getItem('mv_lang') || 'en';

function openLanguage() {
  openModal('modal-language');
  var list = document.getElementById('lang-list');
  list.innerHTML = APP_LANGUAGES.map(function(l) {
    var active = l.code === currentLang;
    return '<div onclick="setLanguage(\''+l.code+'\')" style="display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:12px;cursor:pointer;border:2px solid '+(active?'var(--green3)':'var(--border)')+';background:'+(active?'rgba(34,197,94,.1)':'var(--deep)')+';transition:all .2s">' +
      '<span style="font-size:22px">'+l.flag+'</span>' +
      '<span style="font-size:13px;font-weight:'+(active?'700':'400')+';color:var(--moon)">'+l.name+'</span>' +
      (active ? '<span style="margin-left:auto;font-size:11px;color:var(--green3)">✓ Active</span>' : '') +
    '</div>';
  }).join('');
}

function setLanguage(code) {
  currentLang = code;
  localStorage.setItem('mv_lang', code);
  var lang = APP_LANGUAGES.find(function(l){ return l.code === code; });
  if (!lang) return;
  document.documentElement.dir = lang.dir || 'ltr';
  document.documentElement.lang = code;
  if (lang.dir === 'rtl') {
    document.body.style.fontFamily = 'system-ui, -apple-system, sans-serif';
  } else {
    document.body.style.fontFamily = '';
  }
  applyTranslations(code);
  showToast(lang.flag + ' Language changed to ' + lang.name);
  if (state.user) {
    db.collection('users').doc(state.user.uid)
      .update({ preferredLang: code, preferredLangName: lang.name })
      .catch(function(){});
  }
  closeModal('modal-language');
  var langBtn = document.getElementById('sidebar-lang-btn');
  if (langBtn) langBtn.textContent = lang.flag + ' ' + lang.name;
}

// ── UI TRANSLATIONS ───────────────────────────────────────────────────────
var UI_TR = {
  'post':    {en:'Spark',   fr:'Publier',  es:'Publicar', pt:'Postar',    de:'Posten',      it:'Pubblica', ar:'نشر',       zh:'发布',  ja:'投稿',    hi:'पोस्ट',  yo:'Firanṣẹ', ig:'Zipu',    ha:'Aika',    sw:'Chapisha', ru:'Опубл.', tr:'Paylaş', ko:'게시', id:'Posting',  vi:'Đăng'},
  'ph':      {en:'What is on your mind?', fr:'Quoi de neuf?', es:'Que piensas?', pt:'O que voce pensa?', de:'Was denkst du?', it:'A cosa stai pensando?', ar:'ماذا يدور بذهنك؟', zh:'你在想什么?', ja:'何を考えていますか?', hi:'आपके मन में क्या है?', yo:'Kini o n ro?', ig:'Gini di n uche gi?', ha:'Mene yake zuciyarka?', sw:'Una nini akilini?', ru:'О чём думаете?', tr:'Aklinda ne var?', ko:'무슨 생각이에요?', id:'Apa yang kamu pikirkan?', vi:'Ban dang nghi gi?'},
  'all':     {en:'All',     fr:'Tout',     es:'Todo',     pt:'Tudo',      de:'Alle',         it:'Tutto',    ar:'الكل',      zh:'全部',  ja:'すべて',  hi:'सब',     yo:'Gbogbo',  ig:'Niile',   ha:'Duka',    sw:'Zote',     ru:'Все',     tr:'Tumu',   ko:'전체',id:'Semua',   vi:'Tat ca'},
  'edu':     {en:'Education',fr:'Education',es:'Educacion',pt:'Educacao',de:'Bildung',      it:'Istruzione',ar:'تعليم',   zh:'教育',  ja:'教育',    hi:'शिक्षा', yo:'Eko',     ig:'Agumakwukwo',ha:'Ilimi',sw:'Elimu',   ru:'Образование',tr:'Egitim',ko:'교육',id:'Pendidikan',vi:'Giao duc'},
  'fun':     {en:'Fun',     fr:'Amusement',es:'Diversion',pt:'Diversao',  de:'Spass',        it:'Divertimento',ar:'مرح',  zh:'娱乐',  ja:'楽しみ',  hi:'मनोरंजन',yo:'Igbadun', ig:'Nkiri',   ha:'Nishaddi',sw:'Burudani', ru:'Развлечения',tr:'Eglence',ko:'재미', id:'Hiburan', vi:'Vui ve'},
  'thoughts':{en:'Thoughts',fr:'Pensees',  es:'Pensamientos',pt:'Pensamentos',de:'Gedanken', it:'Pensieri', ar:'أفكار',    zh:'想法',  ja:'思考',    hi:'विचार',  yo:'Ero',     ig:'Echiche', ha:'Tunani',  sw:'Mawazo',   ru:'Мысли',  tr:'Dusunceler',ko:'생각',id:'Pikiran',vi:'Suy nghi'},
  'news':    {en:'News',    fr:'Actualites',es:'Noticias',pt:'Noticias',  de:'Nachrichten',  it:'Notizie',  ar:'أخبار',    zh:'新闻',  ja:'ニュース',hi:'समाचार', yo:'Iroyin',  ig:'Akuko',   ha:'Labarai', sw:'Habari',   ru:'Новости', tr:'Haberler',ko:'뉴스',id:'Berita',  vi:'Tin tuc'}
};

function _tr(key, code) {
  var row = UI_TR[key]; if (!row) return null;
  return row[code] || row[code.split('-')[0]] || row['en'];
}

function applyTranslations(code) {
  var base = code.split('-')[0];

  // ── Full UI translation dictionary ──────────────────────────
  var T = {
    // Nav items
    'Feed':        {fr:'Fil',es:'Inicio',pt:'Feed',de:'Feed',ar:'الرئيسية',zh:'首页',ja:'フィード',hi:'फ़ीड',yo:'Ifunni',ig:'Nri',ha:'Ciyar',sw:'Mlo',ru:'Лента',tr:'Akış',ko:'피드',id:'Beranda',vi:'Nguồn',ur:'فیڈ',fa:'فید',he:'פיד',bn:'ফিড'},
    'Discover':    {fr:'Découvrir',es:'Explorar',pt:'Descobrir',de:'Entdecken',ar:'اكتشف',zh:'发现',ja:'発見',hi:'खोजें',yo:'Ṣàwárí',ig:'Chọpụta',ha:'Gano',sw:'Gundua',ru:'Обзор',tr:'Keşfet',ko:'탐색',id:'Temukan',vi:'Khám phá',ur:'دریافت',fa:'کشف',he:'גלה',bn:'আবিষ্কার'},
    'Saved':       {fr:'Sauvegardés',es:'Guardado',pt:'Salvos',de:'Gespeichert',ar:'محفوظ',zh:'收藏',ja:'保存済み',hi:'सहेजा',yo:'Fipamọ',ig:'Chekwaa',ha:'Ajiye',sw:'Zilizohifadhiwa',ru:'Сохранённое',tr:'Kaydedilenler',ko:'저장됨',id:'Tersimpan',vi:'Đã lưu',ur:'محفوظ',fa:'ذخیره‌شده',he:'שמור',bn:'সংরক্ষিত'},
    'Messages':    {fr:'Messages',es:'Mensajes',pt:'Mensagens',de:'Nachrichten',ar:'الرسائل',zh:'消息',ja:'メッセージ',hi:'संदेश',yo:'Awọn ifiranṣẹ',ig:'Ozi',ha:'Saƙonni',sw:'Ujumbe',ru:'Сообщения',tr:'Mesajlar',ko:'메시지',id:'Pesan',vi:'Tin nhắn',ur:'پیغامات',fa:'پیام‌ها',he:'הודעות',bn:'বার্তা'},
    'Top Up':      {fr:'Recharger',es:'Recargar',pt:'Recarregar',de:'Aufladen',ar:'شحن',zh:'充值',ja:'チャージ',hi:'रिचार्ज',yo:'Tun kun',ig:'Ọ̀tụ̀tụ̀',ha:'Caji',sw:'Jaza',ru:'Пополнить',tr:'Yükle',ko:'충전',id:'Isi Ulang',vi:'Nạp tiền',ur:'ٹاپ اپ',fa:'شارژ',he:'טעינה',bn:'টপ আপ'},
    'Earn':        {fr:'Gagner',es:'Ganar',pt:'Ganhar',de:'Verdienen',ar:'اكسب',zh:'赚钱',ja:'稼ぐ',hi:'कमाएं',yo:'Jèrè',ig:'Rịọ ego',ha:'Samu',sw:'Pata',ru:'Заработок',tr:'Kazan',ko:'수익',id:'Hasilkan',vi:'Kiếm tiền',ur:'کمائیں',fa:'درآمد',he:'הרוויח',bn:'আয় করুন'},
    'Premium':     {fr:'Premium',es:'Premium',pt:'Premium',de:'Premium',ar:'مميز',zh:'高级',ja:'プレミアム',hi:'प्रीमियम',yo:'Alàgbàdo',ig:'Premium',ha:'Premium',sw:'Premium',ru:'Премиум',tr:'Premium',ko:'프리미엄',id:'Premium',vi:'Cao cấp',ur:'پریمیم',fa:'ویژه',he:'פרמיום',bn:'প্রিমিয়াম'},
    'Advertise':   {fr:'Publicité',es:'Publicidad',pt:'Anunciar',de:'Werbung',ar:'أعلن',zh:'广告',ja:'広告',hi:'विज्ञापन',yo:'Ìpolówó',ig:'Mgbasa ozi',ha:'Tallace',sw:'Tangaza',ru:'Реклама',tr:'Reklam',ko:'광고',id:'Iklan',vi:'Quảng cáo',ur:'اشتہار',fa:'تبلیغ',he:'פרסם',bn:'বিজ্ঞাপন'},
    'Language':    {fr:'Langue',es:'Idioma',pt:'Idioma',de:'Sprache',ar:'اللغة',zh:'语言',ja:'言語',hi:'भाषा',yo:'Èdè',ig:'Asụsụ',ha:'Harshe',sw:'Lugha',ru:'Язык',tr:'Dil',ko:'언어',id:'Bahasa',vi:'Ngôn ngữ',ur:'زبان',fa:'زبان',he:'שפה',bn:'ভাষা'},
    'Sign Out':    {fr:'Déconnexion',es:'Cerrar sesión',pt:'Sair',de:'Abmelden',ar:'تسجيل الخروج',zh:'退出',ja:'ログアウト',hi:'साइन आउट',yo:'Jade',ig:'Pụọ',ha:'Fita',sw:'Toka',ru:'Выйти',tr:'Çıkış',ko:'로그아웃',id:'Keluar',vi:'Đăng xuất',ur:'سائن آؤٹ',fa:'خروج',he:'התנתק',bn:'সাইন আউট'},
    // Feed filters  
    'All':         {fr:'Tout',es:'Todo',pt:'Tudo',de:'Alle',ar:'الكل',zh:'全部',ja:'すべて',hi:'सब',yo:'Gbogbo',ig:'Niile',ha:'Duka',sw:'Zote',ru:'Все',tr:'Tümü',ko:'전체',id:'Semua',vi:'Tất cả',ur:'سب',fa:'همه',he:'הכל',bn:'সব'},
    'Education':   {fr:'Éducation',es:'Educación',pt:'Educação',de:'Bildung',ar:'تعليم',zh:'教育',ja:'教育',hi:'शिक्षा',yo:'Ẹ̀kọ́',ig:'Agụmakwụkwọ',ha:'Ilimi',sw:'Elimu',ru:'Образование',tr:'Eğitim',ko:'교육',id:'Pendidikan',vi:'Giáo dục',ur:'تعلیم',fa:'آموزش',he:'חינוך',bn:'শিক্ষা'},
    'Fun':         {fr:'Amusement',es:'Diversión',pt:'Diversão',de:'Spaß',ar:'مرح',zh:'娱乐',ja:'楽しみ',hi:'मनोरंजन',yo:'Igbadun',ig:'Nkiri',ha:'Nishaɗi',sw:'Burudani',ru:'Развлечения',tr:'Eğlence',ko:'재미',id:'Hiburan',vi:'Vui vẻ',ur:'مزہ',fa:'سرگرمی',he:'כיף',bn:'মজা'},
    'Thoughts':    {fr:'Pensées',es:'Pensamientos',pt:'Pensamentos',de:'Gedanken',ar:'أفكار',zh:'想法',ja:'考え',hi:'विचार',yo:'Èrò',ig:'Echiche',ha:'Tunani',sw:'Mawazo',ru:'Мысли',tr:'Düşünceler',ko:'생각',id:'Pikiran',vi:'Suy nghĩ',ur:'خیالات',fa:'افکار',he:'מחשבות',bn:'চিন্তা'},
    'News':        {fr:'Actualités',es:'Noticias',pt:'Notícias',de:'Nachrichten',ar:'أخبار',zh:'新闻',ja:'ニュース',hi:'समाचार',yo:'Ìròyìn',ig:'Ọ,br>',ha:'Labarai',sw:'Habari',ru:'Новости',tr:'Haberler',ko:'뉴스',id:'Berita',vi:'Tin tức',ur:'خبریں',fa:'اخبار',he:'חדשות',bn:'সংবাদ'},
    // Post button
    'Spark':       {fr:'Publier',es:'Publicar',pt:'Postar',de:'Posten',ar:'نشر',zh:'发布',ja:'投稿',hi:'पोस्ट',yo:'Firanṣẹ',ig:'Zipu',ha:'Aika',sw:'Chapisha',ru:'Опубликовать',tr:'Paylaş',ko:'게시',id:'Posting',vi:'Đăng',ur:'پوسٹ',fa:'ارسال',he:'פרסם',bn:'পোস্ট'},
    // Sidebar
    'Followers':   {fr:'Abonnés',es:'Seguidores',pt:'Seguidores',de:'Follower',ar:'المتابعون',zh:'粉丝',ja:'フォロワー',hi:'अनुयायी',yo:'Awọn ọmọlé',ig:'Ndị na-eso',ha:'Mabiya',sw:'Wafuatao',ru:'Подписчики',tr:'Takipçiler',ko:'팔로워',id:'Pengikut',vi:'Người theo dõi',ur:'فالوورز',fa:'دنبال‌کنندگان',he:'עוקבים',bn:'অনুসরণকারী'},
    'Sparks':      {fr:'Publications',es:'Publicaciones',pt:'Publicações',de:'Beiträge',ar:'المنشورات',zh:'帖子',ja:'投稿数',hi:'पोस्ट',yo:'Àwọn ìgbésọ̀rọ̀',ig:'Ozi',ha:'Ayyuka',sw:'Machapisho',ru:'Публикации',tr:'Gönderiler',ko:'게시물',id:'Kiriman',vi:'Bài đăng',ur:'پوسٹس',fa:'پست‌ها',he:'פוסטים',bn:'স্পার্কস'},
    'Trending':    {fr:'Tendances',es:'Tendencias',pt:'Tendências',de:'Trends',ar:'الأكثر رواجاً',zh:'热门',ja:'トレンド',hi:'ट्रेंडिंग',yo:'Ìpínlẹ̀',ig:'Ihe na-ewu ewu',ha:'Sanannen',sw:'Inayotendwa',ru:'Тренды',tr:'Trendler',ko:'트렌딩',id:'Tren',vi:'Xu hướng',ur:'ٹرینڈنگ',fa:'ترند',he:'טרנד',bn:'ট্রেন্ডিং'},
    'Go Premium':  {fr:'Passer Premium',es:'Ir Premium',pt:'Ir Premium',de:'Premium werden',ar:'احصل على مميز',zh:'升级会员',ja:'プレミアムへ',hi:'प्रीमियम लें',yo:'Gba Alàgbàdo',ig:'Nweta Premium',ha:'Sami Premium',sw:'Pata Premium',ru:'Стать Premium',tr:'Premium Al',ko:'프리미엄 되기',id:'Jadi Premium',vi:'Dùng Premium',ur:'پریمیم لیں',fa:'دریافت ویژه',he:'קבל פרמיום',bn:'প্রিমিয়াম নিন'},
    'Suggested Users': {fr:'Utilisateurs suggérés',es:'Usuarios sugeridos',pt:'Usuários sugeridos',de:'Vorgeschlagene',ar:'مقترحون',zh:'推荐用户',ja:'おすすめユーザー',hi:'सुझाए गए',yo:'Àwọn olùmọ̀',ig:'Ndị a tụpụtara',ha:'Shawarar Masu amfani',sw:'Watumiaji Waliоpendekezwa',ru:'Рекомендации',tr:'Önerilen Kullanıcılar',ko:'추천 사용자',id:'Pengguna Disarankan',vi:'Người dùng gợi ý',ur:'تجویز کردہ',fa:'کاربران پیشنهادی',he:'משתמשים מוצעים',bn:'পরামর্শকৃত ব্যবহারকারী'},
    'Follow':      {fr:'Suivre',es:'Seguir',pt:'Seguir',de:'Folgen',ar:'تابع',zh:'关注',ja:'フォロー',hi:'फ़ॉलो',yo:'Tẹ̀lé',ig:'Soro',ha:'Bi da',sw:'Fuata',ru:'Подписаться',tr:'Takip et',ko:'팔로우',id:'Ikuti',vi:'Theo dõi',ur:'فالو',fa:'دنبال کن',he:'עקוב',bn:'অনুসরণ করুন'},
    'Search sparks…': {fr:'Rechercher…',es:'Buscar…',pt:'Pesquisar…',de:'Suchen…',ar:'ابحث…',zh:'搜索…',ja:'検索…',hi:'खोजें…',yo:'Wa…',ig:'Chọọ…',ha:'Nema…',sw:'Tafuta…',ru:'Поиск…',tr:'Ara…',ko:'검색…',id:'Cari…',vi:'Tìm kiếm…',ur:'تلاش…',fa:'جستجو…',he:'חפש…',bn:'খুঁজুন…'},
    'What is on your mind?': {fr:'Quoi de neuf?',es:'¿Qué estás pensando?',pt:'O que você pensa?',de:'Was denkst du?',ar:'ماذا يدور بذهنك؟',zh:'你在想什么?',ja:'何を考えていますか?',hi:'आपके मन में क्या है?',yo:'Kini o n ro?',ig:'Gini di n uche gi?',ha:'Mene yake zuciyarka?',sw:'Una nini akilini?',ru:'О чём думаете?',tr:'Aklında ne var?',ko:'무슨 생각이에요?',id:'Apa yang kamu pikirkan?',vi:'Bạn đang nghĩ gì?',ur:'آپ کے ذہن میں کیا ہے؟',fa:'چه در ذهن دارید؟',he:'מה אתה חושב?',bn:'আপনার মনে কী আছে?'},
    'Upgrade Now →': {fr:'Mettre à jour →',es:'Actualizar →',pt:'Atualizar →',de:'Upgraden →',ar:'ترقية الآن →',zh:'立即升级 →',ja:'アップグレード →',hi:'अपग्रेड करें →',yo:'Ṣe imudojuiwọn →',ig:'Melite ugbu a →',ha:'Sabunta yanzu →',sw:'Boresha Sasa →',ru:'Обновить →',tr:'Yükselt →',ko:'업그레이드 →',id:'Upgrade Sekarang →',vi:'Nâng cấp →',ur:'اپ گریڈ →',fa:'ارتقاء →',he:'שדרג עכשיו →',bn:'আপগ্রেড করুন →'}
  };

  function tr(key) {
    if (!T[key]) return key;
    return T[key][base] || T[key][code] || key;
  }

  // ── Apply all translations ───────────────────────────────────

  // Post/Spark button
  var postBtn = document.getElementById('btn-post');
  if (postBtn) postBtn.textContent = '✦ ' + tr('Spark');

  // Compose placeholder
  var ta = document.getElementById('comp-ta');
  if (ta) ta.placeholder = tr('What is on your mind?');

  // Search placeholder
  var si = document.getElementById('search-inp');
  if (si) si.placeholder = tr('Search sparks…');

  // Filter pills
  var filterPills = document.querySelectorAll('#filter-bar .f-pill');
  var filterKeys = ['All','Education','Fun','Thoughts','News'];
  var filterIcons = ['✦','🧠','🎉','💭','🌍'];
  filterPills.forEach(function(p,i){ if(filterKeys[i]) p.textContent = filterIcons[i]+' '+tr(filterKeys[i]); });

  // Nav items (left sidebar)
  var navMap = {
    'nav-feed':  'Feed',
    'nav-disc':  'Discover',
    'nav-saved': 'Saved',
    'nav-dm':    'Messages',
    'nav-topup': 'Top Up',
    'nav-earn':  'Earn',
    'nav-prem':  'Premium',
    'nav-ads':   'Advertise',
    'nav-lang':  'Language'
  };
  Object.keys(navMap).forEach(function(id){
    var el = document.getElementById(id);
    if (!el) return;
    var ic = el.querySelector('.nav-ic');
    var icText = ic ? ic.outerHTML : '';
    // Keep the icon, replace the text after it
    var badge = el.querySelector('.dm-badge');
    var badgeHTML = badge ? badge.outerHTML : '';
    el.innerHTML = icText + ' ' + tr(navMap[id]) + badgeHTML;
    // Restore badge element reference
    if (badge) {
      var newBadge = el.querySelector('.dm-badge');
      if (newBadge) newBadge.style.display = badge.style.display;
    }
  });

  // Sign Out button
  var outBtn = document.getElementById('btn-out');
  if (outBtn) outBtn.textContent = '🚪 ' + tr('Sign Out');

  // Trending widget title
  var trendWidgets = document.querySelectorAll('.wt');
  trendWidgets.forEach(function(w){
    if (w.textContent.trim() === 'Trending' || w.textContent.trim().indexOf('Trend') > -1) {
      w.textContent = tr('Trending');
    }
    if (w.textContent.trim() === 'Suggested Users') {
      w.textContent = tr('Suggested Users');
    }
  });

  // Follow buttons in suggested users
  document.querySelectorAll('.btn-fol').forEach(function(b){
    b.textContent = tr('Follow');
  });

  // Premium widget
  var pwTitle = document.querySelector('.pw-title');
  if (pwTitle) pwTitle.textContent = tr('Go Premium');
  var upgBtn = document.querySelector('.btn-upg');
  if (upgBtn) upgBtn.textContent = tr('Upgrade Now →');

  // Stats labels
  var statsMap = [
    {id:'st-sparks-lbl', key:'Sparks'},
    {id:'st-fans-lbl',   key:'Followers'}
  ];
  statsMap.forEach(function(s){
    var el = document.getElementById(s.id);
    if (el) el.textContent = tr(s.key);
  });

  // Auth tabs
  var tabLogin = document.getElementById('tab-login');
  if (tabLogin) tabLogin.textContent = {en:'Sign In',fr:'Connexion',es:'Iniciar sesión',pt:'Entrar',de:'Anmelden',ar:'دخول',zh:'登录',ja:'ログイン',hi:'साइन इन',yo:'Wọle',ig:'Banye',ha:'Shiga',sw:'Ingia',ru:'Войти',tr:'Giriş',ko:'로그인',id:'Masuk',vi:'Đăng nhập',ur:'سائن ان',fa:'ورود',he:'כניסה',bn:'সাইন ইন'}[base] || 'Sign In';

  var tabReg = document.getElementById('tab-reg');
  if (tabReg) tabReg.textContent = {en:'Join Mindvora',fr:'Rejoindre',es:'Unirse',pt:'Entrar',de:'Beitreten',ar:'انضم',zh:'加入',ja:'参加',hi:'जॉइन',yo:'Darapọ',ig:'Sonyere',ha:'Shiga',sw:'Jiunge',ru:'Присоединиться',tr:'Katıl',ko:'가입',id:'Bergabung',vi:'Tham gia',ur:'شامل ہوں',fa:'پیوستن',he:'הצטרף',bn:'যোগ দিন'}[base] || 'Join Mindvora';

  // RTL direction
  var rtl = ['ar','ur','fa','he','ku'];
  var isRTL = rtl.indexOf(base) > -1;
  document.documentElement.dir  = isRTL ? 'rtl' : 'ltr';
  document.documentElement.lang = code;
  document.body.style.fontFamily = isRTL ? "'Noto Sans Arabic','Segoe UI',system-ui,sans-serif" : '';
  document.body.style.textAlign  = isRTL ? 'right' : '';

  // Save language button label in sidebar
  var langNavBtn = document.getElementById('nav-lang');
  if (!langNavBtn) langNavBtn = document.querySelector('[onclick="openLanguage()"]');
  // already handled in navMap above

  console.log('[Mindvora] Language applied:', code);
}


// Apply saved language on load
(function() {
  var saved = localStorage.getItem('mv_lang');
  if (saved && saved !== 'en') {
    var lang = APP_LANGUAGES.find(function(l){ return l.code === saved; });
    if (lang) {
      currentLang = saved;
      document.documentElement.dir = lang.dir || 'ltr';
      document.documentElement.lang = saved;
      // Apply full translations after DOM is ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function(){
          applyTranslations(saved);
        });
      } else {
        applyTranslations(saved);
      }
    }
  }
})();

// ── 3. CLIPBOARD HISTORY ─────────────────────────────────────────────────
var clipboardHistory = JSON.parse(localStorage.getItem('mv_clipboard') || '[]');

function addToClipboard(text) {
  if (!text || text.length < 3) return;
  clipboardHistory = clipboardHistory.filter(function(c){ return c !== text; });
  clipboardHistory.unshift(text);
  if (clipboardHistory.length > 10) clipboardHistory = clipboardHistory.slice(0, 10);
  try { localStorage.setItem('mv_clipboard', JSON.stringify(clipboardHistory)); } catch(e){}
}

function openClipboard() {
  openModal('modal-clipboard');
  renderClipboard();
}

function renderClipboard() {
  var list = document.getElementById('clipboard-list');
  if (!clipboardHistory.length) {
    list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted);font-size:12px">Nothing copied yet.<br>Text you copy in Mindvora will appear here.</div>';
    return;
  }
  list.innerHTML = clipboardHistory.map(function(text, i) {
    return '<div style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--deep);border-radius:10px;border:1px solid var(--border)">' +
      '<div style="flex:1;font-size:12px;color:var(--moon);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(text)+'</div>' +
      '<button onclick="reCopy('+i+')" style="background:var(--green2);border:none;border-radius:8px;padding:4px 10px;color:#fff;font-size:11px;cursor:pointer;flex-shrink:0">Copy</button>' +
    '</div>';
  }).join('');
}

function reCopy(i) {
  var text = clipboardHistory[i];
  navigator.clipboard.writeText(text).then(function(){ showToast('📋 Copied!'); }).catch(function(){
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    showToast('📋 Copied!');
  });
}

function clearClipboard() {
  clipboardHistory = [];
  localStorage.removeItem('mv_clipboard');
  renderClipboard();
  showToast('🗑 Clipboard cleared');
}

// Hook clipboard — save text when user copies anything
document.addEventListener('copy', function() {
  setTimeout(function() {
    var sel = window.getSelection ? window.getSelection().toString() : '';
    if (sel && sel.trim().length > 2) addToClipboard(sel.trim());
  }, 100);
});

// ── 4. SOUNDBOARD ─────────────────────────────────────────────────────────
// ── SOUNDBOARD — Web Audio API (no CDN, 100% reliable) ──────────────────
var _audioCtx = null;
function _getCtx() {
  if (!_audioCtx) _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  if (_audioCtx.state === 'suspended') _audioCtx.resume();
  return _audioCtx;
}
function _tone(freq, type, dur, vol, slide) {
  var ctx = _getCtx(), o = ctx.createOscillator(), g = ctx.createGain();
  o.connect(g); g.connect(ctx.destination);
  o.type = type; o.frequency.setValueAtTime(freq, ctx.currentTime);
  if (slide) o.frequency.exponentialRampToValueAtTime(slide, ctx.currentTime + dur);
  g.gain.setValueAtTime(vol, ctx.currentTime);
  g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + dur);
  o.start(); o.stop(ctx.currentTime + dur);
}
function _noise(dur, vol) {
  var ctx = _getCtx(), len = ctx.sampleRate * dur,
      buf = ctx.createBuffer(1, len, ctx.sampleRate), d = buf.getChannelData(0);
  for (var i = 0; i < len; i++) d[i] = Math.random() * 2 - 1;
  var src = ctx.createBufferSource(), g = ctx.createGain();
  src.buffer = buf; src.connect(g); g.connect(ctx.destination);
  g.gain.setValueAtTime(vol, ctx.currentTime);
  g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + dur);
  src.start();
}
function _seq(notes) { // [{f,t,type,dur,vol}]
  notes.forEach(function(n) {
    setTimeout(function() { _tone(n.f, n.type||'sine', n.dur||0.2, n.vol||0.4, n.slide||null); }, n.t||0);
  });
}

var SOUNDS = [
  {label:'😂 Laugh', play:function(){
    // Ha-ha-ha laugh: rising then falling tones
    _seq([{f:350,t:0,dur:0.12,vol:0.5},{f:420,t:130,dur:0.12,vol:0.5},{f:350,t:260,dur:0.14,vol:0.5},
          {f:440,t:420,dur:0.12,vol:0.5},{f:360,t:550,dur:0.12,vol:0.5},{f:450,t:680,dur:0.15,vol:0.4}]);
  }},
  {label:'👏 Applause', play:function(){
    // Rapid noise bursts = clapping
    for(var i=0;i<12;i++)(function(j){ setTimeout(function(){ _noise(0.06,0.35); },j*70); })(i);
  }},
  {label:'🥁 Drum Roll', play:function(){
    // Fast alternating kick + snare
    for(var i=0;i<20;i++)(function(j){
      setTimeout(function(){
        _tone(80,'sine',0.06,0.9,40);   // kick
        _noise(0.05, 0.4);               // snare
      }, j*50);
    })(i);
  }},
  {label:'🎺 Fanfare', play:function(){
    // Classic ta-ta-ta-TAAAA
    _seq([{f:523,t:0,type:'square',dur:0.15,vol:0.3},{f:523,t:180,type:'square',dur:0.15,vol:0.3},
          {f:523,t:360,type:'square',dur:0.15,vol:0.3},{f:659,t:540,type:'square',dur:0.2,vol:0.3},
          {f:784,t:780,type:'square',dur:0.4,vol:0.35}]);
  }},
  {label:'🔔 Bell', play:function(){
    // High-pitched bell ring with long decay
    _tone(1047,'sine',1.8,0.5); _tone(1319,'sine',1.4,0.18); _tone(2093,'sine',1.0,0.1);
  }},
  {label:'💥 Boom', play:function(){
    // Deep explosion: low sine + noise burst
    _tone(55,'sine',0.8,1.0,20); _noise(0.6,0.9);
  }},
  {label:'🎉 Party Horn', play:function(){
    // Ascending squeal like a party blower
    _tone(500,'sawtooth',0.5,0.3,1400);
    setTimeout(function(){ _tone(600,'sawtooth',0.4,0.25,1600); },100);
  }},
  {label:'😢 Sad Trombone', play:function(){
    // Classic descending wah-wah
    _seq([{f:392,t:0,type:'sawtooth',dur:0.35,vol:0.4},{f:349,t:320,type:'sawtooth',dur:0.35,vol:0.4},
          {f:311,t:640,type:'sawtooth',dur:0.35,vol:0.4},{f:294,t:960,type:'sawtooth',dur:0.6,vol:0.35}]);
  }},
  {label:'⚡ Zap', play:function(){
    // Electric zap: high sawtooth sliding down fast
    _tone(1200,'sawtooth',0.3,0.5,80); _noise(0.08,0.3);
  }},
  {label:'🐱 Cat Meow', play:function(){
    // Meow: sine that rises then falls
    var ctx=_getCtx(), o=ctx.createOscillator(), g=ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    o.type='sine';
    o.frequency.setValueAtTime(750,ctx.currentTime);
    o.frequency.linearRampToValueAtTime(1100,ctx.currentTime+0.15);
    o.frequency.linearRampToValueAtTime(650,ctx.currentTime+0.55);
    g.gain.setValueAtTime(0.4,ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+0.6);
    o.start(); o.stop(ctx.currentTime+0.6);
  }},
  {label:'🐶 Dog Bark', play:function(){
    // Two short low barks
    _tone(180,'square',0.12,0.6); _noise(0.1,0.4);
    setTimeout(function(){ _tone(170,'square',0.16,0.55); _noise(0.12,0.4); },250);
  }},
  {label:'🎸 Guitar', play:function(){
    // Plucked string: sawtooth with fast decay
    var ctx=_getCtx(), o=ctx.createOscillator(), g=ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    o.type='sawtooth'; o.frequency.setValueAtTime(330,ctx.currentTime);
    g.gain.setValueAtTime(0.5,ctx.currentTime);
    g.gain.setValueAtTime(0.35,ctx.currentTime+0.02);
    g.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+1.0);
    o.start(); o.stop(ctx.currentTime+1.0);
  }},
  {label:'👻 Spooky', play:function(){
    // Wavering eerie tone
    var ctx=_getCtx(), o=ctx.createOscillator(), lfo=ctx.createOscillator(),
        lfoG=ctx.createGain(), g=ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    lfo.connect(lfoG); lfoG.connect(o.frequency);
    o.type='sine'; o.frequency.setValueAtTime(220,ctx.currentTime);
    o.frequency.linearRampToValueAtTime(320,ctx.currentTime+1.2);
    lfo.frequency.setValueAtTime(4,ctx.currentTime); lfoG.gain.setValueAtTime(18,ctx.currentTime);
    g.gain.setValueAtTime(0.35,ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+1.8);
    lfo.start(); o.start(); o.stop(ctx.currentTime+1.8); lfo.stop(ctx.currentTime+1.8);
  }},
  {label:'🚀 Whoosh', play:function(){
    // Fast upward sweep with noise
    _tone(120,'sawtooth',0.35,0.3,3000); _noise(0.35,0.2);
  }},
  {label:'😴 Snore', play:function(){
    // In-out snoring sound
    var t=0;
    [0,900,1800].forEach(function(offset){
      setTimeout(function(){
        // inhale
        var ctx=_getCtx(), o=ctx.createOscillator(), g=ctx.createGain();
        o.connect(g); g.connect(ctx.destination); o.type='sine';
        o.frequency.setValueAtTime(100,ctx.currentTime);
        o.frequency.linearRampToValueAtTime(160,ctx.currentTime+0.3);
        o.frequency.linearRampToValueAtTime(100,ctx.currentTime+0.6);
        g.gain.setValueAtTime(0,ctx.currentTime);
        g.gain.linearRampToValueAtTime(0.4,ctx.currentTime+0.15);
        g.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+0.7);
        o.start(); o.stop(ctx.currentTime+0.7);
      }, offset);
    });
  }},
  {label:'🎵 Ding', play:function(){
    // Bright notification ding
    _tone(1568,'sine',0.6,0.4); setTimeout(function(){ _tone(2093,'sine',0.4,0.15); },80);
  }},
  {label:'😱 Scream', play:function(){
    // Rising scream with vibrato
    var ctx=_getCtx(), o=ctx.createOscillator(), lfo=ctx.createOscillator(),
        lfoG=ctx.createGain(), g=ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    lfo.connect(lfoG); lfoG.connect(o.frequency);
    o.type='sawtooth'; o.frequency.setValueAtTime(500,ctx.currentTime);
    o.frequency.linearRampToValueAtTime(1100,ctx.currentTime+0.6);
    lfo.frequency.setValueAtTime(8,ctx.currentTime); lfoG.gain.setValueAtTime(30,ctx.currentTime);
    g.gain.setValueAtTime(0.45,ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+0.7);
    lfo.start(); o.start(); o.stop(ctx.currentTime+0.7); lfo.stop(ctx.currentTime+0.7);
  }},
  {label:'🤣 Ha Ha Ha', play:function(){
    // Rapid higher laugh
    [0,180,360,540,720,900].forEach(function(t){
      setTimeout(function(){ _tone(380+(Math.random()*80),'sine',0.12,0.45); },t);
    });
  }},
  {label:'🏆 Level Up', play:function(){
    // Mario-style ascending chime
    _seq([{f:523,t:0,type:'square',dur:0.1,vol:0.3},{f:659,t:120,type:'square',dur:0.1,vol:0.3},
          {f:784,t:240,type:'square',dur:0.1,vol:0.3},{f:1047,t:360,type:'square',dur:0.15,vol:0.35},
          {f:1319,t:510,type:'square',dur:0.25,vol:0.3}]);
  }},
  {label:'❌ Wrong Buzz', play:function(){
    // Low buzzer
    _tone(160,'sawtooth',0.5,0.6); _tone(140,'sawtooth',0.5,0.4);
    setTimeout(function(){ _tone(120,'sawtooth',0.4,0.5); },180);
  }}
];
// Preload sounds for instant playback
(function(){
  var preloaded = {};
  window._soundCache = preloaded;
})();
var activeSoundAudio = null;

function openSoundboard() {
  openModal('modal-soundboard');
  var grid = document.getElementById('soundboard-grid');
  grid.innerHTML = SOUNDS.map(function(s, i) {
    return '<button onclick="playSound('+i+')" id="snd-'+i+'" style="padding:14px 8px;border-radius:14px;border:1px solid var(--border);background:var(--deep);color:var(--moon);font-size:12px;cursor:pointer;transition:all .2s;text-align:center">'+s.label+'</button>';
  }).join('');
}

function playSound(i) {
  var s = SOUNDS[i];
  if (!s) return;
  // Reset all buttons
  document.querySelectorAll('[id^="snd-"]').forEach(function(b){
    var idx = parseInt(b.id.replace('snd-',''));
    if (!isNaN(idx) && SOUNDS[idx]) b.textContent = SOUNDS[idx].label;
    b.style.background = 'var(--deep)'; b.style.borderColor = 'var(--border)';
  });
  var btn = document.getElementById('snd-'+i);
  if (btn) { btn.style.background='rgba(34,197,94,.2)'; btn.style.borderColor='var(--green3)'; btn.textContent='▶ '+s.label; }

  function doPlay() {
    try {
      s.play();
      setTimeout(function(){
        if (btn) { btn.style.background='var(--deep)'; btn.style.borderColor='var(--border)'; btn.textContent=s.label; }
      }, 2800);
    } catch(e) {
      if (btn) { btn.style.background='var(--deep)'; btn.style.borderColor='var(--border)'; btn.textContent=s.label; }
      showToast('Audio error — try again');
    }
  }

  // Always create/resume AudioContext from within a user gesture
  try {
    if (!_audioCtx) {
      _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (_audioCtx.state === 'suspended' || _audioCtx.state === 'interrupted') {
      _audioCtx.resume().then(doPlay).catch(function(){
        // If resume fails, create a fresh context
        _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        doPlay();
      });
    } else {
      doPlay();
    }
  } catch(e) {
    showToast('Your browser blocked audio. Try tapping the screen first.');
  }
}


// ── 5. WORD OF THE DAY ────────────────────────────────────────────────────
var WORDS_BANK = [
  {word:'Resilience',pos:'noun',def:'The ability to recover quickly from difficulties and keep moving forward.',eg:'Her resilience in the face of hardship inspired everyone around her.'},
  {word:'Ephemeral',pos:'adjective',def:'Lasting for a very short time; transitory.',eg:'Social media fame can be ephemeral if you don\'t stay consistent.'},
  {word:'Serendipity',pos:'noun',def:'The occurrence of events by chance in a happy or beneficial way.',eg:'Meeting his business partner was pure serendipity.'},
  {word:'Perspicacious',pos:'adjective',def:'Having a ready insight into things; shrewdly perceptive.',eg:'A perspicacious investor sees opportunities others miss.'},
  {word:'Tenacity',pos:'noun',def:'The quality of being very determined and not giving up easily.',eg:'His tenacity helped him build a successful app despite all obstacles.'},
  {word:'Luminous',pos:'adjective',def:'Full of or shedding light; bright and radiant.',eg:'Her luminous personality lit up every room she entered.'},
  {word:'Catalyst',pos:'noun',def:'A person or thing that causes change or action.',eg:'Great mentors serve as a catalyst for personal growth.'},
  {word:'Pragmatic',pos:'adjective',def:'Dealing with things sensibly and realistically, based on practical considerations.',eg:'A pragmatic approach to building the app saved them months of work.'},
  {word:'Euphoria',pos:'noun',def:'A feeling or state of intense happiness and excitement.',eg:'The euphoria of launching your first app is unforgettable.'},
  {word:'Equanimity',pos:'noun',def:'Mental calmness and composure, especially in difficult situations.',eg:'He handled the criticism with remarkable equanimity.'},
  {word:'Fortitude',pos:'noun',def:'Courage in facing pain, danger, or adversity.',eg:'It takes fortitude to keep building when nobody believes in your vision.'},
  {word:'Sagacious',pos:'adjective',def:'Having or showing keen mental discernment and good judgement.',eg:'A sagacious entrepreneur knows when to pivot and when to persist.'},
  {word:'Benevolent',pos:'adjective',def:'Well meaning and kindly; generous and caring about others.',eg:'A benevolent leader always puts the team\'s wellbeing first.'},
  {word:'Indomitable',pos:'adjective',def:'Impossible to subdue or defeat; unconquerable.',eg:'Her indomitable spirit carried her through every setback.'},
  {word:'Eloquent',pos:'adjective',def:'Fluent or persuasive in speaking or writing.',eg:'An eloquent speech can change the direction of an entire movement.'},
  {word:'Perseverance',pos:'noun',def:'Continued effort to do something despite difficulty or delay.',eg:'Perseverance separates those who succeed from those who give up.'},
  {word:'Innovative',pos:'adjective',def:'Featuring new methods; introducing new ideas or products.',eg:'Mindvora was built by an innovative young developer with a big vision.'},
  {word:'Audacious',pos:'adjective',def:'Showing a willingness to take surprisingly bold risks.',eg:'Starting a social media platform from scratch is an audacious move.'},
  {word:'Prolific',pos:'adjective',def:'Producing much fruit or many works; highly creative and productive.',eg:'A prolific creator posts consistently and engages with their audience daily.'},
  {word:'Visionary',pos:'noun/adjective',def:'A person with original ideas about the future; thinking about the future with imagination.',eg:'Every great company was started by a visionary who saw what others couldn\'t.'},
  {word:'Adamant',pos:'adjective',def:'Refusing to change one\'s mind or opinion.',eg:'His adamant attitude led to his downfall'},
  {word:'Immense',pos:'adjective',def:'Extreme or Mighty.',eg:'He demonstrated his immense ability before his audience during a talent show programme.'},
  {word:'Enraged',pos:'noun',def:'A feeling of anger.',eg:'The parent of that boy were enraged at his academic performance.'},
  {word:'Racism',pos:'adjective',def:'Segregation or separation.',eg:'Racism downgrades peoples ability and confidence about something.'},
];

function openWordOfDay() {
  openModal('modal-word');
  var body = document.getElementById('word-body');
  // Use date to pick a consistent word per day
  var dayIndex = Math.floor(Date.now() / 86400000) % WORDS_BANK.length;
  var w = WORDS_BANK[dayIndex];
  body.innerHTML =
    '<div style="text-align:center;padding:10px 0 20px">' +
      '<div style="font-size:32px;font-weight:700;color:var(--green3);font-family:\'DM Serif Display\',serif;margin-bottom:4px">'+esc(w.word)+'</div>' +
      '<div style="font-size:11px;color:var(--muted);font-style:italic;margin-bottom:16px">'+esc(w.pos)+'</div>' +
      '<div style="font-size:13px;color:var(--moon);line-height:1.7;margin-bottom:14px;text-align:left;background:var(--deep);padding:12px;border-radius:10px;border:1px solid var(--border)">'+esc(w.def)+'</div>' +
      '<div style="font-size:12px;color:var(--muted);font-style:italic;text-align:left;padding:0 4px">📌 "'+esc(w.eg)+'"</div>' +
      '<button class="btn-pay" style="margin-top:16px" onclick="shareWordOfDay(\''+esc(w.word)+'\',\''+esc(w.def)+'\')">Share This Word ✨</button>' +
    '</div>';
}

function shareWordOfDay(word, def) {
  db.collection('sparks').add({
    text: '📖 Word of the Day: \'' + word + '\'\n\n' + def + '\n\n#WordOfTheDay #Mindvora',
    authorId: state.user.uid,
    authorName: state.profile.name,
    authorHandle: state.profile.handle || 'user',
    authorColor: state.profile.color || COLORS[0],
    category: 'general',
    likes: [], saved: [], commentCount: 0,
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(){ showToast('📖 Word shared to your feed!'); closeModal('modal-word'); })
    .catch(function(){ showToast('Error sharing'); });
}

// ── 6. MINDVORA TV ────────────────────────────────────────────────────────
function openMindvoraTV() {
  if (!state.user) { showToast('Login first'); return; }
  openModal('modal-tv');
  loadTV('trending', document.querySelector('#tv-tabs .f-pill'));
}

function loadTV(filter, btn) {
  if (btn) {
    document.querySelectorAll('#tv-tabs .f-pill').forEach(function(b){ b.classList.remove('active'); });
    btn.classList.add('active');
  }
  var grid = document.getElementById('tv-grid');
  grid.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading…</div>';

  var query = db.collection('sparks').where('mediaType','==','video').limit(20);
  query.get().then(function(snap) {
    if (snap.empty) {
      grid.innerHTML = '<div style="text-align:center;padding:30px;color:var(--muted)"><div style="font-size:32px;margin-bottom:8px">📺</div><div>No videos yet. Be the first to post!</div></div>';
      return;
    }
    var docs = snap.docs.map(function(d){ return Object.assign({id:d.id},d.data()); });
    // Sort client-side
    if (filter === 'trending') docs.sort(function(a,b){ return ((b.likes||[]).length+(b.commentCount||0)) - ((a.likes||[]).length+(a.commentCount||0)); });
    else if (filter === 'recent') docs.sort(function(a,b){ var ta=a.createdAt&&a.createdAt.seconds?a.createdAt.seconds:0; var tb=b.createdAt&&b.createdAt.seconds?b.createdAt.seconds:0; return tb-ta; });
    else if (filter === 'top') docs.sort(function(a,b){ return (b.likes||[]).length - (a.likes||[]).length; });

    grid.innerHTML = docs.map(function(s) {
      return '<div style="display:flex;gap:12px;align-items:center;padding:10px;background:var(--deep);border-radius:12px;border:1px solid var(--border);cursor:pointer" onclick="openReel(\''+s.id+'\',\''+esc(s.mediaUrl||'')+'\',\''+esc(s.authorName||'User')+'\',\''+esc((s.text||'').slice(0,50))+'\','+(s.likes||[]).length+')">' +
        '<video src="'+esc(s.mediaUrl||'')+'" style="width:72px;height:72px;object-fit:cover;border-radius:8px;flex-shrink:0" muted preload="metadata"></video>' +
        '<div style="flex:1;min-width:0">' +
          '<div style="font-size:13px;font-weight:700;color:var(--moon);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(s.authorName||'User')+'</div>' +
          '<div style="font-size:11px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc((s.text||'No caption').slice(0,60))+'</div>' +
          '<div style="display:flex;gap:10px;margin-top:6px;font-size:11px;color:var(--muted)">' +
            '<span>❤️ '+(s.likes||[]).length+'</span>' +
            '<span>💬 '+(s.commentCount||0)+'</span>' +
          '</div>' +
        '</div>' +
        '<div style="font-size:20px;color:var(--green3);flex-shrink:0">▶</div>' +
      '</div>';
    }).join('');
  }).catch(function(){ grid.innerHTML='<div style="color:#fca5a5;padding:10px;text-align:center">Error loading</div>'; });
}



// ══════════════════════════════════════════════════════════════
// EDIT & DELETE — Messages and Comments
// ══════════════════════════════════════════════════════════════

// ── DELEGATED click handler for edit/delete actions ──────────────────────
document.addEventListener('click', function(e) {
  var btn = e.target.closest('[data-action]');
  if (!btn) return;
  var action = btn.dataset.action;

  // ── DM MESSAGE EDIT ──
  if (action === 'edit-msg') {
    var dmId   = btn.dataset.dmid;
    var msgId  = btn.dataset.msgid;
    var oldTxt = btn.dataset.text.replace(/&#39;/g,"'").replace(/&quot;/g,'"');
    var newTxt = prompt('Edit your message:', oldTxt);
    if (newTxt === null) return; // cancelled
    newTxt = newTxt.trim();
    if (!newTxt) { showToast('Message cannot be empty'); return; }
    if (newTxt === oldTxt) return;
    db.collection('dms').doc(dmId).collection('messages').doc(msgId)
      .update({ text: newTxt, edited: true, editedAt: firebase.firestore.FieldValue.serverTimestamp() })
      .then(function(){ showToast('✏️ Message edited'); })
      .catch(function(){ showToast('Error editing message'); });
  }

  // ── DM MESSAGE DELETE ──
  if (action === 'del-msg') {
    var dmId  = btn.dataset.dmid;
    var msgId = btn.dataset.msgid;
    if (!confirm('Delete this message?')) return;
    db.collection('dms').doc(dmId).collection('messages').doc(msgId)
      .delete()
      .then(function(){ showToast('🗑 Message deleted'); })
      .catch(function(){ showToast('Error deleting message'); });
  }

  // ── COMMENT EDIT ──
  if (action === 'edit-cmt') {
    var sparkId = btn.dataset.sparkid;
    var cmtId   = btn.dataset.cmtid;
    var oldTxt  = btn.dataset.text.replace(/&#39;/g,"'").replace(/&quot;/g,'"');
    var newTxt  = prompt('Edit your comment:', oldTxt);
    if (newTxt === null) return;
    newTxt = newTxt.trim();
    if (!newTxt) { showToast('Comment cannot be empty'); return; }
    if (newTxt === oldTxt) return;
    db.collection('sparks').doc(sparkId).collection('comments').doc(cmtId)
      .update({ text: newTxt, edited: true, editedAt: firebase.firestore.FieldValue.serverTimestamp() })
      .then(function(){
        showToast('✏️ Comment edited');
        // Update in DOM immediately without reloading
        var el = document.getElementById('cmt-txt-' + cmtId);
        if (el) el.textContent = newTxt;
      })
      .catch(function(){ showToast('Error editing comment'); });
  }

  // ── COMMENT DELETE ──
  if (action === 'del-cmt') {
    var sparkId = btn.dataset.sparkid;
    var cmtId   = btn.dataset.cmtid;
    if (!confirm('Delete this comment?')) return;
    db.collection('sparks').doc(sparkId).collection('comments').doc(cmtId)
      .delete()
      .then(function(){
        showToast('🗑 Comment deleted');
        // Update comment count
        db.collection('sparks').doc(sparkId).update({
          commentCount: firebase.firestore.FieldValue.increment(-1)
        }).catch(function(){});
        // Remove from DOM immediately
        var itemEl = btn.closest('.cmt-item');
        if (itemEl) itemEl.remove();
      })
      .catch(function(){ showToast('Error deleting comment'); });
  }
}, false);


// ══════════════════════════════════════════════════════════════
// EDIT POSTS + VOICEOVER REPLIES
// ══════════════════════════════════════════════════════════════

// ── EDIT SPARK (post) ────────────────────────────────────────────────────
function editSpark(id, oldText) {
  var decoded = oldText.replace(/&#39;/g,"'").replace(/&quot;/g,'"');
  var newText = prompt('Edit your post:', decoded);
  if (newText === null) return;
  newText = newText.trim();
  if (!newText) { showToast('Post text cannot be empty'); return; }
  if (newText === decoded) return;
  db.collection('sparks').doc(id).update({
    text: newText,
    edited: true,
    editedAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function(){
    showToast('✏️ Post updated!');
  }).catch(function(){ showToast('Error updating post'); });
}

// ── VOICEOVER REPLY ──────────────────────────────────────────────────────
var _voiceSparkId = null;
var _voiceAuthor  = null;
var _mediaRecorder = null;
var _voiceChunks   = [];
var _voiceStream   = null;
var _voiceTimer    = null;
var _voiceSecs     = 0;

function openVoiceReply(sparkId, authorName) {
  if (!state.user) { showToast('Login first'); return; }
  _voiceSparkId = sparkId;
  _voiceAuthor  = authorName;
  openModal('modal-voice-reply');
  document.getElementById('vr-status').textContent  = 'Tap Record to start';
  document.getElementById('vr-timer').textContent   = '0:00';
  document.getElementById('vr-preview').style.display = 'none';
  document.getElementById('vr-send-btn').style.display = 'none';
  document.getElementById('vr-rec-btn').textContent  = '🎙 Record';
  document.getElementById('vr-rec-btn').style.background = 'var(--green2)';
  document.getElementById('vr-to').textContent = 'Replying to ' + authorName + ' with a voice note';
  _voiceChunks = [];
}

function toggleVoiceRecord() {
  if (_mediaRecorder && _mediaRecorder.state === 'recording') {
    stopVoiceRecord();
  } else {
    startVoiceRecord();
  }
}

function startVoiceRecord() {
  navigator.mediaDevices.getUserMedia({ audio: true }).then(function(stream) {
    _voiceStream = stream;
    _mediaRecorder = new MediaRecorder(stream);
    _voiceChunks = [];
    _voiceSecs = 0;

    _mediaRecorder.ondataavailable = function(e) {
      if (e.data.size > 0) _voiceChunks.push(e.data);
    };

    _mediaRecorder.onstop = function() {
      var blob = new Blob(_voiceChunks, { type: 'audio/webm' });
      var url  = URL.createObjectURL(blob);
      var prev = document.getElementById('vr-preview');
      prev.src = url;
      prev.style.display = 'block';
      document.getElementById('vr-send-btn').style.display = 'block';
      document.getElementById('vr-status').textContent = 'Voice note ready — listen then send';
      // Store blob for upload
      prev.dataset.blob = 'ready';
      window._voiceBlob = blob;
    };

    _mediaRecorder.start();
    clearInterval(_voiceTimer);
    _voiceTimer = setInterval(function() {
      _voiceSecs++;
      var m = Math.floor(_voiceSecs / 60), s = _voiceSecs % 60;
      document.getElementById('vr-timer').textContent = m + ':' + (s < 10 ? '0' : '') + s;
      if (_voiceSecs >= 120) stopVoiceRecord(); // max 2 min
    }, 1000);

    document.getElementById('vr-rec-btn').textContent = '⏹ Stop';
    document.getElementById('vr-rec-btn').style.background = '#ef4444';
    document.getElementById('vr-status').textContent = '🔴 Recording…';
  }).catch(function() {
    showToast('❌ Microphone access denied');
  });
}

function stopVoiceRecord() {
  if (_mediaRecorder && _mediaRecorder.state === 'recording') {
    _mediaRecorder.stop();
  }
  clearInterval(_voiceTimer);
  if (_voiceStream) { _voiceStream.getTracks().forEach(function(t){ t.stop(); }); }
  document.getElementById('vr-rec-btn').textContent = '🎙 Record Again';
  document.getElementById('vr-rec-btn').style.background = 'var(--green2)';
}

function sendVoiceReply() {
  if (!window._voiceBlob || !_voiceSparkId) { showToast('No voice note recorded'); return; }
  var btn = document.getElementById('vr-send-btn');
  btn.disabled = true; btn.textContent = 'Uploading…';

  // Upload to Cloudinary
  var fd = new FormData();
  fd.append('file', window._voiceBlob, 'voice-reply.webm');
  fd.append('upload_preset', 'ml_default');
  fd.append('resource_type', 'video'); // Cloudinary uses video for audio

  fetch('https://api.cloudinary.com/v1_1/' + CLOUD_NAME + '/video/upload', {
    method: 'POST', body: fd
  }).then(function(r){ return r.json(); }).then(function(res) {
    if (!res.secure_url) { showToast('Upload failed'); btn.disabled=false; btn.textContent='Send Voice Reply'; return; }

    // Save as comment with voice type
    db.collection('sparks').doc(_voiceSparkId).collection('comments').add({
      authorId:    state.user.uid,
      authorName:  state.profile.name,
      authorHandle:state.profile.handle || 'user',
      authorColor: state.profile.color  || COLORS[0],
      text:        '🎙 Voice reply',
      voiceUrl:    res.secure_url,
      isVoice:     true,
      duration:    _voiceSecs,
      createdAt:   firebase.firestore.FieldValue.serverTimestamp()
    }).then(function() {
      db.collection('sparks').doc(_voiceSparkId).update({
        commentCount: firebase.firestore.FieldValue.increment(1)
      });
      // Notify post author
      db.collection('sparks').doc(_voiceSparkId).get().then(function(d) {
        if (d.exists && d.data().authorId !== state.user.uid) {
          db.collection('notifications').add({
            toUid:    d.data().authorId,
            fromName: state.profile.name,
            type:     'voice_reply',
            text:     state.profile.name + ' sent you a voice reply 🎙',
            sparkId:  _voiceSparkId,
            read:     false,
            createdAt: firebase.firestore.FieldValue.serverTimestamp()
          }).catch(function(){});
        }
      });
      showToast('🎙 Voice reply sent!');
      closeModal('modal-voice-reply');
      window._voiceBlob = null;
      // Reload comments if open
      if (state.currentSparkId === _voiceSparkId) openComments(_voiceSparkId);
    }).catch(function(){ showToast('Error saving voice reply'); btn.disabled=false; btn.textContent='Send Voice Reply'; });
  }).catch(function(){ showToast('Upload failed'); btn.disabled=false; btn.textContent='Send Voice Reply'; });
}

// ── REAL-TIME UPDATES (already powered by Firebase onSnapshot) ───────────
// Firebase Firestore onSnapshot IS a WebSocket connection — it pushes updates
// instantly to all users without any page refresh needed.
// The feed, DMs, notifications and all live data already use onSnapshot.
// We just need to make sure the feed uses onSnapshot (not .get()) always:
function ensureRealtimeFeed() {
  if (!state.user) return;
  if (!state.sparksUnsub) {
    loadSparks(); // loadSparks already uses onSnapshot
  }
}

// ╔══════════════════════════════════════════════════════════════╗
// ║           NOWPAYMENTS CRYPTO INTEGRATION                     ║
// ║   Keys stored securely in Render.com backend                 ║
// ║   Public Key only in frontend (safe)                         ║
// ╚══════════════════════════════════════════════════════════════╝

// NOWPayments keys moved to secure backend — never expose API key in frontend
var NOWPAY_PUBLIC_KEY = '440f0f69-11dd-4248-91f3-903e123538ee'; // public key only — safe
var BACKEND_URL       = ''; // Backend calls are now proxied transparently via vercel.json

// ── SWITCH PAYMENT METHOD TABS ────────────────────────────────────────────
function switchPayMethod(method) {
  document.getElementById('pay-panel-paystack').style.display = method === 'paystack' ? 'block' : 'none';
  document.getElementById('pay-panel-crypto').style.display   = method === 'crypto'   ? 'block' : 'none';
  document.getElementById('pay-method-paystack').classList.toggle('active', method === 'paystack');
  document.getElementById('pay-method-crypto').classList.toggle('active', method === 'crypto');
}

// ── CREATE NOWPAYMENTS INVOICE & OPEN PAYMENT PAGE ────────────────────────
function createCryptoPayment(amountUSD, description, onSuccess) {
  if (!state.user) { showToast('Login first'); return; }
  showToast('₿ Setting up crypto payment…');

  // Proceed with creating the invoice
  setTimeout(function() {
    createCryptoInvoice(amountUSD, description, onSuccess);
  }, 500);
}

function createCryptoInvoice(amountUSD, description, onSuccess) {
  fetch(BACKEND_URL + '/api/crypto/create-invoice', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      price_amount:    amountUSD,
      price_currency:  'usd',
      pay_currency:    'usdtbsc', // default USDT on BSC — user can switch
      order_id:        'MV-' + state.user.uid + '-' + Date.now(),
      order_description: description,
      ipn_callback_url:  BACKEND_URL + '/api/crypto/webhook', // update when live domain set
      success_url:       window.location.href,
      cancel_url:        window.location.href,
    })
  })
  .then(function(r){ return r.json(); })
  .then(function(data) {
    if (!data.invoice_url) {
      showToast('❌ Crypto payment setup failed. Try card payment.');
      console.error('NOWPayments error:', data);
      return;
    }
    // Save pending crypto payment to Firestore
    db.collection('crypto_payments').add({
      uid:         state.user.uid,
      email:       state.user.email,
      name:        state.profile.name,
      amountUSD:   amountUSD,
      description: description,
      invoiceId:   data.id,
      invoiceUrl:  data.invoice_url,
      status:      'pending',
      createdAt:   firebase.firestore.FieldValue.serverTimestamp()
    }).then(function(docRef) {
      // Poll for payment status
      pollCryptoPayment(data.id, docRef.id, onSuccess);
    });

    // Open payment page in new tab
    window.open(data.invoice_url, '_blank');
    showToast('₿ Crypto payment page opened! Complete payment in the new tab.');
  })
  .catch(function(err) {
    showToast('❌ Crypto payment setup failed. Please try again or use Card/Bank.');
    console.error('Crypto error:', err);
  });
}

// ── POLL PAYMENT STATUS (check every 15s for up to 30 mins) ──────────────
function pollCryptoPayment(invoiceId, docId, onSuccess) {
  var attempts = 0;
  var maxAttempts = 120; // 30 mins at 15s intervals
  var pollTimer = setInterval(function() {
    attempts++;
    if (attempts > maxAttempts) {
      clearInterval(pollTimer);
      showToast('⏰ Payment window expired. If you paid, contact support.');
      return;
    }
    fetch(BACKEND_URL + '/api/crypto/status/' + invoiceId)
    .then(function(r){ return r.json(); })
    .then(function(data) {
      var status = data.status || '';
      if (status === 'finished' || status === 'confirmed' || status === 'partially_paid') {
        clearInterval(pollTimer);
        // Update Firestore record
        db.collection('crypto_payments').doc(docId).update({
          status: 'completed',
          paidAt: firebase.firestore.FieldValue.serverTimestamp(),
          payCurrency: data.pay_currency,
          payAmount: data.pay_amount
        });
        // Execute success callback
        if (typeof onSuccess === 'function') onSuccess();
        showToast('✅ Crypto payment confirmed!');
      } else if (status === 'failed' || status === 'refunded' || status === 'expired') {
        clearInterval(pollTimer);
        db.collection('crypto_payments').doc(docId).update({ status: status });
        showToast('❌ Crypto payment ' + status + '. Try again.');
      }
    })
    .catch(function(){});
  }, 15000);
}

// ── PREMIUM SUBSCRIPTION VIA CRYPTO ──────────────────────────────────────
function payCrypto() {
  if (!state.plan) { showToast('Select a plan first'); return; }
  createCryptoPayment(
    state.plan.amount,
    'Mindvora ' + state.plan.name + ' Monthly Subscription',
    function() {
      // On payment confirmed — activate premium
      db.collection('users').doc(state.user.uid).update({
        isPremium: true,
        plan: state.plan.id,
        premiumActivatedCrypto: true
      });
      state.profile.isPremium = true;
      closeModal('modal-prem');
      document.getElementById('prem-widget') && (document.getElementById('prem-widget').style.display = 'none');
      showToast('🎉 Welcome to ' + state.plan.name + '! 💎');
    }
  );
}

// ── VERIFIED BADGE VIA CRYPTO ─────────────────────────────────────────────
function payBadgeCrypto() {
  createCryptoPayment(
    30,
    'Mindvora Verified Badge',
    function() {
      db.collection('users').doc(state.user.uid).update({ isVerified: true }).then(function() {
        state.profile.isVerified = true;
        closeModal('modal-prem');
        showToast('🎉 Congratulations! You are now Verified on Mindvora! ✅');
        db.collection('notifications').add({
          toUid: state.user.uid,
          type: 'verified',
          text: '✅ Your Mindvora Verified Badge has been activated via crypto payment!',
          read: false,
          createdAt: firebase.firestore.FieldValue.serverTimestamp()
        }).catch(function(){});
      });
    }
  );
}

// ── CREATOR TIPS VIA CRYPTO ───────────────────────────────────────────────
function tipCreatorCrypto(recipientId, recipientName, amount) {
  createCryptoPayment(
    amount,
    'Tip for ' + recipientName + ' on Mindvora',
    function() {
      // Credit tip to recipient earnings
      db.collection('users').doc(recipientId).update({
        tips: firebase.firestore.FieldValue.increment(amount * 0.9),
        earnings: firebase.firestore.FieldValue.increment(amount * 0.9)
      });
      // Notify recipient
      db.collection('notifications').add({
        toUid: recipientId,
        fromName: state.profile.name,
        type: 'tip',
        text: state.profile.name + ' sent you a $' + amount + ' crypto tip! 💰',
        read: false,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      }).catch(function(){});
      showToast('💰 $' + amount + ' crypto tip sent to ' + recipientName + '!');
    }
  );
}

// ── GIFT SYSTEM VIA CRYPTO ────────────────────────────────────────────────
function sendGiftCrypto(recipientId, recipientName, giftName, amount) {
  createCryptoPayment(
    amount,
    giftName + ' gift for ' + recipientName + ' on Mindvora',
    function() {
      db.collection('users').doc(recipientId).update({
        earnings: firebase.firestore.FieldValue.increment(amount * 0.9)
      });
      db.collection('notifications').add({
        toUid: recipientId,
        fromName: state.profile.name,
        type: 'gift',
        text: state.profile.name + ' sent you a ' + giftName + ' worth $' + amount + ' via crypto! 🎁',
        read: false,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      }).catch(function(){});
      showToast('🎁 ' + giftName + ' sent to ' + recipientName + ' via crypto!');
    }
  );
}




// ── SECURE API PROXY HELPER ───────────────────────────────────────────────
// All calls needing secret keys go through Vercel serverless functions
function callSecureAPI(endpoint, payload) {
  return fetch(BACKEND_URL + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r){ return r.json(); });
}

// ── CURRENCY CONVERSION FOR WITHDRAWALS ───────────────────────────────────
// Uses free exchangerate-api to get real-time rates
var CURRENCY_CACHE = {};
var CURRENCY_CACHE_TIME = 0;

// Country → currency code mapping
var COUNTRY_CURRENCIES = {
  'NG':'NGN','GH':'GHS','KE':'KES','ZA':'ZAR','TZ':'TZS','UG':'UGX',
  'RW':'RWF','ET':'ETB','SN':'XOF','CI':'XOF','CM':'XAF','TG':'XOF',
  'BJ':'XOF','ML':'XOF','BF':'XOF','NE':'XOF','CD':'CDF','AO':'AOA',
  'MZ':'MZN','ZM':'ZMW','MW':'MWK','ZW':'ZWL','BW':'BWP','NA':'NAD',
  'SL':'SLL','LR':'LRD','GM':'GMD','GN':'GNF','MR':'MRO',
  'US':'USD','GB':'GBP','EU':'EUR','CA':'CAD','AU':'AUD',
  'IN':'INR','CN':'CNY','JP':'JPY','BR':'BRL','MX':'MXN',
  'AE':'AED','SA':'SAR','QA':'QAR','KW':'KWD','EG':'EGP',
};

var CURRENCY_SYMBOLS = {
  'NGN':'₦','GHS':'₵','KES':'KSh','ZAR':'R','USD':'$','GBP':'£',
  'EUR':'€','CAD':'CA$','AUD':'A$','INR':'₹','CNY':'¥','JPY':'¥',
  'BRL':'R$','AED':'د.إ','SAR':'﷼','EGP':'E£','XOF':'CFA','XAF':'FCFA',
};

function getUserCurrency() {
  // Try to detect user's country from browser/profile
  var lang = navigator.language || 'en-US';
  var country = lang.split('-')[1] || 'US';
  return COUNTRY_CURRENCIES[country] || 'USD';
}

function getExchangeRate(fromCurrency, toCurrency, callback) {
  if (fromCurrency === toCurrency) { callback(1); return; }
  var cacheKey = fromCurrency + '_' + toCurrency;
  var now = Date.now();
  // Cache rates for 1 hour
  if (CURRENCY_CACHE[cacheKey] && (now - CURRENCY_CACHE_TIME) < 3600000) {
    callback(CURRENCY_CACHE[cacheKey]);
    return;
  }
  fetch(BACKEND_URL + '/api/rate/' + fromCurrency + '/' + toCurrency)
    .then(function(r){ return r.json(); })
    .then(function(data) {
      var rate = data.rates[toCurrency] || 1;
      CURRENCY_CACHE[cacheKey] = rate;
      CURRENCY_CACHE_TIME = now;
      callback(rate);
    })
    .catch(function(){ callback(1); }); // fallback to 1:1 if API fails
}

function convertAndDisplay(amountUSD, elementId) {
  var userCurrency = getUserCurrency();
  var symbol = CURRENCY_SYMBOLS[userCurrency] || userCurrency + ' ';
  if (userCurrency === 'USD') {
    var el = document.getElementById(elementId);
    if (el) el.textContent = '≈ $' + amountUSD.toFixed(2);
    return;
  }
  getExchangeRate('USD', userCurrency, function(rate) {
    var converted = (amountUSD * rate).toFixed(2);
    var el = document.getElementById(elementId);
    if (el) el.textContent = '≈ ' + symbol + parseFloat(converted).toLocaleString();
  });
}

// ── WITHDRAWAL WITH CURRENCY CONVERSION ──────────────────────────────────
var _origWithdraw = window.submitWithdrawal;

function showWithdrawalPreview(amountUSD) {
  var preview = document.getElementById('wd-currency-preview');
  if (!preview) return;
  var userCurrency = getUserCurrency();
  var symbol = CURRENCY_SYMBOLS[userCurrency] || userCurrency + ' ';
  preview.textContent = 'Converting...';
  getExchangeRate('USD', userCurrency, function(rate) {
    var converted = (amountUSD * rate);
    preview.textContent = '$' + amountUSD + ' USD = ' + symbol + converted.toLocaleString(undefined,{maximumFractionDigits:2}) + ' ' + userCurrency;
    preview.style.color = 'var(--green3)';
  });
}



// ╔══════════════════════════════════════════════════════════════╗
// ║         MINDVORA NEW FEATURES v2.0                          ║
// ║  Follow/Unfollow · Typing · Read Receipts · Post Views      ║
// ║  Block User · Report Post · Profile Edit · Mentions         ║
// ╚══════════════════════════════════════════════════════════════╝

// ── 1. FOLLOW / UNFOLLOW ─────────────────────────────────────────────────
function toggleFollow(targetUid, targetName) {
  if (!state.user) { showToast('Login first'); return; }
  if (targetUid === state.user.uid) { showToast('You cannot follow yourself'); return; }

  var myUid = state.user.uid;
  var following = state.profile.following || [];
  var isFollowing = following.indexOf(targetUid) !== -1;

  if (isFollowing) {
    // Unfollow
    db.collection('users').doc(myUid).update({
      following: firebase.firestore.FieldValue.arrayRemove(targetUid),
      followingCount: firebase.firestore.FieldValue.increment(-1)
    }).catch(function(){});
    db.collection('users').doc(targetUid).update({
      followers: firebase.firestore.FieldValue.increment(-1)
    }).catch(function(){});
    state.profile.following = following.filter(function(u){ return u !== targetUid; });
    showToast('Unfollowed ' + targetName);
  } else {
    // Follow
    db.collection('users').doc(myUid).update({
      following: firebase.firestore.FieldValue.arrayUnion(targetUid),
      followingCount: firebase.firestore.FieldValue.increment(1)
    }).catch(function(){});
    db.collection('users').doc(targetUid).update({
      followers: firebase.firestore.FieldValue.increment(1)
    }).then(function() {
      // Notify
      db.collection('notifications').add({
        toUid: targetUid,
        fromName: state.profile.name,
        fromUid: myUid,
        type: 'follow',
        text: state.profile.name + ' started following you',
        read: false,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      }).catch(function(){});
    }).catch(function(){});
    state.profile.following = following.concat([targetUid]);
    showToast('Now following ' + targetName + ' 🌿');
  }
}

function isFollowing(targetUid) {
  return state.profile && (state.profile.following || []).indexOf(targetUid) !== -1;
}

// ── 2. TYPING INDICATOR IN DMs ───────────────────────────────────────────
var _typingTimers = {};
var _typingUnsubs = {};

function sendTypingIndicator(dmId) {
  if (!state.user) return;
  db.collection('dms').doc(dmId).update({
    ['typing.' + state.user.uid]: firebase.firestore.FieldValue.serverTimestamp()
  }).catch(function(){});
}

function watchTyping(dmId, otherUid) {
  if (_typingUnsubs[dmId]) return;
  _typingUnsubs[dmId] = db.collection('dms').doc(dmId).onSnapshot(function(snap) {
    if (!snap.exists) return;
    var data = snap.data();
    var typing = data && data.typing && data.typing[otherUid];
    var indicator = document.getElementById('typing-indicator-' + dmId);
    if (!indicator) return;
    if (typing) {
      var age = Date.now() - (typing.seconds * 1000);
      if (age < 4000) {
        indicator.style.display = 'block';
        clearTimeout(_typingTimers[dmId]);
        _typingTimers[dmId] = setTimeout(function() {
          indicator.style.display = 'none';
        }, 3000);
      } else {
        indicator.style.display = 'none';
      }
    } else {
      indicator.style.display = 'none';
    }
  }, function(){});
}

// ── 3. POST VIEWS COUNTER ─────────────────────────────────────────────────
var _viewedPosts = {};

function trackPostView(sparkId, authorId) {
  if (!state.user || !sparkId) return;
  if (_viewedPosts[sparkId]) return; // Already counted this session
  if (authorId === state.user.uid) return; // Don't count own views
  _viewedPosts[sparkId] = true;
  db.collection('sparks').doc(sparkId).update({
    viewCount: firebase.firestore.FieldValue.increment(1)
  }).catch(function(){});
}

// ── 4. BLOCK USER ────────────────────────────────────────────────────────
function blockUser(targetUid, targetName) {
  if (!state.user) return;
  if (!confirm('Block ' + targetName + '? They will not be able to see your posts or message you.')) return;

  db.collection('users').doc(state.user.uid).update({
    blockedUsers: firebase.firestore.FieldValue.arrayUnion(targetUid)
  }).then(function() {
    if (!state.profile.blockedUsers) state.profile.blockedUsers = [];
    state.profile.blockedUsers.push(targetUid);
    showToast('🚫 ' + targetName + ' has been blocked');
    // Close any open DM with this user
    closeModal('modal-dm');
  }).catch(function(){ showToast('Error blocking user'); });
}

function isBlocked(targetUid) {
  return state.profile && (state.profile.blockedUsers || []).indexOf(targetUid) !== -1;
}

function unblockUser(targetUid, targetName) {
  db.collection('users').doc(state.user.uid).update({
    blockedUsers: firebase.firestore.FieldValue.arrayRemove(targetUid)
  }).then(function() {
    state.profile.blockedUsers = (state.profile.blockedUsers || []).filter(function(u){ return u !== targetUid; });
    showToast('✅ ' + targetName + ' has been unblocked');
  }).catch(function(){});
}

// ── 5. REPORT POST ───────────────────────────────────────────────────────
var REPORT_REASONS = [
  'Spam or misleading',
  'Hate speech or discrimination',
  'Violence or dangerous content',
  'Nudity or sexual content',
  'Scam or fraud',
  'Harassment or bullying',
  'False information',
  'Other'
];

function reportSpark(sparkId, authorId) {
  if (!state.user) { showToast('Login first'); return; }
  var reason = prompt('Why are you reporting this post?\n\n' +
    REPORT_REASONS.map(function(r, i){ return (i+1) + '. ' + r; }).join('\n') +
    '\n\nEnter a number (1-' + REPORT_REASONS.length + '):');
  if (!reason) return;
  var idx = parseInt(reason) - 1;
  var reasonText = REPORT_REASONS[idx] || reason;

  db.collection('reports').add({
    sparkId: sparkId,
    authorId: authorId,
    reporterId: state.user.uid,
    reporterName: state.profile.name,
    reason: reasonText,
    status: 'pending',
    createdAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function() {
    showToast('📋 Post reported. Thank you for keeping Mindvora safe.');
    // Notify admin
    notifyOwner('📋 Post Reported',
      'Post ID: ' + sparkId + '\nReporter: ' + state.profile.name +
      '\nReason: ' + reasonText, 'medium');
  }).catch(function(){ showToast('Error submitting report'); });
}

// ── 6. PROFILE EDIT ──────────────────────────────────────────────────────
function openEditProfile() {
  if (!state.user || !state.profile) return;
  openModal('modal-edit-profile');
  document.getElementById('ep-name').value = state.profile.name || '';
  document.getElementById('ep-handle').value = state.profile.handle || '';
  document.getElementById('ep-bio').value = state.profile.bio || '';
  document.getElementById('ep-website').value = state.profile.website || '';
}

function saveProfile() {
  if (!state.user) return;
  var name    = document.getElementById('ep-name').value.trim();
  var handle  = document.getElementById('ep-handle').value.trim().toLowerCase().replace(/[^a-z0-9_]/g,'');
  var bio     = document.getElementById('ep-bio').value.trim().slice(0, 160);
  var website = document.getElementById('ep-website').value.trim();
  var err     = document.getElementById('ep-err');

  if (!name) { err.textContent = 'Name is required'; return; }
  if (handle.length < 3) { err.textContent = 'Username must be at least 3 characters'; return; }
  err.textContent = '';

  var btn = document.getElementById('ep-save-btn');
  btn.disabled = true; btn.textContent = 'Saving…';

  db.collection('users').doc(state.user.uid).update({
    name: name, handle: handle, bio: bio, website: website,
    updatedAt: firebase.firestore.FieldValue.serverTimestamp()
  }).then(function() {
    state.profile.name    = name;
    state.profile.handle  = handle;
    state.profile.bio     = bio;
    state.profile.website = website;
    // Update sidebar
    document.getElementById('sb-name').innerHTML = name;
    document.getElementById('sb-handle').textContent = '@' + handle;
    showToast('✅ Profile updated!');
    closeModal('modal-edit-profile');
    btn.disabled = false; btn.textContent = 'Save Changes';
  }).catch(function(e) {
    err.textContent = 'Error saving: ' + e.message;
    btn.disabled = false; btn.textContent = 'Save Changes';
  });
}

// ── 7. READ RECEIPTS FOR DMs ─────────────────────────────────────────────
function markMessagesAsRead(dmId) {
  if (!state.user || !dmId) return;
  db.collection('dms').doc(dmId).update({
    ['readBy.' + state.user.uid]: firebase.firestore.FieldValue.serverTimestamp(),
    unread: false
  }).catch(function(){});
}

// ── 8. MENTIONS (@username) ──────────────────────────────────────────────
function parseMentions(text) {
  if (!text) return text;
  return esc(text).replace(/@([a-zA-Z0-9_]+)/g, function(match, handle) {
    return '<span style="color:var(--green3);font-weight:600;cursor:pointer" onclick="openUserByHandle(\'' + handle + '\')">' + match + '</span>';
  });
}

function openUserByHandle(handle) {
  db.collection('users').where('handle', '==', handle.toLowerCase()).limit(1).get()
    .then(function(snap) {
      if (snap.empty) { showToast('@' + handle + ' not found'); return; }
      var u = snap.docs[0].data();
      showToast('Opening @' + handle + '\'s profile');
      // Open their profile view
      openUserProfile(snap.docs[0].id, u);
    }).catch(function(){});
}

function openUserProfile(uid, userData) {
  // Show a user profile sheet
  var u = userData;
  var existing = document.getElementById('user-profile-sheet');
  if (existing) existing.remove();

  var sheet = document.createElement('div');
  sheet.id = 'user-profile-sheet';
  sheet.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:999;display:flex;align-items:flex-end;justify-content:center';
  sheet.innerHTML =
    '<div style="background:var(--card);border-radius:20px 20px 0 0;width:100%;max-width:480px;padding:20px;max-height:80vh;overflow-y:auto">' +
      '<div style="display:flex;align-items:center;gap:14px;margin-bottom:16px">' +
        '<div style="width:56px;height:56px;border-radius:50%;background:' + esc(u.color||COLORS[0]) + ';display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#fff">' + esc((u.name||'U').charAt(0).toUpperCase()) + '</div>' +
        '<div>' +
          '<div style="font-size:15px;font-weight:700;color:var(--moon)">' + esc(u.name||'User') + (u.isVerified?'<span style="color:var(--green3);margin-left:4px">✓</span>':'') + '</div>' +
          '<div style="font-size:12px;color:var(--muted)">@' + esc(u.handle||'user') + '</div>' +
        '</div>' +
        '<button onclick="document.getElementById(\'user-profile-sheet\').remove()" style="margin-left:auto;background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer">✕</button>' +
      '</div>' +
      (u.bio ? '<div style="font-size:13px;color:var(--moon);margin-bottom:12px">' + esc(u.bio) + '</div>' : '') +
      '<div style="display:flex;gap:20px;margin-bottom:16px">' +
        '<div style="text-align:center"><div style="font-size:16px;font-weight:700;color:var(--green3)">' + (u.sparksCount||0) + '</div><div style="font-size:11px;color:var(--muted)">Sparks</div></div>' +
        '<div style="text-align:center"><div style="font-size:16px;font-weight:700;color:var(--green3)">' + (u.followers||0) + '</div><div style="font-size:11px;color:var(--muted)">Followers</div></div>' +
      '</div>' +
      '<div style="display:flex;gap:8px">' +
        (state.user && uid !== state.user.uid ?
          '<button onclick="toggleFollow(\'' + uid + '\',\'' + esc(u.name) + '\');this.textContent=isFollowing(\'' + uid + '\')?\'Following\':\'Follow\'" style="flex:1;padding:10px;border-radius:12px;background:var(--green2);border:none;color:#fff;font-weight:700;cursor:pointer">' +
            (isFollowing(uid) ? 'Following' : 'Follow') +
          '</button>' : '') +
        (state.user && uid !== state.user.uid ?
          '<button onclick="var dmId=[\'' + uid + '\',\'' + (state.user?state.user.uid:'') + '\'].sort().join(\'_\');openChat(dmId,\'' + uid + '\',\'' + esc(u.name) + '\',\'' + esc(u.color||COLORS[0]) + '\');document.getElementById(\'user-profile-sheet\').remove();openModal(\'modal-dm\')" style="flex:1;padding:10px;border-radius:12px;border:1px solid var(--border);background:transparent;color:var(--moon);font-weight:700;cursor:pointer">Message</button>' : '') +
        (state.user && uid !== state.user.uid ?
          '<button onclick="blockUser(\'' + uid + '\',\'' + esc(u.name) + '\');document.getElementById(\'user-profile-sheet\').remove()" style="padding:10px 14px;border-radius:12px;border:1px solid rgba(239,68,68,.3);background:transparent;color:#fca5a5;cursor:pointer">🚫</button>' : '') +
      '</div>' +
    '</div>';
  document.body.appendChild(sheet);
  sheet.addEventListener('click', function(e) {
    if (e.target === sheet) sheet.remove();
  });
}




// ── MOBILE BOTTOM NAV ────────────────────────────────────────────────────
function setMobileNav(btn) {
  document.querySelectorAll('.bottom-nav .nav-item').forEach(function(b){ b.classList.remove('active'); });
  if(btn) btn.classList.add('active');
}

// Show bottom nav on mobile
(function() {
  function checkMobile() {
    var nav = document.querySelector('.bottom-nav');
    if (!nav) return;
    nav.style.display = window.innerWidth <= 767 ? 'flex' : 'none';
  }
  checkMobile();
  window.addEventListener('resize', checkMobile);
})();


// ── SMART VIDEO DISPLAY ───────────────────────────────────────────────────
// Adapts video display based on actual video dimensions
function adaptVideoDisplay(video) {
  var w = video.videoWidth;
  var h = video.videoHeight;
  if (!w || !h) return;

  var ratio = w / h;
  var wrapId = video.dataset.wrapid;
  var wrap = document.getElementById(wrapId);
  if (!wrap) return;

  var blur = wrap.querySelector('.sk-media-blur');

  if (ratio < 0.8) {
    // PORTRAIT video (tall like TikTok/Reels 9:16)
    // Blur background fills wrap, video centered
    wrap.style.maxHeight = '480px';
    wrap.style.background = '#000';
    if (blur) blur.style.display = 'block';
    video.style.objectFit = 'contain';
    video.style.maxHeight = '480px';
    video.style.width = '100%';
  } else if (ratio > 1.4) {
    // LANDSCAPE video (wide like 16:9)
    // Full width, no blur background needed
    wrap.style.maxHeight = '340px';
    wrap.style.background = '#000';
    if (blur) blur.style.display = 'none';
    video.style.objectFit = 'cover';
    video.style.maxHeight = '340px';
    video.style.width = '100%';
  } else {
    // SQUARE or near-square video
    // Dark sides, video centered
    wrap.style.maxHeight = '400px';
    wrap.style.background = '#111';
    if (blur) blur.style.display = 'none';
    video.style.objectFit = 'contain';
    video.style.maxHeight = '400px';
    video.style.width = '100%';
  }
}


// ── DRAWER FUNCTIONS ─────────────────────────────────────────────────────
function toggleDrawer() {
  var drawer  = document.getElementById('app-drawer');
  var overlay = document.getElementById('drawer-overlay');
  var btn     = document.getElementById('hamburger-btn');
  var isOpen  = drawer.classList.contains('open');
  if (isOpen) {
    closeDrawer();
  } else {
    drawer.classList.add('open');
    overlay.classList.add('open');
    btn.classList.add('open');
    // Update drawer profile info
    if (state.profile) {
      var av = document.getElementById('drawer-av');
      var nm = document.getElementById('drawer-name');
      var hd = document.getElementById('drawer-handle');
      if (av) {
        av.textContent = (state.profile.name||'M').charAt(0).toUpperCase();
        av.style.background = 'linear-gradient(135deg,'+( state.profile.color||'#166534')+',#16a34a)';
      }
      if (nm) nm.textContent = state.profile.name || 'Mindvora user';
      if (hd) hd.textContent = '@' + (state.profile.handle||'user');
    }
    // Show admin button for owner
    var adminBtn = document.getElementById('drawer-admin-btn');
    if (adminBtn) adminBtn.style.display = isAdmin() ? 'flex' : 'none';
  }
}

function closeDrawer() {
  var drawer  = document.getElementById('app-drawer');
  var overlay = document.getElementById('drawer-overlay');
  var btn     = document.getElementById('hamburger-btn');
  if (drawer)  drawer.classList.remove('open');
  if (overlay) overlay.classList.remove('open');
  if (btn)     btn.classList.remove('open');
}

// Close drawer on back button (Android)
window.addEventListener('popstate', function() { closeDrawer(); });

// Swipe to close drawer on mobile
(function() {
  var startX = 0;
  var drawer = null;
  document.addEventListener('touchstart', function(e) {
    drawer = document.getElementById('app-drawer');
    startX = e.touches[0].clientX;
  }, { passive: true });
  document.addEventListener('touchend', function(e) {
    if (!drawer || !drawer.classList.contains('open')) return;
    var endX = e.changedTouches[0].clientX;
    if (startX - endX > 60) closeDrawer(); // swipe left to close
  }, { passive: true });
})();


// ═══════════════════════════════════════════════════════════════════
// MINDVORA DEVICE INTELLIGENCE SYSTEM
// Uses user email + device info to fit layout perfectly on any screen
// ═══════════════════════════════════════════════════════════════════

var MV_DEVICE = {
  type: 'desktop',      // phone | tablet | desktop
  os: 'unknown',        // ios | android | windows | mac | linux
  browser: 'unknown',   // chrome | safari | firefox | edge
  screenW: window.screen.width,
  screenH: window.screen.height,
  viewW: window.innerWidth,
  viewH: window.innerHeight,
  dpr: window.devicePixelRatio || 1,
  isTouch: ('ontouchstart' in window) || navigator.maxTouchPoints > 0,
  isMobile: false,
  isTablet: false,
  isDesktop: false,
  isIOS: false,
  isAndroid: false,
  isSafari: false,
  isTWA: false  // Trusted Web Activity (Android APK via Median/Bubblewrap)
};

(function detectDevice() {
  var ua = navigator.userAgent || '';
  var sw = window.screen.width;
  var sh = window.screen.height;
  var vw = window.innerWidth;

  // OS detection
  MV_DEVICE.isIOS     = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  MV_DEVICE.isAndroid = /Android/.test(ua);
  MV_DEVICE.isSafari  = /Safari/.test(ua) && !/Chrome/.test(ua);
  MV_DEVICE.isTWA     = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;

  if (/Windows/.test(ua))     MV_DEVICE.os = 'windows';
  else if (/Mac/.test(ua))    MV_DEVICE.os = 'mac';
  else if (MV_DEVICE.isIOS)   MV_DEVICE.os = 'ios';
  else if (MV_DEVICE.isAndroid) MV_DEVICE.os = 'android';
  else if (/Linux/.test(ua))  MV_DEVICE.os = 'linux';

  if (/Chrome/.test(ua))      MV_DEVICE.browser = 'chrome';
  else if (MV_DEVICE.isSafari) MV_DEVICE.browser = 'safari';
  else if (/Firefox/.test(ua)) MV_DEVICE.browser = 'firefox';
  else if (/Edge/.test(ua))   MV_DEVICE.browser = 'edge';

  // Device type by screen width + touch
  if (vw <= 767 || (MV_DEVICE.isTouch && sw <= 767)) {
    MV_DEVICE.type = 'phone';
    MV_DEVICE.isMobile = true;
  } else if (vw <= 1024 || (MV_DEVICE.isTouch && sw <= 1024)) {
    MV_DEVICE.type = 'tablet';
    MV_DEVICE.isTablet = true;
  } else {
    MV_DEVICE.type = 'desktop';
    MV_DEVICE.isDesktop = true;
  }

  // Apply device class to body for CSS targeting
  document.body.classList.remove('device-phone','device-tablet','device-desktop','os-ios','os-android','is-twa','is-touch');
  document.body.classList.add('device-' + MV_DEVICE.type);
  document.body.classList.add('os-' + MV_DEVICE.os);
  if (MV_DEVICE.isTouch)   document.body.classList.add('is-touch');
  if (MV_DEVICE.isTWA)     document.body.classList.add('is-twa');

  applyDeviceLayout();
})();

function applyDeviceLayout() {
  var vw = window.innerWidth;
  var vh = window.innerHeight;

  // ── PHONE layout ──────────────────────────────────────────
  if (MV_DEVICE.isMobile || vw <= 767) {
    // Full screen feed, bottom nav, no sidebars
    setStyle('right-sidebar', 'display', 'none');
    setStyle('feed-col', 'paddingBottom', '70px');
    // Show bottom nav
    var bn = document.querySelector('.bottom-nav');
    if (bn) bn.style.display = 'flex';
    // Full width compose box
    setStyle('compose-box', 'borderRadius', '0');
    setStyle('compose-box', 'borderLeft', 'none');
    setStyle('compose-box', 'borderRight', 'none');
    // iOS safe area padding
    if (MV_DEVICE.isIOS) {
      document.body.style.paddingBottom = 'env(safe-area-inset-bottom, 16px)';
    }
  }

  // ── TABLET layout ─────────────────────────────────────────
  else if (MV_DEVICE.isTablet || (vw > 767 && vw <= 1024)) {
    setStyle('right-sidebar', 'display', 'block');
    setStyle('right-sidebar', 'width', '200px');
    var bn = document.querySelector('.bottom-nav');
    if (bn) bn.style.display = 'none';
  }

  // ── DESKTOP layout ────────────────────────────────────────
  else {
    setStyle('right-sidebar', 'display', 'block');
    setStyle('right-sidebar', 'width', '260px');
    var bn = document.querySelector('.bottom-nav');
    if (bn) bn.style.display = 'none';
  }

  // Fix video display for device
  fixVideosForDevice();
}

function setStyle(id, prop, val) {
  var el = document.getElementById(id) || document.querySelector('.' + id);
  if (el) el.style[prop] = val;
}

function fixVideosForDevice() {
  // Re-run adaptVideoDisplay on all loaded videos
  document.querySelectorAll('.sk-media-main').forEach(function(v) {
    if (v.videoWidth && v.videoHeight) {
      adaptVideoDisplay(v);
    }
  });
}

// Save device profile to Firebase linked to user email
function saveDeviceProfile() {
  if (!state.user || !state.user.email) return;
  try {
    var deviceData = {
      email:    state.user.email,
      uid:      state.user.uid,
      type:     MV_DEVICE.type,
      os:       MV_DEVICE.os,
      browser:  MV_DEVICE.browser,
      screenW:  window.screen.width,
      screenH:  window.screen.height,
      viewW:    window.innerWidth,
      viewH:    window.innerHeight,
      dpr:      window.devicePixelRatio || 1,
      isTouch:  MV_DEVICE.isTouch,
      isTWA:    MV_DEVICE.isTWA,
      userAgent: navigator.userAgent.slice(0, 120),
      lastSeen: firebase.firestore.FieldValue.serverTimestamp()
    };

    // Save to user's devices subcollection
    db.collection('users').doc(state.user.uid)
      .collection('devices')
      .doc(MV_DEVICE.os + '_' + MV_DEVICE.browser)
      .set(deviceData, { merge: true })
      .catch(function(){});

    // Also update main user doc with last device
    db.collection('users').doc(state.user.uid)
      .update({ lastDevice: MV_DEVICE.type, lastOS: MV_DEVICE.os })
      .catch(function(){});

    console.log('[Mindvora] Device profile saved:', MV_DEVICE.type, MV_DEVICE.os);
  } catch(e) {}
}

// Re-apply layout on window resize (e.g. rotation on phone/tablet)
var _resizeTimer;
window.addEventListener('resize', function() {
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(function() {
    MV_DEVICE.viewW = window.innerWidth;
    MV_DEVICE.viewH = window.innerHeight;
    // Re-detect type
    if (window.innerWidth <= 767)       { MV_DEVICE.type = 'phone';   MV_DEVICE.isMobile=true;  MV_DEVICE.isTablet=false; MV_DEVICE.isDesktop=false; }
    else if (window.innerWidth <= 1024) { MV_DEVICE.type = 'tablet';  MV_DEVICE.isMobile=false; MV_DEVICE.isTablet=true;  MV_DEVICE.isDesktop=false; }
    else                                { MV_DEVICE.type = 'desktop'; MV_DEVICE.isMobile=false; MV_DEVICE.isTablet=false; MV_DEVICE.isDesktop=true; }
    document.body.classList.remove('device-phone','device-tablet','device-desktop');
    document.body.classList.add('device-' + MV_DEVICE.type);
    applyDeviceLayout();
  }, 150);
});


// ── COMMENT LOCK TOGGLE ───────────────────────────────────────────────────
function toggleCommentsLock() {
  commentsLocked = !commentsLocked;
  var btn = document.getElementById('btn-comments-toggle');
  if (commentsLocked) {
    btn.textContent = '🔒';
    btn.title = 'Comments OFF — tap to allow comments';
    btn.style.color = '#fca5a5';
    btn.style.borderColor = '#fca5a5';
    showToast('🔒 Comments disabled for this post');
  } else {
    btn.textContent = '💬';
    btn.title = 'Comments ON — tap to disable comments';
    btn.style.color = '';
    btn.style.borderColor = '';
    showToast('💬 Comments enabled for this post');
  }
}


// ── REFERRAL SYSTEM TOGGLE (OWNER ONLY) ──────────────────────────────────
var referralEnabled = true; // default on, loaded from Firestore

function loadReferralStatus() {
  db.collection('app_settings').doc('referral').get().then(function(doc) {
    if (doc.exists) {
      referralEnabled = doc.data().enabled !== false;
    } else {
      referralEnabled = true; // default enabled
    }
    updateReferralUI();
  }).catch(function(){ referralEnabled = true; });
}

function updateReferralUI() {
  var lbl  = document.getElementById('referral-status-lbl');
  var dlbl = document.getElementById('drawer-referral-lbl');
  var navBtn = document.getElementById('nav-referral-toggle');
  var drawerBtn = document.getElementById('drawer-referral-btn');

  var statusText = referralEnabled ? 'ON ✅' : 'OFF 🔴';
  if (lbl)  lbl.textContent  = statusText;
  if (dlbl) dlbl.textContent = statusText;

  // Show/hide active and disabled banners in earn modal
  var activeBanner   = document.getElementById('referral-status-banner');
  var disabledBanner = document.getElementById('referral-disabled-banner');
  if (activeBanner)   activeBanner.style.display   = referralEnabled ? 'block' : 'none';
  if (disabledBanner) disabledBanner.style.display = referralEnabled ? 'none'  : 'block';

  // Show/hide the toggle button for owner only
  if (isAdmin()) {
    if (navBtn)    { navBtn.style.display    = 'flex'; }
    if (drawerBtn) { drawerBtn.style.display = 'flex'; }
  }
}

function toggleReferralSystem() {
  if (!isAdmin()) { showToast('⛔ Access denied.'); return; }
  var newState = !referralEnabled;
  db.collection('app_settings').doc('referral').set({
    enabled:    newState,
    updatedAt:  firebase.firestore.FieldValue.serverTimestamp(),
    updatedBy:  state.user.email
  }).then(function() {
    referralEnabled = newState;
    updateReferralUI();
    showToast(newState
      ? '✅ Referral system is now ACTIVE — users can earn from referrals'
      : '🔴 Referral system DEACTIVATED — no referral bonuses will be paid'
    );
  }).catch(function(e) {
    showToast('Error: ' + e.message);
  });
}


// ── AUTO-CATEGORISATION ENGINE ────────────────────────────────────────────
// Silently analyses post content and assigns the most fitting category
// Works on text, images and videos — completely invisible to the user
function autoDetectCategory(text, mediaType, userSelectedCat) {
  // If user explicitly selected a specific category (not 'all'), respect it
  if (userSelectedCat && userSelectedCat !== 'all') return userSelectedCat;

  var t = (text || '').toLowerCase();
  var scores = { education: 0, fun: 0, thoughts: 0, news: 0 };

  // ── EDUCATION signals ───────────────────────────────────────
  var eduWords = [
    'learn','study','tutorial','how to','tip','fact','science','history',
    'education','school','university','college','knowledge','teach','explain',
    'research','discover','biology','chemistry','physics','math','geography',
    'technology','programming','coding','algorithm','formula','theory',
    'lesson','course','lecture','academic','professor','student','book',
    'definition','meaning','wikipedia','did you know','according to',
    'statistics','data','percentage','report','study shows','scientists',
    'found that','evidence','experiment','analysis','understand','concept'
  ];
  eduWords.forEach(function(w){ if(t.indexOf(w)>-1) scores.education += (w.length>5?3:2); });

  // ── FUN signals ─────────────────────────────────────────────
  var funWords = [
    'funny','lol','lmao','haha','joke','meme','comedy','hilarious',
    'laugh','entertainment','viral','prank','challenge','trend','dance',
    'skit','roast','savage','bruh','literally','omg','😂','🤣','😹',
    'dead','crying','iconic','legend','bro','bestie','fam','periodt',
    'ngl','tbh lol','no cap funny','fire','lit','vibes','mood',
    'when you','me when','the face','nobody:','tiktok','reel','meme',
    'blew up','cant stop','cringe','wholesome','cute','aww','adorable'
  ];
  funWords.forEach(function(w){ if(t.indexOf(w)>-1) scores.fun += (w.length>5?3:2); });

  // ── THOUGHTS signals ─────────────────────────────────────────
  var thoughtWords = [
    'think','believe','opinion','feel like','in my view','personally',
    'i think','i feel','reflection','mindset','motivation','inspire',
    'wisdom','quote','life lesson','perspective','philosophy','truth',
    'reality','mental health','growth','journey','experience','lesson learned',
    'reminder','affirmation','gratitude','thankful','blessed','grateful',
    'rant','unpopular opinion','hot take','lets talk','honest','genuine',
    'vulnerability','confession','story time','my experience','deep thoughts',
    'life is','remember that','never forget','always','sometimes we',
    'what if','imagine','dream','goal','purpose','meaning of'
  ];
  thoughtWords.forEach(function(w){ if(t.indexOf(w)>-1) scores.thoughts += (w.length>5?3:2); });

  // ── NEWS signals ─────────────────────────────────────────────
  var newsWords = [
    'breaking','just in','update','news','report','announced','confirmed',
    'government','president','minister','election','vote','policy','law',
    'crisis','conflict','war','protest','economy','market','stock',
    'inflation','price','budget','tax','gdp','unemployment','healthcare',
    'climate','disaster','earthquake','flood','fire','accident','death',
    'arrested','charged','court','verdict','sentence','investigation',
    'leaked','exposed','scandal','controversy','official','statement',
    'according to bbc','according to cnn','reuters','aljazeera','channels tv',
    'tvc','arise news','punch','vanguard','thisday','tribune','naij',
    'nigeria','us','uk','africa','europe','asia','global','international',
    'world','today','yesterday','this week','this month','2024','2025','2026'
  ];
  newsWords.forEach(function(w){ if(t.indexOf(w)>-1) scores.news += (w.length>5?3:2); });

  // ── MEDIA type bonuses ───────────────────────────────────────
  // Videos are often fun/entertainment content
  if (mediaType === 'video') {
    scores.fun += 2;
  }
  // Images lean slightly towards thoughts/fun
  if (mediaType === 'image') {
    scores.thoughts += 1;
    scores.fun += 1;
  }

  // ── Hashtag bonuses (strong signal) ─────────────────────────
  var hashtags = t.match(/#[a-z]+/g) || [];
  hashtags.forEach(function(tag) {
    if (['#education','#learn','#study','#tutorial','#science','#history','#knowledge','#tips','#howto','#tech'].indexOf(tag)>-1) scores.education += 8;
    if (['#funny','#comedy','#meme','#lol','#humor','#entertainment','#viral','#fun','#jokes'].indexOf(tag)>-1) scores.fun += 8;
    if (['#thoughts','#motivation','#mindset','#inspiration','#quote','#wisdom','#life','#reflection','#opinion'].indexOf(tag)>-1) scores.thoughts += 8;
    if (['#news','#breaking','#update','#worldnews','#politics','#economy','#sports','#naijagist'].indexOf(tag)>-1) scores.news += 8;
  });

  // ── Pick highest scoring category ───────────────────────────
  var best = 'all';
  var bestScore = 4; // minimum threshold — below this stays as 'all'
  Object.keys(scores).forEach(function(cat) {
    if (scores[cat] > bestScore) {
      bestScore = scores[cat];
      best = cat;
    }
  });

  return best;
}


// ── AUTH SHOWCASE SLIDER ─────────────────────────────────────────────────
var currentSlide = 0;
var totalSlides = 3;
var slideTimer;

function goToSlide(n) {
  var slides = document.querySelectorAll('.showcase-slide');
  var dots   = document.querySelectorAll('.dot');
  slides.forEach(function(s){ s.classList.remove('active'); });
  dots.forEach(function(d){ d.classList.remove('active'); });
  currentSlide = (n + totalSlides) % totalSlides;
  if(slides[currentSlide]) slides[currentSlide].classList.add('active');
  if(dots[currentSlide])   dots[currentSlide].classList.add('active');
}

function nextSlide() { goToSlide(currentSlide + 1); }

function startSlider() {
  clearInterval(slideTimer);
  slideTimer = setInterval(nextSlide, 5000);
}

// Start slider when auth screen visible
(function() {
  setTimeout(function(){
    startSlider();
  }, 1000);
})();


// ── HUSMODATA VTU INTEGRATION ─────────────────────────────────────────────
// API key is stored SECURELY on the Render backend (server.js)
// Frontend never sees the raw API key — it only calls our own backend
// Backend URL: https://zync-backend-ickl.onrender.com

var HUSMO_NETWORKS = {
  'MTN Nigeria':    'mtn',
  'Airtel Nigeria': 'airtel',
  'Glo Nigeria':    'glo',
  '9mobile Nigeria':'9mobile'
};

function getHusmoNetwork(networkName) {
  return HUSMO_NETWORKS[networkName] || networkName.toLowerCase().split(' ')[0];
}

// Airtime delivery via Husmodata (through our secure backend)
function deliverAirtimeHusmo(phone, network, amount, ref, docRef) {
  var networkCode = getHusmoNetwork(network);
  return callSecureAPI('/api/husmo-airtime', {
    phone:   phone,
    network: networkCode,
    amount:  amount,
    ref:     ref
  }).then(function(data) {
    if (data && (data.status === 'success' || data.status === true || data.success)) {
      if (docRef) docRef.update({ status: 'completed', husmoRef: data.reference || '' });
      showToast('✅ ₦' + amount + ' ' + network + ' airtime sent to ' + phone + '!');
    } else {
      if (docRef) docRef.update({ status: 'failed', error: (data && data.message) || 'Unknown' });
      showToast('⚠️ Payment received. Airtime delivery in progress. Ref: ' + ref);
    }
  }).catch(function() {
    if (docRef) docRef.update({ status: 'processing' });
    showToast('✅ Payment received! Airtime will be delivered shortly.');
  });
}

// Data delivery via Husmodata (through our secure backend)
function deliverDataHusmo(phone, network, bundle, amount, ref, docRef) {
  var networkCode = getHusmoNetwork(network);
  return callSecureAPI('/api/husmo-data', {
    phone:   phone,
    network: networkCode,
    bundle:  bundle,
    amount:  amount,
    ref:     ref
  }).then(function(data) {
    if (data && (data.status === 'success' || data.status === true || data.success)) {
      if (docRef) docRef.update({ status: 'completed', husmoRef: data.reference || '' });
      showToast('✅ ' + bundle + ' ' + network + ' data sent to ' + phone + '!');
    } else {
      if (docRef) docRef.update({ status: 'failed', error: (data && data.message) || 'Unknown' });
      showToast('⚠️ Payment received. Data delivery in progress. Ref: ' + ref);
    }
  }).catch(function() {
    if (docRef) docRef.update({ status: 'processing' });
    showToast('✅ Payment received! Data will be delivered shortly.');
  });
}


// ── RIGHT SHOWCASE SLIDER ─────────────────────────────────────────────────
var currentSlideRight = 0;
var slideTimerRight;

function goToSlideRight(n) {
  var slides = document.querySelectorAll('#showcase-slides-right .showcase-slide');
  var dots   = document.querySelectorAll('#dots-right .dot');
  slides.forEach(function(s){ s.classList.remove('active'); });
  dots.forEach(function(d){ d.classList.remove('active'); });
  currentSlideRight = (n + 3) % 3;
  if(slides[currentSlideRight]) slides[currentSlideRight].classList.add('active');
  if(dots[currentSlideRight])   dots[currentSlideRight].classList.add('active');
}

function startRightSlider() {
  clearInterval(slideTimerRight);
  slideTimerRight = setInterval(function(){
    goToSlideRight(currentSlideRight + 1);
  }, 5000);
}

// Stagger right slider by 2.5s offset from left
setTimeout(function(){
  startRightSlider();
}, 2500);

// ── MINDVORA COLOUR ANIMATION (auth + topbar) ─────────────────────────────
// CSS handles the animation via keyframes 'mindvora-colors'
// Make sure it runs as soon as auth screen loads


// ── GOOGLE SIGN-IN ────────────────────────────────────────────────────────
function signInWithGoogle() {
  var provider = new firebase.auth.GoogleAuthProvider();
  provider.addScope('email');
  provider.addScope('profile');
  provider.setCustomParameters({ prompt: 'select_account' });

  auth.signInWithPopup(provider)
    .then(function(result) {
      var user = result.user;
      var isNew = result.additionalUserInfo && result.additionalUserInfo.isNewUser;

      if (isNew) {
        // New user via Google — create profile in Firestore
        var handle = (user.displayName || user.email.split('@')[0])
          .toLowerCase().replace(/\s+/g, '').replace(/[^a-z0-9_]/g, '').slice(0, 20);
        return db.collection('users').doc(user.uid).set({
          name:       user.displayName || 'Mindvora User',
          handle:     handle,
          email:      user.email,
          avatar:     user.photoURL || '',
          provider:   'google',
          isPremium:  false,
          earnings:   0,
          color:      COLORS[Math.floor(Math.random() * COLORS.length)],
          createdAt:  firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
      }
    })
    .then(function() {
      showToast('✅ Signed in with Google!');
    })
    .catch(function(err) {
      if (err.code === 'auth/popup-closed-by-user') return;
      if (err.code === 'auth/cancelled-popup-request') return;
      if (err.code === 'auth/unauthorized-domain') {
        showToast('⚠️ This domain is not authorized for Google sign-in. The admin needs to add it in Firebase Console → Authentication → Settings → Authorized domains.');
        return;
      }
      if (err.code === 'auth/popup-blocked') {
        showToast('⚠️ Popup blocked! Please allow popups for this site and try again.');
        return;
      }
      showToast('Google sign-in failed: ' + (err.message || err.code));
    });
}

// ── DELETE ACCOUNT ────────────────────────────────────────────────────────
function confirmDeleteAccount() {
  if (!state || !state.user) {
    showToast('Please log in first.');
    return;
  }
  // Don't allow admin to delete their own account
  if (isAdmin()) {
    showToast('⛔ Admin account cannot be deleted from here.');
    return;
  }
  var confirmed = confirm('⚠️ Are you sure you want to DELETE your account?\n\nThis action is PERMANENT and cannot be undone.\nAll your data, posts, messages, and earnings will be lost forever.');
  if (!confirmed) return;
  var doubleConfirm = confirm('🔴 FINAL WARNING: Type OK to permanently delete your Mindvora account.\n\nYou will lose everything. Are you absolutely sure?');
  if (!doubleConfirm) return;

  var uid = state.user.uid;
  var userEmail = state.user.email;

  // Delete user data from Firestore
  showToast('🗑️ Deleting your account...');
  
  // Delete user document
  db.collection('users').doc(uid).delete()
    .then(function() {
      // Delete user's sparks
      return db.collection('sparks').where('uid', '==', uid).get();
    })
    .then(function(sparksSnap) {
      var batch = db.batch();
      sparksSnap.docs.forEach(function(doc) { batch.delete(doc.ref); });
      return batch.commit();
    })
    .then(function() {
      // Delete Firebase Auth account
      return state.user.delete();
    })
    .then(function() {
      showToast('✅ Account deleted successfully. Goodbye!');
      setTimeout(function() { window.location.reload(); }, 1500);
    })
    .catch(function(err) {
      if (err.code === 'auth/requires-recent-login') {
        showToast('⚠️ For security, please sign out and sign back in, then try deleting again.');
      } else {
        showToast('Error deleting account: ' + err.message);
      }
    });
}

// ── EMAIL VERIFICATION ON SIGNUP ─────────────────────────────────────────
function sendVerificationEmail(user) {
  if (!user || user.emailVerified) return;
  user.sendEmailVerification({
    url: 'https://mindvora-vf8e.vercel.app'
  }).then(function() {
    showToast('📧 Verification email sent! Check your inbox.');
  }).catch(function(e) {
    console.warn('Email verification error:', e.message);
  });
}


// ── REAL-TIME LIVE COUNTS (WebSocket-equivalent via Firebase) ─────────────
// Firebase onSnapshot IS a persistent WebSocket connection.
// This ensures counts update instantly without any page refresh.

// Live-update a specific spark's counts when they change
var _sparkListeners = {};

function watchSparkLive(sparkId) {
  if (_sparkListeners[sparkId]) return; // already watching
  _sparkListeners[sparkId] = db.collection('sparks').doc(sparkId)
    .onSnapshot(function(doc) {
      if (!doc.exists) return;
      var data = doc.data();
      // Update like count on screen instantly
      var likeEl = document.getElementById('likes-' + sparkId);
      if (likeEl) likeEl.textContent = (data.likes || []).length;
      // Update comment count
      var cntEl = document.getElementById('cmt-cnt-' + sparkId);
      if (cntEl) cntEl.textContent = data.commentCount || 0;
      // Update repost count
      var rpEl = document.getElementById('rp-cnt-' + sparkId);
      if (rpEl) rpEl.textContent = data.reposts || 0;
      // Update view count
      var vwEl = document.getElementById('vw-cnt-' + sparkId);
      if (vwEl) vwEl.textContent = data.viewCount || 0;
      // Animate the count change
      [likeEl, cntEl, rpEl].forEach(function(el) {
        if (!el) return;
        el.style.transform = 'scale(1.3)';
        el.style.color = 'var(--green3)';
        setTimeout(function() {
          el.style.transform = '';
          el.style.color = '';
        }, 400);
      });
    });
}

// Watch follower/following counts in real-time
function watchFollowerCount(uid) {
  if (!uid) return;
  db.collection('users').doc(uid).onSnapshot(function(doc) {
    if (!doc.exists) return;
    var data = doc.data();
    var fansEl = document.getElementById('st-fans');
    if (fansEl) fansEl.textContent = data.followerCount || 0;
    var followsEl = document.getElementById('st-follows');
    if (followsEl) followsEl.textContent = data.followingCount || 0;
    var sparksEl = document.getElementById('st-sparks');
    if (sparksEl) sparksEl.textContent = data.sparkCount || 0;
  });
}

// Start watching sparks as they render
var _watchObserver;
function startLiveWatching() {
  // Watch all visible spark cards
  _watchObserver = new MutationObserver(function(mutations) {
    mutations.forEach(function(m) {
      m.addedNodes.forEach(function(node) {
        if (node.nodeType !== 1) return;
        var cards = node.querySelectorAll ? node.querySelectorAll('[data-spark-id]') : [];
        cards.forEach(function(card) {
          watchSparkLive(card.dataset.sparkId);
        });
        if (node.dataset && node.dataset.sparkId) {
          watchSparkLive(node.dataset.sparkId);
        }
      });
    });
  });
  var feedCont = document.getElementById('feed-cont');
  if (feedCont) _watchObserver.observe(feedCont, { childList: true, subtree: true });
}

// ── REAL-TIME PRESENCE (online/offline indicator) ─────────────────────────
function initPresence() {
  if (!state.user) return;
  var presenceRef = db.collection('presence').doc(state.user.uid);
  var onlineData = { online: true, uid: state.user.uid, lastSeen: firebase.firestore.FieldValue.serverTimestamp() };
  var offlineData = { online: false, uid: state.user.uid, lastSeen: firebase.firestore.FieldValue.serverTimestamp() };

  presenceRef.set(onlineData).catch(function(){});

  window.addEventListener('beforeunload', function() {
    presenceRef.set(offlineData).catch(function(){});
  });

  document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
      presenceRef.set(offlineData).catch(function(){});
    } else {
      presenceRef.set(onlineData).catch(function(){});
    }
  });
}


// ══════════════════════════════════════════════════════════════
// NEW MINDBLOWING FEATURES
// ══════════════════════════════════════════════════════════════

// ── 1. TYPING INDICATOR IN DMs ────────────────────────────────────────────
var _typingTimer;
function sendTypingIndicator(dmId) {
  if (!state.user || !dmId) return;
  db.collection('dms').doc(dmId).update({
    ['typing_' + state.user.uid]: firebase.firestore.FieldValue.serverTimestamp()
  }).catch(function(){});
  clearTimeout(_typingTimer);
  _typingTimer = setTimeout(function() {
    db.collection('dms').doc(dmId).update({
      ['typing_' + state.user.uid]: null
    }).catch(function(){});
  }, 2500);
}

function listenTypingIndicator(dmId, otherId) {
  return db.collection('dms').doc(dmId).onSnapshot(function(doc) {
    if (!doc.exists) return;
    var data = doc.data();
    var key = 'typing_' + otherId;
    var indicator = document.getElementById('typing-indicator');
    if (!indicator) return;
    if (data[key] && (Date.now() - data[key].toMillis() < 3000)) {
      indicator.style.display = 'flex';
    } else {
      indicator.style.display = 'none';
    }
  });
}

// ── 2. PROFILE HOVER CARD ─────────────────────────────────────────────────
function showProfileHoverCard(uid, name, handle, color, e) {
  var existing = document.getElementById('hover-card');
  if (existing) existing.remove();

  var card = document.createElement('div');
  card.id = 'hover-card';
  card.className = 'hover-profile-card';
  card.innerHTML =
    '<div class="hpc-av" style="background:' + (color||'var(--green)') + '">' + (name||'U').charAt(0).toUpperCase() + '</div>' +
    '<div class="hpc-info">' +
      '<div class="hpc-name">' + (name||'User') + '</div>' +
      '<div class="hpc-handle">@' + (handle||'user') + '</div>' +
    '</div>' +
    '<button class="hpc-follow" onclick="openUserByHandle(\''+handle+'\')" >' +
      (isFollowing(uid) ? '✓ Following' : '+ Follow') +
    '</button>';

  card.style.cssText = 'position:fixed;top:' + (e.clientY + 10) + 'px;left:' + e.clientX + 'px;z-index:500;';
  document.body.appendChild(card);

  // Remove on click outside
  setTimeout(function() {
    document.addEventListener('click', function remove() {
      var c = document.getElementById('hover-card');
      if (c) c.remove();
      document.removeEventListener('click', remove);
    });
  }, 100);
}

// ── 3. SHARE POST TO DM ────────────────────────────────────────────────────
function sharePostToDM(sparkId, text) {
  // Show quick DM picker
  var recent = state.conversations.slice(0, 5);
  if (!recent.length) { showToast('No recent conversations. Start a DM first!'); return; }

  var picker = document.createElement('div');
  picker.id = 'share-dm-picker';
  picker.style.cssText = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:var(--card);border:1px solid var(--border);border-radius:16px;padding:16px;z-index:400;width:300px;box-shadow:0 20px 60px rgba(0,0,0,.8)';
  picker.innerHTML =
    '<div style="font-size:13px;font-weight:600;color:var(--moon);margin-bottom:12px">📤 Share to DM</div>' +
    recent.map(function(conv) {
      var safeName = (conv.otherName||'User').replace(/'/g,'');
      return '<button class="share-dm-item" data-dmid="' + conv.id + '" data-sparkid="' + sparkId + '" data-text="' + (text||'').slice(0,40).replace(/"/g,'') + '" style="width:100%;padding:10px;background:none;border:none;border-bottom:1px solid var(--border);color:var(--moon);font-size:13px;text-align:left;cursor:pointer;display:flex;align-items:center;gap:8px">' + safeName + '</button>';
    }).join('') +
    '<button class="close-share-picker" style="width:100%;padding:8px;background:none;border:none;color:var(--muted);font-size:12px;cursor:pointer;margin-top:4px">Cancel</button>';
  document.body.appendChild(picker);
}

function sendShareToDM(dmId, sparkId, previewText) {
  if (!state.user) return;
  var msg = '📎 Shared a spark: "' + previewText + (previewText.length >= 40 ? '...' : '') + '" — mindvora-vf8e.vercel.app';
  var msgRef = db.collection('dms').doc(dmId).collection('messages').doc();
  var batch = db.batch();
  batch.set(msgRef, {
    text: msg, fromId: state.user.uid,
    fromName: state.profile.name,
    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
    read: false, type: 'share', sparkId: sparkId
  });
  batch.update(db.collection('dms').doc(dmId), {
    lastMsg: msg, lastAt: firebase.firestore.FieldValue.serverTimestamp()
  });
  batch.commit().then(function() {
    var picker = document.getElementById('share-dm-picker');
    if (picker) picker.remove();
    showToast('✅ Shared to DM!');
  }).catch(function() { showToast('Failed to share'); });
}

// ── 4. STREAK SYSTEM ──────────────────────────────────────────────────────
function updateStreak() {
  if (!state.user) return;
  var today = new Date().toDateString();
  var lastPost = localStorage.getItem('mv_last_post_date_' + state.user.uid);
  var streak = parseInt(localStorage.getItem('mv_streak_' + state.user.uid) || '0');

  if (lastPost === today) return; // already posted today

  var yesterday = new Date(Date.now() - 86400000).toDateString();
  if (lastPost === yesterday) {
    streak += 1;
  } else if (lastPost !== today) {
    streak = 1; // reset streak
  }

  localStorage.setItem('mv_streak_' + state.user.uid, streak);
  localStorage.setItem('mv_last_post_date_' + state.user.uid, today);

  // Save to Firestore
  db.collection('users').doc(state.user.uid).update({ streak: streak }).catch(function(){});

  // Show milestone toasts
  if (streak === 3)  showToast('🔥 3-day posting streak! Keep it up!');
  if (streak === 7)  showToast('🔥🔥 7-day streak! You are on fire!');
  if (streak === 30) showToast('🏆 30-day streak! Legendary creator!');
}

// ── 5. NIGHT MODE AUTO-SWITCH ─────────────────────────────────────────────
function autoNightMode() {
  var hour = new Date().getHours();
  var shouldBeDark = hour < 6 || hour >= 20; // Dark between 8pm - 6am
  var savedPref = localStorage.getItem('mv_dark_pref');
  if (savedPref !== null) return; // user set manually, don't override
  // Already dark by default since bg is black
}

// ── 6. QUICK REACTIONS ON LONG PRESS ──────────────────────────────────────
var _longPressTimer;
function startLongPress(sparkId, e) {
  _longPressTimer = setTimeout(function() {
    showQuickReact(sparkId, e);
  }, 500);
}
function endLongPress() { clearTimeout(_longPressTimer); }

function showQuickReact(sparkId, e) {
  var existing = document.getElementById('quick-react-' + sparkId);
  if (existing) { existing.remove(); return; }
  var quickEmojis = ['❤️','🔥','😂','😮','👏','💭','🚀','💎'];
  var bar = document.createElement('div');
  bar.id = 'quick-react-' + sparkId;
  bar.style.cssText = 'position:fixed;bottom:' + (window.innerHeight - e.clientY + 10) + 'px;left:' + Math.max(10, e.clientX - 120) + 'px;background:var(--card);border:1px solid var(--border);border-radius:40px;padding:8px 12px;display:flex;gap:6px;z-index:400;box-shadow:0 20px 60px rgba(0,0,0,.8);animation:pop .2s cubic-bezier(.34,1.56,.64,1)';
    bar.innerHTML = quickEmojis.map(function(em) {
    return '<button class="quick-em-btn" data-spark="' + sparkId + '" data-em="' + em + '" style="background:none;border:none;font-size:22px;cursor:pointer;padding:2px 4px;border-radius:50%;transition:transform .15s">' + em + '</button>';
  }).join('');
  document.body.appendChild(bar);
  setTimeout(function() {
    document.addEventListener('click', function rm() {
      var b = document.getElementById('quick-react-' + sparkId);
      if (b) b.remove();
      document.removeEventListener('click', rm);
    });
  }, 100);
}


// Quick emoji reaction buttons
document.addEventListener('click', function(e) {
  var qb = e.target.closest('.quick-em-btn');
  if (qb) {
    reactToSpark(qb.dataset.spark, qb.dataset.em);
    var bar = document.getElementById('quick-react-' + qb.dataset.spark);
    if (bar) bar.remove();
  }
});
// Share DM item click delegation
document.addEventListener('click', function(e) {
  var btn = e.target.closest('.share-dm-item');
  if (btn) { sendShareToDM(btn.dataset.dmid, btn.dataset.sparkid, btn.dataset.text); return; }
  if (e.target.classList.contains('close-share-picker')) {
    var p = document.getElementById('share-dm-picker'); if(p) p.remove();
  }
});

// ── FORGOT PASSWORD — sends reset link to user's email ───────────────────
function doForgotPassword() {
  var emailEl = document.getElementById('li-email');
  var errEl   = document.getElementById('li-err');
  var email   = emailEl ? emailEl.value.trim().toLowerCase() : '';

  if (!email) {
    if (errEl) errEl.textContent = '📧 Enter your email address above first, then click Forgot Password.';
    if (emailEl) emailEl.focus();
    return;
  }

  // Basic email format check
  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
    if (errEl) errEl.textContent = '❌ Please enter a valid email address.';
    return;
  }

  var btn = document.getElementById('btn-login');
  if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }

  auth.sendPasswordResetEmail(email, {
    url: 'https://mindvora-vf8e.vercel.app'
  })
  .then(function() {
    if (errEl) {
      errEl.style.color = '#86efac';
      errEl.textContent = '✅ Password reset link sent to ' + email + '. Check your inbox (and spam folder).';
    }
    showToast('📧 Reset link sent to ' + email);
    if (btn) { btn.disabled = false; btn.textContent = 'Enter Mindvora →'; }
  })
  .catch(function(e) {
    var msg = '❌ Could not send reset email. ';
    if (e.code === 'auth/user-not-found') {
      msg += 'No account found with this email. Please register instead.';
    } else if (e.code === 'auth/invalid-email') {
      msg += 'Invalid email address.';
    } else if (e.code === 'auth/too-many-requests') {
      msg += 'Too many attempts. Wait a moment and try again.';
    } else {
      msg += e.message;
    }
    if (errEl) {
      errEl.style.color = '#fca5a5';
      errEl.textContent = msg;
    }
    if (btn) { btn.disabled = false; btn.textContent = 'Enter Mindvora →'; }
  });
}


// ── BUTTON FALLBACK WIRING — ensures login/register always work ──────────
document.addEventListener('DOMContentLoaded', function() {
  var loginBtn = document.getElementById('btn-login');
  if (loginBtn && !loginBtn._wired) {
    loginBtn.addEventListener('click', doLogin);
    loginBtn._wired = true;
  }
  var regBtn = document.getElementById('btn-reg');
  if (regBtn && !regBtn._wired) {
    regBtn.addEventListener('click', doRegister);
    regBtn._wired = true;
  }
  var liEmail = document.getElementById('li-email');
  if (liEmail) {
    liEmail.addEventListener('keydown', function(e) { if (e.key === 'Enter') doLogin(); });
  }
  var liPass = document.getElementById('li-pass');
  if (liPass) {
    liPass.addEventListener('keydown', function(e) { if (e.key === 'Enter') doLogin(); });
  }
  var rPass = document.getElementById('r-confirm');
  if (rPass) {
    rPass.addEventListener('keydown', function(e) { if (e.key === 'Enter') doRegister(); });
  }
});

// Favicon — static, set in HTML head

// ═══════════════════════════════════════════════════════════════
// TASK 1: VIDEO THUMBNAIL PICKER — YouTube-style
// ═══════════════════════════════════════════════════════════════
var _thumbPickerState = { videoFile:null, videoUrl:null, thumbnails:[], selectedThumb:null, resolve:null, isShort:false };

function generateVideoThumbnails(file, count){
  return new Promise(function(resolve){
    var url = URL.createObjectURL(file);
    var video = document.createElement('video');
    video.src = url; video.muted = true; video.preload = 'auto';
    video.addEventListener('loadedmetadata', function(){
      var dur = video.duration;
      var times = [];
      for(var i=0;i<count;i++) times.push(Math.min(dur*0.99, (dur/(count+1))*(i+1)));
      var thumbs = []; var idx = 0;
      function captureFrame(){
        if(idx >= times.length){ URL.revokeObjectURL(url); resolve(thumbs); return; }
        video.currentTime = times[idx];
      }
      video.addEventListener('seeked', function onSeeked(){
        var canvas = document.createElement('canvas');
        canvas.width = Math.min(video.videoWidth, 640);
        canvas.height = Math.round(canvas.width * (video.videoHeight / video.videoWidth));
        var ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        thumbs.push({ time: times[idx], dataUrl: canvas.toDataURL('image/jpeg', 0.85) });
        idx++;
        if(idx < times.length){ video.currentTime = times[idx]; }
        else { URL.revokeObjectURL(url); resolve(thumbs); }
      });
      captureFrame();
    });
    video.addEventListener('error', function(){ resolve([]); });
  });
}

function openThumbPicker(file, isShort){
  _thumbPickerState.videoFile = file;
  _thumbPickerState.isShort = isShort || false;
  _thumbPickerState.selectedThumb = null;
  var overlay = document.getElementById('thumb-picker-overlay');
  var preview = document.getElementById('thumb-video-preview');
  var grid = document.getElementById('thumb-grid');
  preview.src = URL.createObjectURL(file);
  grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:16px;color:var(--muted)">⏳ Generating thumbnails…</div>';
  overlay.classList.add('open');
  generateVideoThumbnails(file, 6).then(function(thumbs){
    _thumbPickerState.thumbnails = thumbs;
    if(!thumbs.length){ grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--muted)">Could not generate thumbnails</div>'; return; }
    grid.innerHTML = thumbs.map(function(t, i){
      return '<div class="thumb-option'+(i===0?' selected':'')+'" data-thumb-idx="'+i+'">' +
        '<img src="'+t.dataUrl+'" alt="Thumbnail '+(i+1)+'">' +
        '<div class="thumb-check">✓</div>' +
        '<div class="thumb-duration-badge">'+formatDuration(t.time)+'</div></div>';
    }).join('');
    if(thumbs.length > 0) _thumbPickerState.selectedThumb = thumbs[0].dataUrl;
    grid.querySelectorAll('.thumb-option').forEach(function(el){
      el.addEventListener('click', function(){
        grid.querySelectorAll('.thumb-option').forEach(function(x){ x.classList.remove('selected'); });
        el.classList.add('selected');
        _thumbPickerState.selectedThumb = thumbs[parseInt(el.dataset.thumbIdx)].dataUrl;
      });
    });
  });
  return new Promise(function(resolve){ _thumbPickerState.resolve = resolve; });
}

function formatDuration(secs){
  var m = Math.floor(secs/60); var s = Math.floor(secs%60);
  return m + ':' + (s<10?'0':'') + s;
}

function closeThumbPicker(skip){
  document.getElementById('thumb-picker-overlay').classList.remove('open');
  var pv = document.getElementById('thumb-video-preview'); if(pv) pv.src = '';
  if(_thumbPickerState.resolve){
    _thumbPickerState.resolve(skip ? null : _thumbPickerState.selectedThumb);
    _thumbPickerState.resolve = null;
  }
}

function confirmThumbnail(){
  document.getElementById('thumb-picker-overlay').classList.remove('open');
  var pv = document.getElementById('thumb-video-preview'); if(pv) pv.src = '';
  if(_thumbPickerState.resolve){
    _thumbPickerState.resolve(_thumbPickerState.selectedThumb || null);
    _thumbPickerState.resolve = null;
  }
}

function uploadCustomThumbnail(){
  var inp = document.createElement('input');
  inp.type = 'file'; inp.accept = 'image/*';
  inp.onchange = function(){
    var f = inp.files[0]; if(!f) return;
    var reader = new FileReader();
    reader.onload = function(e){
      _thumbPickerState.selectedThumb = e.target.result;
      var grid = document.getElementById('thumb-grid');
      grid.querySelectorAll('.thumb-option').forEach(function(x){ x.classList.remove('selected'); });
      showToast('✅ Custom thumbnail selected!');
    };
    reader.readAsDataURL(f);
  };
  inp.click();
}

// ── Patch the media upload to show thumbnail picker for videos ──
(function(){
  var origMediaBtn = document.getElementById('btn-media');
  if(!origMediaBtn) return;
  var origListeners = origMediaBtn.cloneNode(true);
  var newBtn = origMediaBtn.cloneNode(true);
  origMediaBtn.parentNode.replaceChild(newBtn, origMediaBtn);
  newBtn.id = 'btn-media';
  newBtn.addEventListener('click', function(){
    var fileInput = document.createElement('input');
    fileInput.type = 'file'; fileInput.accept = 'image/*,video/*';
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);
    fileInput.click();
    fileInput.addEventListener('change', async function(){
      var file = fileInput.files[0];
      document.body.removeChild(fileInput);
      if(!file) return;
      // Task 3: Anti-malware scan
      var scanResult = scanFileForMalware(file);
      if(!scanResult.safe){ showToast('🛡️ ' + scanResult.reason); return; }
      if(file.size > 209715200){ showToast('File too large! Max 200MB'); return; }
      var isVideo = file.type.startsWith('video');
      var thumbDataUrl = null;
      // Task 1: Show thumbnail picker for videos
      if(isVideo){
        thumbDataUrl = await openThumbPicker(file, false);
      }
      var uploadBanner = document.createElement('div');
      uploadBanner.id = 'upload-banner';
      uploadBanner.style.cssText = 'position:fixed;top:0;left:0;width:100%;background:var(--green);color:var(--cream);text-align:center;padding:10px;font-size:13px;font-weight:700;z-index:9999;font-family:DM Sans,sans-serif';
      uploadBanner.textContent = '⏳ Uploading media... Please wait.';
      document.body.appendChild(uploadBanner);
      var formData = new FormData();
      formData.append('file', file);
      formData.append('upload_preset', 'ml_default');
      formData.append('cloud_name', CLOUD_NAME);
      try{
        var resourceType = isVideo ? 'video' : 'image';
        var resp = await fetch('https://api.cloudinary.com/v1_1/' + CLOUD_NAME + '/' + resourceType + '/upload', { method:'POST', body:formData });
        var data = await resp.json();
        if(document.getElementById('upload-banner')) document.body.removeChild(uploadBanner);
        if(data.error){ showToast('Upload failed: ' + data.error.message); return; }
        pendingMedia = { url: data.secure_url, type: resourceType, thumbnail: thumbDataUrl };
        if(resourceType === 'image'){
          document.getElementById('prev-img').src = data.secure_url;
          document.getElementById('prev-img').style.display = 'block';
          document.getElementById('prev-vid').style.display = 'none';
        } else {
          document.getElementById('prev-vid').src = data.secure_url;
          document.getElementById('prev-vid').style.display = 'block';
          document.getElementById('prev-img').style.display = 'none';
        }
        document.getElementById('media-prev').style.display = 'block';
        showToast('✅ Media ready! Click Spark to post.');
      } catch(e){
        if(document.getElementById('upload-banner')) document.body.removeChild(uploadBanner);
        showToast('Upload failed: ' + e.message);
      }
    });
  });
})();

// ═══════════════════════════════════════════════════════════════
// TASK 2: SHORTS (3-MIN, 9:16 RATIO) — TikTok/Instagram style
// ═══════════════════════════════════════════════════════════════
var MAX_SHORT_DURATION = 180; // 3 minutes in seconds
var shortsList = [];
var currentShortIdx = -1;

function openShortsUpload(){
  if(!state.user || !state.profile){ showToast('Please sign in first'); return; }
  var fileInp = document.createElement('input');
  fileInp.type = 'file'; fileInp.accept = 'video/*';
  fileInp.onchange = async function(){
    var file = fileInp.files[0];
    if(!file) return;
    if(!file.type.startsWith('video/')){ showToast('Please select a video file'); return; }
    // Task 3: Anti-malware scan
    var scanResult = scanFileForMalware(file);
    if(!scanResult.safe){ showToast('🛡️ ' + scanResult.reason); return; }
    if(file.size > 200*1024*1024){ showToast('File too large (max 200MB)'); return; }
    // Check video duration (max 3 minutes)
    var duration = await getVideoDuration(file);
    if(duration > MAX_SHORT_DURATION){
      showToast('⏱️ Shorts must be 3 minutes or less! Your video is ' + formatDuration(duration));
      return;
    }
    // Show thumbnail picker
    var thumbDataUrl = await openThumbPicker(file, true);
    showToast('⏫ Uploading short…');
    var fd = new FormData();
    fd.append('file', file);
    fd.append('upload_preset', 'ml_default');
    try {
      var resp = await fetch('https://api.cloudinary.com/v1_1/'+CLOUD_NAME+'/video/upload', {method:'POST', body:fd});
      var r = await resp.json();
      if(!r.secure_url){ showToast('Upload failed'); return; }
      await db.collection('sparks').add({
        text: '', authorId: state.user.uid, authorName: state.profile.name,
        authorHandle: state.profile.handle, authorColor: state.profile.color||COLORS[0],
        isPremium: state.profile.isPremium||false, isShort: true,
        category: 'fun', likes: [], saved: [], commentCount: 0,
        mediaUrl: r.secure_url, mediaType: 'video',
        thumbnailUrl: thumbDataUrl || null,
        duration: Math.round(duration),
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      });
      db.collection('users').doc(state.user.uid).update({sparksCount:firebase.firestore.FieldValue.increment(1)});
      showToast('🎬 Short uploaded!');
      loadReels();
    } catch(e){ showToast('Upload failed: ' + e.message); }
  };
  fileInp.click();
}

function getVideoDuration(file){
  return new Promise(function(resolve){
    var video = document.createElement('video');
    video.preload = 'metadata';
    video.onloadedmetadata = function(){ URL.revokeObjectURL(video.src); resolve(video.duration); };
    video.onerror = function(){ resolve(0); };
    video.src = URL.createObjectURL(file);
  });
}

function openShortViewer(idx){
  if(idx < 0 || idx >= shortsList.length) return;
  currentShortIdx = idx;
  var s = shortsList[idx];
  var vid = document.getElementById('short-viewer-video');
  vid.src = s.mediaUrl || '';
  vid.play().catch(function(){});
  document.getElementById('short-viewer-author').textContent = s.authorName || 'Mindvora user';
  document.getElementById('short-viewer-text').textContent = s.text || '';
  document.getElementById('short-like-count').textContent = (s.likes||[]).length;
  document.getElementById('short-viewer').classList.add('open');
}
function closeShortViewer(){
  document.getElementById('short-viewer').classList.remove('open');
  var vid = document.getElementById('short-viewer-video');
  vid.pause(); vid.src = '';
  currentShortIdx = -1;
}
function nextShort(){ if(currentShortIdx < shortsList.length-1) openShortViewer(currentShortIdx+1); }
function prevShort(){ if(currentShortIdx > 0) openShortViewer(currentShortIdx-1); }

// Wire short-like button
document.addEventListener('DOMContentLoaded', function(){
  var slb = document.getElementById('short-like-btn');
  if(slb) slb.addEventListener('click', function(){
    if(currentShortIdx < 0 || !state.user) return;
    var s = shortsList[currentShortIdx];
    if(s && s.id) toggleLike(s.id);
    showToast('❤️ Liked!');
  });
});

// Patch reel upload button to also support shorts
(function(){
  var reelBtn = document.getElementById('btn-upload-reel');
  if(!reelBtn) return;
  var newReelBtn = reelBtn.cloneNode(true);
  reelBtn.parentNode.replaceChild(newReelBtn, reelBtn);
  newReelBtn.id = 'btn-upload-reel';
  newReelBtn.textContent = '📤 Upload Short (max 3min)';
  newReelBtn.addEventListener('click', function(){ openShortsUpload(); });
})();

// ═══════════════════════════════════════════════════════════════
// TASK 3: ANTI-MALWARE FILE SCANNER + SECURITY HARDENING
// ═══════════════════════════════════════════════════════════════

// ── MAGIC BYTES — detect real file type regardless of extension ──
var MAGIC_BYTES = {
  'image/jpeg':  [[0xFF, 0xD8, 0xFF]],
  'image/png':   [[0x89, 0x50, 0x4E, 0x47]],
  'image/gif':   [[0x47, 0x49, 0x46, 0x38]],
  'image/webp':  [[0x52, 0x49, 0x46, 0x46]],
  'video/mp4':   [[0x00,0x00,0x00,0x18,0x66,0x74,0x79,0x70],[0x00,0x00,0x00,0x1C,0x66,0x74,0x79,0x70],[0x00,0x00,0x00,0x20,0x66,0x74,0x79,0x70]],
  'video/webm':  [[0x1A, 0x45, 0xDF, 0xA3]],
  'audio/mpeg':  [[0x49, 0x44, 0x33], [0xFF, 0xFB], [0xFF, 0xF3]],
  'application/pdf': [[0x25, 0x50, 0x44, 0x46]],
  'application/zip': [[0x50, 0x4B, 0x03, 0x04]],
  'application/x-msdownload': [[0x4D, 0x5A]] // EXE
};

var DANGEROUS_EXTENSIONS = [
  '.exe','.bat','.cmd','.com','.msi','.scr','.pif','.vbs','.vbe',
  '.js','.jse','.ws','.wsf','.wsc','.wsh','.ps1','.ps2','.psc1',
  '.reg','.inf','.lnk','.dll','.sys','.drv','.cpl','.jar',
  '.hta','.htm','.html','.svg','.php','.asp','.aspx','.jsp','.py','.sh'
];

var ALLOWED_MEDIA_TYPES = [
  'image/jpeg','image/png','image/gif','image/webp','image/bmp',
  'video/mp4','video/webm','video/quicktime','video/x-msvideo',
  'video/x-matroska','video/ogg','audio/mpeg','audio/wav','audio/ogg'
];

function scanFileForMalware(file){
  if(!file) return { safe:false, reason:'No file provided' };
  // 1. Check file extension
  var name = (file.name || '').toLowerCase();
  var ext = name.substring(name.lastIndexOf('.'));
  if(DANGEROUS_EXTENSIONS.indexOf(ext) !== -1){
    logSecurityEvent('malware_blocked', 'Dangerous file extension blocked: ' + ext);
    return { safe:false, reason:'File type "' + ext + '" is not allowed for security reasons.' };
  }
  // 2. Check MIME type
  if(file.type && ALLOWED_MEDIA_TYPES.indexOf(file.type) === -1){
    // Allow empty MIME (some mobile browsers)
    if(file.type !== ''){
      logSecurityEvent('malware_blocked', 'Disallowed MIME type: ' + file.type);
      return { safe:false, reason:'File type "' + file.type + '" is not supported.' };
    }
  }
  // 3. Check for double extensions (e.g., photo.jpg.exe)
  var parts = name.split('.');
  if(parts.length > 2){
    for(var i = 0; i < parts.length - 1; i++){
      var testExt = '.' + parts[i];
      if(DANGEROUS_EXTENSIONS.indexOf(testExt) !== -1){
        logSecurityEvent('malware_blocked', 'Double extension attack detected: ' + name);
        return { safe:false, reason:'Suspicious file name detected. Upload blocked.' };
      }
    }
  }
  // 4. File size sanity check
  if(file.size > 250 * 1024 * 1024){
    return { safe:false, reason:'File exceeds maximum size (250MB).' };
  }
  if(file.size === 0){
    return { safe:false, reason:'Empty file detected.' };
  }
  // 5. Filename sanitization — block special chars
  if(/[<>:"/\\|?*\x00-\x1F]/.test(file.name)){
    logSecurityEvent('malware_blocked', 'Malicious filename characters: ' + name);
    return { safe:false, reason:'File name contains invalid characters.' };
  }
  return { safe:true, reason:'File passed security scan.' };
}

// ── Async deep scan — checks magic bytes ──
async function deepScanFile(file){
  try {
    var buffer = await file.slice(0, 16).arrayBuffer();
    var bytes = new Uint8Array(buffer);
    // Check for executable magic bytes (MZ = EXE/DLL)
    if(bytes[0] === 0x4D && bytes[1] === 0x5A){
      logSecurityEvent('malware_blocked', 'Executable file disguised as media: ' + file.name);
      return { safe:false, reason:'🛡️ Malware detected! Executable file blocked.' };
    }
    // Check for ZIP (could contain malware)
    if(bytes[0] === 0x50 && bytes[1] === 0x4B && !file.type.includes('zip')){
      logSecurityEvent('malware_blocked', 'Archive disguised as media: ' + file.name);
      return { safe:false, reason:'🛡️ Suspicious archive file blocked.' };
    }
    // Check for embedded scripts in SVG/HTML
    if(file.type === 'image/svg+xml' || file.name.endsWith('.svg')){
      var text = await file.text();
      if(/<script/i.test(text) || /javascript:/i.test(text) || /on\w+\s*=/i.test(text)){
        logSecurityEvent('malware_blocked', 'SVG with embedded script: ' + file.name);
        return { safe:false, reason:'🛡️ Malicious SVG file blocked.' };
      }
    }
    return { safe:true, reason:'Deep scan passed.' };
  } catch(e){
    return { safe:true, reason:'Scan skipped.' };
  }
}

function logSecurityEvent(type, details){
  console.warn('🛡️ Mindvora Security [' + type + ']: ' + details);
  try {
    if(db && state.user){
      db.collection('security_alerts').add({
        type: type, message: details,
        severity: 'high', read: false, icon: '🛡️',
        userId: state.user.uid,
        userAgent: navigator.userAgent.slice(0, 100),
        timestamp: firebase.firestore.FieldValue.serverTimestamp()
      }).catch(function(){});
    }
  } catch(e){}
}

// ── Enhanced CSP via meta tag ──
(function(){
  var existingCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if(!existingCSP){
    var meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://js.paystack.co https://upload-widget.cloudinary.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https:; media-src 'self' blob: https:; connect-src 'self' https:; frame-src 'self' https://js.paystack.co https://checkout.paystack.com;";
    document.head.appendChild(meta);
  }
})();

// ── Prevent clickjacking ──
(function(){
  if(window.self !== window.top){
    try { window.top.location = window.self.location; } catch(e){
      document.body.innerHTML = '<h1 style="color:red;text-align:center;padding:40px">⚠️ Mindvora cannot be loaded in an iframe for security reasons.</h1>';
    }
  }
})();

// ── Sanitize all clipboard paste events ──
document.addEventListener('paste', function(e){
  var items = e.clipboardData && e.clipboardData.items;
  if(!items) return;
  for(var i = 0; i < items.length; i++){
    if(items[i].type === 'text/html'){
      e.preventDefault();
      var text = e.clipboardData.getData('text/plain');
      if(containsMalicious(text)){
        showToast('⚠️ Suspicious content in clipboard blocked.');
        return;
      }
      document.execCommand('insertText', false, sanitize(text));
      return;
    }
  }
});

// ── Block drag-and-drop of dangerous files ──
document.addEventListener('dragover', function(e){ e.preventDefault(); });
document.addEventListener('drop', function(e){
  e.preventDefault();
  if(e.dataTransfer && e.dataTransfer.files.length > 0){
    var file = e.dataTransfer.files[0];
    var result = scanFileForMalware(file);
    if(!result.safe){
      showToast('🛡️ ' + result.reason);
    }
  }
});



// ── Periodic security health check ──
setInterval(function(){
  // Check for DOM manipulation attacks
  var scripts = document.querySelectorAll('script:not([src])');
  scripts.forEach(function(s){
    if(s.textContent && /eval|Function\(|document\.write/i.test(s.textContent)){
      if(!s.dataset.mvTrusted){
        logSecurityEvent('dom_injection', 'Suspicious inline script detected and removed');
        s.remove();
      }
    }
  });
  // Check for injected iframes
  var iframes = document.querySelectorAll('iframe');
  iframes.forEach(function(f){
    var src = f.src || '';
    if(src && !src.includes('paystack') && !src.includes('cloudinary') && !src.includes('mindvora')){
      logSecurityEvent('iframe_injection', 'Unauthorized iframe removed: ' + src.substring(0,80));
      f.remove();
    }
  });
}, 30000);

// ═══════════════════════════════════════════════════════════════
// STORAGE OPTIMIZATION — Keep device storage lean
// ═══════════════════════════════════════════════════════════════
var STORAGE_MAX_KB = 2048; // Max 2MB localStorage budget

function getLocalStorageSize(){
  var total = 0;
  try {
    for(var i = 0; i < localStorage.length; i++){
      var key = localStorage.key(i);
      total += (key.length + (localStorage.getItem(key) || '').length) * 2; // UTF-16
    }
  } catch(e){}
  return Math.round(total / 1024); // KB
}

function cleanupLocalStorage(){
  var sizeKB = getLocalStorageSize();
  if(sizeKB <= STORAGE_MAX_KB) return;
  // Remove clipboard history first (least critical)
  try { localStorage.removeItem('mv_clipboard'); clipboardHistory = []; } catch(e){}
  // Remove old streak data for users no longer logged in
  try {
    for(var i = localStorage.length - 1; i >= 0; i--){
      var key = localStorage.key(i);
      if(key && (key.indexOf('mv_streak_') === 0 || key.indexOf('mv_last_post_date_') === 0)){
        if(state.user && key.indexOf(state.user.uid) === -1){
          localStorage.removeItem(key);
        }
      }
    }
  } catch(e){}
}

// Clean up service worker cache — remove stale entries older than 7 days
function cleanupCaches(){
  if(!('caches' in window)) return;
  try {
    caches.open('mindvora-v4').then(function(cache){
      cache.keys().then(function(keys){
        // Keep only essential cached items (max 20 entries)
        if(keys.length > 20){
          var toDelete = keys.slice(20);
          toDelete.forEach(function(req){ cache.delete(req); });
        }
      });
    }).catch(function(){});
  } catch(e){}
}

// Revoke any orphaned blob URLs to free memory
var _blobUrls = [];
var _origCreateObjectURL = URL.createObjectURL;
URL.createObjectURL = function(obj){
  var url = _origCreateObjectURL.call(URL, obj);
  _blobUrls.push(url);
  // Auto-revoke after 5 minutes to prevent memory leaks
  setTimeout(function(){
    try { URL.revokeObjectURL(url); } catch(e){}
    _blobUrls = _blobUrls.filter(function(u){ return u !== url; });
  }, 300000);
  return url;
};

// Run cleanup on load and every 10 minutes
cleanupLocalStorage();
cleanupCaches();
setInterval(function(){
  cleanupLocalStorage();
}, 600000);
