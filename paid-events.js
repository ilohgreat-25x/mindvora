/**
 * MINDVORA — PAID EVENTS (slide-out "Paid Events")  ·  paid-events.js
 * Replaces the old browser-side Paid Events code: events are created by the server
 * (price $0 = free, capacity, link private to ticket holders), tickets are paid via
 * Paystack and verified + issued by the server (organiser 80%, Mindvora 20%).
 * Live streams are not affected.
 */
(function () {
window.loadPaidEvents = function loadPaidEvents() {
  var list = document.getElementById('paid-events-list');
  list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">Loading events...</div>';
  db.collection('paid_events').orderBy('eventDate','desc').limit(40).get()
    .then(function(snap) {
      var docs = snap.docs.filter(function(d){ return d.data().status !== 'cancelled'; });
      if (!docs.length) { list.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted)">No upcoming events.<br>Create one!</div>'; return; }
      var pill = 'font-size:10px;padding:5px 12px;border-radius:20px;border:none;cursor:pointer;font-family:\'DM Sans\',sans-serif;';
      list.innerHTML = docs.map(function(d) {
        var ev = d.data(), price = Number(ev.price)||0, sold = ev.ticketsSold || (ev.attendees||[]).length;
        var isOwn = ev.hostId===state.user.uid, has = (ev.attendees||[]).indexOf(state.user.uid)>-1;
        var full = ev.capacity && sold >= ev.capacity;
        var when = new Date(ev.eventDate&&ev.eventDate.seconds?ev.eventDate.seconds*1000:ev.eventDate);
        var btn = (isOwn || has)
          ? '<button onclick="openEventAccess(\''+d.id+'\')" style="'+pill+'background:rgba(34,197,94,.15);color:var(--green3)">'+(isOwn?'Your Event · Link':'✓ Ticket · Open')+'</button>'
          : full ? '<span style="'+pill+'background:rgba(239,68,68,.15);color:#fca5a5;cursor:default">Sold out</span>'
          : '<button onclick="buyEventTicket(\''+d.id+'\',\''+escJs(ev.title||'Event')+'\','+price+')" style="'+pill+'background:var(--green2);color:#fff">'+(price>0?'Get ticket $'+price:'Join free')+'</button>';
        return '<div class="sched-item"><div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px"><div>'+
          '<div style="font-size:13px;font-weight:700;color:var(--moon)">'+esc(ev.title||'Event')+'</div>'+
          '<div style="font-size:11px;color:var(--muted);margin-top:2px">📅 '+when.toLocaleString()+' · 👤 by @'+esc(ev.hostHandle||'user')+'</div>'+
          '<div style="font-size:11px;color:var(--muted)">🎟 '+sold+(ev.capacity?' / '+ev.capacity:'')+' attending · '+(price>0?'💵 $'+price:'🆓 Free')+'</div>'+
          '<div style="font-size:11px;color:var(--moon);margin-top:4px">'+esc((ev.description||'').slice(0,120))+'</div>'+
          '</div>'+btn+'</div></div>';
      }).join('');
    }).catch(function(e){console.warn('Events error:',e);list.innerHTML='<div style="color:#fca5a5;padding:10px">Error loading events</div>';});
}

window.showCreateEvent = function showCreateEvent() {
  document.getElementById('events-list-view').style.display='none';
  document.getElementById('create-event-view').style.display='block';
}

window.cancelCreateEvent = function cancelCreateEvent() {
  document.getElementById('events-list-view').style.display='block';
  document.getElementById('create-event-view').style.display='none';
}

// Events are created by the server (price $0 = free, capacity, link kept private for ticket holders).
window.createPaidEvent = function createPaidEvent() {
  var g = function(id){ var el=document.getElementById(id); return el ? el.value.trim() : ''; };
  var err = document.getElementById('ev-err');
  var title=g('ev-title'), date=g('ev-date'), price=parseFloat(g('ev-price'))||0, cap=parseInt(g('ev-capacity'),10)||0;
  if (!title){err.textContent='Enter a title';return;}
  if (!date){err.textContent='Enter event date';return;}
  if (price!==0 && price<1){err.textContent='Price must be $0 (free) or at least $1';return;}
  err.textContent='Creating…';
  mvApi('/api/events', { title:title, description:g('ev-desc'), eventDate:new Date(date).toISOString(), price:price, capacity:cap, meetingLink:g('ev-link') })
    .then(function(d){
      if (!d || !d.ok) { err.textContent = (d && d.message) || 'Error creating event'; return; }
      err.textContent=''; showToast('🎟 Event created!'); cancelCreateEvent(); loadPaidEvents();
    }).catch(function(){ err.textContent='Network error — try again'; });
}

// Paid: Paystack, then the server verifies the payment and issues the ticket. Free: join.
window.buyEventTicket = function buyEventTicket(eventId, eventTitle, price) {
  if (!state.user){showToast('Login first');return;}
  if (!(price > 0)) {
    mvApi('/api/events/'+encodeURIComponent(eventId)+'/join', {}).then(function(d){
      showToast(d && d.ok ? '🎟 You\'re in: "'+eventTitle+'"' : '❌ '+((d && d.message)||'Could not join'));
      loadPaidEvents();
    }).catch(function(){ showToast('Network error — try again'); });
    return;
  }
  var fee = Math.round(price*20)/100;
  payForPurpose({
    amountKobo: usdToNGNKobo(price), refPrefix: 'ZEVT', purpose: 'event_ticket',
    params: { eventId: eventId }, closeMsg: 'Purchase cancelled',
    success: function(d){
      var r = d && d.result;
      if (r && r.refunded) showToast('↩️ The event sold out — your payment was refunded.');
      else showToast('🎟 Ticket confirmed for "'+eventTitle+'"!');
      loadPaidEvents();
    }
  });
}

window.openEventAccess = function openEventAccess(eventId) {
  mvApi('/api/events/'+encodeURIComponent(eventId)+'/access').then(function(d){
    if (!d || !d.ok) { showToast('❌ '+((d && d.message)||'No access')); return; }
    if (d.meetingLink) window.open(d.meetingLink, '_blank', 'noopener');
    else showToast(d.host ? 'Your event has no link yet.' : 'The organiser has not added a link yet.');
  }).catch(function(){ showToast('Network error — try again'); });
}


// Form: free events + capacity + fee note (the old form required >= $1).
function patchForm() {
  var pr = document.getElementById('ev-price');
  if (!pr || document.getElementById('ev-capacity')) return;
  pr.min = '0'; pr.placeholder = '0 = free event';
  var note = document.createElement('div');
  note.style.cssText = 'font-size:10px;color:var(--muted);margin:-6px 0 10px';
  note.textContent = 'You receive 80% of each ticket. Mindvora keeps 20%.';
  var lab = document.createElement('label'); lab.className = 'm-label'; lab.textContent = 'Capacity (0 = unlimited)';
  var cap = document.createElement('input'); cap.className = 'm-input'; cap.id = 'ev-capacity'; cap.type = 'number'; cap.min = '0'; cap.placeholder = '0'; cap.style.marginBottom = '10px';
  pr.insertAdjacentElement('afterend', cap); pr.insertAdjacentElement('afterend', lab); pr.insertAdjacentElement('afterend', note);
  document.querySelectorAll('#create-event-view .m-label').forEach(function (l) {
    if (/^Ticket Price/.test(l.textContent)) l.textContent = 'Ticket Price (USD, 0 = free)';
    if (/^Meeting Link/.test(l.textContent)) l.textContent = 'Event Link (only ticket holders see it)';
  });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', patchForm); else patchForm();

// Notification taps (?action=events) open Paid Events.
var prevOpen = window.handleOpenUrl;
window.handleOpenUrl = function (url) {
  try { if (new URL(url, location.origin).searchParams.get('action') === 'events') { if (window.openPaidEvents) openPaidEvents(); return; } } catch (e) {}
  if (prevOpen) return prevOpen(url);
};
try {
  if (new URLSearchParams(location.search).get('action') === 'events')
    setTimeout(function () { if (window.state && state.user && window.openPaidEvents) openPaidEvents(); }, 4000);
} catch (e) {}
})();
