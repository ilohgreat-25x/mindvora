/* Mindvora service marketplace handoff. Provider credentials stay server-side. */
(function () {
  'use strict';
  var providers = {
    esim: {
      title: 'Get / recharge foreign eSIMs',
      kicker: 'TRAVEL CONNECTIVITY',
      body: 'Sell travel data under the Mindvora brand. The recommended first integration is eSIM Signal: it advertises a REST reseller API, 210+ destinations, instant activation details, signed webhooks, refunds for unused eSIMs, and a prepaid partner balance.',
      links: '<a href="https://business.esimsignal.com/business/register" target="_blank" rel="noopener">Apply for an eSIM Signal business account</a><a href="https://esimgo.com/platform/integration" target="_blank" rel="noopener">Compare eSIM Go</a>',
      next: 'After approval, provide the API documentation and test credentials. Mindvora will collect payment through Paystack, confirm the transaction server-side, then place the supplier order from the provider balance. Do not paste supplier secrets into this page.'
    },
    email: {
      title: 'Get business emails',
      kicker: 'PROFESSIONAL MAILBOXES',
      body: 'The recommended provider is Openprovider Business Email. It supports reseller provisioning through REST API or WHMCS, mailbox storage upgrades, aliases, forwarding, spam protection, and a single reseller balance for services.',
      links: '<a href="https://www.openprovider.com/products/business-email-solution" target="_blank" rel="noopener">Review Openprovider Business Email</a><a href="https://cp.openprovider.eu/signup" target="_blank" rel="noopener">Create an Openprovider account</a>',
      next: 'Business-email sales also require a domain flow, mailbox lifecycle rules, abuse handling, password reset, and cancellation/refund policy. After you create the reseller account, provide the API docs and sandbox credentials so provisioning can be implemented server-side.'
    }
  };
  function close() { var old = document.getElementById('mv-service-modal'); if (old) old.remove(); document.body.style.overflow = ''; }
  window.openMindvoraService = function (kind) {
    var p = providers[kind] || providers.esim;
    close();
    var el = document.createElement('div'); el.id = 'mv-service-modal'; el.className = 'mv-service-modal';
    el.innerHTML = '<div class="mv-service-card" role="dialog" aria-modal="true" aria-labelledby="mv-service-title"><button class="mv-service-close" type="button" aria-label="Close">×</button><span class="mv-service-kicker">' + p.kicker + '</span><h2 id="mv-service-title">' + p.title + '</h2><p>' + p.body + '</p><div class="mv-service-links">' + p.links + '</div><div class="mv-service-next"><strong>Integration path</strong><p>' + p.next + '</p></div><button class="mv-service-close mv-service-done" type="button">I understand</button></div>';
    document.body.appendChild(el); document.body.style.overflow = 'hidden';
    el.addEventListener('click', function (e) { if (e.target === el || e.target.closest('.mv-service-close')) close(); });
  };
})();
