(function () {
  'use strict';

  // Theme toggle
  var root = document.documentElement;
  var themeBtn = document.querySelector('.theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var current = root.getAttribute('data-theme');
      var next = current === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) {}
    });
  }

  // Mobile nav toggle
  var nav = document.querySelector('.site-nav');
  var navToggle = document.querySelector('.nav-toggle');
  if (nav && navToggle) {
    navToggle.addEventListener('click', function () {
      var open = nav.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  // Copy-to-clipboard for code blocks
  if (navigator.clipboard && navigator.clipboard.writeText) {
    document.querySelectorAll('pre > code').forEach(function (code) {
      var pre = code.parentElement;
      if (pre.querySelector('.copy-btn')) return;
      var btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.type = 'button';
      btn.setAttribute('aria-label', 'Copy code');
      btn.textContent = 'Copy';
      btn.addEventListener('click', function () {
        navigator.clipboard.writeText(code.textContent)
          .then(function () {
            btn.textContent = 'Copied';
            setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
          })
          .catch(function () {
            btn.textContent = 'Error';
            setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
          });
      });
      pre.appendChild(btn);
    });
  }

  // Tabbed install snippets
  document.querySelectorAll('.tabs').forEach(function (tabs) {
    var triggers = tabs.querySelectorAll('[role="tab"]');
    var panels = tabs.querySelectorAll('[role="tabpanel"]');
    triggers.forEach(function (trigger) {
      trigger.addEventListener('click', function () {
        var id = trigger.getAttribute('aria-controls');
        triggers.forEach(function (t) { t.setAttribute('aria-selected', 'false'); });
        panels.forEach(function (p) { p.hidden = (p.id !== id); });
        trigger.setAttribute('aria-selected', 'true');
      });
    });
  });

  // Animate benchmark bars on scroll-into-view
  var bars = document.querySelectorAll('.bar[data-pct]');
  if (bars.length && 'IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var el = entry.target;
          el.style.width = el.getAttribute('data-pct') + '%';
          io.unobserve(el);
        }
      });
    }, { threshold: 0.2 });
    bars.forEach(function (b) { io.observe(b); });
  } else {
    bars.forEach(function (b) { b.style.width = b.getAttribute('data-pct') + '%'; });
  }
})();
