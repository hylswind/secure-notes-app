(function () {
  function $(id) { return document.getElementById(id); }
  fetch('/api/me').then(function (r) { return r.json(); }).then(function (m) {
    $('acct-name').textContent = m.name; $('acct-email').textContent = m.email;
  });
  fetch('/api/status').then(function (r) { return r.json(); }).then(function (s) {
    $('vol-state').textContent = s.volume;
    $('vol-reason').textContent = s.volume_reason || '—';
    $('cert-exp').textContent = s.certificate_expires_at || 'none';
    $('version').textContent = s.version;
  });
  $('logout').addEventListener('click', function () {
    fetch('/auth/logout', { method: 'POST' }).then(function () { location.href = '/'; });
  });
})();
