// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

document.getElementById('login-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  var err = document.getElementById('err');
  err.textContent = '';
  var body = {
    username: document.getElementById('u').value,
    password: document.getElementById('p').value
  };
  var res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (res.ok) {
    var j = await res.json().catch(function () { return {}; });
    if (j.setup && j.setup_grant) {
      // First-run: the default credential doesn't open a session, it hands
      // back a one-time grant for /api/setup. Keep it out of the URL (no
      // secrets in history/referrers) -- sessionStorage only.
      window.sessionStorage.setItem('iris_setup_grant', j.setup_grant);
      window.location.href = '/setup.html';
      return;
    }
    if (window.sessionStorage.getItem('iris_post_setup')) {
      // One-shot: the sign-in immediately after first-run setup continues the
      // checklist. Cleared here so later sign-ins land on the Overview.
      window.sessionStorage.removeItem('iris_post_setup');
      window.location.href = '/#setup';
      return;
    }
    window.location.href = '/';
  } else {
    err.textContent = 'Invalid username or password.';
  }
});
