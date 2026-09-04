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
  var res;
  try {
    res = await fetch('/api/v1/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  } catch (e) {
    err.textContent = 'Could not reach the server. Check the connection and try again.';
    return;
  }
  if (res.ok) {
    var j = await res.json().catch(function () { return {}; });
    if (j.setup && j.setup_grant) {
      // First-run: the operator-held setup credential doesn't open a session;
      // it returns a one-time grant for /api/v1/setup. Keep it out of the URL
      // (no secrets in history/referrers) -- sessionStorage only.
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
  } else if (res.status === 429) {
    // throttled: the credential was NOT checked, so never call it wrong --
    // that only makes the operator retry and extend the lockout
    var wait = parseInt(res.headers.get('Retry-After') || '', 10);
    err.textContent = 'Too many login attempts. Try again' +
      (wait > 0 ? ' in ' + wait + ' second' + (wait === 1 ? '' : 's') : ' shortly') + '.';
  } else if (res.status === 503) {
    err.textContent = 'The server is busy; try again in a moment.';
  } else if (res.status === 401) {
    err.textContent = 'Invalid username or password.';
  } else {
    err.textContent = 'Sign-in failed (' + res.status + '). Try again.';
  }
});
