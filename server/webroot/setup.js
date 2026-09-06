// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Grantless visit (deep link, stale tab): bounce to the login page, where the
// documented first-run credential mints the grant that authorizes this form.
if (!window.sessionStorage.getItem('iris_setup_grant')) {
  window.location.replace('/login.html');
}

document.getElementById('setup-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  var err = document.getElementById('err'); err.textContent = '';
  var u = document.getElementById('u').value;
  var p = document.getElementById('p').value;
  var p2 = document.getElementById('p2').value;
  if (!u || !p) { err.textContent = 'Username and password are required.'; return; }
  if (p.length < 8) { err.textContent = 'Password must be at least 8 characters.'; return; }
  if (p !== p2) { err.textContent = 'Passwords do not match.'; return; }
  // The grant was handed back by /api/v1/login after the operator entered the
  // documented first-run credential, and passed here via
  // sessionStorage -- never the URL, so it never lands in browser history or
  // a referrer header.
  var grant = window.sessionStorage.getItem('iris_setup_grant');
  if (!grant) {
    err.textContent = 'Sign in with the default credential first.';
    return;
  }
  var res = await fetch('/api/v1/setup', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p, setup_grant: grant })
  });
  if (res.ok) {
    window.sessionStorage.removeItem('iris_setup_grant');
    // Creating the admin is step one of post-install setup, so hand the next
    // sign-in straight to the checklist instead of the Overview. Only a
    // genuine first-run success arms this -- a 409 means setup already ran.
    window.sessionStorage.setItem('iris_post_setup', '1');
    window.location.href = '/login.html';
  } else if (res.status === 409) {
    window.sessionStorage.removeItem('iris_setup_grant');
    window.location.href = '/login.html';
  } else {
    var j = await res.json().catch(function () { return {}; });
    err.textContent = j.error || ('Setup failed (' + res.status + ')');
  }
});
