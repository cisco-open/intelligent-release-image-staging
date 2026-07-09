// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

document.getElementById('setup-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  var err = document.getElementById('err'); err.textContent = '';
  var u = document.getElementById('u').value;
  var p = document.getElementById('p').value;
  var p2 = document.getElementById('p2').value;
  if (!u || !p) { err.textContent = 'Username and password are required.'; return; }
  if (p !== p2) { err.textContent = 'Passwords do not match.'; return; }
  var res = await fetch('/api/setup', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  });
  if (res.ok) { window.location.href = '/login.html'; }
  else if (res.status === 409) { window.location.href = '/login.html'; }
  else { var j = await res.json().catch(function () { return {}; });
         err.textContent = j.error || ('Setup failed (' + res.status + ')'); }
});
