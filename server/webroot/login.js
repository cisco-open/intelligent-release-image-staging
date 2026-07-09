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
    window.location.href = '/';
  } else {
    err.textContent = 'Invalid username or password.';
  }
});
