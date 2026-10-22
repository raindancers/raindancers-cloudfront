// Minimal admin SPA. It ENFORCES NOTHING (R9.3): on load it asks the management
// API which operations the caller may perform and reveals only those, hiding
// everything else (fail-closed to hidden, R9.2). The regional Lambda re-checks
// every call server-side, so a hidden-but-forged request is still denied.
//
// The API is mounted at `<prefix>/api/` on the same distribution the SPA is
// served from, so the base is derived from the current path — no origin config
// is baked into the bundle.
(function () {
  'use strict';

  var statusEl = document.getElementById('status');

  // Derive `<prefix>/api` from the SPA's own location, e.g. /admin/index.html
  // -> /admin/api. The SPA lives directly under the prefix.
  function apiBase() {
    var parts = window.location.pathname.split('/').filter(Boolean);
    var prefix = parts.length ? parts[0] : 'admin';
    return '/' + prefix + '/api';
  }

  function reveal(id) {
    var el = document.getElementById(id);
    if (el) { el.classList.remove('hidden'); }
  }

  // op -> (screen to show, button to reveal)
  var OP_UI = {
    listRoles: { screen: 'roles-screen', btn: 'btn-list-roles' },
    createRole: { screen: 'roles-screen', btn: 'btn-create-role' },
    deleteRole: { screen: 'roles-screen', btn: 'btn-delete-role' },
    listAssignments: { screen: 'assignments-screen', btn: 'btn-list-assignments' },
    createAssignment: { screen: 'assignments-screen', btn: 'btn-create-assignment' },
    deleteAssignment: { screen: 'assignments-screen', btn: 'btn-delete-assignment' },
  };

  function applyReflection(operations) {
    var any = false;
    Object.keys(OP_UI).forEach(function (op) {
      if (operations && operations[op]) {
        any = true;
        reveal(OP_UI[op].screen);
        reveal(OP_UI[op].btn);
      }
    });
    statusEl.textContent = any
      ? 'Showing the actions your permissions allow.'
      : 'You have no management permissions on this surface.';
  }

  fetch(apiBase() + '/reflect', { credentials: 'include' })
    .then(function (r) {
      if (!r.ok) { throw new Error('reflect failed: ' + r.status); }
      return r.json();
    })
    .then(function (data) { applyReflection(data.operations || {}); })
    .catch(function (err) {
      // Fail-closed: on any error, reveal nothing.
      statusEl.textContent = 'Could not load your permissions. No actions are available.';
      console.error(err);
    });
})();
