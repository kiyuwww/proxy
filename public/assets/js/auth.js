// Username + password login against this server's /api endpoints.
// The session lives in an HttpOnly cookie, so JavaScript never sees the token.
(function () {
  const $ = (id) => document.getElementById(id);

  async function api(path, fields) {
    const init = { credentials: 'same-origin' };
    if (fields) {
      init.method = 'POST';
      init.body = new URLSearchParams(fields);
    }
    try {
      const res = await fetch(path, init);
      let data = {};
      try { data = await res.json(); } catch (_) { /* non-JSON error page */ }
      return { ok: res.ok, status: res.status, data };
    } catch (_) {
      return { ok: false, status: 0, data: { error: 'Нет связи с сервером' } };
    }
  }

  function showApp(loggedIn) {
    $('auth-view').classList.toggle('hidden', loggedIn);
    $('app-view').classList.toggle('hidden', !loggedIn);
    $('logout-btn').classList.toggle('hidden', !loggedIn);
  }

  function setBusy(busy) {
    document.querySelectorAll('#auth-form button').forEach((b) => (b.disabled = busy));
  }

  async function submit(kind) {
    const username = $('auth-username').value.trim();
    const password = $('auth-password').value;
    $('auth-msg').textContent = '';
    if (!username || !password) {
      $('auth-msg').textContent = 'Введите имя пользователя и пароль';
      return;
    }
    setBusy(true);
    const r = await api('/api/' + kind, { username, password });
    setBusy(false);
    if (r.ok) {
      location.reload();
    } else {
      $('auth-msg').textContent = r.data.error || 'Ошибка ' + r.status;
    }
  }

  document.addEventListener('DOMContentLoaded', async () => {
    $('auth-form').addEventListener('submit', (e) => {
      e.preventDefault();
      submit('login');
    });
    $('register-btn').addEventListener('click', () => submit('register'));
    $('logout-btn').addEventListener('click', async () => {
      await api('/api/logout', {});
      location.reload();
    });

    const me = await api('/api/me');
    showApp(me.ok);
  });
})();
