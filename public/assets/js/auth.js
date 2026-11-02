// Optional Supabase login. Config comes from the server (/app-config.js, built from
// SUPABASE_URL / SUPABASE_ANON_KEY env vars), so nothing secret is stored in the repo.
// If the config is empty, the login box stays hidden and the search works without login.
(function () {
  const cfg = window.APP_CONFIG || {};
  const hasSupabase = !!(cfg.supabaseUrl && cfg.supabaseAnonKey && window.supabase);

  const supabase = hasSupabase
    ? window.supabase.createClient(cfg.supabaseUrl, cfg.supabaseAnonKey, {
        auth: { persistSession: true, autoRefreshToken: true },
      })
    : null;

  function showLoggedIn() {
    document.getElementById('loginBox')?.classList.add('hidden');
    document.getElementById('logout-btn')?.classList.remove('hidden');
    document.getElementById('sj-form')?.classList.remove('hidden');
  }

  function showLoggedOut() {
    document.getElementById('loginBox')?.classList.remove('hidden');
    document.getElementById('logout-btn')?.classList.add('hidden');
    document.getElementById('sj-form')?.classList.add('hidden');
  }

  async function checkSession() {
    if (!supabase) {
      // Auth not configured: behave like an open search page.
      showLoggedIn();
      return;
    }
    const { data: { session } } = await supabase.auth.getSession();
    session ? showLoggedIn() : showLoggedOut();
  }

  function fieldValues() {
    return {
      email: document.getElementById('login-email').value,
      password: document.getElementById('login-password').value,
    };
  }

  document.addEventListener('DOMContentLoaded', () => {
    checkSession();
    if (!supabase) return;

    document.getElementById('login-btn')?.addEventListener('click', async () => {
      const { email, password } = fieldValues();
      const { error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) alert('Ошибка входа: ' + error.message);
      else location.reload();
    });

    document.getElementById('signup-btn')?.addEventListener('click', async () => {
      const { email, password } = fieldValues();
      const { error } = await supabase.auth.signUp({ email, password });
      if (error) alert('Ошибка регистрации: ' + error.message);
      else alert('Проверьте почту для подтверждения');
    });

    document.getElementById('logout-btn')?.addEventListener('click', async () => {
      await supabase.auth.signOut();
      location.reload();
    });
  });
})();
