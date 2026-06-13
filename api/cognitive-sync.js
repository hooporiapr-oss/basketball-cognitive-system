// cognitive-sync.js — Reactific Score Sync
// Connects Number Hunt to the leaderboard API

(function() {
  var API_URL = 'https://api.reactificgaming.com'; // update after deploy
  var TOKEN_KEY = 'reactific-token';
  var USER_KEY = 'reactific-user';

  // ── Auth helpers ──────────────────────────────────────
  function getToken() { return localStorage.getItem(TOKEN_KEY); }
  function getUser() { try { return JSON.parse(localStorage.getItem(USER_KEY)); } catch(e) { return null; } }
  function setAuth(token, user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
  function clearAuth() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }
  function isLoggedIn() { return !!getToken(); }
  function isSubscribed() { var u = getUser(); return u && u.subscription_status === 'active'; }

  // ── API calls ─────────────────────────────────────────
  function api(method, path, body) {
    var opts = {
      method: method,
      headers: { 'Content-Type': 'application/json' }
    };
    var token = getToken();
    if (token) opts.headers['Authorization'] = 'Bearer ' + token;
    if (body) opts.body = JSON.stringify(body);

    return fetch(API_URL + path, opts).then(function(r) {
      if (r.status === 401) { clearAuth(); }
      return r.json();
    });
  }

  // ── Public API ────────────────────────────────────────

  // Register
  window.reactificRegister = function(email, username, password) {
    return api('POST', '/api/auth/register', { email: email, username: username, password: password })
      .then(function(data) {
        if (data.token) setAuth(data.token, data.user);
        return data;
      });
  };

  // Login
  window.reactificLogin = function(email, password) {
    return api('POST', '/api/auth/login', { email: email, password: password })
      .then(function(data) {
        if (data.token) setAuth(data.token, data.user);
        return data;
      });
  };

  // Logout
  window.reactificLogout = function() { clearAuth(); };

  // Get current user
  window.reactificGetUser = function() { return getUser(); };
  window.reactificIsLoggedIn = function() { return isLoggedIn(); };
  window.reactificIsSubscribed = function() { return isSubscribed(); };

  // Refresh user data from server
  window.reactificRefreshUser = function() {
    if (!isLoggedIn()) return Promise.resolve(null);
    return api('GET', '/api/auth/me').then(function(data) {
      if (data.user) {
        var token = getToken();
        setAuth(token, data.user);
      }
      return data.user;
    });
  };

  // ── Score sync (called by games) ──────────────────────
  window.syncCognitiveScore = function(speed, level, score, streak, tier) {
    if (!isLoggedIn()) {
      console.log('[reactific] not logged in — score saved locally only');
      return;
    }

    var court = window.REACTIFIC_COURT || 'half';

    // Full Court requires subscription
    if (court === 'full' && !isSubscribed()) {
      console.log('[reactific] Full Court requires subscription');
      return;
    }

    api('POST', '/api/scores', {
      court: court,
      speed: speed,
      level: level,
      score: score,
      streak: streak || 0,
      tier: tier || 1,
      targets_found: level,
      time_remaining_ms: 0
    }).then(function(data) {
      if (data.rank) {
        console.log('[reactific] score posted — rank #' + data.rank);
        // Fire event for UI to show rank
        window.dispatchEvent(new CustomEvent('reactific-rank', { detail: data }));
      }
    }).catch(function(err) {
      console.error('[reactific] sync failed:', err);
    });
  };

  // ── Leaderboard ───────────────────────────────────────
  window.reactificLeaderboard = function(period, speed, limit) {
    period = period || 'daily';
    speed = speed || 'slow';
    limit = limit || 50;
    return api('GET', '/api/leaderboard/' + period + '?speed=' + speed + '&limit=' + limit);
  };

  window.reactificMyRank = function(speed) {
    if (!isLoggedIn()) return Promise.resolve({ rank: null });
    return api('GET', '/api/leaderboard/myrank?speed=' + (speed || 'slow'));
  };

  // ── Stripe ────────────────────────────────────────────
  window.reactificSubscribe = function() {
    if (!isLoggedIn()) return Promise.reject('Login required');
    return api('POST', '/api/stripe/checkout').then(function(data) {
      if (data.url) window.location.href = data.url;
      return data;
    });
  };

  window.reactificManageSubscription = function() {
    if (!isLoggedIn()) return Promise.reject('Login required');
    return api('POST', '/api/stripe/portal').then(function(data) {
      if (data.url) window.location.href = data.url;
      return data;
    });
  };

})();
