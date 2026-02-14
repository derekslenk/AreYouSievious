<script>
  import { api } from '../lib/api.js';
  import { user, view, showToast } from '../lib/stores.js';

  let host = localStorage.getItem('ays_host') || '';
  let username = '';
  let password = '';
  let portImap = 993;
  let portSieve = 4190;
  let loading = false;
  let showAdvanced = false;
  let error = '';

  async function handleLogin() {
    loading = true;
    error = '';
    try {
      const result = await api.login({
        host, username, password,
        port_imap: portImap,
        port_sieve: portSieve,
      });
      localStorage.setItem('ays_host', host);
      user.set({ username: result.username, host });
      view.set('dashboard');
      showToast('Connected');
    } catch (e) {
      error = e.message.includes('401') ? 'Invalid credentials' : e.message;
    } finally {
      loading = false;
    }
  }
</script>

<div class="login-container">
  <div class="login-card">
    <h1>AreYouSievious</h1>
    <p class="subtitle">Sieve filter management</p>

    <form on:submit|preventDefault={handleLogin}>
      <div class="field">
        <label for="host">Mail Server</label>
        <input id="host" type="text" bind:value={host} placeholder="mail.example.com" required />
      </div>

      <div class="field">
        <label for="username">Username</label>
        <input id="username" type="text" bind:value={username} placeholder="you@example.com" required />
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input id="password" type="password" bind:value={password} required />
      </div>

      <button
        type="button"
        class="advanced-toggle"
        on:click={() => showAdvanced = !showAdvanced}
      >
        {showAdvanced ? '▾' : '▸'} Advanced
      </button>

      {#if showAdvanced}
        <div class="advanced">
          <div class="field-row">
            <div class="field">
              <label for="port-imap">IMAP Port</label>
              <input id="port-imap" type="number" bind:value={portImap} />
            </div>
            <div class="field">
              <label for="port-sieve">ManageSieve Port</label>
              <input id="port-sieve" type="number" bind:value={portSieve} />
            </div>
          </div>
        </div>
      {/if}

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button type="submit" class="btn-primary" disabled={loading}>
        {loading ? 'Connecting...' : 'Connect'}
      </button>
    </form>
  </div>
</div>

<style>
  .login-container {
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 1rem;
  }
  .login-card {
    background: var(--surface); border-radius: 12px; padding: 2rem;
    width: 100%; max-width: 420px; box-shadow: 0 4px 24px rgba(0,0,0,0.3);
  }
  h1 { margin: 0 0 0.25rem; font-size: 1.5rem; color: var(--text); }
  .subtitle { margin: 0 0 1.5rem; color: var(--text2); font-size: 0.9rem; }
  .field { margin-bottom: 1rem; }
  .field label { display: block; margin-bottom: 0.25rem; color: var(--text2); font-size: 0.85rem; }
  .field input {
    width: 100%; padding: 0.6rem 0.75rem; border-radius: 6px;
    border: 1px solid var(--border); background: var(--bg);
    color: var(--text); font-size: 0.9rem;
    box-sizing: border-box;
  }
  .field input:focus { outline: none; border-color: var(--accent); }
  .field-row { display: flex; gap: 1rem; }
  .field-row .field { flex: 1; }
  .advanced-toggle {
    background: none; border: none; color: var(--text2); cursor: pointer;
    padding: 0; margin-bottom: 0.5rem; font-size: 0.85rem;
  }
  .advanced { margin-bottom: 1rem; }
  .error {
    background: rgba(255,60,60,0.15); color: #ff6b6b; padding: 0.5rem 0.75rem;
    border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem;
  }
  .btn-primary {
    width: 100%; padding: 0.7rem; border-radius: 6px; border: none;
    background: var(--accent); color: #fff; font-size: 0.95rem;
    cursor: pointer; font-weight: 500;
  }
  .btn-primary:hover { opacity: 0.9; }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
