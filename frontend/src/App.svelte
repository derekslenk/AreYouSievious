<script>
  import { onMount } from 'svelte';
  import { api } from './lib/api.js';
  import { user, view, toast } from './lib/stores.js';
  import Login from './routes/Login.svelte';

  const lazyDashboard = () => import('./routes/Dashboard.svelte').then(m => m.default);
  const lazyRuleEditor = () => import('./routes/RuleEditor.svelte').then(m => m.default);
  const lazyRawEditor = () => import('./routes/RawEditor.svelte').then(m => m.default);
  const lazyPrivacy = () => import('./routes/Privacy.svelte').then(m => m.default);

  let skipPush = false;

  // Push history state when view changes
  view.subscribe(v => {
    if (!skipPush && typeof window !== 'undefined') {
      history.pushState({ view: v }, '', `#${v}`);
    }
    skipPush = false;
  });

  onMount(async () => {
    // Handle browser back/forward
    window.addEventListener('popstate', (e) => {
      if (e.state?.view) {
        skipPush = true;
        view.set(e.state.view);
      }
    });

    // Check existing session
    try {
      const status = await api.status();
      if (status.authenticated) {
        user.set({ username: status.username, host: status.host });
        view.set('dashboard');
      }
    } catch (e) { /* no session */ }

    // Listen for forced logout
    window.addEventListener('ays:logout', () => {
      user.set(null);
      view.set('login');
    });
  });
</script>

<main>
  {#if $view === 'login'}
    <Login />
  {:else if $view === 'dashboard'}
    {#await lazyDashboard()}
      <div class="route-loading">Loading…</div>
    {:then Component}
      <svelte:component this={Component} />
    {:catch err}
      <div class="route-error">Failed to load Dashboard: {err.message}</div>
    {/await}
  {:else if $view === 'editor'}
    {#await lazyRuleEditor()}
      <div class="route-loading">Loading…</div>
    {:then Component}
      <svelte:component this={Component} />
    {:catch err}
      <div class="route-error">Failed to load Rule Editor: {err.message}</div>
    {/await}
  {:else if $view === 'raw'}
    {#await lazyRawEditor()}
      <div class="route-loading">Loading…</div>
    {:then Component}
      <svelte:component this={Component} />
    {:catch err}
      <div class="route-error">Failed to load Raw Editor: {err.message}</div>
    {/await}
  {:else if $view === 'privacy'}
    {#await lazyPrivacy()}
      <div class="route-loading">Loading…</div>
    {:then Component}
      <svelte:component this={Component} />
    {:catch err}
      <div class="route-error">Failed to load Privacy: {err.message}</div>
    {/await}
  {/if}
</main>

{#if $toast}
  <div class="toast" class:error={$toast.type === 'error'}>
    {$toast.message}
  </div>
{/if}

<footer>
  <a href="https://github.com/derekslenk/AreYouSievious" target="_blank" rel="noopener">GitHub</a>
  <span class="sep">·</span>
  <a href="#privacy" on:click|preventDefault={() => view.set('privacy')}>Privacy Policy</a>
</footer>

<style>
  :global(:root) {
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --text: #e0e0e0;
    --text2: #888;
    --accent: #5b7fff;
    --danger: #ff4d4d;
  }
  :global(*) { box-sizing: border-box; }
  :global(body) {
    margin: 0; padding: 0;
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  :global(.btn-sm) {
    padding: 0.35rem 0.7rem; font-size: 0.8rem; border-radius: 5px;
    border: 1px solid var(--border); background: var(--surface); color: var(--text);
    cursor: pointer;
  }
  :global(.btn-sm:hover) { background: var(--bg); }
  :global(.btn-accent) { background: var(--accent); border-color: var(--accent); color: #fff; }
  :global(.btn-accent:hover) { opacity: 0.9; }
  :global(.btn-danger) { color: var(--danger); }
  :global(.btn-danger:hover) { background: rgba(255,77,77,0.1); }

  .toast {
    position: fixed; bottom: 1.5rem; right: 1.5rem;
    padding: 0.6rem 1rem; border-radius: 8px;
    background: var(--accent); color: #fff; font-size: 0.85rem;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 200;
    animation: slideIn 0.2s ease;
  }
  .toast.error { background: var(--danger); }
  @keyframes slideIn { from { transform: translateY(10px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

  .route-loading {
    padding: 2rem 1rem; text-align: center; color: var(--text2); font-size: 0.85rem;
  }
  .route-error {
    padding: 2rem 1rem; text-align: center; color: var(--danger); font-size: 0.85rem;
  }

  footer {
    text-align: center; padding: 1.5rem 0.6rem 0.6rem;
    font-size: 0.75rem; color: var(--text2);
  }
  footer a {
    color: var(--text2); text-decoration: none;
  }
  footer a:hover { color: var(--text); }
  footer .sep { margin: 0 0.4rem; }
</style>
