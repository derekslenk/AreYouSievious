<script>
  import { onMount } from 'svelte';
  import { api } from './lib/api.js';
  import { user, view, toast } from './lib/stores.js';
  import Login from './routes/Login.svelte';
  import Dashboard from './routes/Dashboard.svelte';
  import RuleEditor from './routes/RuleEditor.svelte';
  import RawEditor from './routes/RawEditor.svelte';

  onMount(async () => {
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
    <Dashboard />
  {:else if $view === 'editor'}
    <RuleEditor />
  {:else if $view === 'raw'}
    <RawEditor />
  {/if}
</main>

{#if $toast}
  <div class="toast" class:error={$toast.type === 'error'}>
    {$toast.message}
  </div>
{/if}

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
</style>
