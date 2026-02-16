<script>
  import { view } from '../lib/stores.js';
</script>

<div class="privacy">
  <button class="back" on:click={() => view.set('login')}>← Back</button>

  <h1>Privacy Policy</h1>
  <p class="updated">Last updated: February 16, 2026</p>

  <h2>What AreYouSievious Does</h2>
  <p>AreYouSievious is a self-hostable web interface for managing email Sieve filters via the ManageSieve protocol. It connects directly to your mail server using credentials you provide.</p>

  <h2>Data We Collect</h2>
  <p><strong>None.</strong></p>
  <ul>
    <li>No accounts, no databases, no analytics, no tracking.</li>
    <li>Your mail server credentials are held in memory only for the duration of your session (max 30 minutes) and are never written to disk.</li>
    <li>No cookies are used other than a session token (HttpOnly, Secure, SameSite=Strict) to maintain your authenticated session.</li>
  </ul>

  <h2>Data We Store</h2>
  <p><strong>Nothing.</strong> There is no database. When your session expires or you log out, all credentials are gone.</p>

  <h2>Third Parties</h2>
  <p>AreYouSievious does not send data to any third party. The only network connections made are between your browser, this server, and the mail server you specify.</p>

  <h2>Self-Hosting</h2>
  <p>AreYouSievious is open source. You can <a href="https://github.com/derekslenk/AreYouSievious" target="_blank" rel="noopener">self-host it</a> and have full control over the environment your credentials pass through.</p>

  <h2>Contact</h2>
  <p>Questions? Open an issue on <a href="https://github.com/derekslenk/AreYouSievious/issues" target="_blank" rel="noopener">GitHub</a>.</p>
</div>

<style>
  .privacy {
    max-width: 640px; margin: 2rem auto; padding: 2rem;
    line-height: 1.6;
  }
  h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
  h2 { font-size: 1.1rem; margin-top: 1.5rem; color: var(--accent); }
  .updated { color: var(--text2); font-size: 0.85rem; margin-bottom: 1.5rem; }
  a { color: var(--accent); }
  a:hover { text-decoration: underline; }
  ul { padding-left: 1.2rem; }
  li { margin-bottom: 0.4rem; }
  .back {
    background: none; border: none; color: var(--text2);
    cursor: pointer; padding: 0; font-size: 0.85rem;
  }
  .back:hover { color: var(--text); }
</style>
