<script lang="ts">
  let { currentPage = 'home', isAdmin = false, onLogout }: { currentPage?: string; isAdmin?: boolean; onLogout: () => void } = $props()
</script>

<header class="topnav">
  <div class="left">
    <a href="/" class="brand">
      <div class="logo">
        <span class="logo-icon">◊</span>
      </div>
      <span class="app-name">MDR Compass</span>
    </a>
    <span class="page-label">
      {#if currentPage === 'admin'}
        ADMIN
      {:else if currentPage === 'processes'}
        PROCESS ATLAS
      {:else if currentPage === 'news'}
        SECURITY NEWS
      {:else if currentPage === 'console'}
        ANALYST CONSOLE
      {:else}
        HOME
      {/if}
    </span>
  </div>
  <div class="right">
    {#if currentPage === 'home'}
      {#if isAdmin}
        <a href="/admin" class="nav-link nav-pill">Alert editor</a>
        <a href="http://131.163.89.66:3000/d/gr255ps/mdr-compass?orgId=1&from=now-6h&to=now&timezone=browser" target="_blank" rel="noopener noreferrer" class="nav-link nav-pill">Grafana</a>
      {/if}
    {:else}
      <a href="/" class="nav-link">← Back to home</a>
      {#if isAdmin}
        <a href="/admin" class="nav-link nav-pill">Alert editor</a>
        <a href="http://131.163.89.66:3000/d/gr255ps/mdr-compass?orgId=1&from=now-6h&to=now&timezone=browser" target="_blank" rel="noopener noreferrer" class="nav-link nav-pill">Grafana</a>
      {/if}
    {/if}
    <button class="nav-logout" onclick={onLogout}>Log out</button>
  </div>
</header>

<style>
  .topnav {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 48px;
    padding: 0 16px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
  }
  .left {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    text-decoration: none;
  }
  .logo {
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    background: rgba(74, 158, 255, 0.15);
    font-size: 14px;
    color: var(--ring);
  }
  .app-name {
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
  }
  .page-label {
    margin-left: 8px;
    padding: 2px 8px;
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--text-muted);
    background: var(--bg-elevated);
    border-radius: 4px;
  }
  .right {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .nav-link {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 13px;
  }
  .nav-link:hover {
    color: var(--text-primary);
  }
  .nav-pill {
    font-size: 12px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .nav-pill:hover {
    border-color: var(--ring);
    color: var(--ring);
  }
  .nav-logout {
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-secondary);
    font-size: 12px;
    padding: 4px 10px;
    cursor: pointer;
    font-family: inherit;
  }
  .nav-logout:hover {
    border-color: var(--kc-exfil);
    color: var(--kc-exfil);
  }
  @media (max-width: 768px) {
    .page-label {
      display: none;
    }
    .app-name {
      font-size: 13px;
    }
  }
</style>