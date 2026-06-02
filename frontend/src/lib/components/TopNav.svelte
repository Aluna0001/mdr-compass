<script lang="ts">
  let { currentPage = 'console' }: { currentPage?: string } = $props()
</script>

<header class="topnav">
  <div class="left">
    <div class="logo">
      <span class="logo-icon">◊</span>
    </div>
    <span class="app-name">MDR Compass</span>
    <span class="page-label">
      {#if currentPage === 'admin'}
        ADMIN
      {:else if currentPage === 'processes'}
        PROCESS ATLAS
      {:else}
        ANALYST CONSOLE
      {/if}
    </span>
  </div>
  <div class="right">
    {#if currentPage === 'admin'}
      <a href="/" class="nav-link">← Back to analyst console</a>
    {:else if currentPage === 'processes'}
      <a href="/" class="nav-link">← Back to analyst console</a>
    {:else}
      <a href="/processes" class="nav-link nav-atlas">Process Atlas</a>
      <a href="/admin" class="nav-link nav-settings">⚙</a>
    {/if}
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
  .nav-atlas {
    font-size: 12px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .nav-atlas:hover {
    border-color: var(--teal);
    color: var(--teal);
  }
</style>