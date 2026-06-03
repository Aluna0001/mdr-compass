<script lang="ts">
  import type { Alert } from '$lib/types'
  import { getAlerts } from '$lib/api'
  import AlertSidebar from '$lib/components/AlertSidebar.svelte'
  import AlertDetail from '$lib/components/AlertDetail.svelte'

  let alerts = $state<Alert[]>([])
  let selectedAlert = $state<Alert | null>(null)
  let showDetail = $state(false)

  async function loadAlerts() {
    alerts = await getAlerts()
    if (alerts.length > 0 && !selectedAlert) {
      selectedAlert = alerts[0]
    }
  }

  function handleSelect(alert: Alert) {
    selectedAlert = alert
    showDetail = true
  }

  function handleBack() {
    showDetail = false
  }

  loadAlerts()
</script>

<div class="layout" class:show-detail={showDetail}>
  <div class="sidebar-container">
    <AlertSidebar
      {alerts}
      selectedId={selectedAlert?.id ?? null}
      onSelect={handleSelect}
    />
  </div>
  <main class="content">
    {#if selectedAlert}
      <button class="back-btn" onclick={handleBack}>← Back to alerts</button>
      <AlertDetail alert={selectedAlert} />
    {:else}
      <p class="empty">Select an alert from the sidebar</p>
    {/if}
  </main>
</div>

<style>
  .layout {
    display: flex;
    height: calc(100vh - 48px);
  }
  .sidebar-container {
    flex-shrink: 0;
  }
  .content {
    flex: 1;
    overflow-y: auto;
  }
  .empty {
    color: var(--text-muted);
    font-size: 16px;
    padding: 40px 32px;
  }
  .back-btn {
    display: none;
    padding: 10px 16px;
    background: var(--bg-surface);
    border: none;
    border-bottom: 1px solid var(--border);
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    width: 100%;
    text-align: left;
    font-family: inherit;
  }
  .back-btn:hover {
    color: var(--text-primary);
  }

  @media (max-width: 768px) {
    .layout {
      flex-direction: column;
    }
    .sidebar-container {
      display: block;
      width: 100%;
    }
    .content {
      display: none;
    }
    .layout.show-detail .sidebar-container {
      display: none;
    }
    .layout.show-detail .content {
      display: block;
    }
    .back-btn {
      display: block;
    }
  }
</style>