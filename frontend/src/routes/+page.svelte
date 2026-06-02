<script lang="ts">
  import type { Alert } from '$lib/types'
  import { getAlerts } from '$lib/api'
  import AlertSidebar from '$lib/components/AlertSidebar.svelte'
  import AlertDetail from '$lib/components/AlertDetail.svelte'

  let alerts = $state<Alert[]>([])
  let selectedAlert = $state<Alert | null>(null)

  async function loadAlerts() {
    alerts = await getAlerts()
    if (alerts.length > 0 && !selectedAlert) {
      selectedAlert = alerts[0]
    }
  }

  function handleSelect(alert: Alert) {
    selectedAlert = alert
  }

  loadAlerts()
</script>

<div class="layout">
  <AlertSidebar
    {alerts}
    selectedId={selectedAlert?.id ?? null}
    onSelect={handleSelect}
  />
  <main class="content">
    {#if selectedAlert}
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
  .content {
    flex: 1;
    overflow-y: auto;
  }
  .empty {
    color: var(--text-muted);
    font-size: 16px;
    padding: 40px 32px;
  }
</style>