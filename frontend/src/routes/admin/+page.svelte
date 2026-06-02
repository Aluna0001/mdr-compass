<script lang="ts">
  import type { Alert } from '$lib/types'
  import { getAlerts, deleteAlert } from '$lib/api'
  import AlertList from '$lib/components/AlertList.svelte'
  import AlertForm from '$lib/components/AlertForm.svelte'

  let alerts = $state<Alert[]>([])
  let editingAlert = $state<Alert | null>(null)
  let showForm = $state(false)

  async function loadAlerts() {
    alerts = await getAlerts()
  }

  function handleNew() {
    editingAlert = null
    showForm = true
  }

  function handleEdit(alert: Alert) {
    editingAlert = alert
    showForm = true
  }

  async function handleDelete(id: number) {
    await deleteAlert(id)
    await loadAlerts()
  }

  function handleSaved() {
    showForm = false
    editingAlert = null
    loadAlerts()
  }

  function handleCancel() {
    showForm = false
    editingAlert = null
  }

  loadAlerts()
</script>

<div class="admin">
  {#if showForm}
    <AlertForm
      alert={editingAlert}
      onSaved={handleSaved}
      onCancel={handleCancel}
    />
  {:else}
    <div class="admin-header">
      <div>
        <h1>Alert administration</h1>
        <p class="subtitle">Manage detection playbooks shown to analysts.</p>
      </div>
      <button class="btn-new" onclick={handleNew}>+ New alert</button>
    </div>
    <AlertList
      {alerts}
      onEdit={handleEdit}
      onDelete={handleDelete}
    />
  {/if}
</div>

<style>
  .admin {
    max-width: 1000px;
    margin: 0 auto;
    padding: 32px;
  }
  .admin-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 24px;
  }
  h1 {
    font-size: 24px;
    font-weight: 600;
    color: var(--text-primary);
  }
  .subtitle {
    margin-top: 4px;
    font-size: 14px;
    color: var(--text-secondary);
  }
  .btn-new {
    padding: 8px 16px;
    background: var(--ring);
    color: #fff;
    border: none;
    border-radius: var(--radius);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
  }
  .btn-new:hover {
    opacity: 0.9;
  }
</style>