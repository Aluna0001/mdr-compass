<script lang="ts">
  import type { Alert } from '$lib/types'
  import { getAlerts, deleteAlert } from '$lib/api'
  import AlertList from '$lib/components/AlertList.svelte'
  import AlertForm from '$lib/components/AlertForm.svelte'
  import Toast from '$lib/components/Toast.svelte'

  let alerts = $state<Alert[]>([])
  let editingAlert = $state<Alert | null>(null)
  let showForm = $state(false)
  let searchQuery = $state('')

  let toastMessage = $state('')
  let toastVisible = $state(false)

  let filteredAlerts = $derived(
    alerts.filter(a =>
      a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.mitreId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.killChain.toLowerCase().includes(searchQuery.toLowerCase())
    )
  )

  function showToast(message: string) {
    toastMessage = message
    toastVisible = true
    setTimeout(() => {
      toastVisible = false
    }, 2000)
  }

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
    showToast('Alert deleted')
  }

  function handleSaved() {
    const wasEditing = editingAlert !== null
    showForm = false
    editingAlert = null
    loadAlerts()
    showToast(wasEditing ? 'Alert updated' : 'Alert created')
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
    <input
      class="search"
      type="text"
      placeholder="Search alerts..."
      bind:value={searchQuery}
    />
    <AlertList
      alerts={filteredAlerts}
      onEdit={handleEdit}
      onDelete={handleDelete}
    />
  {/if}
</div>

<Toast message={toastMessage} visible={toastVisible} />

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
  .search {
    width: 100%;
    padding: 8px 12px;
    margin-bottom: 16px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text-primary);
    font-size: 14px;
    font-family: inherit;
    outline: none;
  }
  .search:focus {
    border-color: var(--ring);
  }
</style>