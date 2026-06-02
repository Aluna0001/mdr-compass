<script lang="ts">
  import type { Alert } from '$lib/types'
  import KillChainBadge from './KillChainBadge.svelte'

  let { alerts, onEdit, onDelete }: {
    alerts: Alert[]
    onEdit: (alert: Alert) => void
    onDelete: (id: number) => void
  } = $props()
</script>

<div class="table-wrapper">
  <table>
    <thead>
      <tr>
        <th class="col-name">Name</th>
        <th class="col-kc">Kill Chain</th>
        <th class="col-mitre">MITRE</th>
        <th class="col-actions">Actions</th>
      </tr>
    </thead>
    <tbody>
      {#each alerts as alert}
        <tr>
          <td>
            <span class="alert-name">{alert.name}</span>
            <span class="alert-desc">{alert.description.slice(0, 80)}...</span>
          </td>
          <td>
            <KillChainBadge phase={alert.killChain} />
          </td>
          <td>
            <span class="mitre-id">{alert.mitreId}</span>
          </td>
          <td class="actions">
            <button class="btn-edit" onclick={() => onEdit(alert)}>Edit</button>
            <button class="btn-delete" onclick={() => onDelete(alert.id)}>Delete</button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .table-wrapper {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  thead {
    background: var(--bg-elevated);
  }
  th {
    padding: 10px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
  }
  tbody tr {
    border-top: 1px solid var(--border);
    background: var(--bg-card);
  }
  tbody tr:hover {
    background: var(--bg-elevated);
  }
  td {
    padding: 12px 14px;
    vertical-align: middle;
  }
  .alert-name {
    display: block;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
  }
  .alert-desc {
    display: block;
    margin-top: 2px;
    font-size: 12px;
    color: var(--text-muted);
  }
  .mitre-id {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-secondary);
  }
  .actions {
    display: flex;
    gap: 8px;
  }
  .btn-edit, .btn-delete {
    padding: 4px 12px;
    font-size: 12px;
    border-radius: 4px;
    cursor: pointer;
    border: 1px solid var(--border);
    background: var(--bg-elevated);
    color: var(--text-secondary);
  }
  .btn-edit:hover {
    color: var(--text-primary);
    border-color: var(--ring);
  }
  .btn-delete:hover {
    color: var(--kc-exfil);
    border-color: var(--kc-exfil);
  }
</style>