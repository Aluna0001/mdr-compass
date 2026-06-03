<script lang="ts">
  import type { Alert } from '$lib/types'
  import KillChainBadge from './KillChainBadge.svelte'
  import MitreTag from './MitreTag.svelte'

  let { alerts, selectedId, onSelect }: {
    alerts: Alert[]
    selectedId: number | null
    onSelect: (alert: Alert) => void
  } = $props()

  let searchQuery = $state('')

  let filteredAlerts = $derived(
    alerts.filter(a =>
      a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.mitreId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.killChain.toLowerCase().includes(searchQuery.toLowerCase())
    )
  )
</script>

<aside class="sidebar">
  <div class="search-box">
    <input
      type="text"
      placeholder="Search alerts..."
      bind:value={searchQuery}
    />
    <span class="alert-count">{filteredAlerts.length} alerts</span>
  </div>
  <ul class="alert-list">
    {#each filteredAlerts as alert}
      <li>
        <button
          class="alert-item"
          class:active={alert.id === selectedId}
          onclick={() => onSelect(alert)}
        >
          <div class="alert-header">
            <span class="alert-name">{alert.name}</span>
            <span class="mitre-id">{alert.mitreId}</span>
          </div>
          <div class="alert-badges">
            <KillChainBadge phase={alert.killChain} />
          </div>
        </button>
      </li>
    {/each}
    {#if filteredAlerts.length === 0}
      <li class="no-results">No matching alerts.</li>
    {/if}
  </ul>
</aside>

<style>
  .sidebar {
    width: 300px;
    height: 100%;
    background: var(--bg-surface);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }
  .search-box {
    padding: 12px;
    border-bottom: 1px solid var(--border);
  }
  .search-box input {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text-primary);
    font-size: 14px;
    outline: none;
  }
  .search-box input::placeholder {
    color: var(--text-muted);
  }
  .search-box input:focus {
    border-color: var(--ring);
  }
  .alert-count {
    display: block;
    margin-top: 8px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
  }
  .alert-list {
    list-style: none;
    overflow-y: auto;
    flex: 1;
  }
  .alert-item {
    width: 100%;
    padding: 10px 12px;
    background: none;
    border: none;
    border-left: 2px solid transparent;
    color: var(--text-primary);
    text-align: left;
    cursor: pointer;
    font-family: inherit;
  }
  .alert-item:hover {
    background: rgba(255, 255, 255, 0.03);
  }
  .alert-item.active {
    border-left-color: var(--ring);
    background: rgba(74, 158, 255, 0.08);
  }
  .alert-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .alert-name {
    font-size: 14px;
    font-weight: 500;
  }
  .mitre-id {
    font-size: 10px;
    font-family: var(--font-mono);
    color: var(--text-muted);
  }
  .alert-badges {
    margin-top: 6px;
  }
  .no-results {
    padding: 32px 16px;
    text-align: center;
    color: var(--text-muted);
    font-size: 14px;
  }
  @media (max-width: 768px) {
    .sidebar {
      width: 100%;
      height: calc(100vh - 48px);
    }
  }
</style>