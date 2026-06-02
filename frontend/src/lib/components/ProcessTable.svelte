<script lang="ts">
  import type { RelatedProcess } from '$lib/types'

  let { processes }: { processes: RelatedProcess[] } = $props()
</script>

<section class="processes">
  <h2 class="section-title">Related processes</h2>
  {#if processes.length === 0}
    <p class="empty">No process atlas entries for this alert.</p>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Process</th>
            <th>Legitimate path</th>
            <th>Suspicious path</th>
          </tr>
        </thead>
        <tbody>
          {#each processes as process}
            <tr>
              <td class="process-name">{process.name}</td>
              <td class="path">{process.legitimatePath}</td>
              <td class="path suspicious">{process.suspiciousPath}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .processes {
    margin-bottom: 32px;
  }
  .section-title {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-primary);
    margin-bottom: 12px;
  }
  .table-wrapper {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  thead {
    background: var(--bg-elevated);
  }
  th {
    padding: 8px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
  }
  tbody {
    background: var(--bg-card);
  }
  td {
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    vertical-align: top;
  }
  .process-name {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 500;
    color: var(--text-primary);
  }
  .path {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-secondary);
  }
  .suspicious {
    color: var(--kc-c2);
  }
  .empty {
    padding: 24px 14px;
    font-size: 13px;
    color: var(--text-muted);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg-card);
  }
</style>