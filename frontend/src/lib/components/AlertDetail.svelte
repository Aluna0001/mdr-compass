<script lang="ts">
  import type { Alert } from '$lib/types'
  import KillChainBadge from './KillChainBadge.svelte'
  import MitreTag from './MitreTag.svelte'
  import InvestigationHints from './InvestigationHints.svelte'
  import SuspiciousIndicators from './SuspiciousIndicators.svelte'
  import ProcessTable from './ProcessTable.svelte'

  let { alert }: { alert: Alert } = $props()
</script>

<div class="detail">
  <header class="detail-header">
    <div class="badges">
      <KillChainBadge phase={alert.killChain} />
      <MitreTag id={alert.mitreId} />
    </div>
    <h1>{alert.name}</h1>
    <p class="description">{alert.description}</p>
  </header>

  <InvestigationHints hints={alert.whatToLookFor} />
  <SuspiciousIndicators indicators={alert.suspiciousIndicators} />
  <ProcessTable processes={alert.relatedProcesses} />
</div>

<style>
  .detail {
    max-width: 900px;
    margin: 0 auto;
    padding: 32px;
  }
  .detail-header {
    margin-bottom: 32px;
    padding-bottom: 24px;
    border-bottom: 1px solid var(--border);
  }
  .badges {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
  }
  h1 {
    font-size: 28px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 12px;
  }
  .description {
    font-size: 14px;
    line-height: 1.6;
    color: var(--text-secondary);
    max-width: 700px;
  }
</style>