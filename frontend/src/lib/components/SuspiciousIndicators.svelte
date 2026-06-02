<script lang="ts">
  let { indicators }: { indicators: string[] } = $props()
</script>

<section class="indicators">
  <h2 class="section-title">Suspicious indicators</h2>
  <ul class="indicator-list">
    {#each indicators as indicator}
      <li class="indicator-item">
        <span class="dot"></span>
        <span>{indicator}</span>
      </li>
    {/each}
  </ul>
</section>

<style>
  .indicators {
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
  .indicator-list {
    list-style: none;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    background: var(--bg-card);
  }
  .indicator-item {
    display: flex;
    gap: 12px;
    padding: 10px 14px;
    font-size: 13px;
    line-height: 1.5;
    color: var(--text-primary);
    border-bottom: 1px solid var(--border);
  }
  .indicator-item:last-child {
    border-bottom: none;
  }
  .dot {
    margin-top: 7px;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--teal);
    flex-shrink: 0;
  }
</style>