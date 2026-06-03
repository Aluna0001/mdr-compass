<script lang="ts">
  import type { WhatToLookFor } from '$lib/types'

  let { hints }: { hints: WhatToLookFor[] } = $props()
</script>

<section class="hints">
  <h2 class="section-title">What to look for</h2>
  <div class="grid">
    {#each hints as hint}
      <div class="hint-card">
        <span class="label">{hint.label}</span>
        <p class="question">{hint.question}</p>
      </div>
    {/each}
  </div>
</section>

<style>
  .hints {
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
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1px;
    background: var(--border);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .hint-card {
    padding: 14px;
    background: var(--bg-card);
  }
  .label {
    display: block;
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--ring);
    margin-bottom: 4px;
  }
  .question {
    font-size: 13px;
    line-height: 1.5;
    color: var(--text-primary);
  }
  @media (max-width: 768px) {
    .grid {
      grid-template-columns: 1fr;
    }
  }
</style>