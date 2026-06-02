<script lang="ts">
  let { phase }: { phase: string } = $props()

  const colors: Record<string, string> = {
    'Reconnaissance': 'var(--kc-recon)',
    'Initial Access': 'var(--kc-access)',
    'Lateral Movement': 'var(--kc-lateral)',
    'Command and Control': 'var(--kc-c2)',
    'Exfiltration': 'var(--kc-exfil)'
  }

  let color = $derived(colors[phase] || 'var(--text-muted)')
</script>

<span class="badge" style="--badge-color: {color}">
  <span class="dot"></span>
  {phase}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 500;
    border-radius: 4px;
    background: color-mix(in srgb, var(--badge-color) 15%, transparent);
    color: var(--badge-color);
    ring: 1px solid color-mix(in srgb, var(--badge-color) 30%, transparent);
    border: 1px solid color-mix(in srgb, var(--badge-color) 30%, transparent);
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--badge-color);
  }
</style>