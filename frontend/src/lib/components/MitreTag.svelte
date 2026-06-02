<script lang="ts">
  let { id }: { id: string } = $props()
</script>

<span class="tag">MITRE {id}</span>

<style>
  .tag {
    display: inline-flex;
    align-items: center;
    padding: 3px 8px;
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 500;
    border-radius: 4px;
    background: rgba(93, 202, 165, 0.1);
    color: var(--teal);
    border: 1px solid rgba(93, 202, 165, 0.3);
  }
</style>