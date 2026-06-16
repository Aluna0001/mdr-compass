<script lang="ts">
  let { id }: { id: string } = $props()

  let mitreUrl = $derived(
    'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/'
  )
</script>

<a class="tag" href={mitreUrl} target="_blank" rel="noopener noreferrer">MITRE {id}</a>

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
    text-decoration: none;
  }
  .tag:hover {
    background: rgba(93, 202, 165, 0.2);
    border-color: var(--teal);
  }
</style>