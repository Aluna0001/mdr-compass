<script lang="ts">
  import '../app.css'
  import TopNav from '$lib/components/TopNav.svelte'
  import { page } from '$app/state'

  let { children } = $props()

  let currentPage = $derived(
    page.url.pathname.startsWith('/admin') ? 'admin' :
    page.url.pathname.startsWith('/processes') ? 'processes' :
    'console'
  )
</script>

<TopNav {currentPage} />
{@render children()}