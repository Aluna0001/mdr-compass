<script lang="ts">
  import '../app.css'
  import TopNav from '$lib/components/TopNav.svelte'
  import LoginPage from '$lib/components/LoginPage.svelte'
  import { checkAuth } from '$lib/api'
  import { page } from '$app/state'

  let { children } = $props()

  let authenticated = $state(false)
  let checking = $state(true)

  let currentPage = $derived(
    page.url.pathname.startsWith('/admin') ? 'admin' :
    page.url.pathname.startsWith('/processes') ? 'processes' :
    'console'
  )

  async function verifyAuth() {
    authenticated = await checkAuth()
    checking = false
  }

  function handleLogin() {
    authenticated = true
  }

  verifyAuth()
</script>

{#if checking}
  <div class="loading"></div>
{:else if !authenticated}
  <LoginPage onLogin={handleLogin} />
{:else}
  <TopNav {currentPage} />
  {@render children()}
{/if}

<style>
  .loading {
    height: 100vh;
    background: var(--bg-primary);
  }
</style>