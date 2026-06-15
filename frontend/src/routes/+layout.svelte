<script lang="ts">
  import '../app.css'
  import TopNav from '$lib/components/TopNav.svelte'
  import LoginPage from '$lib/components/LoginPage.svelte'
  import { checkAuth } from '$lib/api'
  import { page } from '$app/state'

  let { children } = $props()
  let authenticated = $state(false)
  let role = $state('')
  let checking = $state(true)

  let isAdmin = $derived(role === 'ROLE_ADMIN')

  let currentPage = $derived(
    page.url.pathname.startsWith('/admin') ? 'admin' :
    page.url.pathname.startsWith('/processes') ? 'processes' :
    'console'
  )

  async function verifyAuth() {
    const result = await checkAuth()
    authenticated = result.authenticated
    role = result.role
    checking = false
  }

  function handleLogin() {
    verifyAuth()
  }

  verifyAuth()
</script>

{#if checking}
  <div class="loading"></div>
{:else if !authenticated}
  <LoginPage onLogin={handleLogin} />
{:else if currentPage === 'admin' && !isAdmin}
  <TopNav {currentPage} {isAdmin} />
  <div class="no-access">
    <h1>Access denied</h1>
    <p>You do not have permission to view this page.</p>
    <a href="/">← Back to analyst console</a>
  </div>
{:else}
  <TopNav {currentPage} {isAdmin} />
  {@render children()}
{/if}

<style>
  .loading {
    height: 100vh;
    background: var(--bg-primary);
  }
  .no-access {
    max-width: 600px;
    margin: 80px auto;
    text-align: center;
    color: var(--text-primary);
  }
  .no-access h1 {
    font-size: 24px;
    font-weight: 600;
    margin-bottom: 12px;
  }
  .no-access p {
    color: var(--text-secondary);
    margin-bottom: 20px;
  }
  .no-access a {
    color: var(--ring);
    text-decoration: none;
  }
</style>