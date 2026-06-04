<script lang="ts">
  import { login } from '$lib/api'

  let { onLogin }: { onLogin: () => void } = $props()

  let username = $state('')
  let password = $state('')
  let error = $state('')
  let loading = $state(false)

  async function handleLogin() {
    error = ''
    loading = true
    const success = await login(username, password)
    loading = false

    if (success) {
      onLogin()
    } else {
      error = 'Invalid username or password'
    }
  }
</script>

<div class="login-container">
  <div class="login-card">
    <div class="login-header">
      <div class="logo">◊</div>
      <h1>MDR Compass</h1>
      <p>Sign in to access the analyst console</p>
    </div>

    <div class="login-form">
      <div class="field">
        <label for="username">Username</label>
        <input
          id="username"
          type="text"
          bind:value={username}
          onkeydown={(e) => e.key === 'Enter' && handleLogin()}
          placeholder="Enter username"
        />
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          onkeydown={(e) => e.key === 'Enter' && handleLogin()}
          placeholder="Enter password"
        />
      </div>

      {#if error}
        <p class="error">{error}</p>
      {/if}

      <button class="login-btn" onclick={handleLogin} disabled={loading}>
        {loading ? 'Signing in...' : 'Sign in'}
      </button>
    </div>
  </div>
</div>

<style>
  .login-container {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    background: var(--bg-primary);
  }
  .login-card {
    width: 100%;
    max-width: 380px;
    padding: 40px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 12px;
  }
  .login-header {
    text-align: center;
    margin-bottom: 32px;
  }
  .logo {
    width: 48px;
    height: 48px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 12px;
    background: rgba(74, 158, 255, 0.15);
    font-size: 24px;
    color: var(--ring);
    margin-bottom: 16px;
  }
  h1 {
    font-size: 22px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 4px;
  }
  .login-header p {
    font-size: 14px;
    color: var(--text-muted);
  }
  .field {
    margin-bottom: 16px;
  }
  label {
    display: block;
    margin-bottom: 6px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
  }
  input {
    width: 100%;
    padding: 10px 12px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text-primary);
    font-size: 14px;
    outline: none;
    font-family: inherit;
  }
  input:focus {
    border-color: var(--ring);
  }
  input::placeholder {
    color: var(--text-muted);
  }
  .error {
    color: var(--kc-exfil);
    font-size: 13px;
    margin-bottom: 12px;
  }
  .login-btn {
    width: 100%;
    padding: 10px;
    background: var(--ring);
    border: none;
    border-radius: var(--radius);
    color: #fff;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    font-family: inherit;
  }
  .login-btn:hover {
    opacity: 0.9;
  }
  .login-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  @media (max-width: 768px) {
    .login-card {
      margin: 16px;
      padding: 24px;
    }
  }
</style>