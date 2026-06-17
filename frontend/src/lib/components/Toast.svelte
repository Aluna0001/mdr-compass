<script lang="ts">
  let { message = '', visible = false }: { message?: string; visible?: boolean } = $props()
</script>

{#if visible}
  <div class="toast">
    <span class="toast-icon">🛡️</span>
    <span class="toast-message">{message}</span>
    <div class="toast-progress"></div>
  </div>
{/if}

<style>
  .toast {
    position: fixed;
    top: 64px;
    right: 24px;
    min-width: 300px;
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 24px 26px;
    background: var(--bg-elevated);
    border: 1px solid var(--ring);
    border-radius: var(--radius);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 16px;
    font-weight: 500;
    letter-spacing: 0.3px;
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.4);
    z-index: 1000;
    overflow: hidden;
    animation: slide-in 0.2s ease-out;
  }
  .toast-icon {
    font-size: 22px;
    line-height: 1;
  }
  .toast-message {
    display: block;
  }
  .toast-progress {
    position: absolute;
    bottom: 0;
    left: 0;
    height: 4px;
    width: 100%;
    background: var(--ring);
    transform-origin: left;
    animation: shrink 2s linear forwards;
  }
  @keyframes slide-in {
    from {
      opacity: 0;
      transform: translateY(-10px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }
  @keyframes shrink {
    from {
      transform: scaleX(1);
    }
    to {
      transform: scaleX(0);
    }
  }
</style>