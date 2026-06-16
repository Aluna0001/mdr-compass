<script lang="ts">
  const tools = [
    { href: '/console', title: 'Analyst Console', description: 'Look up alert types with investigation guidance and related processes.' },
    { href: '/processes', title: 'Process Atlas', description: 'Browse Windows processes with legitimate and suspicious paths.' },
    { href: '/news', title: 'Security News', description: 'Latest headlines from The Hacker News.' }
  ]
</script>

<div class="home-bg">
  <div class="home">
    <header class="home-header">
      <h1>MDR Compass</h1>
      <p class="subtitle">Choose a tool to get started.</p>
    </header>

    <div class="card-grid">
      {#each tools as tool}
        <a class="card" href={tool.href}>
          <h2>{tool.title}</h2>
          <p>{tool.description}</p>
        </a>
      {/each}
    </div>
  </div>
</div>

<style>
  .home-bg {
    min-height: calc(100vh - 48px);
    background-image: linear-gradient(rgba(13, 17, 23, 0.88), rgba(13, 17, 23, 0.92)), url('/cyber.jpg');
    background-size: cover;
    background-position: center;
  }
  .home {
    max-width: 900px;
    margin: 0 auto;
    padding: 48px 32px;
  }
  .home-header {
    margin-bottom: 32px;
  }
  h1 {
    font-size: 28px;
    font-weight: 600;
    color: var(--text-primary);
  }
  .subtitle {
    margin-top: 6px;
    font-size: 15px;
    color: var(--text-secondary);
  }
  .card-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
  }
  .card {
    display: block;
    padding: 24px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    text-decoration: none;
  }
  .card:hover {
    border-color: var(--ring);
  }
  .card h2 {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 8px;
  }
  .card p {
    font-size: 13px;
    line-height: 1.5;
    color: var(--text-secondary);
  }
  @media (max-width: 768px) {
    .home {
      padding: 24px 16px;
    }
    .card-grid {
      grid-template-columns: 1fr;
    }
  }
</style>