<script lang="ts">
  import type { NewsItem } from '$lib/types'
  import { getNews } from '$lib/api'

  let news = $state<NewsItem[]>([])
  let loading = $state(true)

  async function loadNews() {
    news = await getNews()
    loading = false
  }

  loadNews()
</script>

<div class="news">
  <header class="news-header">
    <h1>Security News</h1>
    <p class="subtitle">Latest headlines from The Hacker News.</p>
  </header>

  {#if loading}
    <p class="status">Loading news...</p>
  {:else if news.length === 0}
    <p class="status">No news available right now.</p>
  {:else}
    <ul class="news-list">
      {#each news as item}
        <li class="news-item">
          <a href={item.link} target="_blank" rel="noopener noreferrer">
            <span class="news-title">{item.title}</span>
            <span class="news-date">{item.pubDate}</span>
          </a>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .news {
    max-width: 800px;
    margin: 0 auto;
    padding: 32px;
  }
  .news-header {
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  h1 {
    font-size: 24px;
    font-weight: 600;
    color: var(--text-primary);
  }
  .subtitle {
    margin-top: 4px;
    font-size: 14px;
    color: var(--text-secondary);
  }
  .status {
    color: var(--text-muted);
    font-size: 14px;
    padding: 24px 0;
  }
  .news-list {
    list-style: none;
  }
  .news-item {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg-card);
    margin-bottom: 8px;
  }
  .news-item a {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 14px 16px;
    text-decoration: none;
  }
  .news-item:hover {
    border-color: var(--ring);
  }
  .news-title {
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
  }
  .news-date {
    font-size: 12px;
    color: var(--text-muted);
  }
  @media (max-width: 768px) {
    .news {
      padding: 16px;
    }
  }
</style>