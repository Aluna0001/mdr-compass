<script lang="ts">
  import { windowsProcesses, type ProcessInfo } from '$lib/data/processes'

  let selectedCategory = $state<string | null>(null)
  let searchQuery = $state('')
  let selectedProcess = $state<ProcessInfo | null>(null)

  const categories: Record<string, string> = {
    'system': 'System Processes',
    'security': 'Security Services',
    'lolbin': 'LOLBins',
    'sysinternals': 'Sysinternals',
    'admin': 'Admin Tools',
    'remote': 'Remote Access',
    'network': 'Network Tools',
    'recon': 'Reconnaissance',
    'office': 'Office Applications',
    'scripting': 'Scripting Engines',
    'browsers': 'Web Browsers',
    'dll': 'DLLs',
    'database': 'Database Services'
  }

  let categoryCounts = $derived(() => {
    const counts: Record<string, number> = {}
    for (const p of windowsProcesses) {
      counts[p.category] = (counts[p.category] || 0) + 1
    }
    return counts
  })

  let filteredProcesses = $derived(
    windowsProcesses.filter(p => {
      const matchesCategory = !selectedCategory || p.category === selectedCategory
      const matchesSearch = !searchQuery ||
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.description.toLowerCase().includes(searchQuery.toLowerCase())
      return matchesCategory && matchesSearch
    })
  )

  function selectCategory(cat: string | null) {
    selectedCategory = cat === selectedCategory ? null : cat
    selectedProcess = null
  }

  function selectProcess(p: ProcessInfo) {
    selectedProcess = p
  }

  if (windowsProcesses.length > 0) {
    selectedProcess = windowsProcesses[0]
  }
</script>

<div class="layout">
  <aside class="categories">
    <button
      class="cat-item"
      class:active={selectedCategory === null}
      onclick={() => selectCategory(null)}
    >
      <span>All Processes</span>
      <span class="count">{windowsProcesses.length}</span>
    </button>
    {#each Object.entries(categories) as [key, label]}
      {@const count = categoryCounts()[key] || 0}
      {#if count > 0}
        <button
          class="cat-item"
          class:active={selectedCategory === key}
          onclick={() => selectCategory(key)}
        >
          <span>{label}</span>
          <span class="count">{count}</span>
        </button>
      {/if}
    {/each}
  </aside>

  <div class="process-list">
    <div class="search-box">
      <input
        type="text"
        placeholder="Search processes..."
        bind:value={searchQuery}
      />
      <span class="result-count">{filteredProcesses.length} of {windowsProcesses.length} processes</span>
    </div>
    <ul class="list">
      {#each filteredProcesses as process}
        <li>
          <button
            class="process-item"
            class:active={selectedProcess?.name === process.name}
            onclick={() => selectProcess(process)}
          >
            <span class="process-name">{process.name}</span>
            <span class="process-desc">{process.description}</span>
          </button>
        </li>
      {/each}
    </ul>
  </div>

  <div class="detail-panel">
    {#if selectedProcess}
      <div class="detail-header">
        <h1>{selectedProcess.name}</h1>
        <p class="detail-desc">{selectedProcess.description}</p>
      </div>

      <section class="detail-section">
        <h2 class="section-title legit-title">Legitimate paths ({selectedProcess.legitimatePaths.length})</h2>
        <div class="path-list legit">
          {#each selectedProcess.legitimatePaths as path}
            <div class="path-item">{path}</div>
          {/each}
        </div>
      </section>

      {#if selectedProcess.commonMalwarePaths && selectedProcess.commonMalwarePaths.length > 0}
        <section class="detail-section">
          <h2 class="section-title suspicious-title">Suspicious paths ({selectedProcess.commonMalwarePaths.length})</h2>
          <div class="path-list suspicious">
            {#each selectedProcess.commonMalwarePaths as path}
              <div class="path-item">{path}</div>
            {/each}
          </div>
        </section>
      {/if}

      {#if selectedProcess.commandLinePatterns}
        <section class="detail-section">
          <h2 class="section-title cmd-title">Command line patterns</h2>
          <div class="cmd-grid">
            <div>
              <h3 class="cmd-subtitle legit-title">Legitimate</h3>
              {#each selectedProcess.commandLinePatterns.legitimate as pattern}
                <div class="cmd-item cmd-legit">{pattern}</div>
              {/each}
            </div>
            <div>
              <h3 class="cmd-subtitle suspicious-title">Suspicious</h3>
              {#each selectedProcess.commandLinePatterns.suspicious as pattern}
                <div class="cmd-item cmd-suspicious">{pattern}</div>
              {/each}
            </div>
          </div>
        </section>
      {/if}

      {#if selectedProcess.parentProcesses}
        <section class="detail-section">
          <h2 class="section-title cmd-title">Parent processes</h2>
          <div class="cmd-grid">
            <div>
              <h3 class="cmd-subtitle legit-title">Legitimate</h3>
              {#each selectedProcess.parentProcesses.legitimate as parent}
                <div class="cmd-item cmd-legit">{parent}</div>
              {/each}
            </div>
            <div>
              <h3 class="cmd-subtitle suspicious-title">Suspicious</h3>
              {#each selectedProcess.parentProcesses.suspicious as parent}
                <div class="cmd-item cmd-suspicious">{parent}</div>
              {/each}
            </div>
          </div>
        </section>
      {/if}

      {#if selectedProcess.childProcesses}
        <section class="detail-section">
          <h2 class="section-title cmd-title">Child processes</h2>
          <div class="cmd-grid">
            <div>
              <h3 class="cmd-subtitle legit-title">Common</h3>
              {#each selectedProcess.childProcesses.common as child}
                <div class="cmd-item cmd-legit">{child}</div>
              {/each}
            </div>
            <div>
              <h3 class="cmd-subtitle suspicious-title">Suspicious</h3>
              {#each selectedProcess.childProcesses.suspicious as child}
                <div class="cmd-item cmd-suspicious">{child}</div>
              {/each}
            </div>
          </div>
        </section>
      {/if}

      {#if selectedProcess.networkInfo}
        <section class="detail-section">
          <h2 class="section-title cmd-title">Network info</h2>
          <div class="network-grid">
            <div class="network-item">
              <span class="network-label">Ports</span>
              <span class="network-value">{selectedProcess.networkInfo.ports.join(', ')}</span>
            </div>
            <div class="network-item">
              <span class="network-label">Protocols</span>
              <span class="network-value">{selectedProcess.networkInfo.protocols.join(', ')}</span>
            </div>
            <div class="network-item">
              <span class="network-label">Connections</span>
              <span class="network-value">{selectedProcess.networkInfo.connections.join(', ')}</span>
            </div>
          </div>
        </section>
      {/if}

      <section class="detail-section">
        <h2 class="section-title notes-title">Analysis notes</h2>
        <div class="notes-box">
          {selectedProcess.notes}
        </div>
      </section>
    {:else}
      <p class="empty">Select a process to view details</p>
    {/if}
  </div>
</div>

<style>
  .layout {
    display: flex;
    height: calc(100vh - 48px);
  }
  .categories {
    width: 200px;
    background: var(--bg-surface);
    border-right: 1px solid var(--border);
    padding: 8px 0;
    overflow-y: auto;
    flex-shrink: 0;
  }
  .cat-item {
    width: 100%;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 14px;
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    text-align: left;
    font-family: inherit;
  }
  .cat-item:hover {
    background: rgba(255,255,255,0.03);
  }
  .cat-item.active {
    color: var(--teal);
    background: rgba(93,202,165,0.08);
  }
  .count {
    font-size: 12px;
    color: var(--text-muted);
  }
  .cat-item.active .count {
    color: var(--teal);
  }
  .process-list {
    width: 340px;
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }
  .search-box {
    padding: 12px;
    border-bottom: 1px solid var(--border);
  }
  .search-box input {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text-primary);
    font-size: 14px;
    outline: none;
  }
  .search-box input::placeholder {
    color: var(--text-muted);
  }
  .search-box input:focus {
    border-color: var(--ring);
  }
  .result-count {
    display: block;
    margin-top: 6px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .list {
    list-style: none;
    overflow-y: auto;
    flex: 1;
  }
  .process-item {
    width: 100%;
    padding: 12px 14px;
    background: none;
    border: none;
    border-bottom: 1px solid var(--border);
    color: var(--text-primary);
    text-align: left;
    cursor: pointer;
    font-family: inherit;
  }
  .process-item:hover {
    background: rgba(255,255,255,0.03);
  }
  .process-item.active {
    background: rgba(93,202,165,0.08);
    border-left: 2px solid var(--teal);
  }
  .process-name {
    display: block;
    font-family: var(--font-mono);
    font-size: 13px;
    font-weight: 500;
  }
  .process-desc {
    display: block;
    margin-top: 4px;
    font-size: 12px;
    color: var(--text-muted);
  }
  .detail-panel {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }
  .detail-header {
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .detail-header h1 {
    font-family: var(--font-mono);
    font-size: 22px;
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 6px;
  }
  .detail-desc {
    font-size: 14px;
    color: var(--text-secondary);
  }
  .detail-section {
    margin-bottom: 20px;
  }
  .section-title {
    font-size: 12px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
  }
  .legit-title { color: #1D9E75; }
  .suspicious-title { color: #E24B4A; }
  .cmd-title { color: var(--ring); }
  .notes-title { color: #BA7517; }
  .path-list {
    border-radius: var(--radius);
    overflow: hidden;
  }
  .path-item {
    padding: 8px 12px;
    font-family: var(--font-mono);
    font-size: 12px;
    border-bottom: 1px solid var(--border);
  }
  .path-item:last-child {
    border-bottom: none;
  }
  .path-list.legit {
    background: rgba(29,158,117,0.08);
    border: 1px solid rgba(29,158,117,0.2);
  }
  .path-list.legit .path-item {
    color: #1D9E75;
    border-color: rgba(29,158,117,0.15);
  }
  .path-list.suspicious {
    background: rgba(226,75,74,0.08);
    border: 1px solid rgba(226,75,74,0.2);
  }
  .path-list.suspicious .path-item {
    color: #E24B4A;
    border-color: rgba(226,75,74,0.15);
  }
  .cmd-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  .cmd-subtitle {
    font-size: 11px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 6px;
  }
  .cmd-item {
    padding: 6px 10px;
    font-family: var(--font-mono);
    font-size: 11px;
    border-radius: 4px;
    margin-bottom: 4px;
  }
  .cmd-legit {
    background: rgba(29,158,117,0.08);
    color: #1D9E75;
  }
  .cmd-suspicious {
    background: rgba(226,75,74,0.08);
    color: #E24B4A;
  }
  .network-grid {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .network-item {
    display: flex;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  .network-item:last-child {
    border-bottom: none;
  }
  .network-label {
    width: 100px;
    color: var(--text-muted);
    font-size: 12px;
    flex-shrink: 0;
  }
  .network-value {
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .notes-box {
    background: rgba(186,117,23,0.08);
    border: 1px solid rgba(186,117,23,0.2);
    border-radius: var(--radius);
    padding: 12px;
    font-size: 13px;
    line-height: 1.5;
    color: var(--text-primary);
  }
  .empty {
    color: var(--text-muted);
    font-size: 16px;
    margin-top: 40px;
  }
</style>