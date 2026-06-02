<script lang="ts">
  import type { Alert, WhatToLookFor, RelatedProcess } from '$lib/types'
  import { createAlert, updateAlert } from '$lib/api'

  let { alert, onSaved, onCancel }: {
    alert: Alert | null
    onSaved: () => void
    onCancel: () => void
  } = $props()

  let name = $state(alert?.name ?? '')
  let description = $state(alert?.description ?? '')
  let killChain = $state(alert?.killChain ?? 'Reconnaissance')
  let mitreId = $state(alert?.mitreId ?? '')
  let hints = $state<WhatToLookFor[]>(alert?.whatToLookFor ?? [
    { label: 'Who', question: '' },
    { label: 'What', question: '' },
    { label: 'When', question: '' },
    { label: 'Where', question: '' },
    { label: 'Why', question: '' },
    { label: 'How', question: '' }
  ])
  let indicators = $state<string[]>(alert?.suspiciousIndicators ?? [''])
  let processes = $state<RelatedProcess[]>(alert?.relatedProcesses ?? [])

  const killChainOptions = [
    'Reconnaissance',
    'Initial Access',
    'Lateral Movement',
    'Command and Control',
    'Exfiltration'
  ]

  function addIndicator() {
    indicators = [...indicators, '']
  }

  function removeIndicator(index: number) {
    indicators = indicators.filter((_, i) => i !== index)
  }

  function addProcess() {
    processes = [...processes, { name: '', legitimatePath: '', suspiciousPath: '' }]
  }

  function removeProcess(index: number) {
    processes = processes.filter((_, i) => i !== index)
  }

  function removeHint(index: number) {
    hints = hints.filter((_, i) => i !== index)
  }

  function addHint() {
    hints = [...hints, { label: '', question: '' }]
  }

  async function handleSubmit() {
    const data = {
      name,
      description,
      killChain,
      mitreId,
      whatToLookFor: hints.filter(h => h.question.trim() !== ''),
      suspiciousIndicators: indicators.filter(i => i.trim() !== ''),
      relatedProcesses: processes.filter(p => p.name.trim() !== '')
    }

    if (alert) {
      await updateAlert(alert.id, { ...data, id: alert.id } as Alert)
    } else {
      await createAlert(data)
    }

    onSaved()
  }
</script>

<div class="form-container">
  <div class="form-header">
    <h1>{alert ? 'Edit alert' : 'New alert'}</h1>
    <div class="form-actions">
      <button class="btn-cancel" onclick={onCancel}>Cancel</button>
      <button class="btn-save" onclick={handleSubmit}>Save alert</button>
    </div>
  </div>

  <div class="field">
    <label>Name</label>
    <input type="text" bind:value={name} />
  </div>

  <div class="field-row">
    <div class="field">
      <label>Kill Chain phase</label>
      <select bind:value={killChain}>
        {#each killChainOptions as option}
          <option value={option}>{option}</option>
        {/each}
      </select>
    </div>
    <div class="field">
      <label>MITRE ATT&CK ID</label>
      <input type="text" bind:value={mitreId} />
    </div>
  </div>

  <div class="field">
    <label>Description</label>
    <textarea rows="4" bind:value={description}></textarea>
  </div>

  <div class="section">
    <div class="section-header">
      <label>What to look for (5W1H)</label>
      <button class="btn-add" onclick={addHint}>+ Add question</button>
    </div>
    {#each hints as hint, i}
      <div class="hint-row">
        <input class="hint-label" type="text" bind:value={hint.label} placeholder="Label" />
        <input class="hint-question" type="text" bind:value={hint.question} placeholder="Question" />
        <button class="btn-remove" onclick={() => removeHint(i)}>×</button>
      </div>
    {/each}
  </div>

  <div class="section">
    <div class="section-header">
      <label>Suspicious indicators</label>
      <button class="btn-add" onclick={addIndicator}>+ Add indicator</button>
    </div>
    {#each indicators as indicator, i}
      <div class="indicator-row">
        <input type="text" bind:value={indicators[i]} placeholder="Indicator" />
        <button class="btn-remove" onclick={() => removeIndicator(i)}>×</button>
      </div>
    {/each}
  </div>

  <div class="section">
    <div class="section-header">
      <label>Related processes</label>
      <button class="btn-add" onclick={addProcess}>+ Add process</button>
    </div>
    {#each processes as process, i}
      <div class="process-row">
        <input type="text" bind:value={process.name} placeholder="Process" />
        <input type="text" bind:value={process.legitimatePath} placeholder="Legitimate path" />
        <input type="text" bind:value={process.suspiciousPath} placeholder="Suspicious path" />
        <button class="btn-remove" onclick={() => removeProcess(i)}>×</button>
      </div>
    {/each}
  </div>
</div>

<style>
  .form-container {
    max-width: 800px;
    margin: 0 auto;
  }
  .form-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
  }
  h1 {
    font-size: 24px;
    font-weight: 600;
    color: var(--text-primary);
  }
  .form-actions {
    display: flex;
    gap: 8px;
  }
  .btn-cancel {
    padding: 8px 16px;
    background: none;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
  }
  .btn-save {
    padding: 8px 16px;
    background: var(--ring);
    border: none;
    border-radius: var(--radius);
    color: #fff;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }
  .field {
    margin-bottom: 16px;
    flex: 1;
  }
  .field-row {
    display: flex;
    gap: 16px;
  }
  label {
    display: block;
    margin-bottom: 6px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
  }
  input, textarea, select {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text-primary);
    font-size: 14px;
    font-family: inherit;
    outline: none;
  }
  input:focus, textarea:focus, select:focus {
    border-color: var(--ring);
  }
  textarea {
    resize: vertical;
  }
  select {
    cursor: pointer;
  }
  option {
    background: var(--bg-elevated);
    color: var(--text-primary);
  }
  .section {
    margin-bottom: 24px;
  }
  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }
  .section-header label {
    margin-bottom: 0;
  }
  .btn-add {
    padding: 4px 10px;
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
  }
  .btn-add:hover {
    border-color: var(--ring);
    color: var(--ring);
  }
  .hint-row {
    display: flex;
    gap: 8px;
    margin-bottom: 6px;
  }
  .hint-label {
    width: 100px;
    flex-shrink: 0;
  }
  .hint-question {
    flex: 1;
  }
  .indicator-row {
    display: flex;
    gap: 8px;
    margin-bottom: 6px;
  }
  .indicator-row input {
    flex: 1;
  }
  .process-row {
    display: flex;
    gap: 8px;
    margin-bottom: 6px;
  }
  .process-row input {
    flex: 1;
  }
  .btn-remove {
    width: 30px;
    height: 30px;
    padding: 0;
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-muted);
    font-size: 16px;
    cursor: pointer;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .btn-remove:hover {
    color: var(--kc-exfil);
    border-color: var(--kc-exfil);
  }
</style>