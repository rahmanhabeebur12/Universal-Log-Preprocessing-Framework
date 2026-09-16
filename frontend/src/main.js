import './style.css'
import { api } from './api.js'

const app = document.querySelector('#app')
const sampleNames = [
  ['fortigate.log', 'Fortinet / FortiGate'],
  ['cisco_asa.log', 'Cisco / ASA'],
  ['paloalto.csv', 'Palo Alto / CSV'],
  ['generic_cef.log', 'Generic / CEF'],
  ['firewall.json', 'Generic / JSON'],
]
const nav = [
  ['processor', '01', 'Live Processor'],
  ['events', '02', 'Event Explorer'],
  ['parsers', '03', 'Parser Registry'],
  ['schema', '04', 'Universal Schema'],
  ['overview', '05', 'Overview'],
  ['system', '06', 'System'],
]
const state = {
  page: 'processor', rawInput: '', sample: '', current: null, resultTab: 'normalized',
  busy: false, error: '', notice: '', integrity: null, events: [], selectedId: null,
  filters: { search: '', vendor: '', format: '', action: '', severity: '' }, offset: 0,
  stats: null, parsers: null, apiOnline: false, uploadResults: null, schemaSearch: '', recentEvents: [],
}
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
const data = value => esc(typeof value === 'object' ? JSON.stringify(value) : value)
const short = (value, n = 56) => value && String(value).length > n ? String(value).slice(0, n) + '…' : value
const label = value => value == null || value === '' ? '<span class="null">—</span>' : esc(value)
const fmtTime = value => value ? new Date(value).toLocaleString(undefined, { hour12: false }) : '—'
const status = value => `<span class="status ${esc(value || 'unknown')}"><i></i>${esc(value || 'unknown')}</span>`
const sectionTitle = (number, title, meta = '') => `<div class="section-heading"><span class="section-index">${number}</span><h2>${title}</h2><span class="section-meta">${meta}</span></div>`
const item = (name, value) => `<div class="kv"><span>${esc(name)}</span><strong title="${esc(value ?? '')}">${label(value)}</strong></div>`
const notice = () => state.error ? `<div class="notice error">${esc(state.error)}</div>` : state.notice ? `<div class="notice">${esc(state.notice)}</div>` : ''

function shell() {
  app.innerHTML = `
    <aside class="sidebar">
      <div class="brand"><div class="brand-glyph">U<span>∕</span></div><div><strong>ULPF</strong><small>SECURITY EVENT WORKSTATION</small></div></div>
      <div class="sidebar-label">WORKSPACE <span>PHASE 02</span></div>
      <nav aria-label="Main navigation">${nav.map(([id, n, title]) => `<button class="nav-item ${state.page === id ? 'active' : ''}" data-page="${id}"><span>${n}</span>${title}<b>›</b></button>`).join('')}</nav>
      <div class="sidebar-bottom"><div class="system-indicator"><i class="${state.apiOnline ? 'online' : 'offline'}"></i><span>PROCESSING API</span><strong>${state.apiOnline ? 'CONNECTED' : 'UNAVAILABLE'}</strong></div><div class="sidebar-foot">LOCAL INSTANCE <span>·</span> NO EXTERNAL SERVICES</div></div>
    </aside>
    <main class="workspace"><header class="topbar"><div class="breadcrumb">ULPF <span>/</span> ${esc(nav.find(x => x[0] === state.page)?.[2])}</div><div class="top-actions"><span class="environment">LOCAL WORKSPACE</span><span class="top-clock" id="clock"></span></div></header><div class="content" id="content"></div></main>`
  app.querySelectorAll('[data-page]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.page)))
  updateClock()
}
function updateClock() {
  const node = document.querySelector('#clock')
  if (node) node.textContent = new Date().toLocaleString(undefined, { hour12: false })
}
setInterval(updateClock, 1000)

function render() {
  shell()
  const views = { processor: renderProcessor, events: renderEvents, parsers: renderParsers, schema: renderSchema, overview: renderOverview, system: renderSystem }
  views[state.page]()
}
async function navigate(page) {
  state.page = page; state.error = ''; state.notice = ''
  render()
  if (page === 'events') await loadEvents()
  if (page === 'overview') await loadStats()
  if (page === 'parsers') await loadParsers()
  if (page === 'system') await Promise.all([loadStats(), loadParsers()])
}
async function init() {
  try {
    const [stats, parsers] = await Promise.all([api.stats(), api.parsers()])
    state.stats = stats; state.parsers = parsers; state.apiOnline = true
  } catch { state.apiOnline = false }
  render()
}

function renderProcessor() {
  const event = state.current?.normalized_event || null
  document.querySelector('#content').innerHTML = `
    <div class="page-intro"><div><div class="eyebrow">WORKBENCH / EVENT TRANSFORMATION</div><h1>Live Processor</h1><p>Submit one source event. Inspect every transformation and what was preserved.</p></div><div class="intro-right"><span class="small-label">PROCESSOR STATE</span>${state.busy ? status('processing') : event ? status(event.metadata.normalization_status) : '<span class="idle-mark">AWAITING INPUT</span>'}</div></div>
    ${notice()}
    <div class="processor-grid">
      <section class="panel input-panel">${sectionTitle('01', 'Source event', 'INPUT / UTF-8')}
        <div class="input-toolbar"><label for="sample-select">REFERENCE INPUT</label><select id="sample-select"><option value="">Select a sample…</option>${sampleNames.map(([file, name]) => `<option value="${file}" ${state.sample === file ? 'selected' : ''}>${name}</option>`).join('')}</select><span class="toolbar-divider"></span><label class="file-button" for="upload-file">UPLOAD FILE</label><input id="upload-file" type="file" accept=".log,.txt,.json,.csv" hidden></div>
        <div class="editor-wrap"><div class="line-numbers" id="line-numbers">1</div><textarea id="raw-input" spellcheck="false" aria-label="Raw event input" placeholder="Paste a firewall, syslog, CEF, JSON, key=value, or CSV event here…">${esc(state.rawInput)}</textarea></div>
        <div class="input-footer"><span id="input-bytes">0 BYTES</span><span class="input-hint">Source input is stored with each processed event</span></div>
        <div class="input-actions"><button class="primary-button" id="process-button" ${state.busy ? 'disabled' : ''}><span>▶</span> ${state.busy ? 'PROCESSING…' : 'PROCESS EVENT'}</button><button class="text-button" id="clear-button">CLEAR</button></div>
        ${state.uploadResults ? `<div class="upload-summary"><span>UPLOAD RESULT</span><strong>${state.uploadResults.total_received} received · ${state.uploadResults.successful} success · ${state.uploadResults.partial} partial · ${state.uploadResults.failed} failed</strong></div>` : ''}
      </section>
      <section class="panel pipeline-panel">${sectionTitle('02', 'Processing path', 'BACKEND-REPORTED')}${renderPipeline(event)}</section>
    </div>
    <section class="panel result-panel">${sectionTitle('03', 'Normalized output', event ? `EVENT ID / ${esc(event.event.id)}` : 'NO EVENT PROCESSED')}${event ? renderResult(event) : `<div class="empty-result"><div class="empty-symbol">{ }</div><strong>Awaiting a processed event</strong><p>Choose a reference input, paste a record, or upload a supported file.</p></div>`}</section>`
  bindProcessor()
}
function renderPipeline(event) {
  const steps = [
    ['INGESTION', event ? `${event.raw.byte_length} UTF-8 bytes` : 'Awaiting source'],
    ['FORMAT DETECTION', event ? `${event.raw.detected_format.toUpperCase()} · ${(event.metadata.format_confidence * 100).toFixed(0)}% confidence` : 'Pending'],
    ['PARSER SELECTION', event ? `${event.parser.name} / v${event.parser.version}` : 'Pending'],
    ['SOURCE IDENTIFICATION', event ? `${event.device.vendor || 'Unknown'} · ${(event.metadata.vendor_confidence * 100).toFixed(0)}% confidence` : 'Pending'],
    ['NORMALIZATION', event ? `${Object.keys(event.provenance).length} canonical mappings` : 'Pending'],
    ['PRESERVATION', event ? `${Object.keys(event.unmapped).length} unmapped attributes retained` : 'Pending'],
    ['INTEGRITY', event ? `SHA-256 / ${event.raw.sha256.slice(0, 12)}…` : 'Pending'],
  ]
  return `<div class="pipeline-list">${steps.map(([title, detail], i) => `<div class="pipeline-step ${event ? 'complete' : ''}"><div class="step-marker">${String(i + 1).padStart(2, '0')}</div><div><strong>${title}</strong><span>${esc(detail)}</span></div><i></i></div>`).join('')}</div>${event ? `<div class="pipeline-footer"><span>PROCESSING TIME</span><strong>${esc(event.metadata.processing_time_ms)} ms</strong></div>` : `<div class="pipeline-footer"><span>VALUES APPEAR AFTER PROCESSING</span></div>`}`
}
function renderResult(event) {
  const tabs = [['normalized', 'NORMALIZED EVENT'], ['trace', `FIELD TRACEABILITY <b>${Object.keys(event.provenance).length}</b>`], ['unmapped', `PRESERVED FIELDS <b>${Object.keys(event.unmapped).length}</b>`], ['raw', 'RAW & INTEGRITY'], ['json', 'JSON DOCUMENT']]
  return `<div class="event-summary"><div class="summary-primary"><span class="small-label">SOURCE → DESTINATION</span><div class="flow-address"><strong>${label(event.source.ip)}<small>${event.source.port != null ? ':' + esc(event.source.port) : ''}</small></strong><span>→</span><strong>${label(event.destination.ip)}<small>${event.destination.port != null ? ':' + esc(event.destination.port) : ''}</small></strong></div></div><div class="summary-facts">${item('VENDOR', event.device.vendor)}${item('ACTION', event.event.action)}${item('TRANSPORT', event.network.transport)}${item('STATUS', event.metadata.normalization_status)}</div></div>
    <div class="result-tabs" role="tablist">${tabs.map(([id, title]) => `<button role="tab" aria-selected="${state.resultTab === id}" class="${state.resultTab === id ? 'active' : ''}" data-result-tab="${id}">${title}</button>`).join('')}</div>
    <div class="result-body" id="result-body">${renderResultBody(event)}</div>`
}
function renderResultBody(event) {
  if (state.resultTab === 'trace') return renderTrace(event)
  if (state.resultTab === 'unmapped') return renderUnmapped(event)
  if (state.resultTab === 'raw') return renderRaw(event)
  if (state.resultTab === 'json') return `<div class="tab-explainer"><strong>VALIDATED EVENT DOCUMENT</strong><span>The exact normalized event returned by the processing API.</span></div><pre class="json-block">${esc(JSON.stringify(event, null, 2))}</pre>`
  return renderNormalized(event)
}
function renderNormalized(event) {
  const groups = [['EVENT', event.event], ['SOURCE', event.source], ['DESTINATION', event.destination], ['NETWORK', event.network], ['USER', event.user], ['DEVICE', event.device], ['OBSERVER', event.observer], ['RULE', event.rule], ['HTTP', event.http], ['DNS', event.dns]]
  return `<div class="normalized-layout"><div class="field-grid">${groups.map(([name, fields]) => `<div class="field-group"><div class="group-heading">${name}<span>${Object.values(fields).filter(x => x != null).length} populated</span></div>${Object.entries(fields).map(([key, value]) => `<div class="field-row"><span>${esc(key)}</span><strong title="${esc(value ?? '')}">${label(value)}</strong></div>`).join('')}</div>`).join('')}</div><aside class="result-aside"><div class="aside-block"><span class="small-label">MESSAGE</span><p>${label(event.message)}</p></div><div class="aside-block"><span class="small-label">SOURCE EVIDENCE</span><p>${esc(event.metadata.vendor_evidence)}</p></div><div class="aside-block"><span class="small-label">PARSE WARNINGS</span>${event.parse_warnings.length ? event.parse_warnings.map(w => `<p class="warning-line"><i></i>${esc(w)}</p>`).join('') : '<p class="muted">None</p>'}</div><div class="aside-block"><span class="small-label">SCHEMA</span><p>${esc(event.schema.name)} / ${esc(event.schema.version)}</p></div></aside></div>`
}
function renderTrace(event) {
  const entries = Object.entries(event.provenance)
  return `<div class="tab-explainer"><strong>FIELD-LEVEL PROVENANCE</strong><span>Each canonical value links back to the exact parsed source field and its original value.</span></div>${entries.length ? `<div class="table-scroll"><table><thead><tr><th>CANONICAL FIELD</th><th>ORIGINAL FIELD</th><th>ORIGINAL VALUE</th><th>NORMALIZED VALUE</th></tr></thead><tbody>${entries.map(([path, source]) => `<tr><td class="cyan">${esc(path)}</td><td>${esc(source.source_field)}</td><td class="wrap">${data(source.original_value)}</td><td class="wrap">${data(path.split('.').reduce((obj, part) => obj?.[part], event))}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty-tab">No fields were mapped from this event.</div>'}`
}
function renderUnmapped(event) {
  const entries = Object.entries(event.unmapped)
  return `<div class="tab-explainer"><strong>RETAINED SOURCE ATTRIBUTES</strong><span>Parsed attributes without a canonical destination remain available here. The exact raw input is also retained.</span></div>${entries.length ? `<div class="table-scroll"><table><thead><tr><th>SOURCE FIELD</th><th>ORIGINAL VALUE</th></tr></thead><tbody>${entries.map(([key, value]) => `<tr><td class="amber">${esc(key)}</td><td class="wrap">${data(value)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty-tab">All extracted attributes mapped to canonical fields.</div>'}`
}
function renderRaw(event) {
  const verify = state.integrity
  return `<div class="integrity-bar"><div><span class="small-label">SHA-256 / STORED RAW EVENT</span><strong class="hash">${esc(event.raw.sha256)}</strong></div><button class="secondary-button" id="verify-button">VERIFY STORED EVENT</button></div><div class="integrity-meta">${item('BYTE LENGTH', event.raw.byte_length)}${item('FORMAT', event.raw.detected_format)}${item('VERIFICATION', verify ? verify.verified ? 'MATCH' : 'MISMATCH' : 'NOT RUN')}</div>${verify ? `<div class="verification ${verify.verified ? 'valid' : 'invalid'}">${verify.verified ? '✓ Stored raw data matches its SHA-256 digest' : '✕ Stored raw data does not match its SHA-256 digest'}<small>Calculated: ${esc(verify.calculated_hash)}</small></div>` : ''}<div class="raw-heading">EXACT STORED RAW INPUT</div><pre class="raw-block">${esc(event.raw.data)}</pre>`
}
function bindProcessor() {
  const input = document.querySelector('#raw-input')
  const updateInput = () => { state.rawInput = input.value; document.querySelector('#input-bytes').textContent = `${new TextEncoder().encode(input.value).length} BYTES`; document.querySelector('#line-numbers').textContent = Array.from({ length: Math.max(1, input.value.split('\n').length) }, (_, i) => i + 1).join('\n') }
  updateInput()
  input.addEventListener('input', () => { state.sample = ''; updateInput() })
  input.addEventListener('scroll', () => { document.querySelector('#line-numbers').scrollTop = input.scrollTop })
  document.querySelector('#sample-select').addEventListener('change', async event => {
    state.sample = event.target.value
    if (!state.sample) return
    try { const response = await fetch(`/samples/${encodeURIComponent(state.sample)}`); if (!response.ok) throw new Error('Sample unavailable'); state.rawInput = (await response.text()).trimEnd(); state.error = ''; renderProcessor() }
    catch (error) { state.error = error.message; renderProcessor() }
  })
  document.querySelector('#clear-button').addEventListener('click', () => { state.rawInput = ''; state.sample = ''; state.current = null; state.integrity = null; state.uploadResults = null; state.error = ''; renderProcessor() })
  document.querySelector('#process-button').addEventListener('click', processInput)
  document.querySelector('#upload-file').addEventListener('change', uploadFile)
  document.querySelectorAll('[data-result-tab]').forEach(button => button.addEventListener('click', () => { state.resultTab = button.dataset.resultTab; renderProcessor() }))
  document.querySelector('#verify-button')?.addEventListener('click', verifyCurrent)
}
async function processInput() {
  if (!state.rawInput) { state.error = 'Enter a raw event before processing.'; renderProcessor(); return }
  state.busy = true; state.error = ''; state.notice = ''; state.uploadResults = null; renderProcessor()
  try { state.current = await api.process(state.rawInput); state.integrity = null; state.resultTab = 'normalized'; state.apiOnline = true }
  catch (error) { state.error = error.message; state.apiOnline = false }
  finally { state.busy = false; render() }
}
async function uploadFile(event) {
  const file = event.target.files?.[0]
  if (!file) return
  if (file.size > 5_000_000) { state.error = 'File exceeds the 5 MB upload limit.'; renderProcessor(); return }
  state.busy = true; state.error = ''; state.notice = ''; renderProcessor()
  try {
    const result = await api.upload(file)
    state.uploadResults = result
    const first = result.results.find(item => item.normalized_event)
    if (first) { state.current = first; state.rawInput = first.normalized_event.raw.data; state.sample = ''; state.integrity = null; state.resultTab = 'normalized' }
    else state.error = 'No events were stored from this file.'
    state.apiOnline = true
  } catch (error) { state.error = error.message }
  finally { state.busy = false; render() }
}
async function verifyCurrent() {
  if (!state.current) return
  try { state.integrity = await api.integrity(state.current.event_id); state.error = '' }
  catch (error) { state.error = error.message }
  renderProcessor()
}

function renderEvents() {
  document.querySelector('#content').innerHTML = `<div class="page-intro"><div><div class="eyebrow">STORED RECORDS / SQLITE</div><h1>Event Explorer</h1><p>Investigate persisted normalized events and return to their full transformation trace.</p></div><div class="intro-right"><a class="secondary-button" href="${api.exportUrl('ndjson')}" download="ulpf-events.ndjson">EXPORT NDJSON</a><a class="secondary-button" href="${api.exportUrl('json')}" download="ulpf-events.json">EXPORT JSON</a></div></div>${notice()}<section class="panel explorer-panel">${sectionTitle('01', 'Stored events', 'SERVER-REPORTED')}
  <div class="filters"><input id="filter-search" placeholder="Search raw or normalized content" value="${esc(state.filters.search)}" aria-label="Search events"><select id="filter-vendor"><option value="">All vendors</option>${filterOptions('vendor', state.stats?.events_by_vendor || {})}</select><select id="filter-format"><option value="">All formats</option>${filterOptions('format', state.stats?.events_by_format || {})}</select><select id="filter-action"><option value="">All actions</option>${filterOptions('action', state.stats?.events_by_action || {})}</select><select id="filter-severity"><option value="">All severities</option>${filterOptions('severity', state.stats?.events_by_severity || {})}</select><button id="filter-button" class="secondary-button">APPLY</button></div>
  <div class="table-scroll"><table class="events-table"><thead><tr><th>INGESTED</th><th>VENDOR / FORMAT</th><th>SOURCE → DESTINATION</th><th>ACTION</th><th>SEVERITY</th><th>STATUS</th><th>EVENT ID</th></tr></thead><tbody>${state.events.length ? state.events.map(event => `<tr class="event-row" data-event-id="${esc(event.event.id)}"><td>${esc(fmtTime(event.event.ingested_at))}</td><td><strong>${label(event.device.vendor)}</strong><small>${esc(event.raw.detected_format)}</small></td><td>${label(event.source.ip)} <span class="arrow">→</span> ${label(event.destination.ip)}</td><td>${label(event.event.action)}</td><td>${label(event.event.severity)}</td><td>${status(event.metadata.normalization_status)}</td><td class="id-cell">${esc(event.event.id.slice(0, 8))}…</td></tr>`).join('') : '<tr><td colspan="7" class="empty-table">No stored events match these filters.</td></tr>'}</tbody></table></div><div class="pagination"><span>OFFSET ${state.offset} · ${state.events.length} SHOWN</span><div><button id="prev-page" ${state.offset === 0 ? 'disabled' : ''}>← PREVIOUS</button><button id="next-page" ${state.events.length < 50 ? 'disabled' : ''}>NEXT →</button></div></div></section>`
  document.querySelector('#filter-button').addEventListener('click', applyFilters)
  document.querySelector('#filter-search').addEventListener('keydown', e => { if (e.key === 'Enter') applyFilters() })
  document.querySelector('#prev-page').addEventListener('click', () => { state.offset = Math.max(0, state.offset - 50); loadEvents() })
  document.querySelector('#next-page').addEventListener('click', () => { state.offset += 50; loadEvents() })
  document.querySelectorAll('[data-event-id]').forEach(row => row.addEventListener('click', () => openEvent(row.dataset.eventId)))
}
function filterOptions(key, values) { return Object.keys(values).filter(value => value !== 'unknown').sort().map(value => `<option value="${esc(value)}" ${state.filters[key] === value ? 'selected' : ''}>${esc(value)}</option>`).join('') }
function applyFilters() {
  for (const key of ['vendor', 'format', 'action', 'severity']) state.filters[key] = document.querySelector(`#filter-${key}`).value
  state.filters.search = document.querySelector('#filter-search').value.trim()
  state.offset = 0; loadEvents()
}
async function loadEvents() {
  try { const [result, stats] = await Promise.all([api.events({ limit: 50, offset: state.offset, ...Object.fromEntries(Object.entries(state.filters).filter(([, value]) => value)) }), api.stats()]); state.events = result.items; state.stats = stats; state.error = ''; state.apiOnline = true }
  catch (error) { state.error = error.message; state.events = [] }
  if (state.page === 'events') render()
}
async function openEvent(id) {
  try {
    const event = await api.event(id)
    state.current = { event_id: id, normalized_event: event }
    state.rawInput = event.raw.data; state.sample = ''; state.integrity = null; state.resultTab = 'normalized'; state.page = 'processor'; state.error = ''; render()
  } catch (error) { state.error = error.message; renderEvents() }
}

function renderParsers() {
  const parsers = state.parsers || []
  document.querySelector('#content').innerHTML = `<div class="page-intro"><div><div class="eyebrow">DETECTION / EXTRACTION</div><h1>Parser Registry</h1><p>Registered parsers reported by the processing API. Selection is confidence-led, then priority ordered.</p></div><div class="intro-right"><span class="small-label">ACTIVE PARSERS</span><strong class="big-value">${parsers.length}</strong></div></div>${notice()}<section class="panel">${sectionTitle('01', 'Registry entries', 'FROM /api/v1/parsers')}<div class="table-scroll"><table><thead><tr><th>PRIORITY</th><th>PARSER</th><th>VERSION</th><th>FORMATS HANDLED</th><th>STATUS</th></tr></thead><tbody>${parsers.map(parser => `<tr><td class="priority">${String(parser.priority).padStart(3, '0')}</td><td class="cyan">${esc(parser.name)}</td><td>${esc(parser.version)}</td><td>${parser.formats_handled.map(format => `<span class="format-chip">${esc(format)}</span>`).join('')}</td><td>${status(parser.status)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty-table">Registry unavailable.</td></tr>'}</tbody></table></div></section><div class="information-strip">The selected parser and its version are recorded on every processed event. Open a stored event to inspect the parser decision and source attributes.</div>`
}
async function loadParsers() { try { state.parsers = await api.parsers(); state.error = ''; state.apiOnline = true } catch (error) { state.error = error.message } if (state.page === 'parsers' || state.page === 'system') render() }

function renderSchema() {
  const groups = [
    ['schema', 'name · version'], ['event', 'id · ingested_at · timestamp · category · type · action · outcome · severity'],
    ['source / destination', 'ip · port · hostname · mac'], ['network', 'transport · protocol · direction · bytes · packets · community_id'],
    ['user', 'name · domain'], ['device', 'vendor · product · model · hostname · serial_number'],
    ['observer', 'ip · hostname'], ['rule', 'id · name · category'], ['http', 'method · url · status_code'],
    ['dns', 'query · record_type'], ['message / tags', 'message · tags[]'], ['raw', 'data · sha256 · byte_length · detected_format'],
    ['parser', 'name · version'], ['provenance', 'canonical path → source_field + original_value'],
    ['unmapped', 'source fields without canonical mapping'], ['parse_warnings / metadata', 'warnings[] · normalization_status · processing_time_ms · confidence + evidence'],
  ]
  const matching = groups.filter(([group, fields]) => `${group} ${fields}`.toLowerCase().includes(state.schemaSearch.toLowerCase()))
  document.querySelector('#content').innerHTML = `<div class="page-intro"><div><div class="eyebrow">CANONICAL CONTRACT / VERSION 1.0.0</div><h1>Universal Schema</h1><p>The output structure returned for every event, including partial and failed parses.</p></div></div><section class="panel">${sectionTitle('01', 'Event document structure', 'PYDANTIC-VALIDATED')}<div class="schema-search"><input id="schema-search" type="search" placeholder="Find a schema field or group" value="${esc(state.schemaSearch)}" aria-label="Search schema"></div><div class="schema-grid" id="schema-results">${matching.length ? matching.map(([group, fields]) => `<div class="schema-item"><strong>${esc(group)}</strong><span>${esc(fields)}</span></div>`).join('') : '<div class="empty-tab">No schema fields match.</div>'}</div></section><div class="information-strip">Unavailable source values remain null. The ingestion timestamp is generated by the API; it is separate from the source event timestamp.</div>`
  document.querySelector('#schema-search').addEventListener('input', event => { state.schemaSearch = event.target.value; const results = document.querySelector('#schema-results'); const filtered = groups.filter(([group, fields]) => `${group} ${fields}`.toLowerCase().includes(state.schemaSearch.toLowerCase())); results.innerHTML = filtered.length ? filtered.map(([group, fields]) => `<div class="schema-item"><strong>${esc(group)}</strong><span>${esc(fields)}</span></div>`).join('') : '<div class="empty-tab">No schema fields match.</div>' })
}
function renderOverview() {
  const s = state.stats
  const count = (value) => s ? String(value ?? 0) : '—'
  document.querySelector('#content').innerHTML = `<div class="page-intro"><div><div class="eyebrow">PERSISTED ACTIVITY / NO ESTIMATES</div><h1>Overview</h1><p>Counts and timing from the local event store.</p></div><div class="intro-right"><button class="secondary-button" id="refresh-stats">REFRESH</button></div></div>${notice()}<div class="metric-grid"><div class="metric"><span>TOTAL PROCESSED</span><strong>${count(s?.total_processed)}</strong></div><div class="metric"><span>SUCCESSFUL</span><strong class="green">${count(s?.successful)}</strong></div><div class="metric"><span>PARTIAL / WARNINGS</span><strong class="amber">${count(s?.partial)}</strong></div><div class="metric"><span>FAILED</span><strong class="red">${count(s?.failed)}</strong></div></div><div class="overview-grid"><section class="panel">${sectionTitle('01', 'Processing', 'STORE AGGREGATE')}${item('AVERAGE PROCESSING TIME', s ? `${Number(s.average_processing_time_ms).toFixed(3)} ms` : null)}${item('LAST EVENT', s?.last_event_time ? fmtTime(s.last_event_time) : null)}</section><section class="panel">${sectionTitle('02', 'By format', 'STORED EVENTS')}${distribution(s?.events_by_format)}</section><section class="panel">${sectionTitle('03', 'By vendor', 'STORED EVENTS')}${distribution(s?.events_by_vendor)}</section><section class="panel">${sectionTitle('04', 'By action', 'STORED EVENTS')}${distribution(s?.events_by_action)}</section></div><section class="panel recent-panel">${sectionTitle('05', 'Recent events', 'STORED EVENTS')}${state.recentEvents.length ? `<div class="table-scroll"><table><thead><tr><th>INGESTED</th><th>VENDOR</th><th>FORMAT</th><th>ACTION</th><th>EVENT ID</th></tr></thead><tbody>${state.recentEvents.map(event => `<tr class="event-row" data-event-id="${esc(event.event.id)}"><td>${esc(fmtTime(event.event.ingested_at))}</td><td>${label(event.device.vendor)}</td><td>${esc(event.raw.detected_format)}</td><td>${label(event.event.action)}</td><td class="id-cell">${esc(event.event.id.slice(0, 8))}…</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty-tab">No stored events yet. Process a source event to populate this view.</div>'}</section>`
  document.querySelector('#refresh-stats').addEventListener('click', loadStats)
  document.querySelectorAll('[data-event-id]').forEach(row => row.addEventListener('click', () => openEvent(row.dataset.eventId)))
}
function distribution(counts) { const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]); return entries.length ? entries.map(([name, count]) => `<div class="distribution"><span>${esc(name)}</span><strong>${esc(count)}</strong></div>`).join('') : '<div class="empty-distribution">No stored events.</div>' }
async function loadStats() { try { const [stats, recent] = await Promise.all([api.stats(), api.events({ limit: 5, offset: 0 })]); state.stats = stats; state.recentEvents = recent.items; state.error = ''; state.apiOnline = true } catch (error) { state.error = error.message } if (state.page === 'overview' || state.page === 'system') render() }
function renderSystem() {
  document.querySelector('#content').innerHTML = `<div class="page-intro"><div><div class="eyebrow">LOCAL DEPLOYMENT / OPERATIONS</div><h1>System</h1><p>Runtime connectivity and supported API boundaries.</p></div></div>${notice()}<div class="overview-grid"><section class="panel">${sectionTitle('01', 'Implementation', 'PACKAGED RUNTIME')}${item('ENGINE', 'ULPF')}${item('API', 'FastAPI')}${item('STORAGE', 'SQLite')}${item('SCHEMA', '1.0.0')}${item('DEPLOYMENT', 'Local / Container')}</section><section class="panel">${sectionTitle('02', 'Connectivity', 'LOCAL API')}${item('API STATUS', state.apiOnline ? 'Connected' : 'Unavailable')}${item('BASE PATH', '/api/v1')}${item('STORED EVENTS', state.stats?.total_processed)}${item('REGISTERED PARSERS', state.parsers?.length)}${item('RUNTIME CLOUD DEPENDENCY', 'None')}${item('RUNTIME EXTERNAL API', 'None')}${item('AIR-GAP RUNTIME', 'Supported')}</section></div><div class="information-strip">The interface reads from the local processing API. No external fonts, assets, telemetry, or hosted services are required at runtime.</div>`
}

init()
