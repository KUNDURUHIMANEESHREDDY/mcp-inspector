const state = {
  events: [],
  summary: {},
  view: 'overview',
  selectedId: null,
  paused: false,
  stream: null,
  baseline: null,
  current: null,
  fuzz: null,
};

const viewMeta = {
  overview: ['Operational overview', 'Protocol activity and tool health, in one place.'],
  traces: ['Live protocol events', 'Search and filter sanitized request and response metadata.'],
  contracts: ['Contract intelligence', 'Track captured tool inventories and compare contract snapshots.'],
  fuzz: ['Fuzz-test reports', 'Review schema cases and results from authorized MCP test runs.'],
};

const byId = (id) => document.getElementById(id);
const svgNs = 'http://www.w3.org/2000/svg';

function safeNumber(value, suffix) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  return (value >= 100 ? Math.round(value).toString() : value.toFixed(value < 10 ? 2 : 1)) + (suffix || '');
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDuration(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  if (value < 1) return value.toFixed(2) + ' ms';
  if (value < 100) return value.toFixed(1) + ' ms';
  return Math.round(value) + ' ms';
}

function el(tag, className, content) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (content !== undefined && content !== null) item.textContent = String(content);
  return item;
}

function svgElement(tag, attrs) {
  const item = document.createElementNS(svgNs, tag);
  Object.entries(attrs || {}).forEach(([key, value]) => item.setAttribute(key, String(value)));
  return item;
}

function toast(message, type) {
  const region = byId('toast-region');
  const item = el('div', 'toast' + (type ? ' ' + type : ''), message);
  region.append(item);
  window.setTimeout(() => item.remove(), 3600);
}

function setConnection(online, message) {
  byId('connection-led').classList.toggle('online', online);
  byId('connection-led').classList.toggle('warning', !online);
  byId('sidebar-connection').textContent = online ? 'Event stream connected' : 'Event stream disconnected';
  byId('connection-label').textContent = message || (online ? 'Receiving live events' : 'Reconnecting to local event stream…');
}

function mergeEvent(event, renderNow) {
  if (!event || typeof event.id !== 'number') return;
  if (state.events.some((item) => item.id === event.id)) return;
  state.events.push(event);
  state.events.sort((a, b) => a.id - b.id);
  if (state.events.length > 1000) state.events.splice(0, state.events.length - 1000);
  if (state.selectedId === null) state.selectedId = event.id;
  if (renderNow !== false && !state.paused) renderAll();
}

function localSummary() {
  const events = state.events;
  const requests = events.filter((event) => event.event === 'rpc.request');
  const responses = events.filter((event) => event.event === 'rpc.response');
  const latencies = responses.map((event) => event.duration_ms).filter((value) => typeof value === 'number').sort((a, b) => a - b);
  const percentile = (ratio) => latencies.length ? latencies[Math.min(latencies.length - 1, Math.ceil(latencies.length * ratio) - 1)] : null;
  return {
    requests: requests.length,
    responses: responses.length,
    toolCalls: requests.filter((event) => event.method === 'tools/call').length,
    errors: events.filter((event) => event.is_error === true || (['warn', 'error'].includes(event.level) && /rpc|contract|proxy|http/.test(event.event))).length,
    breakingChanges: events.filter((event) => event.event === 'contract.diff' && event.breaking === true).length,
    latencyP50Ms: percentile(0.5),
    latencyP95Ms: percentile(0.95),
    retainedEvents: events.length,
    totalEvents: events.length,
  };
}

function allSummary() {
  return localSummary();
}

function eventClass(event) {
  if (event.is_error === true || event.level === 'error' || event.level === 'warn') return 'error';
  if (event.event === 'rpc.request' || event.event === 'rpc.reverse_request') return 'request';
  if (event.event === 'rpc.response') return 'response';
  if (event.event.startsWith('contract.')) return 'contract';
  if (event.event.startsWith('fuzz.')) return 'fuzz';
  return 'other';
}

function eventLabel(event) {
  if (event.event === 'rpc.request') return 'Request';
  if (event.event === 'rpc.reverse_request') return 'Reverse request';
  if (event.event === 'rpc.response') return event.is_error ? 'Error response' : 'Response';
  if (event.event.startsWith('contract.')) return 'Contract';
  return event.level === 'warn' || event.level === 'error' ? 'Warning' : event.event.replaceAll('.', ' ');
}

function eventStatus(event) {
  if (event.event === 'rpc.request') return ['pending', 'In flight'];
  if (event.event === 'rpc.response') return event.is_error ? ['error', 'Error'] : ['ok', 'Success'];
  if (event.level === 'error' || event.level === 'warn' || event.breaking === true) return ['warn', 'Review'];
  if (event.event.startsWith('contract.')) return ['pending', 'Captured'];
  return ['pending', 'Observed'];
}

function filteredEvents(limit) {
  const query = byId('global-search').value.trim().toLowerCase();
  const filter = byId('trace-filter') ? byId('trace-filter').value : 'all';
  let events = state.events;
  if (query) {
    events = events.filter((event) => [event.event, event.method, event.tool, event.transport, event.direction, event.request_id].some((value) => String(value || '').toLowerCase().includes(query)));
  }
  if (state.view === 'traces' && filter !== 'all') {
    if (filter === 'requests') events = events.filter((event) => event.event === 'rpc.request' || event.event === 'rpc.reverse_request');
    if (filter === 'responses') events = events.filter((event) => event.event === 'rpc.response');
    if (filter === 'errors') events = events.filter((event) => event.level === 'warn' || event.level === 'error' || event.is_error === true);
    if (filter === 'tools') events = events.filter((event) => event.method === 'tools/call' || Boolean(event.tool));
  }
  return limit ? events.slice(-limit).reverse() : events.slice().reverse();
}

function renderMetrics() {
  const summary = allSummary();
  byId('metric-requests').textContent = String(summary.requests || 0);
  byId('metric-latency').textContent = summary.latencyP50Ms === null || summary.latencyP50Ms === undefined ? '—' : formatDuration(summary.latencyP50Ms);
  byId('metric-p95').textContent = 'p95 ' + formatDuration(summary.latencyP95Ms);
  byId('metric-errors').textContent = String(summary.errors || 0);
  byId('metric-error-note').textContent = summary.errors ? 'Review event stream' : 'No issues reported';
  byId('metric-contracts').textContent = String(summary.breakingChanges || 0);
  byId('metric-request-delta').textContent = String(summary.toolCalls || 0) + ' tool calls';
  byId('distribution-total').textContent = String(summary.retainedEvents || 0);
  byId('distribution-requests').textContent = String(summary.requests || 0);
  byId('distribution-responses').textContent = String(summary.responses || 0);
  byId('distribution-errors').textContent = String(summary.errors || 0);
  const denominator = Math.max(1, (summary.requests || 0) + (summary.responses || 0) + (summary.errors || 0));
  const requestShare = Math.min(100, 100 * (summary.requests || 0) / denominator);
  byId('distribution-ring').style.setProperty('--ring-percent', requestShare + '%');
  byId('trace-nav-count').textContent = String(summary.requests || 0);
  byId('trace-count').textContent = String(state.events.length) + ' events retained';
}

function renderLatencyChart() {
  const chart = byId('latency-chart');
  chart.replaceChildren();
  const width = 640;
  const height = 190;
  const pad = { top: 13, right: 14, bottom: 26, left: 37 };
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;
  const responses = state.events.filter((event) => event.event === 'rpc.response' && typeof event.duration_ms === 'number').slice(-40);
  byId('latency-sample-count').textContent = responses.length + ' samples';
  for (let i = 0; i <= 3; i += 1) {
    const y = pad.top + (plotHeight * i / 3);
    chart.append(svgElement('line', { x1: pad.left, y1: y, x2: width - pad.right, y2: y, class: 'chart-gridline' }));
    const tick = svgElement('text', { x: pad.left - 8, y: y + 3, 'text-anchor': 'end', class: 'chart-label' });
    tick.textContent = i === 0 ? 'MAX' : i === 3 ? '0' : '';
    chart.append(tick);
  }
  if (!responses.length) {
    const message = svgElement('text', { x: width / 2, y: height / 2, 'text-anchor': 'middle', class: 'chart-label' });
    message.textContent = 'Waiting for response timings';
    chart.append(message);
    return;
  }
  const values = responses.map((event) => Math.max(0, event.duration_ms));
  const maxValue = Math.max(10, ...values) * 1.1;
  const points = values.map((value, index) => ({
    x: pad.left + (values.length === 1 ? plotWidth / 2 : plotWidth * index / (values.length - 1)),
    y: pad.top + plotHeight - (value / maxValue) * plotHeight,
    value,
  }));
  const path = points.map((point, index) => (index === 0 ? 'M ' : 'L ') + point.x.toFixed(2) + ' ' + point.y.toFixed(2)).join(' ');
  const area = path + ' L ' + points[points.length - 1].x + ' ' + (pad.top + plotHeight) + ' L ' + points[0].x + ' ' + (pad.top + plotHeight) + ' Z';
  const defs = svgElement('defs');
  const gradient = svgElement('linearGradient', { id: 'latency-fill', x1: '0', x2: '0', y1: '0', y2: '1' });
  gradient.append(svgElement('stop', { offset: '0%', 'stop-color': '#6ca8ff', 'stop-opacity': '.6' }));
  gradient.append(svgElement('stop', { offset: '100%', 'stop-color': '#6ca8ff', 'stop-opacity': '0' }));
  defs.append(gradient);
  chart.append(defs);
  chart.append(svgElement('path', { d: area, class: 'chart-area' }));
  chart.append(svgElement('path', { d: path, class: 'chart-line' }));
  points.forEach((point, index) => {
    if (index === points.length - 1 || index % 5 === 0) {
      const dot = svgElement('circle', { cx: point.x, cy: point.y, r: index === points.length - 1 ? 4 : 2.5, class: 'chart-point' });
      const title = svgElement('title', {});
      title.textContent = formatDuration(point.value);
      dot.append(title);
      chart.append(dot);
    }
  });
  const olderLabel = svgElement('text', { x: pad.left, y: height - 7, class: 'chart-label' });
  olderLabel.textContent = 'OLDER';
  chart.append(olderLabel);
  const latestLabel = svgElement('text', { x: width - pad.right, y: height - 7, 'text-anchor': 'end', class: 'chart-label' });
  latestLabel.textContent = 'LATEST';
  chart.append(latestLabel);
}

function createEventRow(event, expanded) {
  const row = document.createElement('tr');
  if (state.selectedId === event.id) row.classList.add('selected');
  row.tabIndex = 0;
  row.setAttribute('aria-label', event.event + ' ' + (event.method || event.tool || ''));
  const timestamp = el('td', 'subcell', formatTime(event.time));
  const eventCell = el('td');
  const label = el('span', 'type-label ' + eventClass(event));
  label.append(el('i', 'type-mark'));
  label.append(document.createTextNode(eventLabel(event)));
  eventCell.append(label);
  const methodCell = el('td', 'method-cell');
  methodCell.textContent = event.tool || event.method || event.event;
  const transportCell = el('td', 'subcell', event.transport || '—');
  const durationCell = el('td', 'numeric', event.event === 'rpc.response' ? formatDuration(event.duration_ms) : '—');
  const status = eventStatus(event);
  const statusCell = el('td');
  statusCell.append(el('span', 'status-pill ' + status[0], status[1]));
  if (expanded) row.append(timestamp, eventCell, methodCell, transportCell, durationCell, statusCell);
  else row.append(eventCell, methodCell, transportCell, durationCell, statusCell);
  row.addEventListener('click', () => {
    state.selectedId = event.id;
    renderDetails();
    document.querySelectorAll('tbody tr.selected').forEach((item) => item.classList.remove('selected'));
    row.classList.add('selected');
  });
  row.addEventListener('keydown', (keyboardEvent) => {
    if (keyboardEvent.key === 'Enter' || keyboardEvent.key === ' ') {
      keyboardEvent.preventDefault();
      row.click();
    }
  });
  return row;
}

function renderEventTables() {
  const recent = filteredEvents(9);
  const overviewBody = byId('overview-events');
  overviewBody.replaceChildren(...recent.map((event) => createEventRow(event, false)));
  byId('overview-empty').hidden = recent.length > 0;
  const traceEvents = filteredEvents(500);
  const traceBody = byId('trace-events');
  traceBody.replaceChildren(...traceEvents.map((event) => createEventRow(event, true)));
  byId('trace-empty').hidden = traceEvents.length > 0;
}

function renderDetails() {
  const container = byId('event-details');
  const event = state.events.find((item) => item.id === state.selectedId);
  if (!event) {
    container.className = 'details-empty';
    container.replaceChildren(el('svg', 'icon'), el('span', '', 'Select an event to inspect its metadata.'));
    return;
  }
  container.className = 'details-content';
  container.replaceChildren();
  const label = el('div', 'detail-title', event.method || event.event);
  const subtitle = el('div', 'detail-subtitle', event.tool ? 'Tool call · ' + event.tool : eventLabel(event) + ' · ' + formatTime(event.time));
  container.append(label, subtitle);
  const rows = [
    ['Event', event.event],
    ['Timestamp', event.time],
    ['Level', event.level],
    ['Transport', event.transport],
    ['Direction', event.direction],
    ['Method', event.method],
    ['Tool', event.tool],
    ['Request ID', event.request_id],
    ['Duration', event.duration_ms === undefined ? undefined : formatDuration(event.duration_ms)],
    ['Payload bytes', event.bytes],
    ['Error', event.is_error],
    ['Error code', event.error_code],
    ['Reason', event.reason],
    ['Contract hash', event.hash],
    ['Breaking', event.breaking],
  ].filter((item) => item[1] !== undefined && item[1] !== null && item[1] !== '');
  const divider = el('div', 'detail-separator');
  const grid = el('div', 'detail-rows');
  rows.forEach(([key, value]) => {
    grid.append(el('div', 'detail-key', key), el('div', 'detail-value', typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value));
  });
  container.append(divider, grid);
  const privacy = el('div', 'privacy-note');
  const icon = document.createElementNS(svgNs, 'svg');
  icon.setAttribute('class', 'icon');
  const use = document.createElementNS(svgNs, 'use');
  use.setAttribute('href', '#i-shield');
  icon.append(use);
  privacy.append(icon, el('span', '', 'Arguments and results are intentionally not recorded.'));
  container.append(privacy);
}

function renderContractEvents() {
  const items = state.events.filter((event) => event.event && event.event.startsWith('contract.')).slice(-100).reverse();
  const host = byId('contract-event-list');
  host.replaceChildren();
  byId('contract-captured-count').textContent = String(items.filter((event) => event.event === 'contract.captured' || event.event === 'contract.baseline_created').length);
  byId('contract-breaking-count').textContent = String(items.filter((event) => event.event === 'contract.diff' && event.breaking === true).length);
  const latest = items.find((event) => event.hash);
  byId('contract-latest-hash').textContent = latest ? latest.hash.slice(0, 12) + '…' : 'Not captured';
  if (!items.length) {
    const empty = el('div', 'empty-state compact-empty');
    empty.append(el('strong', '', 'No contract events yet'), el('p', '', 'Capture or compare a contract with the CLI to populate this timeline.'));
    host.append(empty);
    return;
  }
  items.forEach((event) => {
    const row = el('div', 'contract-event' + (event.breaking ? ' breaking' : ''));
    row.append(el('i', 'event-mark'));
    const copy = el('div');
    copy.append(el('strong', '', event.event.replaceAll('.', ' ')));
    let detail = event.tool_count !== undefined ? String(event.tool_count) + ' tools captured' : event.breaking ? 'Potentially breaking schema changes detected' : event.reason || 'Contract metadata event';
    if (event.breaking_count !== undefined) detail = String(event.breaking_count) + ' breaking · ' + String(event.compatible_count || 0) + ' compatible changes';
    copy.append(el('p', '', detail));
    row.append(copy, el('time', '', formatTime(event.time)));
    host.append(row);
  });
}

function stable(value) {
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}';
  return JSON.stringify(value);
}

function compareContracts() {
  const result = byId('contract-compare-result');
  result.replaceChildren();
  if (!state.baseline || !state.current) {
    toast('Choose both contract JSON files before comparing.', 'error');
    return;
  }
  if (!Array.isArray(state.baseline.tools) || !Array.isArray(state.current.tools)) {
    toast('Each file must contain a tools array from an MCP Inspector contract snapshot.', 'error');
    return;
  }
  const before = new Map(state.baseline.tools.filter((tool) => tool && typeof tool.name === 'string').map((tool) => [tool.name, tool]));
  const after = new Map(state.current.tools.filter((tool) => tool && typeof tool.name === 'string').map((tool) => [tool.name, tool]));
  const changes = [];
  before.forEach((tool, name) => {
    if (!after.has(name)) changes.push({ breaking: true, title: 'Tool removed: ' + name, message: 'The current snapshot no longer advertises this tool.' });
    else if (stable(tool.inputSchema || {}) !== stable(after.get(name).inputSchema || {})) changes.push({ breaking: true, title: 'Input schema changed: ' + name, message: 'The input schema differs; review required properties and constraints.' });
    else if (stable(tool.annotations || {}) !== stable(after.get(name).annotations || {})) changes.push({ breaking: true, title: 'Tool annotations changed: ' + name, message: 'The tool safety or behavior annotations changed and should be reviewed.' });
  });
  after.forEach((tool, name) => {
    if (!before.has(name)) changes.push({ breaking: false, title: 'Tool added: ' + name, message: 'A new tool is available in the current snapshot.' });
  });
  const breaking = changes.filter((change) => change.breaking).length;
  const compatible = changes.length - breaking;
  const summary = el('div', 'compare-summary');
  [['BREAKING', breaking, 'red'], ['COMPATIBLE / NEW', compatible, 'green'], ['TOOLS NOW', after.size, 'blue']].forEach(([label, value, color]) => {
    const item = el('div', 'compare-stat');
    const strong = el('strong', '', value);
    strong.style.color = color === 'red' ? 'var(--red)' : color === 'green' ? 'var(--green)' : 'var(--blue)';
    item.append(strong, el('span', '', label));
    summary.append(item);
  });
  result.append(summary);
  if (!changes.length) {
    const empty = el('div', 'empty-state compact-empty');
    empty.append(el('strong', '', 'No tool-level differences detected'), el('p', '', 'The tool names, input schemas and annotations match. Other metadata may still differ.'));
    result.append(empty);
    return;
  }
  const list = el('div', 'contract-change-list');
  changes.forEach((change) => {
    const row = el('div', 'contract-change');
    const icon = el('span', 'change-icon ' + (change.breaking ? 'breaking' : 'compatible'), change.breaking ? '!' : '+');
    const copy = el('div');
    copy.append(el('strong', '', change.title), el('p', '', change.message));
    row.append(icon, copy);
    list.append(row);
  });
  result.append(list);
  toast('Compared ' + before.size + ' baseline tools with ' + after.size + ' current tools.');
}

async function readContractFile(inputId, slot, labelId) {
  const file = byId(inputId).files[0];
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) {
    toast('Contract file exceeds the 8 MiB browser-side limit.', 'error');
    return;
  }
  try {
    state[slot] = JSON.parse(await file.text());
    byId(labelId).textContent = file.name;
  } catch {
    state[slot] = null;
    toast('The selected contract file is not valid JSON.', 'error');
  }
}

function renderFuzzReport() {
  const host = byId('fuzz-report-area');
  host.replaceChildren();
  const report = state.fuzz;
  if (!report || !Array.isArray(report.tools)) return;
  const tools = report.tools;
  let cases = 0;
  let validCases = 0;
  let executed = 0;
  let failed = 0;
  tools.forEach((tool) => {
    const candidates = Array.isArray(tool.cases) ? tool.cases : [];
    const results = Array.isArray(tool.results) ? tool.results : [];
    cases += candidates.length;
    validCases += candidates.filter((item) => item.valid_by_schema === true).length;
    executed += results.length;
    failed += results.filter((item) => ['protocol_error', 'tool_error', 'error', 'failed'].includes(item.outcome)).length;
  });
  const grid = el('div', 'fuzz-summary');
  [['TOOLS TESTED', tools.length], ['CASES GENERATED', cases], ['EXECUTED', report.executed ?? executed], ['FAILURES', failed]].forEach(([label, value]) => {
    const stat = el('div', 'fuzz-stat');
    stat.append(el('span', '', label), el('strong', '', value));
    grid.append(stat);
  });
  host.append(grid);
  const panel = el('article', 'panel');
  const heading = el('div', 'fuzz-report-heading');
  const copy = el('div');
  copy.append(el('h3', '', report.generatedAt ? 'Report · ' + formatTime(report.generatedAt) : 'Imported fuzz report'));
  copy.append(el('p', '', (report.dryRun === true ? 'Dry run — no tool calls executed' : 'Execution report') + ' · ' + validCases + ' schema-valid candidates generated'));
  heading.append(copy, el('span', 'status-pill ' + (failed ? 'error' : 'ok'), failed ? 'Findings' : 'Review results'));
  panel.append(heading);
  tools.forEach((tool) => {
    const row = el('div', 'fuzz-tool-row');
    const top = el('div', 'fuzz-tool-top');
    top.append(el('strong', '', tool.name || 'Unnamed tool'), el('span', 'fuzz-tool-meta', String((tool.cases || []).length) + ' candidates'));
    row.append(top);
    const tags = el('div', 'fuzz-results');
    (tool.cases || []).slice(0, 80).forEach((item, index) => {
      const label = item.label || item.name || ('case ' + (index + 1));
      tags.append(el('span', 'fuzz-tag ' + (item.valid_by_schema ? 'good' : 'bad'), String(label) + (item.valid_by_schema ? ' · valid' : ' · invalid')));
    });
    (tool.results || []).slice(0, 50).forEach((item) => {
      const failedResult = ['protocol_error', 'tool_error', 'error', 'failed'].includes(item.outcome);
      tags.append(el('span', 'fuzz-tag ' + (failedResult ? 'bad' : 'good'), String(item.outcome || 'result')));
    });
    if (!tags.childNodes.length) tags.append(el('span', 'fuzz-tag', 'No cases in report'));
    row.append(tags);
    panel.append(row);
  });
  host.append(panel);
}

function renderAll() {
  renderMetrics();
  renderLatencyChart();
  renderEventTables();
  renderDetails();
  renderContractEvents();
}

function navigate(view) {
  if (!viewMeta[view]) return;
  state.view = view;
  document.querySelectorAll('.view').forEach((section) => section.classList.toggle('active', section.id === 'view-' + view));
  document.querySelectorAll('[data-view]').forEach((button) => button.classList.toggle('active', button.dataset.view === view && button.classList.contains('nav-item')));
  byId('page-title').textContent = viewMeta[view][0];
  byId('page-subtitle').textContent = viewMeta[view][1];
  byId('breadcrumb-view').textContent = view.toUpperCase();
  renderAll();
}

async function loadInitialState() {
  try {
    const response = await fetch('/api/events?limit=500', { headers: { accept: 'application/json' }, cache: 'no-store' });
    if (!response.ok) throw new Error('status ' + response.status);
    const payload = await response.json();
    state.events = Array.isArray(payload.events) ? payload.events : [];
    state.summary = payload.summary || {};
    const last = state.events[state.events.length - 1];
    state.selectedId = last ? last.id : null;
    renderAll();
    setConnection(true, 'Connected to local inspector process');
    const status = await fetch('/api/status', { cache: 'no-store' }).then((item) => item.json());
    byId('app-version').textContent = 'v' + status.version;
    byId('footer-version').textContent = 'v' + status.version;
    byId('session-url').textContent = window.location.host;
  } catch {
    setConnection(false, 'Unable to read local inspector status');
  }
}

function connectStream() {
  if (!('EventSource' in window)) {
    setConnection(false, 'This browser does not support event streaming');
    return;
  }
  const stream = new EventSource('/api/stream');
  state.stream = stream;
  stream.onopen = () => setConnection(true, 'Receiving live events');
  stream.onerror = () => setConnection(false, 'Reconnecting to local event stream…');
  stream.addEventListener('inspector', (message) => {
    try {
      const event = JSON.parse(message.data);
      mergeEvent(event, false);
      if (!state.paused) renderAll();
    } catch {
      toast('An invalid event was ignored.', 'error');
    }
  });
}

function exportSession() {
  const payload = {
    exportedAt: new Date().toISOString(),
    product: 'MCP Inspector',
    privacy: 'Operational metadata only; request arguments and tool results are not captured.',
    summary: allSummary(),
    events: state.events,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'mcp-inspector-session-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  toast('Exported sanitized session metadata.');
}

document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => navigate(button.dataset.view)));
byId('global-search').addEventListener('input', () => { if (!state.paused) renderEventTables(); });
byId('trace-filter').addEventListener('change', renderEventTables);
byId('pause-stream').addEventListener('click', () => {
  state.paused = !state.paused;
  byId('pause-stream').textContent = state.paused ? 'Resume updates' : 'Pause updates';
  if (!state.paused) renderAll();
  toast(state.paused ? 'View updates paused; events continue to be buffered locally.' : 'Live view resumed.');
});
byId('export-events').addEventListener('click', exportSession);
byId('baseline-file').addEventListener('change', () => readContractFile('baseline-file', 'baseline', 'baseline-name'));
byId('current-file').addEventListener('change', () => readContractFile('current-file', 'current', 'current-name'));
byId('compare-contracts').addEventListener('click', compareContracts);
byId('fuzz-file').addEventListener('change', async () => {
  const file = byId('fuzz-file').files[0];
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) {
    toast('Report file exceeds the 8 MiB browser-side limit.', 'error');
    return;
  }
  try {
    state.fuzz = JSON.parse(await file.text());
    if (!state.fuzz || !Array.isArray(state.fuzz.tools)) throw new Error('missing tools array');
    renderFuzzReport();
    toast('Imported fuzz report locally.');
  } catch {
    state.fuzz = null;
    toast('Invalid report. Expected the JSON output from mcp-inspector fuzz.', 'error');
  }
});

loadInitialState().then(connectStream);
window.setInterval(async () => {
  try {
    const response = await fetch('/api/status', { cache: 'no-store' });
    if (!response.ok) return;
    const payload = await response.json();
    state.summary = payload.summary || {};
    if (!state.paused) renderMetrics();
  } catch { /* SSE reconnect state is shown separately. */ }
}, 5000);
