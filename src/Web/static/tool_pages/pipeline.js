// SQLiAgent V2 — Pipeline board
// Builds on top of app.js: reuses `selectedJobId`, `esc()`, `truncate()` and the
// job-selector / new-job-modal / bottom detail tabs wiring already set up there.
// This file only owns the kanban board (summary stats, columns, filters, task modal).

const v2Filters = { pending: true, running: true, done: true, error: true };
// Detector-only sub-filter, driven by the safe/vulnerable/error/discarded
// badges in that column's header (in addition to the generic state filters above).
const v2DetectorFilters = { safe: true, vulnerable: true, error: true, discarded: true };
// Crawler-only sub-filter, driven by the error badge in that column's header.
const v2CrawlerFilters = { error: true };
let v2Search = '';
let v2Interval = null;

const V2_STAT_TILES = [
    { key: 'hosts',           icon: '🖥️', label: 'Hosts' },
    { key: 'webapps',         icon: '🌐', label: 'Web apps' },
    { key: 'pages',           icon: '📄', label: 'Pages' },
    { key: 'sqli_vulnerable', icon: '⚠️', label: 'Vulnerable', cls: 'vuln' },
    { key: 'databases',       icon: '🗄️', label: 'Databases' },
    { key: 'tables',          icon: '📋', label: 'Tables' },
    { key: 'columns',         icon: '🔢', label: 'Columns' },
];

const V2_FLOW_COLUMNS = [
    { key: 'scanners',   col: 'scanner',   meta: s => ({ url: s.target_host, badge: v2StageBadge(s), logStage: 'scanner', logId: s.id }) },
    { key: 'crawlers',   col: 'crawler',   meta: c => {
        // Rows with a `web_app_id` are per-page fetch/parse-error cards merged
        // in from crawl_page (see _websqli_status's crawl_fetch_errors) - they
        // have no log of their own (the page never finished being crawled),
        // only the specific `error_message` reason already shown as a field.
        // Fetching the parent web app's whole crawl log there would show
        // unrelated pages' output instead of "why this URL failed".
        const isFetchError = c.web_app_id !== undefined && c.web_app_id !== null;
        return {
            url: c.target_url,
            badge: v2StageBadge(c),
            logStage: isFetchError ? undefined : 'crawler',
            logId: isFetchError ? undefined : c.id,
        };
    } },
    { key: 'scorers',    col: 'scorer',    meta: s => ({ url: s.target_url,  badge: v2StageBadge(s), logStage: 'scorer', logId: s.id }) },
    { key: 'detectors',  col: 'detector',  meta: d => {
        const category = v2DetectorCategory(d);
        return {
            url: d.url || d.target_url,
            badge: category === 'vulnerable' ? '🔴 Vulnerable' : category === 'safe' ? '🟢 Safe' : v2StageBadge(d),
            priority: v2PriorityBadge(d),
            extraClass: category === 'vulnerable' ? 'state-vulnerable'
                : category === 'safe' ? 'state-safe'
                : category === 'discarded' ? 'state-discarded'
                : undefined,
            logStage: 'detector',
            // SqliDetector rows (per-form errors folded in from /detector/status) carry
            // crawl_page_id; CrawlPage rows are their own id — either way this points
            // at the crawl_page whose module run actually wrote the log.
            logId: d.crawl_page_id ?? d.id,
        };
    } },
    { key: 'exploiters', col: 'exploiter', meta: e => ({ url: `DBs: ${truncate(e.databases_json || '—', 30)}`, badge: v2StageBadge(e), logStage: 'exploiter', logId: e.id }) },
];

function v2Badge(state) {
    const map = { pending: '⏳ Pending', running: '🔄 Running', done: '✅ Done', error: '❌ Error', discarded: '⏭ Discarded' };
    return map[state] || state || '—';
}

/**
 * Same as v2Badge, but an error state gets a specific reason instead of a
 * generic label, and a 'done' item that still carries an error_message
 * (e.g. a crawl that finished but had some page-level failures — see
 * SQLiAgentOrchestrator.py's _count_crawl_warnings) shows a warning instead of a
 * bare "Done".
 */
function v2StageBadge(item) {
    if (item.state === 'error') return `❌ ${v2ErrorType(item.error_message)}`;
    if (item.state === 'done' && item.error_message) return `⚠️ ${v2ErrorType(item.error_message)}`;
    return v2Badge(item.state);
}

/** Priority score/level assigned by the Scorer, shown as a badge on the Detector card. */
function v2PriorityBadge(page) {
    if (page.priority_score === null || page.priority_score === undefined) return null;
    return { score: page.priority_score, level: page.priority_level || null };
}

function v2IsVulnerable(item) {
    return item.is_vulnerable === 1 || item.is_vulnerable === true;
}

/** Classifies a Detector-column item into one of the header badge buckets,
 * or null for pending/running items that don't belong to any of them yet. */
function v2DetectorCategory(item) {
    if (v2IsVulnerable(item)) return 'vulnerable';
    if (item.state === 'error') return 'error';
    if (item.state === 'discarded') return 'discarded';
    if (item.state === 'done') return 'safe';
    return null;
}

function v2PassesDetectorFilter(item) {
    const category = v2DetectorCategory(item);
    return !category || v2DetectorFilters[category];
}

function v2PassesCrawlerFilter(item) {
    return item.state !== 'error' || v2CrawlerFilters.error;
}

function v2StateOf(item) {
    return item.state || 'pending';
}

function v2PassesFilters(item, colKey) {
    // The Detector column repurposes state='pending' to mean "vulnerable,
    // awaiting exploitation" (see WebDetector.py's new_state assignment) -
    // the opposite of what "Pending" means for every other column. Applying
    // the generic pending/running/done/error chips there would let the
    // "Pending" chip silently hide confirmed vulnerabilities. v2DetectorFilters
    // (safe/vulnerable/error/discarded, via v2DetectorCategory) already fully
    // and correctly partitions every detector item, so skip the generic
    // state filter for that column entirely and let its own sub-filter own it.
    if (colKey !== 'detector') {
        const state = v2StateOf(item);
        if (state in v2Filters && !v2Filters[state]) return false;
    }
    if (v2Search) {
        const haystack = JSON.stringify(item).toLowerCase();
        if (!haystack.includes(v2Search.toLowerCase())) return false;
    }
    return true;
}

function v2CardClass(item, meta) {
    if (meta.extraClass) return `v2-task-card ${meta.extraClass}`;
    if (item.state === 'done' && item.error_message) return 'v2-task-card state-warning';
    return `v2-task-card state-${v2StateOf(item)}`;
}

function v2RenderCard(item, meta) {
    const label = meta.url || '—';
    const withMeta = { ...item, _logStage: meta.logStage, _logId: meta.logId };
    const priorityHtml = meta.priority
        ? `<span class="v2-task-priority prio-${esc(meta.priority.level || 'none')}">📊 ${meta.priority.score}${meta.priority.level ? ` · ${esc(meta.priority.level)}` : ''}</span>`
        : '';
    return `<div class="${v2CardClass(item, meta)}" data-json="${esc(JSON.stringify(withMeta))}">
        <span class="v2-task-id">#${item.id ?? '—'}</span>
        <span class="v2-task-url" title="${esc(label)}">${truncate(label, 46)}</span>
        ${priorityHtml}
        <span class="v2-task-badge">${meta.badge}</span>
    </div>`;
}

/**
 * Renders one kanban column. `extraFilter`, when given, is applied on top of
 * the generic state/search filters to decide what's actually shown (used by
 * the Detector column's safe/vulnerable/error header toggles) — the count
 * badge reflects what's rendered, but the function still returns the list
 * filtered by state/search only, so badge *counts* (as opposed to what's
 * rendered) don't collapse to 0 when a caller hides its own category.
 */
function v2RenderColumn(colKey, items, metaFn, extraFilter) {
    const body = document.getElementById(`v2-body-${colKey}`);
    const count = document.getElementById(`v2-count-${colKey}`);
    if (!body || !count) return [];
    const stateFiltered = (items || []).filter(item => v2PassesFilters(item, colKey));
    const rendered = extraFilter ? stateFiltered.filter(extraFilter) : stateFiltered;
    count.textContent = rendered.length;
    body.innerHTML = rendered.length
        ? rendered.map(it => v2RenderCard(it, metaFn(it))).join('')
        : '<p class="v2-col-empty">Empty</p>';
    return stateFiltered;
}

/** Updates the "safe" / "vulnerable" / "error" / "discarded" sub-badges in the Detector column header. */
function v2UpdateDetectorBadges(items) {
    const safeEl = document.getElementById('v2-count-detector-safe');
    const vulnEl = document.getElementById('v2-count-detector-vulnerable');
    const errorEl = document.getElementById('v2-count-detector-error');
    const discardedEl = document.getElementById('v2-count-detector-discarded');
    if (!safeEl || !vulnEl || !errorEl || !discardedEl) return;
    let safe = 0, vulnerable = 0, error = 0, discarded = 0;
    for (const item of items) {
        const category = v2DetectorCategory(item);
        if (category === 'vulnerable') vulnerable++;
        else if (category === 'error') error++;
        else if (category === 'discarded') discarded++;
        else if (category === 'safe') safe++;
    }
    safeEl.textContent = `🟢 ${safe}`;
    vulnEl.textContent = `🔴 ${vulnerable}`;
    errorEl.textContent = `❌ ${error}`;
    discardedEl.textContent = `⏭ ${discarded}`;
}

/** Updates the "error" sub-badge in the Crawler column header. */
function v2UpdateCrawlerBadges(items) {
    const errorEl = document.getElementById('v2-count-crawler-error');
    if (!errorEl) return;
    const error = items.filter(item => item.state === 'error').length;
    errorEl.textContent = `❌ ${error}`;
}

function v2ErrorType(msg) {
    if (!msg) return 'Unknown error';
    const low = msg.toLowerCase();
    if (low.includes('timeout')) return 'Timeout / possible WAF';
    if (low.includes('form data')) return 'Form data error';
    if (low.includes('database error') || low.includes('db error')) return 'Database error';
    return truncate(msg, 40);
}

async function v2RenderStats(jobId) {
    const wrap = document.getElementById('v2-stats-tiles');
    if (!wrap) return;
    if (!jobId) {
        wrap.innerHTML = '<p class="no-agents">Select a job to see stats</p>';
        return;
    }
    try {
        const data = await API.getStats(jobId);
        const job = (data.stats || [])[0];
        if (!job) { wrap.innerHTML = '<p class="no-agents">No stats yet</p>'; return; }
        wrap.innerHTML = V2_STAT_TILES.map(t => `
            <div class="v2-stat-tile${t.cls ? ' ' + t.cls : ''}">
                <span class="v2-stat-icon">${t.icon}</span>
                <span class="v2-stat-value">${job[t.key] ?? 0}</span>
                <span class="v2-stat-label">${t.label}</span>
            </div>`).join('');
    } catch (err) {
        console.error('v2: error loading stats', err);
        wrap.innerHTML = '<p class="no-agents">Error loading stats</p>';
    }
}

const V2_ALL_COLUMNS = ['scanner', 'crawler', 'scorer', 'detector', 'exploiter'];

/** Shows the page body only once a job is selected; otherwise shows the empty state. */
function v2UpdateBodyVisibility() {
    const body  = document.getElementById('v2-body');
    const empty = document.getElementById('v2-empty-state');
    if (!body || !empty) return;
    body.style.display  = selectedJobId ? 'flex' : 'none';
    empty.style.display = selectedJobId ? 'none' : 'flex';
}

async function v2Refresh() {
    v2UpdateBodyVisibility();
    if (!selectedJobId) {
        V2_ALL_COLUMNS.forEach(col => v2RenderColumn(col, [], () => ({})));
        v2UpdateDetectorBadges([]);
        v2RenderStats(null);
        return;
    }
    let status = {};
    try {
        status = await API.getWebSQLIStatus(selectedJobId);
    } catch (err) {
        console.error('v2: error fetching pipeline status', err);
    }

    let detections = [];
    try {
        const detData = await API.getDetectorStatus(selectedJobId);
        detections = detData.detections || [];
    } catch (err) {
        console.error('v2: error fetching detector status', err);
    }

    // A failed/discarded form/URL check doesn't change its whole crawl_page's
    // state (stays 'done'), so it wouldn't otherwise show up under Detector —
    // fold those sqli_detector rows in here.
    const detectorExtras = detections.filter(d => d.state === 'error' || d.state === 'discarded');

    for (const { key, col, meta } of V2_FLOW_COLUMNS) {
        const items = col === 'detector' ? [...(status[key] || []), ...detectorExtras] : (status[key] || []);
        const extraFilter = col === 'detector' ? v2PassesDetectorFilter : col === 'crawler' ? v2PassesCrawlerFilter : null;
        const stateFiltered = v2RenderColumn(col, items, meta, extraFilter);
        if (col === 'detector') v2UpdateDetectorBadges(stateFiltered);
        if (col === 'crawler') v2UpdateCrawlerBadges(stateFiltered);
    }

    v2RenderStats(selectedJobId);
}

// ------------------------------------------------------------------
// Filters
// ------------------------------------------------------------------

document.querySelectorAll('.v2-filter-chip').forEach(chip => {
    chip.addEventListener('click', () => {
        const state = chip.dataset.state;
        v2Filters[state] = !v2Filters[state];
        chip.classList.toggle('active', v2Filters[state]);
        v2Refresh();
    });
});

document.querySelectorAll('[data-detector-filter]').forEach(badge => {
    badge.addEventListener('click', () => {
        const category = badge.dataset.detectorFilter;
        v2DetectorFilters[category] = !v2DetectorFilters[category];
        badge.classList.toggle('active', v2DetectorFilters[category]);
        v2Refresh();
    });
});

document.querySelectorAll('[data-crawler-filter]').forEach(badge => {
    badge.addEventListener('click', () => {
        const category = badge.dataset.crawlerFilter;
        v2CrawlerFilters[category] = !v2CrawlerFilters[category];
        badge.classList.toggle('active', v2CrawlerFilters[category]);
        v2Refresh();
    });
});

document.getElementById('v2-search')?.addEventListener('input', (e) => {
    v2Search = e.target.value.trim();
    v2Refresh();
});

document.getElementById('v2-refresh-btn')?.addEventListener('click', v2Refresh);

// ------------------------------------------------------------------
// Task detail modal — v2OpenTaskModal() itself, and its close handlers,
// live in app.js since it's shared with the plain Results tables (index.html
// and tools.html load app.js; the kanban board lives on index.html).
// ------------------------------------------------------------------

document.getElementById('v2-board')?.addEventListener('click', (e) => {
    const card = e.target.closest('.v2-task-card');
    if (!card) return;
    let data;
    try { data = JSON.parse(card.dataset.json); } catch (err) { return; }
    v2OpenTaskModal(data);
});

// ------------------------------------------------------------------
// Job selector — app.js already updates `selectedJobId` on 'change'
// before this listener runs (script load order: api.js, app.js, pipeline.js).
// ------------------------------------------------------------------

document.getElementById('job-selector')?.addEventListener('change', () => {
    v2Refresh();
});

// ------------------------------------------------------------------
// Init
// ------------------------------------------------------------------

v2Refresh();
v2Interval = setInterval(v2Refresh, 5000);
