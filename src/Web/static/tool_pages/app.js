// WebScanner Frontend Application
// UI Logic and Orchestration

// ============================================================================
// SQLIAGENT - BOTTOM BAR
// ============================================================================

// ============================================================================
// SQLIAGENT - STATE VARIABLES
// ============================================================================

let sqlicIsRunning = false;
let sqlicAgentsInterval = null;
let sqlicScannerInterval = null;
let sqlicCrawlerInterval = null;
let sqlicDetectorInterval = null;
let sqlicExploiterInterval = null;
let sqlicDumperInterval   = null;

// Active job filter (null = no job selected -> panels show no data)
let selectedJobId   = null;
let selectedJobType = null;

const EMPTY_WEBSQLI_STATUS = { scanners: [], crawlers: [], detectors: [], exploiters: [], scorers: [] };

// ============================================================================
// SQLIAGENT - JOB SELECTOR
// ============================================================================

async function loadJobsSelector() {
    try {
        const data = await API.getJobs();
        const jobs = data.jobs || [];
        const sel = document.getElementById('job-selector');
        if (!sel) return;
        const currentVal = sel.value;
        sel.innerHTML = '<option value="">— Select a job —</option>';
        for (const j of jobs) {
            const type    = j.type || 'Normal';
            const model   = j.model ? ` · ${j.model}` : '';
            const target  = j.target_url ? ` ${j.target_url}` : '';
            const comment = j.comment ? ` — ${j.comment}` : '';
            const ts      = j.timestamp ? ' (' + String(j.timestamp).slice(0, 10) + ')' : '';
            const running = j.state === 'running' ? ' 🔄' : '';
            const opt = document.createElement('option');
            opt.value = j.id;
            opt.textContent = `Job #${j.id}${running} — ${type}${model}${target}${comment}${ts}`;
            sel.appendChild(opt);
        }
        // Restore selection if still valid
        if (currentVal && [...sel.options].some(o => o.value === currentVal)) {
            sel.value = currentVal;
        }
    } catch (err) {
        console.error('Error loading jobs selector:', err);
    }
}

function renderJobInfoPanel(job) {
    const panel = document.getElementById('job-info-panel');
    if (!panel) return;
    if (!job) {
        panel.innerHTML = '<p class="job-info-empty">No job selected.<br>Use the selector above to view a specific job,<br>or <strong>+ New Job</strong> to launch a new analysis.</p>';
        selectedJobType = null;
        sqlicUpdateJobStats(null);
        return;
    }
    const type     = job.type || 'Normal';
    selectedJobType = type;
    const isIA     = type === 'IA';
    const state    = job.state || 'done';
    const isRunning = state === 'running';
    const stateBadge = isRunning
        ? '<span class="job-state-badge running">🔄 Running</span>'
        : state === 'error'
            ? '<span class="job-state-badge error">❌ Error</span>'
            : '<span class="job-state-badge done">✅ Done</span>';
    const ts         = job.timestamp   ? String(job.timestamp).slice(0, 19).replace('T', ' ')   : '—';
    const finishedTs = job.finished_at ? String(job.finished_at).slice(0, 19).replace('T', ' ') : null;
    panel.innerHTML = `
        <div class="job-info-card">
            <div class="job-id-line">
                Job #${job.id}
                <span class="job-badge${isIA ? ' ia' : ''}">${escapeHtml(type)}</span>
                ${stateBadge}
                <button class="job-delete-btn" onclick="deleteSelectedJob(${job.id})" title="Delete this job and all its data">🗑 Delete</button>
            </div>
            <div class="job-meta">
                ${job.target_url ? `<span class="lbl">Target</span><span>${escapeHtml(job.target_url)}</span>` : ''}
                ${job.model ? `<span class="lbl">Model</span><span>${escapeHtml(job.model)}</span>` : ''}
                <span class="lbl">Depth</span><span>${job.depth ?? 4}</span>
                <span class="lbl">Started</span><span>${ts}</span>
                ${finishedTs ? `<span class="lbl">Finished</span><span>${finishedTs}</span>` : ''}
            </div>
            ${job.comment ? `<div class="job-comment">"${escapeHtml(job.comment)}"</div>` : ''}
        </div>`;
    sqlicUpdateJobStats(job.id);
}

/** Shows the page body only once a job is selected; otherwise shows the empty state. */
function sqlicUpdateBodyVisibility() {
    const body  = document.getElementById('sqlic-body');
    const empty = document.getElementById('sqlic-empty-state');
    if (!body || !empty) return;
    body.style.display  = selectedJobId ? 'flex' : 'none';
    empty.style.display = selectedJobId ? 'none' : 'flex';
}

async function deleteSelectedJob(jobId) {
    if (!confirm(`Delete Job #${jobId} and ALL its data? This cannot be undone.`)) return;
    try {
        await API.deleteJob(jobId);
        selectedJobId   = null;
        selectedJobType = null;
        renderJobInfoPanel(null);
        sqlicUpdateBodyVisibility();
        await loadJobsSelector();
        sqlicUpdateScannerStatus();
        sqlicUpdateCrawlerStatus(true);
        sqlicUpdateDetectorStatus(true);
        sqlicUpdateExploiterStatus(true);
        sqlicUpdateDumperStatus(true);
    } catch (err) {
        alert('Error deleting job: ' + err.message);
    }
}

document.getElementById('job-selector')?.addEventListener('change', async (e) => {
    const val = e.target.value;
    selectedJobId = val ? parseInt(val, 10) : null;
    sqlicUpdateBodyVisibility();
    if (selectedJobId) {
        // Fetch the selected job details for the info panel
        try {
            const data = await API.getScannerStatus(selectedJobId);
            const job = (data.jobs || [])[0] || null;
            renderJobInfoPanel(job);
        } catch (_) { renderJobInfoPanel(null); }
    } else {
        renderJobInfoPanel(null);
    }
    // Refresh all panels with the new filter
    sqlicUpdateScannerStatus();
    sqlicUpdateCrawlerStatus(true);
    sqlicUpdateDetectorStatus(true);
    sqlicUpdateExploiterStatus(true);
    sqlicUpdateDumperStatus(true);
});

/** Selects a newly-created job in the dropdown once it exists in the DB,
 * reusing the normal 'change' handling (this page's, plus the pipeline board's
 * when present) via a real dispatched event instead of duplicating it. */
async function autoSelectNewJob(jobId) {
    await loadJobsSelector();
    const sel = document.getElementById('job-selector');
    if (!sel) return;
    if (![...sel.options].some(o => o.value === String(jobId))) return;
    sel.value = String(jobId);
    sel.dispatchEvent(new Event('change'));
}

// Load selector on page load
loadJobsSelector();
sqlicUpdateBodyVisibility();

// Start agent auto-refresh on page load (every 5s, always)
sqlicUpdateAgents();
sqlicAgentsInterval = setInterval(sqlicUpdateAgents, 5000);

// ============================================================================
// SQLIAGENT - MODAL (New Job)
// ============================================================================

let modalMode = 'iterative';

function applyModalMode(mode) {
    modalMode = mode;
    document.querySelectorAll('#new-job-modal .sqlic-mode-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
    });
}

// Fetched once from .env's DEFAULT_TARGET_URL (via GET /api/config) and
// reused every time the New Job modal opens, instead of hardcoding it here.
let defaultTargetUrl = '';
API.getConfig().then(cfg => { defaultTargetUrl = cfg.default_target_url || ''; }).catch(() => {});

document.getElementById('open-new-job-modal-btn')?.addEventListener('click', () => {
    document.getElementById('new-job-modal').style.display = 'flex';
    const urlInput = document.getElementById('modal-target-url');
    if (urlInput && !urlInput.value) urlInput.value = defaultTargetUrl;
    urlInput?.focus();
});

document.getElementById('close-new-job-modal-btn')?.addEventListener('click', () => {
    document.getElementById('new-job-modal').style.display = 'none';
    document.getElementById('modal-status').textContent = '';
});

document.getElementById('new-job-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) {
        document.getElementById('new-job-modal').style.display = 'none';
        document.getElementById('modal-status').textContent = '';
    }
});

document.querySelectorAll('#new-job-modal .sqlic-mode-btn').forEach(btn => {
    btn.addEventListener('click', () => applyModalMode(btn.dataset.mode));
});

function modalSetStatus(msg, type) {
    const el = document.getElementById('modal-status');
    if (!el) return;
    el.textContent = msg;
    el.className = 'status-message' + (type ? ` ${type}` : '');
}

document.getElementById('modal-start-btn')?.addEventListener('click', async () => {
    if (sqlicIsRunning) return;

    const url = document.getElementById('modal-target-url')?.value.trim();
    if (!url) { modalSetStatus('⚠️ Please enter a target URL', 'error'); return; }

    const depthRaw = parseInt(document.getElementById('modal-depth')?.value || '4', 10);
    const depth = (depthRaw > 0 && depthRaw <= 20) ? depthRaw : 4;
    const comment = document.getElementById('modal-comment')?.value.trim() || null;

    sqlicIsRunning = true;
    const btn = document.getElementById('modal-start-btn');
    if (btn) { btn.querySelector('.btn-text').textContent = 'Running...'; btn.disabled = true; }
    modalSetStatus('🚀 Starting pipeline...', '');

    // Start auto-refresh for scanner (agents already refresh globally every 5s)
    sqlicUpdateAgents();
    if (!sqlicScannerInterval) {
        sqlicScannerInterval = setInterval(sqlicUpdateScannerStatus, 5000);
    }
    sqlicUpdateScannerStatus();
    sqlicUpdateCrawlerStatus(true);

    try {
        const { reader } = await API.startWebSQLI({ url, mode: modalMode, depth, comment });

        // Close modal immediately — job is running, data will appear in the panels
        document.getElementById('new-job-modal').style.display = 'none';
        document.getElementById('modal-status').textContent = '';
        document.getElementById('modal-target-url').value = '';
        document.getElementById('modal-comment').value = '';
        if (btn) { btn.querySelector('.btn-text').textContent = 'Start Pipeline'; btn.disabled = false; }
        await loadJobsSelector();

        // Continue consuming the stream in the background to reset state when done
        let jobAutoSelected = false;
        const processor = new StreamProcessor();
        processor
            .onData((line) => {
                if (jobAutoSelected) return;
                const match = line.match(/Job creado: ID=(\d+)/);
                if (match) {
                    jobAutoSelected = true;
                    autoSelectNewJob(parseInt(match[1], 10));
                }
            })
            .onComplete(() => { sqlicIsRunning = false; })
            .onError((err) => {
                console.error('Pipeline error:', err);
                sqlicIsRunning = false;
            });
        await processor.process(reader);
    } catch (err) {
        modalSetStatus(`❌ Error: ${err.message}`, 'error');
        sqlicIsRunning = false;
        if (btn) { btn.querySelector('.btn-text').textContent = 'Start Pipeline'; btn.disabled = false; }
    }
});

document.getElementById('modal-target-url')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !sqlicIsRunning) document.getElementById('modal-start-btn')?.click();
});

// ============================================================================
// SQLIAGENT - PIPELINE MODE (Iterative / IA)  [kept for agent panel toggle]
// ============================================================================

let sqlicMode = 'iterative'; // 'iterative' | 'ia'

function applySqlicMode(mode) {
    sqlicMode = mode;
    document.querySelectorAll('.sqlic-mode-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
    });
}

document.querySelectorAll('.sqlic-mode-btn').forEach(btn => {
    btn.addEventListener('click', () => applySqlicMode(btn.dataset.mode));
});

document.querySelectorAll('.sqlic-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const panelId = tab.getAttribute('data-panel');

        // Update active tab
        document.querySelectorAll('.sqlic-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        // Show corresponding panel
        document.querySelectorAll('.sqlic-panel').forEach(p => p.classList.remove('active'));
        const target = document.getElementById(panelId);
        if (target) target.classList.add('active');

        // Manage polling for the Scanner panel
        if (panelId === 'sqlic-scanner') {
            if (!sqlicScannerInterval) {
                sqlicUpdateScannerStatus();
                sqlicScannerInterval = setInterval(sqlicUpdateScannerStatus, 5000);
            }
        } else {
            if (sqlicScannerInterval) {
                clearInterval(sqlicScannerInterval);
                sqlicScannerInterval = null;
            }
        }

        // Manage polling for the Crawler panel
        if (panelId === 'sqlic-crawler') {
            if (!sqlicCrawlerInterval) {
                sqlicUpdateCrawlerStatus(true);
                sqlicCrawlerInterval = setInterval(sqlicUpdateCrawlerStatus, 5000);
            }
        } else {
            if (sqlicCrawlerInterval) {
                clearInterval(sqlicCrawlerInterval);
                sqlicCrawlerInterval = null;
            }
        }

        // Manage polling for the Detector panel
        if (panelId === 'sqlic-detector') {
            if (!sqlicDetectorInterval) {
                sqlicUpdateDetectorStatus(true);
                sqlicDetectorInterval = setInterval(sqlicUpdateDetectorStatus, 5000);
            }
        } else {
            if (sqlicDetectorInterval) {
                clearInterval(sqlicDetectorInterval);
                sqlicDetectorInterval = null;
            }
        }

        // Manage polling for the Exploiter panel
        if (panelId === 'sqlic-exploiter') {
            if (!sqlicExploiterInterval) {
                sqlicUpdateExploiterStatus(true);
                sqlicExploiterInterval = setInterval(sqlicUpdateExploiterStatus, 5000);
            }
        } else {
            if (sqlicExploiterInterval) {
                clearInterval(sqlicExploiterInterval);
                sqlicExploiterInterval = null;
            }
        }

        // Manage polling for the Dumper panel
        if (panelId === 'sqlic-dumper') {
            if (!sqlicDumperInterval) {
                sqlicUpdateDumperStatus(true);
                sqlicDumperInterval = setInterval(sqlicUpdateDumperStatus, 5000);
            }
        } else {
            if (sqlicDumperInterval) {
                clearInterval(sqlicDumperInterval);
                sqlicDumperInterval = null;
            }
        }
    });
});

// ============================================================================
// SQLIAGENT - SCANNER PANEL
// ============================================================================


function sqlicSetStatus(msg, type = '') {
    const el = document.getElementById('sqlic-status');
    if (!el) return;
    el.textContent = msg;
    el.className = 'status-message' + (type ? ` ${type}` : '');
    el.style.display = msg ? 'block' : 'none';
}

/** Renders a single scanner agent card */
function scannerAgentCardHtml(s) {
    const label = s.state === 'running' ? '🔄 Running'
                : s.state === 'done'    ? '✅ Done'
                : s.state === 'error'   ? '❌ Error'
                : s.state;
    const cls = s.state === 'error' ? 'error' : (s.state || 'running');
    return `<div class="agent-card ${cls}">
        <div class="agent-info">
            <span class="agent-id">Host ID: ${s.id}</span>
            <span class="agent-url">${s.target_host || 'N/A'}</span>
        </div>
        <div class="agent-status"><span class="status-badge ${cls}">${label}</span></div>
    </div>`;
}

/** Renders a single crawler agent card */
function crawlerAgentCardHtml(c) {
    const label = c.state === 'running' ? '🔄 Running'
                : c.state === 'done'    ? '✅ Done'
                : c.state === 'pending' ? '⏳ Pending'
                : c.state;
    return `<div class="agent-card ${c.state}">
        <div class="agent-info">
            <span class="agent-id">ID: ${c.id}</span>
            <span class="agent-url">${c.target_url || 'N/A'}</span>
        </div>
        <div class="agent-status"><span class="status-badge ${c.state}">${label}</span></div>
    </div>`;
}

/** Renders a single detector agent card */
function detectorAgentCardHtml(d) {
    const isVuln = d.is_vulnerable === 1 || d.is_vulnerable === '1';
    let badge;
    if (d.state === 'running')      badge = '<span class="status-badge running">🔄 Running</span>';
    else if (d.state === 'pending') badge = '<span class="status-badge pending">⏳ Pending</span>';
    else if (d.state === 'done')    badge = isVuln
        ? '<span class="status-badge vulnerable">⚠️ Vulnerable</span>'
        : '<span class="status-badge safe">✅ Safe</span>';
    else                            badge = `<span class="status-badge">${d.state}</span>`;
    return `<div class="agent-card ${d.state}${isVuln ? ' vulnerable' : ''}">
        <div class="agent-info">
            <span class="agent-id">Page ID: ${d.id}</span>
            <span class="agent-url">${d.url || 'N/A'}</span>
        </div>
        <div class="agent-status">${badge}</div>
    </div>`;
}

/** Renders a single exploiter agent card */
function exploiterAgentCardHtml(e) {
    const label = e.state === 'running' ? '🔄 Running'
                : e.state === 'done'    ? '✅ Done'
                : e.state === 'pending' ? '⏳ Pending'
                : e.state === 'error'   ? '❌ Error'
                : e.state;
    const cls = e.state === 'error' ? 'error' : e.state;
    return `<div class="agent-card ${cls}">
        <div class="agent-info">
            <span class="agent-id">Exploit ID: ${e.id} (Detector: ${e.sqli_detector_id || '—'})</span>
            <span class="agent-url">DBs: ${truncate(e.databases_json, 50)}</span>
        </div>
        <div class="agent-status"><span class="status-badge ${cls}">${label}</span></div>
    </div>`;
}

/** Renders a single scorer agent card (IA mode) */
function scorerAgentCardHtml(s) {
    const label = s.state === 'running' ? '🔄 Running'
                : s.state === 'done'    ? '✅ Done'
                : s.state === 'pending' ? '⏳ Pending'
                : s.state === 'error'   ? '❌ Error'
                : (s.state || 'pending');
    const cls = s.state === 'error' ? 'error' : (s.state || 'pending');
    return `<div class="agent-card ${cls}">
        <div class="agent-info">
            <span class="agent-id">Page ID: ${s.id}</span>
            <span class="agent-url">${s.target_url || 'N/A'}</span>
        </div>
        <div class="agent-status"><span class="status-badge ${cls}">${label}</span></div>
    </div>`;
}

/** Renders crawlers/detectors/exploiters lists into the given element IDs */
function renderAgentLists(status, crawlersElId, detectorsElId, exploitersElId) {
    // Scanners
    const scannersList = document.getElementById('sqlic-scanners-list');
    if (scannersList) {
        scannersList.innerHTML = (status.scanners && status.scanners.length > 0)
            ? status.scanners.map(scannerAgentCardHtml).join('')
            : '<p class="no-agents">No active scanners</p>';
    }

    const crawlersList   = document.getElementById(crawlersElId);
    const detectorsList  = document.getElementById(detectorsElId);
    const exploitersList = exploitersElId ? document.getElementById(exploitersElId) : null;
    if (crawlersList) {
        crawlersList.innerHTML = (status.crawlers && status.crawlers.length > 0)
            ? status.crawlers.map(crawlerAgentCardHtml).join('')
            : '<p class="no-agents">No active crawlers</p>';
    }
    if (detectorsList) {
        detectorsList.innerHTML = (status.detectors && status.detectors.length > 0)
            ? status.detectors.map(detectorAgentCardHtml).join('')
            : '<p class="no-agents">No active detectors</p>';
    }
    if (exploitersList) {
        exploitersList.innerHTML = (status.exploiters && status.exploiters.length > 0)
            ? status.exploiters.map(exploiterAgentCardHtml).join('')
            : '<p class="no-agents">No active exploiters</p>';
    }

    // Scorer section — only meaningful in IA mode, but always update content
    const scorersList = document.getElementById('sqlic-scorers-list');
    if (scorersList) {
        scorersList.innerHTML = (status.scorers && status.scorers.length > 0)
            ? status.scorers.map(scorerAgentCardHtml).join('')
            : '<p class="no-agents">No active scorers</p>';
    }
}

async function sqlicUpdateAgents() {
    if (!selectedJobId) {
        renderAgentLists(EMPTY_WEBSQLI_STATUS, 'sqlic-crawlers-list', 'sqlic-detectors-list', 'sqlic-exploiters-list');
        return;
    }
    try {
        const status = await API.getWebSQLIStatus(selectedJobId);
        renderAgentLists(status, 'sqlic-crawlers-list', 'sqlic-detectors-list', 'sqlic-exploiters-list');
    } catch (err) {
        console.error('Error updating SQLiAgent agents:', err);
    }
}

// ============================================================================
// SQLIAGENT - SCANNER DATA PANEL
// ============================================================================

function stateBadgeHtml(state) {
    const map = { done: '✅ Done', running: '🔄 Running', pending: '⏳ Pending', error: '❌ Error' };
    const label = map[state] || state;
    return `<span class="state-badge state-${state || 'pending'}">${label}</span>`;
}

function truncate(str, max = 60) {
    if (!str) return '—';
    return str.length > max ? str.substring(0, max) + '…' : str;
}

/** Escapes a string for safe use inside an HTML attribute value */
function esc(s) {
    return s ? String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;') : '';
}

/** Returns ✅ for truthy 1/'1', — otherwise */
function boolCol(v) {
    return (v === 1 || v === '1') ? '\u2705' : '\u2014';
}

/**
 * Renders a scanner data section: updates count badge and innerHTML.
 * @param {string} wrapId   - id of the table-wrap element
 * @param {string} countId  - id of the count badge element
 * @param {string} html     - rendered table HTML (or empty-state message)
 * @param {number} count    - total row count
 */
function renderScannerSection(wrapId, countId, html, count) {
    const wrap  = document.getElementById(wrapId);
    const badge = document.getElementById(countId);
    if (!wrap) return;
    if (badge) badge.textContent = count;
    wrap.innerHTML = html;
}

/**
 * Registers prev/next pagination button listeners for a paginated panel section.
 * @param {string}   prevId    - id of the Prev button
 * @param {string}   nextId    - id of the Next button
 * @param {Function} getIndex  - () => current page index
 * @param {Function} setIndex  - (i) => void  sets page index
 * @param {Function} getLen    - () => total number of rows
 * @param {Function} getSize   - () => page size
 * @param {Function} render    - () => void  re-renders the page
 */
function bindPaginationBtns(prevId, nextId, getIndex, setIndex, getLen, getSize, render) {
    document.getElementById(prevId)?.addEventListener('click', () => {
        if (getIndex() > 0) { setIndex(getIndex() - 1); render(); }
    });
    document.getElementById(nextId)?.addEventListener('click', () => {
        const totalPages = Math.ceil(getLen() / getSize());
        if (getIndex() < totalPages - 1) { setIndex(getIndex() + 1); render(); }
    });
}

/**
 * Generic pagination renderer — updates wrap, count badge, prev/next buttons and info span.
 * @param {Object} cfg
 * @param {Array}    cfg.data       full data array
 * @param {number}   cfg.pageIndex  current page index
 * @param {number}   cfg.pageSize   rows per page
 * @param {string}   cfg.wrapId
 * @param {string}   cfg.countId
 * @param {string}   cfg.prevId
 * @param {string}   cfg.nextId
 * @param {string}   cfg.infoId
 * @param {Function} cfg.renderFn   (slice) => HTML string
 */
function renderPaginatedSection(cfg) {
    const { data, pageIndex, pageSize, wrapId, countId, prevId, nextId, infoId, renderFn } = cfg;
    const total    = data.length;
    const slice    = data.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize);
    const totalPgs = Math.max(1, Math.ceil(total / pageSize));

    const wrap  = document.getElementById(wrapId);
    const count = document.getElementById(countId);
    const prev  = document.getElementById(prevId);
    const next  = document.getElementById(nextId);
    const info  = document.getElementById(infoId);

    if (count) count.textContent = total;
    if (wrap)  wrap.innerHTML    = renderFn(slice);

    const from = total === 0 ? 0 : pageIndex * pageSize + 1;
    const to   = Math.min((pageIndex + 1) * pageSize, total);
    if (info)  info.textContent  = `${from}\u2013${to} of ${total}`;
    if (prev)  prev.disabled     = pageIndex === 0;
    if (next)  next.disabled     = pageIndex >= totalPgs - 1;
}

async function sqlicUpdateScannerStatus() {
    if (!selectedJobId) {
        renderScannerSection('scanner-hosts-table-wrap', 'scanner-hosts-count', '<p class="no-agents">No job selected</p>', 0);
        renderScannerSection('scanner-webapps-table-wrap', 'scanner-webapps-count', '<p class="no-agents">No job selected</p>', 0);
        renderScannerSection('scanner-nmap-table-wrap', 'scanner-nmap-count', '<p class="no-agents">No job selected</p>', 0);
        return;
    }
    try {
        const data = await API.getScannerStatus(selectedJobId);

        const jobs    = data.jobs    || [];
        const hosts   = data.hosts   || [];
        const webapps = data.webapps || [];
        const nmap    = data.nmap    || [];

        // --- Hosts ---
        renderScannerSection('scanner-hosts-table-wrap', 'scanner-hosts-count',
            hosts.length > 0
                ? `<table><thead><tr>
                        <th>ID</th><th>Job</th><th>Host</th><th>State</th><th>Timestamp</th><th>Details</th>
                   </tr></thead><tbody>${hosts.map(h => `
                        <tr>
                            <td>${h.id}</td>
                            <td>${h.jobs_id || '\u2014'}</td>
                            <td title="${esc(h.target_host)}">${truncate(h.target_host, 40)}</td>
                            <td>${stateBadgeHtml(h.state)}</td>
                            <td>${h.timestamp || '\u2014'}</td>
                            <td>${resultsDetailsBtn(h, 'scanner', h.id)}</td>
                        </tr>`).join('')}
                   </tbody></table>`
                : '<p class="no-agents">No hosts yet</p>',
            hosts.length);

        // --- Web Apps ---
        renderScannerSection('scanner-webapps-table-wrap', 'scanner-webapps-count',
            webapps.length > 0
                ? `<table><thead><tr>
                        <th>ID</th><th>Host</th><th>URL</th><th>HTTP</th>
                        <th>Redirect</th><th>Technologies</th><th>Cookies</th>
                        <th>Headers</th><th>Uncommon Headers</th><th>State</th><th>Timestamp</th><th>Job</th><th>Details</th>
                   </tr></thead><tbody>${webapps.map(w => `
                        <tr>
                            <td>${w.id}</td>
                            <td>${w.host_id || '\u2014'}</td>
                            <td title="${esc(w.target_url)}">${truncate(w.target_url, 50)}</td>
                            <td>${w.http_status || '\u2014'}</td>
                            <td title="${esc(w.redirect_location)}">${truncate(w.redirect_location, 40)}</td>
                            <td title="${esc(w.technologies_json)}">${truncate(w.technologies_json, 40)}</td>
                            <td title="${esc(w.cookies_json)}">${truncate(w.cookies_json, 40)}</td>
                            <td title="${esc(w.headers_json)}">${truncate(w.headers_json, 40)}</td>
                            <td title="${esc(w.uncommon_headers_json)}">${truncate(w.uncommon_headers_json, 40)}</td>
                            <td>${stateBadgeHtml(w.state)}</td>
                            <td>${w.timestamp || '\u2014'}</td>
                            <td>${w.jobs_id || '\u2014'}</td>
                            <td>${resultsDetailsBtn(w, 'crawler', w.id)}</td>
                        </tr>`).join('')}
                   </tbody></table>`
                : '<p class="no-agents">No web apps yet</p>',
            webapps.length);

        // --- Nmap ---
        renderScannerSection('scanner-nmap-table-wrap', 'scanner-nmap-count',
            nmap.length > 0
                ? `<table><thead><tr>
                        <th>ID</th><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Job</th><th>Details</th>
                   </tr></thead><tbody>${nmap.map(n => `
                        <tr>
                            <td>${n.id}</td>
                            <td>${n.host_id || '\u2014'}</td>
                            <td>${n.port || '\u2014'}</td>
                            <td>${stateBadgeHtml(n.nmap_state)}</td>
                            <td>${n.nmap_service || '\u2014'}</td>
                            <td title="${esc(n.nmap_version)}">${truncate(n.nmap_version, 30)}</td>
                            <td>${n.jobs_id || '\u2014'}</td>
                            <td>${resultsDetailsBtn(n, null, null)}</td>
                        </tr>`).join('')}
                   </tbody></table>`
                : '<p class="no-agents">No nmap results yet</p>',
            nmap.length);

    } catch (err) {
        console.error('Error updating scanner status:', err);
    }
}

// Refresh manual button
document.getElementById('scanner-manual-refresh')?.addEventListener('click', () => {
    sqlicUpdateScannerStatus();
});

// Initial load of scanner data (Scanner tab is active by default)
sqlicUpdateScannerStatus();
sqlicScannerInterval = setInterval(sqlicUpdateScannerStatus, 5000);

// ============================================================================
// COLLAPSIBLE SECTION HEADERS
// ============================================================================

document.addEventListener('click', (e) => {
    const header = e.target.closest('.scanner-section-header.collapsible');
    if (!header) return;
    const section = header.closest('.scanner-data-section');
    if (!section) return;
    const isCollapsed = header.classList.contains('collapsed');
    // Toggle all .section-body siblings inside this section
    section.querySelectorAll('.section-body').forEach(el => {
        el.style.display = isCollapsed ? '' : 'none';
    });
    header.classList.toggle('collapsed', !isCollapsed);
});

// ============================================================================
// SQLIAGENT - CRAWLER DATA PANEL
// ============================================================================

const crawlerState = {
    pages:        [],
    details:      [],
    nikto:        [],
    pageIndexP:   0,   // current page index for crawl_page
    pageIndexD:   0,   // current page index for crawl_page_details
    pageIndexN:   0,   // current page index for host_web_app_nikto
    pageSize:     50
};

function renderCrawlPagesTable(rows) {
    if (!rows || rows.length === 0) return '<p class="no-agents">No crawl pages yet</p>';
    return `<table>
        <thead><tr>
            <th>ID</th><th>WebApp</th><th>URL</th><th>Base URL</th>
            <th>Admin</th><th>Login</th><th>Register</th><th>Search</th>
            <th>Upload</th><th>No CSRF</th><th>Errors</th><th>Params URL</th>
            <th>Robots</th><th>GET</th><th>POST</th>
            <th>Priority Score</th><th>Priority Level</th>
            <th>State</th><th>Timestamp</th><th>Job</th><th>Depth</th><th>Details</th>
        </tr></thead>
        <tbody>${rows.map(p => `
            <tr>
                <td>${p.id}</td>
                <td>${p.web_app_id || '\u2014'}</td>
                <td title="${esc(p.url)}">${truncate(p.url, 50)}</td>
                <td title="${esc(p.base_url)}">${truncate(p.base_url, 40)}</td>
                <td>${boolCol(p.is_admin_path)}</td>
                <td>${boolCol(p.has_login_form)}</td>
                <td>${boolCol(p.has_register_form)}</td>
                <td>${boolCol(p.has_search_form)}</td>
                <td>${boolCol(p.has_upload_form)}</td>
                <td>${boolCol(p.has_form_without_csrf)}</td>
                <td>${boolCol(p.has_errors)}</td>
                <td>${boolCol(p.has_parametres_url)}</td>
                <td>${boolCol(p.is_referred_robots)}</td>
                <td>${boolCol(p.has_get_params)}</td>
                <td>${boolCol(p.has_post_params)}</td>
                <td>${p.priority_score ?? '\u2014'}</td>
                <td>${p.priority_level ?? '\u2014'}</td>
                <td>${stateBadgeHtml(p.state)}</td>
                <td>${p.timestamp || '\u2014'}</td>
                <td>${p.jobs_id || '\u2014'}</td>
                <td>${p.depth || '\u2014'}</td>
                <td>${resultsDetailsBtn(p, 'detector', p.id)}</td>
            </tr>`).join('')}
        </tbody>
    </table>`;
}

function renderCrawlDetailsTable(rows) {
    if (!rows || rows.length === 0) return '<p class="no-agents">No crawl page details yet</p>';
    return `<table>
        <thead><tr>
            <th>ID</th><th>Page ID</th><th>Forms</th>
            <th>Standalone Inputs</th><th>URL Params</th><th>Error Details</th>
            <th>State</th><th>Timestamp</th><th>Job</th><th>Details</th>
        </tr></thead>
        <tbody>${rows.map(d => `
            <tr>
                <td>${d.id}</td>
                <td>${d.crawl_page_id || '\u2014'}</td>
                <td title="${esc(d.forms_json)}">${truncate(d.forms_json, 50)}</td>
                <td title="${esc(d.standalone_inputs_json)}">${truncate(d.standalone_inputs_json, 50)}</td>
                <td title="${esc(d.url_params_json)}">${truncate(d.url_params_json, 50)}</td>
                <td title="${esc(d.error_details_json)}">${truncate(d.error_details_json, 50)}</td>
                <td>${stateBadgeHtml(d.state)}</td>
                <td>${d.timestamp || '\u2014'}</td>
                <td>${d.jobs_id || '\u2014'}</td>
                <td>${resultsDetailsBtn(d, 'detector', d.crawl_page_id)}</td>
            </tr>`).join('')}
        </tbody>
    </table>`;
}

function renderNiktoTable(rows) {
    if (!rows || rows.length === 0) return '<p class="no-agents">No Nikto discoveries yet</p>';
    return `<table>
        <thead><tr>
            <th>ID</th><th>WebApp</th><th>URL</th><th>Timestamp</th><th>Job</th><th>Details</th>
        </tr></thead>
        <tbody>${rows.map(n => `
            <tr>
                <td>${n.id}</td>
                <td>${n.web_app_id || '—'}</td>
                <td title="${esc(n.url)}">${truncate(n.url, 60)}</td>
                <td>${n.timestamp || '—'}</td>
                <td>${n.jobs_id || '—'}</td>
                <td>${resultsDetailsBtn(n, 'crawler', n.web_app_id)}</td>
            </tr>`).join('')}
        </tbody>
    </table>`;
}

const CRAWLER_PANELS = {
    pages:   { wrapId: 'crawler-pages-table-wrap',   countId: 'crawler-pages-count',   prevId: 'crawler-pages-prev',   nextId: 'crawler-pages-next',   infoId: 'crawler-pages-info',   renderFn: renderCrawlPagesTable,  data: () => crawlerState.pages,  index: () => crawlerState.pageIndexP, setIndex: i => (crawlerState.pageIndexP = i) },
    details: { wrapId: 'crawler-details-table-wrap', countId: 'crawler-details-count', prevId: 'crawler-details-prev', nextId: 'crawler-details-next', infoId: 'crawler-details-info', renderFn: renderCrawlDetailsTable, data: () => crawlerState.details, index: () => crawlerState.pageIndexD, setIndex: i => (crawlerState.pageIndexD = i) },
    nikto:   { wrapId: 'crawler-nikto-table-wrap',   countId: 'crawler-nikto-count',   prevId: 'crawler-nikto-prev',   nextId: 'crawler-nikto-next',   infoId: 'crawler-nikto-info',   renderFn: renderNiktoTable,        data: () => crawlerState.nikto,   index: () => crawlerState.pageIndexN, setIndex: i => (crawlerState.pageIndexN = i) },
};

function renderCrawlerPage(which) {
    const panel = CRAWLER_PANELS[which];
    renderPaginatedSection({
        data:      panel.data(),
        pageIndex: panel.index(),
        pageSize:  crawlerState.pageSize,
        wrapId:    panel.wrapId,
        countId:   panel.countId,
        prevId:    panel.prevId,
        nextId:    panel.nextId,
        infoId:    panel.infoId,
        renderFn:  panel.renderFn,
    });
}

async function sqlicUpdateCrawlerStatus(resetPages = false) {
    if (!selectedJobId) {
        crawlerState.pages = [];
        crawlerState.details = [];
        crawlerState.nikto = [];
        if (resetPages) { crawlerState.pageIndexP = 0; crawlerState.pageIndexD = 0; crawlerState.pageIndexN = 0; }
        renderCrawlerPage('pages');
        renderCrawlerPage('details');
        renderCrawlerPage('nikto');
        return;
    }
    try {
        const data = await API.getCrawlerStatus(selectedJobId);
        crawlerState.pages   = data.pages   || [];
        crawlerState.details = data.details || [];
        crawlerState.nikto   = data.nikto   || [];
        // Only reset page position on explicit manual refresh, not on auto-poll
        if (resetPages) {
            crawlerState.pageIndexP = 0;
            crawlerState.pageIndexD = 0;
            crawlerState.pageIndexN = 0;
        }
        renderCrawlerPage('pages');
        renderCrawlerPage('details');
        renderCrawlerPage('nikto');
    } catch (err) {
        console.error('Error updating crawler status:', err);
    }
}

// Pagination buttons
bindPaginationBtns(
    'crawler-pages-prev', 'crawler-pages-next',
    () => crawlerState.pageIndexP, i => (crawlerState.pageIndexP = i),
    () => crawlerState.pages.length, () => crawlerState.pageSize,
    () => renderCrawlerPage('pages')
);
bindPaginationBtns(
    'crawler-details-prev', 'crawler-details-next',
    () => crawlerState.pageIndexD, i => (crawlerState.pageIndexD = i),
    () => crawlerState.details.length, () => crawlerState.pageSize,
    () => renderCrawlerPage('details')
);
bindPaginationBtns(
    'crawler-nikto-prev', 'crawler-nikto-next',
    () => crawlerState.pageIndexN, i => (crawlerState.pageIndexN = i),
    () => crawlerState.nikto.length, () => crawlerState.pageSize,
    () => renderCrawlerPage('nikto')
);

// Manual refresh button
document.getElementById('crawler-manual-refresh')?.addEventListener('click', () => {
    sqlicUpdateCrawlerStatus(true);
});

// ============================================================================
// SQLIAGENT - DETECTOR DATA PANEL
// ============================================================================

const detectorState = {
    detections:   [],
    pageIndex:    0,
    pageSize:     50
};

function renderDetectionsTable(rows) {
    if (!rows || rows.length === 0) return '<p class="no-agents">No detections yet</p>';
    return `<table>
        <thead><tr>
            <th>ID</th><th>Page ID</th><th>Target URL</th><th>Method</th>
            <th>Vulnerable</th><th>DBMS</th><th>Injection Points</th>
            <th>Injection Types</th><th>Error</th><th>State</th><th>Timestamp</th><th>Job</th><th>Details</th>
        </tr></thead>
        <tbody>${rows.map(d => `
            <tr>
                <td>${d.id}</td>
                <td>${d.crawl_page_id || '\u2014'}</td>
                <td title="${esc(d.target_url)}">${truncate(d.target_url, 50)}</td>
                <td>${d.method || '\u2014'}</td>
                <td>${boolCol(d.is_vulnerable)}</td>
                <td>${d.dbms || '\u2014'}</td>
                <td title="${esc(d.injection_points_json)}">${truncate(d.injection_points_json, 40)}</td>
                <td title="${esc(d.injection_types_json)}">${truncate(d.injection_types_json, 40)}</td>
                <td title="${esc(d.error_message)}">${truncate(d.error_message, 40)}</td>
                <td>${stateBadgeHtml(d.state)}</td>
                <td>${d.timestamp || '\u2014'}</td>
                <td>${d.jobs_id || '\u2014'}</td>
                <td>${resultsDetailsBtn(d, 'detector', d.crawl_page_id ?? d.id)}</td>
            </tr>`).join('')}
        </tbody>
    </table>`;
}

// ------------------------------------------------------------------
// Task detail modal — shared by the V2 kanban board (pipeline.js) and the plain
// Results tables below, so "analysis of that row" is inspectable from the
// main page (index.html — formerly v2.html — carries both the kanban board
// and the #task-detail-modal markup; tools.html also loads this file).
// ------------------------------------------------------------------

const V2_MODAL_HIDDEN_KEYS = new Set(['_logStage', '_logId', 'priority_score', 'priority_level', 'log']);
let v2LogRequestSeq = 0;

async function v2OpenTaskModal(data) {
    const modal    = document.getElementById('task-detail-modal');
    const title    = document.getElementById('task-modal-title');
    const body     = document.getElementById('task-modal-body');
    const priority = document.getElementById('task-modal-priority');
    const logSection = document.getElementById('task-modal-log-section');
    const logPre   = document.getElementById('task-modal-log');
    if (!modal || !body) return;

    title.textContent = data.url || data.target_url || data.target_host || `Task #${data.id ?? ''}`;

    if (priority) {
        if (data.priority_score !== null && data.priority_score !== undefined) {
            priority.textContent = `📊 Priority score: ${data.priority_score}${data.priority_level ? ` (${data.priority_level})` : ''}`;
            priority.style.display = 'block';
        } else {
            priority.style.display = 'none';
        }
    }

    let html = '';
    for (const [k, v] of Object.entries(data)) {
        if (V2_MODAL_HIDDEN_KEYS.has(k) || v === null || v === undefined || v === '') continue;
        const value = typeof v === 'object' ? JSON.stringify(v) : String(v);
        html += `<dt>${esc(k)}</dt><dd>${esc(value)}</dd>`;
    }
    body.innerHTML = html || '<dt>—</dt><dd>No data</dd>';
    modal.style.display = 'flex';

    if (logSection && logPre) {
        const requestId = ++v2LogRequestSeq;
        if (data._logStage && data._logId !== null && data._logId !== undefined) {
            logSection.style.display = 'block';
            logPre.textContent = 'Loading…';
            try {
                const { log } = await API.getV2Log(data._logStage, data._logId);
                if (requestId === v2LogRequestSeq) logPre.textContent = log || '(no log captured)';
            } catch (err) {
                if (requestId === v2LogRequestSeq) logPre.textContent = `Could not load log: ${err.message}`;
            }
        } else {
            logSection.style.display = 'none';
            logPre.textContent = '';
        }
    }
}

document.getElementById('close-task-modal-btn')?.addEventListener('click', () => {
    document.getElementById('task-detail-modal').style.display = 'none';
});

document.getElementById('task-detail-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.style.display = 'none';
});

/**
 * Builds a "Details" button `<td>` for any Results-section table row: opens
 * the shared task-detail modal with the row's full (untruncated) fields.
 * `logStage`/`logId`, when given, additionally fetch that row's persisted
 * log (only host/web_app/crawl_page/sqli_exploit rows have one — pass null
 * for tables that don't, e.g. nmap/exploit-tables/exploit-columns/dumps).
 */
function resultsDetailsBtn(row, logStage, logId) {
    const stageAttr = logStage ? ` data-log-stage="${esc(logStage)}"` : '';
    const idAttr = (logId !== undefined && logId !== null) ? ` data-log-id="${esc(String(logId))}"` : '';
    return `<button type="button" class="page-btn results-details-btn" data-json="${esc(JSON.stringify(row))}"${stageAttr}${idAttr}>🔍 Details</button>`;
}

// Delegated globally (not per-wrap) since every Results table below carries
// its own Details button now.
document.addEventListener('click', (e) => {
    const btn = e.target.closest('.results-details-btn');
    if (!btn) return;
    let data;
    try { data = JSON.parse(btn.dataset.json); } catch (err) { return; }
    v2OpenTaskModal({
        ...data,
        _logStage: btn.dataset.logStage || undefined,
        _logId: btn.dataset.logId !== undefined ? btn.dataset.logId : undefined,
    });
});

function renderDetectorPage() {
    renderPaginatedSection({
        data:      detectorState.detections,
        pageIndex: detectorState.pageIndex,
        pageSize:  detectorState.pageSize,
        wrapId:    'detector-detections-table-wrap',
        countId:   'detector-detections-count',
        prevId:    'detector-detections-prev',
        nextId:    'detector-detections-next',
        infoId:    'detector-detections-info',
        renderFn:  renderDetectionsTable,
    });
}

async function sqlicUpdateDetectorStatus(resetPages = false) {
    if (!selectedJobId) {
        detectorState.detections = [];
        if (resetPages) detectorState.pageIndex = 0;
        renderDetectorPage();
        return;
    }
    try {
        const data = await API.getDetectorStatus(selectedJobId);
        detectorState.detections = data.detections || [];
        if (resetPages) detectorState.pageIndex = 0;
        renderDetectorPage();
    } catch (err) {
        console.error('Error updating detector status:', err);
    }
}

// Pagination buttons
bindPaginationBtns(
    'detector-detections-prev', 'detector-detections-next',
    () => detectorState.pageIndex, i => (detectorState.pageIndex = i),
    () => detectorState.detections.length, () => detectorState.pageSize,
    renderDetectorPage
);

// Manual refresh button
document.getElementById('detector-manual-refresh')?.addEventListener('click', () => {
    sqlicUpdateDetectorStatus(true);
});

// ============================================================================
// SQLIAGENT - EXPLOITER DATA PANEL
// ============================================================================

const exploiterState = {
    exploits:    [],
    tables:      [],
    columns:     [],
    pageIndexT:  0,   // current page for sqli_exploit_tables
    pageIndexC:  0,   // current page for sqli_exploit_columns
    pageSize:    50
};

function renderExploitsTable(rows) {
    if (!rows || rows.length === 0) return '<p class="no-agents">No exploits yet</p>';
    return `<table>
        <thead><tr>
            <th>ID</th><th>Detector ID</th><th>Databases</th>
            <th>Total DBs</th><th>State</th><th>Timestamp</th><th>Job</th><th>Details</th>
        </tr></thead>
        <tbody>${rows.map(r => `
            <tr>
                <td>${r.id}</td>
                <td>${r.sqli_detector_id || '\u2014'}</td>
                <td title="${esc(r.databases_json)}">${truncate(r.databases_json, 60)}</td>
                <td>${r.total_databases ?? '\u2014'}</td>
                <td>${stateBadgeHtml(r.state)}</td>
                <td>${r.timestamp || '\u2014'}</td>
                <td>${r.jobs_id || '\u2014'}</td>
                <td>${resultsDetailsBtn(r, 'exploiter', r.id)}</td>
            </tr>`).join('')}
        </tbody>
    </table>`;
}

function renderExploitTablesTable(rows) {
    if (!rows || rows.length === 0) return '<p class="no-agents">No exploit tables yet</p>';
    return `<table>
        <thead><tr>
            <th>ID</th><th>Exploit ID</th><th>DB Name</th>
            <th>Tables</th><th>State</th><th>Timestamp</th><th>Job</th><th>Details</th>
        </tr></thead>
        <tbody>${rows.map(r => `
            <tr>
                <td>${r.id}</td>
                <td>${r.sqli_exploit_id || '\u2014'}</td>
                <td>${r.db_name || '\u2014'}</td>
                <td title="${esc(r.tables_json)}">${truncate(r.tables_json, 60)}</td>
                <td>${stateBadgeHtml(r.state)}</td>
                <td>${r.timestamp || '\u2014'}</td>
                <td>${r.jobs_id || '\u2014'}</td>
                <td>${resultsDetailsBtn(r, 'exploiter', r.sqli_exploit_id)}</td>
            </tr>`).join('')}
        </tbody>
    </table>`;
}

function renderExploitColumnsTable(rows) {
    if (!rows || rows.length === 0) return '<p class="no-agents">No exploit columns yet</p>';
    return `<table>
        <thead><tr>
            <th>ID</th><th>Tables ID</th><th>Table Name</th>
            <th>Columns</th><th>State</th><th>Timestamp</th><th>Job</th><th>Details</th>
        </tr></thead>
        <tbody>${rows.map(r => `
            <tr>
                <td>${r.id}</td>
                <td>${r.sqli_exploit_tables_id || '\u2014'}</td>
                <td>${r.table_name || '\u2014'}</td>
                <td title="${esc(r.columns_json)}">${truncate(r.columns_json, 60)}</td>
                <td>${stateBadgeHtml(r.state)}</td>
                <td>${r.timestamp || '\u2014'}</td>
                <td>${r.jobs_id || '\u2014'}</td>
                <td>${resultsDetailsBtn(r, null, null)}</td>
            </tr>`).join('')}
        </tbody>
    </table>`;
}

function renderExploiterPage(which) {
    const isTables = which === 'tables';
    renderPaginatedSection({
        data:      isTables ? exploiterState.tables   : exploiterState.columns,
        pageIndex: isTables ? exploiterState.pageIndexT : exploiterState.pageIndexC,
        pageSize:  exploiterState.pageSize,
        wrapId:    isTables ? 'exploiter-tables-table-wrap'  : 'exploiter-columns-table-wrap',
        countId:   isTables ? 'exploiter-tables-count'       : 'exploiter-columns-count',
        prevId:    isTables ? 'exploiter-tables-prev'        : 'exploiter-columns-prev',
        nextId:    isTables ? 'exploiter-tables-next'        : 'exploiter-columns-next',
        infoId:    isTables ? 'exploiter-tables-info'        : 'exploiter-columns-info',
        renderFn:  isTables ? renderExploitTablesTable       : renderExploitColumnsTable,
    });
}

async function sqlicUpdateExploiterStatus(resetPages = false) {
    if (!selectedJobId) {
        exploiterState.exploits = [];
        exploiterState.tables = [];
        exploiterState.columns = [];
        if (resetPages) { exploiterState.pageIndexT = 0; exploiterState.pageIndexC = 0; }
        const exploitsWrap  = document.getElementById('exploiter-exploits-table-wrap');
        const exploitsCount = document.getElementById('exploiter-exploits-count');
        if (exploitsCount) exploitsCount.textContent = 0;
        if (exploitsWrap)  exploitsWrap.innerHTML = renderExploitsTable([]);
        renderExploiterPage('tables');
        renderExploiterPage('columns');
        return;
    }
    try {
        const data = await API.getExploiterStatus(selectedJobId);
        exploiterState.exploits = data.exploits || [];
        exploiterState.tables   = data.tables   || [];
        exploiterState.columns  = data.columns  || [];
        if (resetPages) {
            exploiterState.pageIndexT = 0;
            exploiterState.pageIndexC = 0;
        }
        // Render exploits table (no pagination)
        const exploitsWrap  = document.getElementById('exploiter-exploits-table-wrap');
        const exploitsCount = document.getElementById('exploiter-exploits-count');
        if (exploitsCount) exploitsCount.textContent = exploiterState.exploits.length;
        if (exploitsWrap)  exploitsWrap.innerHTML = renderExploitsTable(exploiterState.exploits);
        // Render paginated sections
        renderExploiterPage('tables');
        renderExploiterPage('columns');
    } catch (err) {
        console.error('Error updating exploiter status:', err);
    }
}

// Pagination buttons
bindPaginationBtns(
    'exploiter-tables-prev', 'exploiter-tables-next',
    () => exploiterState.pageIndexT, i => (exploiterState.pageIndexT = i),
    () => exploiterState.tables.length, () => exploiterState.pageSize,
    () => renderExploiterPage('tables')
);
bindPaginationBtns(
    'exploiter-columns-prev', 'exploiter-columns-next',
    () => exploiterState.pageIndexC, i => (exploiterState.pageIndexC = i),
    () => exploiterState.columns.length, () => exploiterState.pageSize,
    () => renderExploiterPage('columns')
);

// Manual refresh button
document.getElementById('exploiter-manual-refresh')?.addEventListener('click', () => {
    sqlicUpdateExploiterStatus(true);
});

// ============================================================================
// SQLIAGENT - DUMPER PANEL
// ============================================================================

const dumperState = {
    dumps: [],
    dumpsById: new Map(),
    pageIndex: 0,
    pageSize: 20,
    expandedIds: new Set(),
    colSpan: 9,
};

function safeParseJson(value) {
    if (!value) return null;
    if (typeof value === 'object') return value;

    try {
        return JSON.parse(value);
    } catch (_) {
        return null;
    }
}

function normalizeDump(dump) {
    const parsedData = safeParseJson(dump.data_json);
    const rows = Array.isArray(parsedData?.rows) ? parsedData.rows : [];
    const entries = parsedData?.entries ?? rows.length;

    return {
        ...dump,
        parsedData,
        hasParsedData: !!parsedData,
        rowCount: entries,
        previewText: parsedData
            ? `${entries} rows`
            : (dump.data_json ? truncate(dump.data_json, 40) : '—'),
    };
}

function setDumps(rawDumps = []) {
    const normalized = rawDumps.map(normalizeDump);
    dumperState.dumps = normalized;
    dumperState.dumpsById = new Map(normalized.map(d => [String(d.id), d]));

    const validIds = new Set(normalized.map(d => String(d.id)));
    dumperState.expandedIds = new Set(
        [...dumperState.expandedIds].filter(id => validIds.has(String(id)))
    );
}

function buildDumperInlineTable(parsed) {
    if (!parsed) {
        return '<p style="padding:8px;color:#f88">Could not parse data.</p>';
    }

    const rows = Array.isArray(parsed.rows) ? parsed.rows : [];
    if (rows.length === 0) {
        return '<p style="padding:8px;">No rows available.</p>';
    }

    const colsSet = new Set();
    for (const row of rows) {
        for (const key of Object.keys(row || {})) {
            colsSet.add(key);
        }
    }
    const cols = [...colsSet];

    let html = `<div class="dumper-inline-table-wrap">
        <h4>📊 ${escapeHtml(String(parsed.database ?? ''))} → ${escapeHtml(String(parsed.table ?? ''))} (${parsed.entries ?? rows.length} entries)</h4>
        <table class="dump-table">
            <thead>
                <tr>${cols.map(col => `<th>${escapeHtml(col)}</th>`).join('')}</tr>
            </thead>
            <tbody>`;

    for (const row of rows) {
        html += '<tr>';
        for (const col of cols) {
            html += `<td>${escapeHtml(String(row?.[col] ?? ''))}</td>`;
        }
        html += '</tr>';
    }

    html += `</tbody></table></div>`;
    return html;
}

function renderExpandedRow(dumpId) {
    const dump = dumperState.dumpsById.get(String(dumpId));
    if (!dump) return '';

    return `
        <tr class="dumper-expanded-row" data-for-dumper="${dumpId}">
            <td colspan="${dumperState.colSpan}">
                ${buildDumperInlineTable(dump.parsedData)}
            </td>
        </tr>
    `;
}

function renderDumperDataTable(rows) {
    if (!rows || rows.length === 0) {
        return '<p class="no-agents">No dump data yet</p>';
    }

    let html = `
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Columns ID</th>
                    <th>DB</th>
                    <th>Table</th>
                    <th>Success</th>
                    <th>Data</th>
                    <th>Timestamp</th>
                    <th>Job</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
    `;

    for (const r of rows) {
        const id = String(r.id);
        const isExpanded = dumperState.expandedIds.has(id);
        const expandBtn = r.hasParsedData || r.data_json
            ? `<button class="dumper-expand-btn ${isExpanded ? 'active' : ''}"
                      data-dumper-id="${id}"
                      title="${isExpanded ? 'Collapse data' : 'Expand data'}">
                   ${isExpanded ? '－' : '＋'}
               </button>`
            : '';

        html += `
            <tr data-dumper-row="${id}">
                <td>${r.id}</td>
                <td>${r.sqli_exploit_columns_id ?? '—'}</td>
                <td>${esc(r.db_name) || '—'}</td>
                <td>${esc(r.table_name) || '—'}</td>
                <td>${r.dump_success ? '✅' : '❌'}</td>
                <td class="dumper-data-cell">
                    <span class="dumper-preview">${esc(r.previewText)}</span>${expandBtn}
                </td>
                <td>${r.timestamp || '—'}</td>
                <td>${r.jobs_id || '—'}</td>
                <td>${resultsDetailsBtn(r, null, null)}</td>
            </tr>
        `;

        if (isExpanded) {
            html += renderExpandedRow(id);
        }
    }

    html += '</tbody></table>';
    return html;
}

async function sqlicUpdateDumperStatus(resetPages = false) {
    if (!selectedJobId) {
        setDumps([]);
        if (resetPages) dumperState.pageIndex = 0;
        renderPaginatedSection({
            data: dumperState.dumps,
            pageIndex: dumperState.pageIndex,
            pageSize: dumperState.pageSize,
            wrapId: 'dumper-data-table-wrap',
            countId: 'dumper-data-count',
            prevId: 'dumper-data-prev',
            nextId: 'dumper-data-next',
            infoId: 'dumper-data-info',
            renderFn: renderDumperDataTable,
        });
        return;
    }
    try {
        const data = await API.getDumperStatus(selectedJobId);
        setDumps(data.dumps || []);

        if (resetPages) {
            dumperState.pageIndex = 0;
        }

        renderPaginatedSection({
            data: dumperState.dumps,
            pageIndex: dumperState.pageIndex,
            pageSize: dumperState.pageSize,
            wrapId: 'dumper-data-table-wrap',
            countId: 'dumper-data-count',
            prevId: 'dumper-data-prev',
            nextId: 'dumper-data-next',
            infoId: 'dumper-data-info',
            renderFn: renderDumperDataTable,
        });
    } catch (err) {
        console.error('Error updating dumper status:', err);
    }
}

function toggleExpandedRow(id, parentRow, btn) {
    const rowId = String(id);
    const existingExpanded = parentRow.nextElementSibling;
    const isExpanded =
        existingExpanded &&
        existingExpanded.classList.contains('dumper-expanded-row') &&
        existingExpanded.dataset.forDumper === rowId;

    if (isExpanded) {
        existingExpanded.remove();
        btn.textContent = '＋';
        btn.title = 'Expand data';
        btn.classList.remove('active');
        dumperState.expandedIds.delete(rowId);
        return;
    }

    const dump = dumperState.dumpsById.get(rowId);
    if (!dump) return;

    const wrapper = document.createElement('tbody');
    wrapper.innerHTML = renderExpandedRow(rowId);
    const expandedRow = wrapper.firstElementChild;

    parentRow.insertAdjacentElement('afterend', expandedRow);

    btn.textContent = '－';
    btn.title = 'Collapse data';
    btn.classList.add('active');
    dumperState.expandedIds.add(rowId);
}

bindPaginationBtns(
    'dumper-data-prev',
    'dumper-data-next',
    () => dumperState.pageIndex,
    i => (dumperState.pageIndex = i),
    () => dumperState.dumps.length,
    () => dumperState.pageSize,
    () => sqlicUpdateDumperStatus()
);

document.getElementById('dumper-manual-refresh')?.addEventListener('click', () => {
    sqlicUpdateDumperStatus(true);
});

document.getElementById('dumper-data-table-wrap')?.addEventListener('click', e => {
    const btn = e.target.closest('.dumper-expand-btn');
    if (!btn) return;

    const id = btn.dataset.dumperId;
    const parentRow = btn.closest('tr[data-dumper-row]');
    if (!id || !parentRow) return;

    toggleExpandedRow(id, parentRow, btn);
});

// ============================================================================
// SQLIAGENT - STATS PANEL
// ============================================================================

const STATS_LABELS = [
    { key: 'hosts',           icon: '🖥️',  label: 'Detected hosts'              },
    { key: 'webapps',         icon: '🌐',  label: 'Detected web apps'           },
    { key: 'pages',           icon: '📄',  label: 'Crawled pages'            },
    { key: 'sqli_vulnerable', icon: '⚠️',  label: 'Vulnerable pages'         },
    { key: 'databases',       icon: '🗄️',  label: 'Obtained databases'      },
    { key: 'tables',          icon: '📋',  label: 'Enumerated tables'             },
    { key: 'columns',         icon: '🔢',  label: 'Enumerated columns'           },
];

async function sqlicUpdateJobStats(jobId) {
    const panel = document.getElementById('job-stats-panel');
    const wrap  = document.getElementById('job-stats-wrap');
    if (!panel || !wrap) return;

    if (!jobId) {
        panel.style.display = 'none';
        wrap.innerHTML = '';
        return;
    }

    try {
        const data = await API.getStats(jobId);
        const job  = (data.stats || [])[0];
        if (!job) { panel.style.display = 'none'; return; }

        let rows = '';
        for (const { key, icon, label } of STATS_LABELS) {
            rows += `<tr><td>${icon} ${label}</td><td>${job[key] ?? 0}</td></tr>`;
        }
        wrap.innerHTML = `<table class="stats-metrics-table">${rows}</table>`;
        panel.style.display = 'block';
    } catch (err) {
        console.error('Error loading job stats:', err);
        panel.style.display = 'none';
    }
}

document.getElementById('sqlic-refresh-btn')?.addEventListener('click', () => {
    sqlicUpdateAgents();
});

// ============================================================================
// TOOLS SECTION
// ============================================================================

const statusDiv = document.getElementById('status');
const resultsContainer = document.getElementById('results-container');
const outputPre = document.getElementById('output');
const clearBtn = document.getElementById('clear-btn');

// Tool forms
const toolForms = {
    scanner: document.getElementById('scanner-form'),
    crawler: document.getElementById('crawler-form'),
    detector: document.getElementById('detector-form'),
    exploiter: document.getElementById('exploiter-form'),
    obtaindata: document.getElementById('obtaindata-form'),
    reporter: document.getElementById('reporter-form'),
    dbanalyzer: document.getElementById('dbanalyzer-form'),
    credentialhunter: document.getElementById('credentialhunter-form'),
    admininyector: document.getElementById('admininyector-form'),
};

let isScanning = false;
let currentTool = null;
let streamProcessor = null;
let stopButton = null;

// Tool card grid — click to open detail view
const toolsGrid = document.getElementById('tools-grid');
const toolDetail = document.getElementById('tool-detail');
const backBtn = document.getElementById('back-btn');

if (toolsGrid) {
    toolsGrid.querySelectorAll('.tool-card').forEach(card => {
        card.addEventListener('click', () => {
            switchTool(card.getAttribute('data-tool'));
        });
    });
}

if (backBtn) {
    backBtn.addEventListener('click', () => {
        // Stop any running scan
        if (isScanning && streamProcessor) {
            streamProcessor.cancel();
            isScanning = false;
        }
        // Hide detail, show grid
        toolDetail.style.display = 'none';
        toolsGrid.style.display = 'grid';
        clearResults();
        currentTool = null;
    });
}

if (clearBtn) {
    clearBtn.addEventListener('click', clearResults);
}

// Scan buttons
document.addEventListener('click', (e) => {
    const btn = e.target.closest('.scan-button[data-tool]');
    if (btn) startScan(btn.getAttribute('data-tool'));
});

// Enter key in text inputs
document.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !isScanning && e.target.matches('input[type="text"], input[type="number"]')) {
        const form = e.target.closest('.tool-form');
        if (form) {
            const btn = form.querySelector('.scan-button[data-tool]');
            if (btn) startScan(btn.getAttribute('data-tool'));
        }
    }
});

// Detector mode switching
const detectorMode = document.getElementById('detector-mode');
if (detectorMode) {
    detectorMode.addEventListener('change', (e) => {
        const mode = e.target.value;
        const urlInputs = document.getElementById('detector-url-inputs');
        const webappInputs = document.getElementById('detector-webapp-inputs');
        const pageInputs = document.getElementById('detector-page-inputs');
        
        // Hide all
        urlInputs.style.display = 'none';
        webappInputs.style.display = 'none';
        pageInputs.style.display = 'none';
        
        // Show selected
        if (mode === 'url') {
            urlInputs.style.display = 'block';
        } else if (mode === 'webapp') {
            webappInputs.style.display = 'block';
        } else if (mode === 'page') {
            pageInputs.style.display = 'block';
        }
    });
}

// ============================================================================
// OBTAIN DATA - CASCADE DROPDOWNS
// ============================================================================

async function loadObtainDataDatabases(jobId = null) {
    const dbSelect = document.getElementById('obtaindata-db');
    const tableSelect = document.getElementById('obtaindata-table');
    const execBtn = document.getElementById('obtaindata-execute-btn');
    const sqliInput = document.getElementById('obtaindata-sqli-id');
    const sqliHint = document.getElementById('obtaindata-sqli-hint');
    if (!dbSelect) return;

    dbSelect.innerHTML = '<option value="">— Loading… —</option>';
    tableSelect.innerHTML = '<option value="">— Select a database first —</option>';
    tableSelect.disabled = true;
    if (execBtn) execBtn.disabled = true;
    if (sqliInput) sqliInput.value = '';
    if (sqliHint) sqliHint.style.display = 'none';

    try {
        const data = await API.getExploitDatabases(jobId);
        const dbs = data.databases || [];
        if (dbs.length === 0) {
            dbSelect.innerHTML = '<option value="">— No databases found —</option>';
        } else {
            // Each entry: { db_name, sqli_detector_id }
            dbSelect.innerHTML = '<option value="">— Select a database —</option>' +
                dbs.map(d => `<option value="${d.db_name}" data-sqli-id="${d.sqli_detector_id}">${d.db_name}</option>`).join('');
        }
    } catch (err) {
        dbSelect.innerHTML = '<option value="">— Error loading databases —</option>';
        console.error('Error loading databases:', err);
    }
}

const obtainJobSelect = document.getElementById('obtaindata-job');
if (obtainJobSelect) {
    // Load jobs into the obtain data job selector
    (async () => {
        try {
            const data = await API.getJobs();
            const jobs = data.jobs || [];
            obtainJobSelect.innerHTML = '<option value="">— All jobs —</option>' +
                jobs.map(j => {
                    const target = j.target_url ? ` ${j.target_url}` : '';
                    const ts = j.timestamp ? ' (' + String(j.timestamp).slice(0, 10) + ')' : '';
                    return `<option value="${j.id}">Job #${j.id}${target}${ts}</option>`;
                }).join('');
        } catch (err) {
            console.error('Error loading jobs for obtain data:', err);
        }
    })();

    obtainJobSelect.addEventListener('change', () => {
        const jobId = obtainJobSelect.value || null;
        loadObtainDataDatabases(jobId);
    });
}

const obtainDbSelect = document.getElementById('obtaindata-db');
if (obtainDbSelect) {
    obtainDbSelect.addEventListener('change', async () => {
        const tableSelect = document.getElementById('obtaindata-table');
        const execBtn = document.getElementById('obtaindata-execute-btn');
        const sqliInput = document.getElementById('obtaindata-sqli-id');
        const sqliHint = document.getElementById('obtaindata-sqli-hint');
        const sqliDisplay = document.getElementById('obtaindata-sqli-id-display');
        const dbName = obtainDbSelect.value;
        const jobId = obtainJobSelect ? (obtainJobSelect.value || null) : null;

        // Auto-populate sqli_id from the selected option's data attribute
        const selectedOpt = obtainDbSelect.options[obtainDbSelect.selectedIndex];
        const sqliId = (selectedOpt && dbName) ? (selectedOpt.dataset.sqliId || '') : '';
        if (sqliInput) sqliInput.value = sqliId;
        if (sqliHint) sqliHint.style.display = sqliId ? 'block' : 'none';
        if (sqliDisplay) sqliDisplay.textContent = sqliId;

        tableSelect.innerHTML = '<option value="">— Loading tables… —</option>';
        tableSelect.disabled = true;
        if (execBtn) execBtn.disabled = true;

        if (!dbName) {
            tableSelect.innerHTML = '<option value="">— Select a database first —</option>';
            return;
        }

        try {
            const data = await API.getExploitTablesForDb(dbName, jobId);
            const tables = data.tables || [];
            if (tables.length === 0) {
                tableSelect.innerHTML = '<option value="">— No tables found —</option>';
            } else {
                tableSelect.innerHTML = '<option value="">— Select a table —</option>' +
                    tables.map(t => `<option value="${t}">${t}</option>`).join('');
                tableSelect.disabled = false;
            }
        } catch (err) {
            tableSelect.innerHTML = '<option value="">— Error loading tables —</option>';
            console.error('Error loading tables:', err);
        }
    });
}

const obtainTableSelect = document.getElementById('obtaindata-table');
if (obtainTableSelect) {
    obtainTableSelect.addEventListener('change', () => {
        const execBtn = document.getElementById('obtaindata-execute-btn');
        if (execBtn) execBtn.disabled = !obtainTableSelect.value;
    });
}

// Load databases when the obtain data tool is opened; extend switchTool after TOOL_CONFIG

function switchTool(tool) {
    if (!toolForms[tool] || !toolDetail || !toolsGrid) return;

    // Hide grid, show detail
    toolsGrid.style.display = 'none';
    toolDetail.style.display = 'block';

    // Hide all forms, show the selected one
    Object.values(toolForms).forEach(f => f.classList.remove('active'));
    toolForms[tool].classList.add('active');
    currentTool = tool;

    clearResults();

    // Cascade dropdowns for Obtain Data
    if (tool === 'obtaindata') {
        const jobSel = document.getElementById('obtaindata-job');
        loadObtainDataDatabases(jobSel ? (jobSel.value || null) : null);
    }

    // Load jobs for Reporter
    if (tool === 'reporter') {
        loadReporterJobs();
    }

    // Load jobs for DB Analyzer
    if (tool === 'dbanalyzer') {
        loadDBAnalyzerJobs();
    }
    if (tool === 'credentialhunter') {
        loadCredentialHunterJobs();
    }
    if (tool === 'admininyector') {
        loadAdminInyectorJobs();
    }
}

// Tool configuration
const TOOL_CONFIG = {
    scanner: {
        name: 'WebScanner',
        inputs: {
            url: 'scanner-ip'
        },
        validate: (inputs) => {
            if (!inputs.url) {
                return 'Please, introduce a valid IP or URL';
            }
            return null;
        },
        buildRequest: (inputs) => inputs.url,
        apiMethod: (data) => API.startScanner(data)
    },
    crawler: {
        name: 'WebCrawler',
        inputs: {
            url: 'crawler-url',
            pages: 'crawler-pages',
            depth: 'crawler-depth',
            skip_nikto: 'crawler-skip-nikto',
            render: 'crawler-render'
        },
        validate: (inputs) => {
            if (!inputs.url) {
                return 'Please, introduce a valid URL';
            }
            return null;
        },
        buildRequest: (inputs) => ({
            url: inputs.url,
            pages: parseInt(inputs.pages),
            depth: parseInt(inputs.depth),
            skip_nikto: inputs.skip_nikto,
            render: inputs.render
        }),
        apiMethod: (data) => API.startCrawler(data)
    },
    detector: {
        name: 'WebDetector',
        inputs: {
            mode: 'detector-mode',
            url: 'detector-url',
            webapp_id: 'detector-webapp-id',
            page_id: 'detector-page-id'
        },
        validate: (inputs) => {
            if (inputs.mode === 'url' && !inputs.url) {
                return 'Please, introduce a valid URL';
            }
            if (inputs.mode === 'webapp' && !inputs.webapp_id) {
                return 'Please, introduce a valid Web App ID';
            }
            if (inputs.mode === 'page' && !inputs.page_id) {
                return 'Please, introduce a valid Crawl Page ID';
            }
            return null;
        },
        buildRequest: (inputs) => {
            const request = { mode: inputs.mode };
            if (inputs.mode === 'url') {
                request.url = inputs.url;
            } else if (inputs.mode === 'webapp') {
                request.webapp_id = parseInt(inputs.webapp_id);
            } else if (inputs.mode === 'page') {
                request.page_id = parseInt(inputs.page_id);
            }
            return request;
        },
        apiMethod: (data) => API.startDetector(data)
    },
    exploiter: {
        name: 'SQLExploiter',
        inputs: {
            sqli_id: 'exploiter-sqli-id'
        },
        validate: (inputs) => {
            if (!inputs.sqli_id) {
                return 'Please, introduce a valid SQLi Detector ID';
            }
            return null;
        },
        buildRequest: (inputs) => ({
            sqli_id: parseInt(inputs.sqli_id)
        }),
        apiMethod: (data) => API.startExploiter(data)
    },
    obtaindata: {
        name: 'Obtain Data',
        inputs: {
            sqli_id: 'obtaindata-sqli-id',
            db_name: 'obtaindata-db',
            table_name: 'obtaindata-table'
        },
        validate: (inputs) => {
            if (!inputs.sqli_id) return 'Could not find a SQLi Detector ID. Make sure you have exploited the vulnerability first.';
            if (!inputs.db_name) return 'Please select a database';
            if (!inputs.table_name) return 'Please select a table';
            return null;
        },
        buildRequest: (inputs) => ({
            sqli_id: parseInt(inputs.sqli_id),
            db_name: inputs.db_name,
            table_name: inputs.table_name,
            job_id: (() => { const s = document.getElementById('obtaindata-job'); return s && s.value ? parseInt(s.value) : null; })()
        }),
        apiMethod: (data) => API.startDump(data),
        onComplete: async () => {
            const dbName = document.getElementById('obtaindata-db').value;
            const tableName = document.getElementById('obtaindata-table').value;
            const jobSel = document.getElementById('obtaindata-job');
            const jobId = jobSel && jobSel.value ? parseInt(jobSel.value) : null;
            try {
                const result = await API.getExploitDumpData(dbName, tableName, jobId);
                if (result && result.data_json) {
                    const parsed = typeof result.data_json === 'string'
                        ? JSON.parse(result.data_json)
                        : result.data_json;
                    renderDumpTable(parsed);
                }
            } catch (e) {
                console.warn('Could not load dump table results:', e);
            }
        }
    },
};

// Main functions
async function startScan(tool) {
    if (isScanning) {
        showStatus('A scan is already in progress', 'error');
        return;
    }
    
    // Get tool configuration
    const config = TOOL_CONFIG[tool];
    if (!config) {
        showStatus('Invalid tool', 'error');
        return;
    }
    
    // Get input values
    const inputs = getToolInputs(config.inputs);
    
    // Validate inputs
    const validationError = config.validate(inputs);
    if (validationError) {
        showStatus(validationError, 'error');
        return;
    }
    
    // Build request data
    const requestData = config.buildRequest(inputs);
    const apiMethod = () => config.apiMethod(requestData);
    const toolName = config.name;
    
    // Get the correct button
    const currentBtn = toolForms[tool].querySelector('.scan-button');
    const btnText = currentBtn.querySelector('.btn-text');
    const btnIcon = currentBtn.querySelector('.btn-icon');
    const originalText = btnText.textContent;
    const originalIcon = btnIcon.textContent;
    
    // Prepare UI
    prepareUIForScan(currentBtn, btnText, btnIcon);
    
    const targetInfo = typeof requestData === 'string' ? requestData : (requestData.url || requestData.ip);
    showStatus(`Running ${toolName} on ${targetInfo}...`, 'info');
    
    try {
        // Start the stream using the API
        const { reader } = await apiMethod();
        
        // Create stream processor
        streamProcessor = new StreamProcessor();
        
        // Configure callbacks
        streamProcessor
            .onSession((sessionId) => {
                console.log('Session ID:', sessionId);
            })
            .onData((data) => {
                outputPre.textContent += data;
                outputPre.scrollTop = outputPre.scrollHeight;
            })
            .onComplete(() => {
                showStatus(`✅ ${toolName} completed successfully`, 'success');
                // Execute onComplete callback from the configuration if it exists
                if (config.onComplete) {
                    config.onComplete();
                }
            })
            .onCancel((message) => {
                showStatus(`⛔ Execution stopped`, 'warning');
                outputPre.textContent += '\n\n⛔ Execution stopped by the user\n';
            })
            .onError((error) => {
                showStatus(`❌ ${error}`, 'error');
                outputPre.textContent += `\n${error}\n`;
            });
        
        // Process the stream
        await streamProcessor.process(reader);
        
    } catch (error) {
        console.error('Error:', error);
        showStatus(`❌ Connection error: ${error.message}`, 'error');
        outputPre.textContent += `\n\n❌ Error: ${error.message}\n`;
    } finally {
        // Restore UI
        restoreUIAfterScan(currentBtn, btnText, btnIcon, originalText, originalIcon);
    }
}

// Helper function to get tool inputs
function getToolInputs(inputsConfig) {
    const inputs = {};
    
    for (const [key, elementId] of Object.entries(inputsConfig)) {
        const element = document.getElementById(elementId);
        if (!element) continue;
        
        if (element.type === 'checkbox') {
            inputs[key] = element.checked;
        } else if (element.type === 'number') {
            inputs[key] = element.value;
        } else {
            inputs[key] = element.value.trim();
        }
    }
    
    return inputs;
}

function prepareUIForScan(currentBtn, btnText, btnIcon) {
    isScanning = true;
    currentBtn.disabled = true;
    currentBtn.classList.add('scanning');
    btnText.textContent = 'Processing...';
    btnIcon.textContent = '⚙️';
    
    // Create stop button
    if (!stopButton) {
        stopButton = document.createElement('button');
        stopButton.className = 'stop-button';
        stopButton.innerHTML = '<span class="btn-text">Stop</span><span class="btn-icon">❌</span>';
        stopButton.addEventListener('click', stopExecution);
    }
    
    // Insert stop button
    currentBtn.parentNode.insertBefore(stopButton, currentBtn.nextSibling);
    
    outputPre.textContent = '';
    resultsContainer.style.display = 'block';
}

function restoreUIAfterScan(currentBtn, btnText, btnIcon, originalText, originalIcon) {
    isScanning = false;
    streamProcessor = null;
    currentBtn.disabled = false;
    currentBtn.classList.remove('scanning');
    btnText.textContent = originalText;
    btnIcon.textContent = originalIcon;
    
    // Delete stop button
    if (stopButton && stopButton.parentNode) {
        stopButton.parentNode.removeChild(stopButton);
    }
}

async function stopExecution() {
    if (!streamProcessor || !streamProcessor.getSessionId()) {
        showStatus('There is no active execution', 'error');
        return;
    }
    
    try {
        const result = await API.cancelExecution(streamProcessor.getSessionId());
        console.log('Cancellation result:', result);
    } catch (error) {
        console.error('Error stopping execution:', error);
        showStatus(`❌ Error stopping execution: ${error.message}`, 'error');
    }
}

function clearResults() {
    outputPre.textContent = '';
    resultsContainer.style.display = 'none';
    statusDiv.style.display = 'none';
    statusDiv.className = 'status-message';
    // Hide dump table results too
    const tableResults = document.getElementById('obtaindata-table-results');
    if (tableResults) tableResults.style.display = 'none';
}

/**
 * Renders the dump JSON data as an HTML table inside #obtaindata-table-results
 * @param {Object} parsed - {database, table, entries, rows: [{col: val, ...}]}
 */
function renderDumpTable(parsed) {
    const wrap = document.getElementById('obtaindata-table-results');
    const titleEl = document.getElementById('obtaindata-table-title');
    const countEl = document.getElementById('obtaindata-table-count');
    const bodyEl = document.getElementById('obtaindata-table-body');

    if (!wrap || !bodyEl) return;

    const rows = parsed.rows || [];
    if (rows.length === 0) {
        wrap.style.display = 'none';
        return;
    }

    const columns = Object.keys(rows[0]);

    // Header info
    titleEl.textContent = `${parsed.database}.${parsed.table}`;
    countEl.textContent = `${parsed.entries ?? rows.length} entries`;

    // Build table
    let html = '<table class="dump-table"><thead><tr>';
    for (const col of columns) {
        html += `<th>${escapeHtml(col)}</th>`;
    }
    html += '</tr></thead><tbody>';
    for (const row of rows) {
        html += '<tr>';
        for (const col of columns) {
            html += `<td>${escapeHtml(String(row[col] ?? ''))}</td>`;
        }
        html += '</tr>';
    }
    html += '</tbody></table>';

    bodyEl.innerHTML = html;
    wrap.style.display = 'block';
}

function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function showStatus(message, type = 'info') {
    statusDiv.textContent = message;
    statusDiv.className = 'status-message';
    if (type === 'info' || type === 'success' || type === 'error' || type === 'warning') {
        statusDiv.classList.add(type);
    }
    statusDiv.style.display = 'block';
}

// Prevent accidental closure during scanning
window.addEventListener('beforeunload', (e) => {
    if (isScanning) {
        e.preventDefault();
        e.returnValue = 'There is a scan in progress. Are you sure you want to leave?';
    }
});

// Check server status on load
window.addEventListener('load', async () => {
    try {
        const data = await API.checkHealth();
        console.log('Server status:', data);
    } catch (error) {
        console.error('Server connection error:', error);
        showStatus('⚠️ Could not connect to the server', 'error');
    }
});

// ============================================================================
// REPORTER — GENERATE & DOWNLOAD PDF REPORT
// ============================================================================

function reporterSyncButtons() {
    const select = document.getElementById('reporter-job');
    const hasJob = select && select.value !== '';
    const btn    = document.getElementById('reporter-generate-btn');
    const csvBtn = document.getElementById('reporter-csv-btn');
    if (btn)    btn.disabled    = !hasJob;
    if (csvBtn) csvBtn.disabled = !hasJob;
}

async function loadReporterJobs() {
    const select = document.getElementById('reporter-job');
    if (!select) return;

    select.innerHTML = '<option value="">— Loading jobs… —</option>';
    reporterSyncButtons();

    try {
        const data = await API.getReporterJobs();
        const jobs = data.jobs || [];

        if (jobs.length === 0) {
            select.innerHTML = '<option value="">— There is no jobs available —</option>';
            reporterSyncButtons();
            return;
        }

        select.innerHTML = jobs.map(j =>
            `<option value="${j.id}">Job #${j.id} — ${j.timestamp}${j.type ? ' [' + j.type + ']' : ''}</option>`
        ).join('');
        reporterSyncButtons();
    } catch (e) {
        select.innerHTML = '<option value="">— Error loading jobs —</option>';
        reporterSyncButtons();
        console.error('loadReporterJobs error:', e);
    }
}

const reporterJobSelect = document.getElementById('reporter-job');
if (reporterJobSelect) {
    reporterJobSelect.addEventListener('change', reporterSyncButtons);
}

const reporterGenBtn = document.getElementById('reporter-generate-btn');
const reporterStatus = document.getElementById('reporter-status');

if (reporterGenBtn) {
    reporterGenBtn.addEventListener('click', async () => {
        const select = document.getElementById('reporter-job');
        const jobId = select ? parseInt(select.value) : null;
        if (!jobId) {
            if (reporterStatus) {
                reporterStatus.style.display = 'block';
                reporterStatus.style.color = '#f85149';
                reporterStatus.textContent = 'Please, select a job.';
            }
            return;
        }

        // UI: loading state
        reporterGenBtn.disabled = true;
        reporterGenBtn.querySelector('.btn-text').textContent = 'Generating report...';
        reporterGenBtn.querySelector('.btn-icon').textContent = '⏳';
        if (reporterStatus) {
            reporterStatus.style.display = 'block';
            reporterStatus.style.color = '#aaa';
            reporterStatus.textContent = '⏳ Running SQLWebReporter.py, this may take a few seconds…';
        }

        try {
            const result = await API.generateReport(jobId);

            if (reporterStatus) {
                reporterStatus.style.color = '#3fb950';
                reporterStatus.textContent = `✅ Report generated: ${result.filename}. Downloading…`;
            }

            // Trigger download
            API.downloadReport(result.filename);
        } catch (e) {
            if (reporterStatus) {
                reporterStatus.style.color = '#f85149';
                reporterStatus.textContent = `❌ Error: ${e.message}`;
            }
        } finally {
            reporterGenBtn.disabled = false;
            reporterGenBtn.querySelector('.btn-text').textContent = 'Generate & Download Report';
            reporterGenBtn.querySelector('.btn-icon').textContent = '📄';
        }
    });
}

const reporterCsvBtn = document.getElementById('reporter-csv-btn');
if (reporterCsvBtn) {
    reporterCsvBtn.addEventListener('click', () => {
        const select = document.getElementById('reporter-job');
        const jobId  = select ? parseInt(select.value) : null;
        if (!jobId) {
            if (reporterStatus) {
                reporterStatus.style.display  = 'block';
                reporterStatus.style.color    = '#f85149';
                reporterStatus.textContent    = 'Please, select a job.';
            }
            return;
        }
        API.downloadCSVPages(jobId);
    });
}

// ============================================================================
// DB ANALYZER — AI DATABASE PRIVILEGE ANALYSIS
// ============================================================================

async function loadDBAnalyzerJobs() {
    const jobSelect = document.getElementById('dbanalyzer-job');
    const dbSelect  = document.getElementById('dbanalyzer-db');
    const btn       = document.getElementById('dbanalyzer-analyse-btn');
    if (!jobSelect) return;

    jobSelect.innerHTML = '<option value="">— Loading jobs… —</option>';
    dbSelect.innerHTML  = '<option value="">— Select a job first —</option>';
    dbSelect.disabled   = true;
    btn.disabled        = true;

    try {
        const data = await API.getReporterJobs(); // reuse the same endpoint
        const jobs = data.jobs || [];
        if (jobs.length === 0) {
            jobSelect.innerHTML = '<option value="">— No jobs available —</option>';
            return;
        }
        jobSelect.innerHTML = '<option value="">— Select a job —</option>' +
            jobs.map(j => `<option value="${j.id}">Job #${j.id} — ${j.timestamp}${j.type ? ' [' + j.type + ']' : ''}</option>`).join('');
    } catch (e) {
        jobSelect.innerHTML = '<option value="">— Error loading jobs —</option>';
        console.error('loadDBAnalyzerJobs error:', e);
    }
}

const dbAnalyzerJobSelect = document.getElementById('dbanalyzer-job');
if (dbAnalyzerJobSelect) {
    dbAnalyzerJobSelect.addEventListener('change', async () => {
        const jobId   = dbAnalyzerJobSelect.value;
        const dbSelect = document.getElementById('dbanalyzer-db');
        const btn      = document.getElementById('dbanalyzer-analyse-btn');
        dbSelect.innerHTML = '<option value="">— Loading databases… —</option>';
        dbSelect.disabled  = true;
        btn.disabled       = true;

        if (!jobId) {
            dbSelect.innerHTML = '<option value="">— Select a job first —</option>';
            return;
        }

        try {
            const data = await API.getDBAnalyzerDatabases(parseInt(jobId));
            const dbs  = data.databases || [];
            if (dbs.length === 0) {
                dbSelect.innerHTML = '<option value="">— No databases in this job —</option>';
                return;
            }
            dbSelect.innerHTML = '<option value="">— Select a database —</option>' +
                dbs.map(d => `<option value="${d}">${d}</option>`).join('');
            dbSelect.disabled = false;
        } catch (e) {
            dbSelect.innerHTML = '<option value="">— Error loading databases —</option>';
            console.error('dbanalyzer db load error:', e);
        }
    });
}

const dbAnalyzerDbSelect = document.getElementById('dbanalyzer-db');
if (dbAnalyzerDbSelect) {
    dbAnalyzerDbSelect.addEventListener('change', () => {
        const btn = document.getElementById('dbanalyzer-analyse-btn');
        if (btn) btn.disabled = !dbAnalyzerDbSelect.value;
    });
}

const dbAnalyzerBtn = document.getElementById('dbanalyzer-analyse-btn');
if (dbAnalyzerBtn) {
    dbAnalyzerBtn.addEventListener('click', async () => {
        const dbName    = document.getElementById('dbanalyzer-db')?.value;
        const jobId     = document.getElementById('dbanalyzer-job')?.value;
        const statusEl  = document.getElementById('dbanalyzer-status');
        const resultEl  = document.getElementById('dbanalyzer-result');
        const outputEl  = document.getElementById('dbanalyzer-output');

        if (!dbName) return;

        // Loading state
        dbAnalyzerBtn.disabled = true;
        dbAnalyzerBtn.querySelector('.btn-text').textContent = 'Analyzing…';
        dbAnalyzerBtn.querySelector('.btn-icon').textContent = '⏳';
        if (statusEl) { statusEl.style.display = 'block'; statusEl.style.color = '#aaa'; statusEl.textContent = '⏳ Running AI analysis, this may take a few seconds…'; }
        if (resultEl) resultEl.style.display = 'none';

        try {
            const data = await API.analyseDB(dbName, jobId ? parseInt(jobId) : null);

            // Show structured result if available, otherwise raw output
            if (outputEl) {
                if (data.result) {
                    outputEl.textContent = JSON.stringify(data.result, null, 2);
                } else {
                    outputEl.textContent = data.output || '(no output)';
                }
            }
            if (resultEl) resultEl.style.display = 'block';
            if (statusEl) { statusEl.style.color = '#3fb950'; statusEl.textContent = `✅ Analysis completed for: ${dbName}`; }
        } catch (e) {
            if (statusEl) { statusEl.style.color = '#f85149'; statusEl.textContent = `❌ Error: ${e.message}`; }
        } finally {
            dbAnalyzerBtn.disabled = false;
            dbAnalyzerBtn.querySelector('.btn-text').textContent = 'Analyze';
            dbAnalyzerBtn.querySelector('.btn-icon').textContent = '🧠';
        }
    });
}

// ── Credential Hunter ──────────────────────────────────────────────────────
async function loadCredentialHunterJobs() {
    const jobSelect = document.getElementById('credentialhunter-job');
    const btn       = document.getElementById('credentialhunter-run-btn');
    if (!jobSelect) return;
    jobSelect.innerHTML = '<option value="">— Loading jobs… —</option>';
    if (btn) btn.disabled = true;
    try {
        const data = await API.getReporterJobs();
        const jobs = data.jobs || [];
        jobSelect.innerHTML = '<option value="">— Select a job —</option>' +
            jobs.map(j => `<option value="${j.id}">Job #${j.id} — ${j.timestamp}${j.type ? ' [' + j.type + ']' : ''}</option>`).join('');
    } catch (e) {
        jobSelect.innerHTML = '<option value="">— Error loading jobs —</option>';
    }
}

const credentialHunterJobSelect = document.getElementById('credentialhunter-job');
if (credentialHunterJobSelect) {
    credentialHunterJobSelect.addEventListener('change', () => {
        const btn = document.getElementById('credentialhunter-run-btn');
        if (btn) btn.disabled = !credentialHunterJobSelect.value;
    });
}

const credentialHunterBtn = document.getElementById('credentialhunter-run-btn');
if (credentialHunterBtn) {
    credentialHunterBtn.addEventListener('click', async () => {
        const jobId    = document.getElementById('credentialhunter-job')?.value;
        const statusEl = document.getElementById('credentialhunter-status');
        const resultEl = document.getElementById('credentialhunter-result');
        const outputEl = document.getElementById('credentialhunter-output');
        if (!jobId) return;

        credentialHunterBtn.disabled = true;
        credentialHunterBtn.querySelector('.btn-text').textContent = 'Running…';
        credentialHunterBtn.querySelector('.btn-icon').textContent = '⏳';
        if (statusEl) { statusEl.style.display = 'block'; statusEl.style.color = '#aaa'; statusEl.textContent = '⏳ Running AI credential analysis…'; }
        if (resultEl) resultEl.style.display = 'none';

        try {
            const data = await API.runCredentialHunter(parseInt(jobId));
            if (outputEl) outputEl.textContent = data.output || '(no output)';
            if (resultEl) resultEl.style.display = 'block';
            if (statusEl) { statusEl.style.color = '#3fb950'; statusEl.textContent = `✅ Analysis completed for job #${jobId}`; }
        } catch (e) {
            if (statusEl) { statusEl.style.color = '#f85149'; statusEl.textContent = `❌ Error: ${e.message}`; }
        } finally {
            credentialHunterBtn.disabled = false;
            credentialHunterBtn.querySelector('.btn-text').textContent = 'Run Analysis';
            credentialHunterBtn.querySelector('.btn-icon').textContent = '🔑';
        }
    });
}

// ── Admin Injector ──────────────────────────────────────────────────────────
async function loadAdminInyectorJobs() {
    const jobSelect = document.getElementById('admininyector-job');
    const btn       = document.getElementById('admininyector-run-btn');
    if (!jobSelect) return;
    jobSelect.innerHTML = '<option value="">— Loading jobs… —</option>';
    if (btn) btn.disabled = true;
    try {
        const data = await API.getReporterJobs();
        const jobs = data.jobs || [];
        jobSelect.innerHTML = '<option value="">— Select a job —</option>' +
            jobs.map(j => `<option value="${j.id}">Job #${j.id} — ${j.timestamp}${j.type ? ' [' + j.type + ']' : ''}</option>`).join('');
    } catch (e) {
        jobSelect.innerHTML = '<option value="">— Error loading jobs —</option>';
    }
}

const adminInyectorJobSelect = document.getElementById('admininyector-job');
if (adminInyectorJobSelect) {
    adminInyectorJobSelect.addEventListener('change', () => {
        const btn = document.getElementById('admininyector-run-btn');
        if (btn) btn.disabled = !adminInyectorJobSelect.value;
    });
}

const adminInyectorBtn = document.getElementById('admininyector-run-btn');
if (adminInyectorBtn) {
    adminInyectorBtn.addEventListener('click', async () => {
        const jobId    = document.getElementById('admininyector-job')?.value;
        const statusEl = document.getElementById('admininyector-status');
        const resultEl = document.getElementById('admininyector-result');
        const outputEl = document.getElementById('admininyector-output');
        if (!jobId) return;

        adminInyectorBtn.disabled = true;
        adminInyectorBtn.querySelector('.btn-text').textContent = 'Running…';
        adminInyectorBtn.querySelector('.btn-icon').textContent = '⏳';
        if (statusEl) { statusEl.style.display = 'block'; statusEl.style.color = '#aaa'; statusEl.textContent = '⏳ Generating admin SQL statements…'; }
        if (resultEl) resultEl.style.display = 'none';

        try {
            const data = await API.runAdminInyector(parseInt(jobId));
            if (outputEl) outputEl.textContent = data.output || '(no output)';
            if (resultEl) resultEl.style.display = 'block';
            if (statusEl) { statusEl.style.color = '#3fb950'; statusEl.textContent = `✅ SQL generated for job #${jobId}`; }
        } catch (e) {
            if (statusEl) { statusEl.style.color = '#f85149'; statusEl.textContent = `❌ Error: ${e.message}`; }
        } finally {
            adminInyectorBtn.disabled = false;
            adminInyectorBtn.querySelector('.btn-text').textContent = 'Generate SQL';
            adminInyectorBtn.querySelector('.btn-icon').textContent = '💉';
        }
    });
}
