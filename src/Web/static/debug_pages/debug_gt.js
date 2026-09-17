// Debug GT — checks a job's detected/exploited pages against a fixed
// ground-truth list of known-vulnerable URLs for the 10.0.0.12 benchmark
// target (OWASP-BWA). Self-contained, mirrors webmap.js's structure.

let gtAutoRefreshInterval = null;
let gtTargetHealthInterval = null;

// Last-rendered data, kept around purely so the "Download CSV" button can
// export exactly what's on screen without re-fetching or scraping the DOM.
let gtLastScope = '';
let gtLastCoverageRows = [];
let gtLastExtraRows = [];
let gtLastJobs = null; // non-null only in "All Jobs" mode
let gtLastShowJob = false;
let gtLastDetections = []; // whole-job detections, for the priority table (not GT-scoped)
let gtLastPages = [];      // whole-job crawl_page rows, same reason

// Ground-truth URL list: fetched once from GET /api/debug-gt/urls (backed by
// debug_data/GT_URLS.json) and cached, instead of being hardcoded here.
let GT_PAGES = [];
let gtPagesLoaded = false;

async function gtEnsurePages() {
    if (gtPagesLoaded) return GT_PAGES;
    try {
        const { gt_pages } = await API.getGtUrls();
        GT_PAGES = gt_pages || [];
    } catch (err) {
        console.error('Debug GT: error loading ground-truth URL list', err);
        GT_PAGES = [];
    }
    gtPagesLoaded = true;
    return GT_PAGES;
}

function gtEsc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Loose match: strips query string/fragment entirely (URLs differing only
 * in parameters are the same page for coverage purposes — GT_URLS.json and
 * zap_detected.json are stored path-only for the same reason), decodes %xx,
 * drops a trailing slash, case-insensitive. Good enough for a debug/coverage
 * tool — mismatches are meant to be eyeballed. */
function gtNormalizeUrl(url) {
    if (!url) return '';
    let u = String(url).trim();
    const qIdx = u.search(/[?#]/);
    if (qIdx !== -1) u = u.slice(0, qIdx);
    try { u = decodeURIComponent(u); } catch (e) { /* malformed escape, use as-is */ }
    return u.replace(/\/$/, '').toLowerCase();
}

/** Warns when the target VM itself is saturated/unresponsive (e.g. Apache's
 * worker pool exhausted by requests stuck on a full-disk MySQL) rather than
 * leaving the user to mistake a wall of fetch errors and "Not Found" GT rows
 * for a crawler/detector bug. Runs on its own slower interval, independent
 * of the main gtLoadAndRender refresh, since each check makes real HTTP
 * requests against the target and shouldn't add extra load on top of an
 * already-struggling VM every 5s. */
async function gtCheckTargetHealth() {
    const banner = document.getElementById('gt-target-warning');
    if (!banner) return;
    try {
        const { saturated, target } = await API.getTargetHealth();
        if (saturated) {
            const host = String(target || '').replace(/^https?:\/\//, '');
            banner.textContent = `⚠️ Target VM (${target}) is not responding on any app checked — it looks saturated or hung `
                + `(the OWASP-BWA VM is prone to this after its MySQL disk fills up, which cascades into every other app timing out too). `
                + `Results below (fetch errors, "Not Found" rows) are likely a symptom of this, not a crawler bug. Recommended: reboot ${host}.`;
            banner.className = 'status-message error';
        } else {
            banner.className = 'status-message';
            banner.textContent = '';
        }
    } catch (err) {
        console.error('Debug GT: error checking target health', err);
        // Leave the banner as-is on a transient check failure — don't flip
        // its state based on our own API being briefly unreachable.
    }
}

function gtStart() {
    if (gtAutoRefreshInterval) clearInterval(gtAutoRefreshInterval);
    if (gtTargetHealthInterval) clearInterval(gtTargetHealthInterval);
    gtLoadAndRender();
    gtCheckTargetHealth();
    gtAutoRefreshInterval = setInterval(gtLoadAndRender, 5000);
    gtTargetHealthInterval = setInterval(gtCheckTargetHealth, 30000);
}

// Static ZAP baseline (GET /api/debug-gt/zap): fetched once and cached as a
// Set of normalized URLs, since it never changes between refreshes.
let zapDetectedKeys = null;

async function gtEnsureZapBaseline() {
    if (zapDetectedKeys) return zapDetectedKeys;
    try {
        const { detected_urls } = await API.getZapBaseline();
        zapDetectedKeys = new Set((detected_urls || []).map(gtNormalizeUrl));
    } catch (err) {
        console.error('Debug GT: error loading ZAP baseline', err);
        zapDetectedKeys = new Set();
    }
    return zapDetectedKeys;
}

/** Shows the page body only once a job is selected; otherwise shows the empty state. */
function gtUpdateBodyVisibility(jobId) {
    const body  = document.getElementById('gt-body');
    const empty = document.getElementById('gt-empty-state');
    if (!body || !empty) return;
    body.style.display  = jobId ? 'flex' : 'none';
    empty.style.display = jobId ? 'none' : 'flex';
}

/** normalized url -> { detection, exploited, vulnerable }, covering EVERY
 * tested target (not just vulnerable ones) so a "tested, came back safe"
 * row can be told apart from "never tested at all". Prefers exploited over
 * merely-vulnerable over merely-tested if the same URL shows up more than once. */
function gtBuildMatch(allDetections, exploitedDetectorIds) {
    const byUrl = new Map();
    for (const d of allDetections) {
        const key = gtNormalizeUrl(d.target_url);
        if (!key) continue;
        const vulnerable = d.is_vulnerable === 1 || d.is_vulnerable === true;
        const exploited = exploitedDetectorIds.has(d.id);
        const existing = byUrl.get(key);
        if (!existing
            || (exploited && !existing.exploited)
            || (vulnerable && !existing.vulnerable && !existing.exploited)) {
            byUrl.set(key, { detection: d, exploited, vulnerable });
        }
    }
    return byUrl;
}

/** 'exploited' | 'detected' | 'safe' | 'skipped' | 'not_found' */
function gtCategory(match, crawled) {
    if (match) {
        if (match.exploited) return 'exploited';
        if (match.vulnerable) return 'detected';
        return 'safe';
    }
    return crawled ? 'skipped' : 'not_found';
}

const GT_FOUND_CATEGORIES = new Set(['exploited', 'detected']);

// Params dropped as pure pagination noise (mirrors utils/common.py's
// url_pattern), unless their value looks like a routing target.
const GT_PATTERN_PAGINATION_PARAMS = new Set(['page', 'pagina', 'p', 'offset', 'start']);
const GT_PATTERN_ROUTING_VALUE_RE = /\.(php|html?|asp|aspx|jsp)$/i;

/** Canonical (host+path + sorted param NAMES, no values) key for a URL —
 * mirrors utils/common.py's url_pattern exactly, so the debug tool's
 * "extra findings" grouping matches what the report counts as one
 * vulnerability. Falls back to a lowercased raw string if `url` doesn't
 * parse (shouldn't happen for target_url values from the DB). */
function gtUrlPattern(url) {
    let u;
    try { u = new URL(url); } catch (e) { return String(url || '').toLowerCase(); }
    const seenKeys = new Set();
    const parts = [];
    for (const key of [...u.searchParams.keys()].sort()) {
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);
        const v = u.searchParams.get(key) || '';
        const kLower = key.toLowerCase();
        if (GT_PATTERN_PAGINATION_PARAMS.has(kLower) && !GT_PATTERN_ROUTING_VALUE_RE.test(v)) {
            continue;
        } else if (GT_PATTERN_PAGINATION_PARAMS.has(kLower) && GT_PATTERN_ROUTING_VALUE_RE.test(v)) {
            parts.push(`${key}=${v}`);
        } else {
            parts.push(key);
        }
    }
    const query = parts.length ? `?${parts.join('&')}` : '';
    // Not lowercased as a whole (matches utils/common.py's url_pattern,
    // which preserves path/host case — only param key names and the routing
    // regex compare case-insensitively).
    return `http://${u.host}${u.pathname}${query}`;
}

/** Sorted, comparable key for a detection's injected field(s), so two
 * genuinely different vulnerable fields sharing a url_pattern still count
 * as separate findings (mirrors reporting.py's _finding_group_key). */
function gtInjectionPointsKey(injectionPointsJson) {
    try {
        const arr = JSON.parse(injectionPointsJson || '[]');
        return Array.isArray(arr) ? [...arr].sort().join(',') : String(injectionPointsJson || '');
    } catch (e) {
        return String(injectionPointsJson || '');
    }
}

/** Same traversal as gtUrlPattern, but instead of dropping a "varying"
 * param's value it replaces it with `*` (and keeps the URL's real scheme,
 * since this is for display, not for use as a grouping key). Pagination/
 * routing-exception params (e.g. page=user-info.php) are left with their
 * real value — url_pattern treats those as significant, not as noise, so
 * they aren't "varying parameters" in the sense meant here. */
function gtStarredUrl(url) {
    let u;
    try { u = new URL(url); } catch (e) { return String(url || ''); }
    if (![...u.searchParams.keys()].length) return url;
    const seenKeys = new Set();
    const parts = [];
    for (const key of [...u.searchParams.keys()].sort()) {
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);
        const v = u.searchParams.get(key) || '';
        const kLower = key.toLowerCase();
        if (GT_PATTERN_PAGINATION_PARAMS.has(kLower) && !GT_PATTERN_ROUTING_VALUE_RE.test(v)) {
            continue;
        } else if (GT_PATTERN_PAGINATION_PARAMS.has(kLower) && GT_PATTERN_ROUTING_VALUE_RE.test(v)) {
            parts.push(`${key}=${v}`);
        } else {
            parts.push(`${key}=*`);
        }
    }
    const query = parts.length ? `?${parts.join('&')}` : '';
    return `${u.origin}${u.pathname}${query}`;
}

/** Collapses extra-findings rows that are the same vulnerability (same page
 * pattern + method + injected field) but were hit through different
 * parameter values into one row — counted once instead of once per value —
 * preferring an exploited entry over a merely-vulnerable one as the
 * representative. Only when a row actually resulted from merging 2+ raw
 * detections is its displayed URL rewritten with `*` in place of the
 * varying parameter value(s) (e.g. CustomerLogin.aspx?ReturnUrl=A/B/C ->
 * CustomerLogin.aspx?ReturnUrl=*); a pattern with just one real hit keeps
 * its concrete URL, since nothing was actually grouped. */
function gtGroupExtraRows(rows) {
    const byGroup = new Map();
    for (const v of rows) {
        const d = v.detection;
        const key = `${gtUrlPattern(d.target_url)}|${d.method || ''}|${gtInjectionPointsKey(d.injection_points_json)}`;
        const entry = byGroup.get(key);
        if (!entry) {
            byGroup.set(key, { best: v, count: 1 });
        } else {
            entry.count++;
            if (v.exploited && !entry.best.exploited) entry.best = v;
        }
    }
    return [...byGroup.values()].map(({ best, count }) => {
        if (count <= 1) return best;
        return {
            ...best,
            detection: { ...best.detection, target_url: gtStarredUrl(best.detection.target_url) },
            groupCount: count,
        };
    });
}

async function gtLoadAndRender() {
    const jobId = (typeof selectedJobId !== 'undefined') ? selectedJobId : null;
    gtUpdateBodyVisibility(jobId);
    if (!jobId) return;

    const isAllJobs = jobId === 'all';
    // Omitting job_id entirely (rather than passing the "all" sentinel) makes
    // both endpoints return unfiltered rows across every job.
    const filterJobId = isAllJobs ? null : jobId;

    await Promise.all([gtEnsureZapBaseline(), gtEnsurePages()]);

    let detections = [];
    let exploits = [];
    let pages = [];
    try {
        const [detData, expData, crawlData] = await Promise.all([
            API.getDetectorStatus(filterJobId),
            API.getExploiterStatus(filterJobId),
            API.getCrawlerStatus(filterJobId),
        ]);
        detections = detData.detections || [];
        exploits = expData.exploits || [];
        pages = crawlData.pages || [];
    } catch (err) {
        console.error('Debug GT: error loading job data', err);
        document.getElementById('gt-coverage-wrap').innerHTML = '<p class="no-agents">Error loading job data</p>';
        document.getElementById('gt-extra-wrap').innerHTML = '';
        return;
    }

    const exploitedDetectorIds = new Set(
        exploits.filter(e => e.state === 'done').map(e => e.sqli_detector_id)
    );

    if (!isAllJobs) {
        const byUrl = gtBuildMatch(detections, exploitedDetectorIds);
        const pageByUrl = new Map();
        for (const p of pages) {
            const key = gtNormalizeUrl(p.url);
            if (key) pageByUrl.set(key, p);
        }
        // Keyed by crawl_page.id: a vulnerable/tested request's target_url
        // (e.g. a form action) can differ from the crawl_page it was found
        // on - SqliDetector.crawl_page_id is the real FK. Used below only
        // when a detection exists; skipped/never-crawled GT rows (no
        // detection at all) fall back to the URL-matched `page` instead.
        const pageById = new Map(pages.map(p => [p.id, p]));
        const matchedKeys = new Set();
        let foundCount = 0;
        const coverageRows = GT_PAGES.map(gt => {
            const key = gtNormalizeUrl(gt.url);
            const match = byUrl.get(key);
            const page = pageByUrl.get(key);
            const category = gtCategory(match, !!page);
            const cpId = match?.detection?.crawl_page_id;
            const priority = cpId != null ? (pageById.get(cpId)?.priority_level || null) : ((page && page.priority_level) || null);
            if (GT_FOUND_CATEGORIES.has(category)) { matchedKeys.add(key); foundCount++; }
            return { ...gt, match, page, category, priority };
        });
        const extraRows = gtGroupExtraRows([...byUrl.entries()]
            .filter(([key, v]) => !matchedKeys.has(key) && (v.vulnerable || v.exploited))
            .map(([, v]) => v));

        gtSetSummary(`Job #${jobId}`, foundCount);
        gtRenderCoverage(coverageRows, null);
        gtRenderAppSummary(coverageRows, null);
        gtRenderPriority(coverageRows, detections, pages, null);
        gtRenderExtra(extraRows, false);
        gtLastScope = `Job #${jobId}`;
        gtLastCoverageRows = coverageRows;
        gtLastExtraRows = extraRows;
        gtLastJobs = null;
        gtLastShowJob = false;
        gtLastDetections = detections;
        gtLastPages = pages;
        return;
    }

    // All Jobs: one column per existing job, plus a combined "Any job" column.
    let jobs = [];
    try {
        const jobsData = await API.getJobs();
        jobs = (jobsData.jobs || []).slice().sort((a, b) => a.id - b.id);
    } catch (err) {
        console.error('Debug GT: error loading jobs list', err);
    }

    const byJob = new Map();       // jobId -> normalized-url match map, for this job only
    const crawledByJob = new Map(); // jobId -> Set of normalized crawled urls, for this job only
    const pageByJobUrl = new Map(); // jobId -> normalized-url -> that job's own crawl_page (fallback only, see below)
    for (const job of jobs) { byJob.set(job.id, new Map()); crawledByJob.set(job.id, new Set()); pageByJobUrl.set(job.id, new Map()); }
    for (const p of pages) {
        if (p.jobs_id == null) continue;
        if (!crawledByJob.has(p.jobs_id)) crawledByJob.set(p.jobs_id, new Set());
        if (!pageByJobUrl.has(p.jobs_id)) pageByJobUrl.set(p.jobs_id, new Map());
        const key = gtNormalizeUrl(p.url);
        if (key) { crawledByJob.get(p.jobs_id).add(key); pageByJobUrl.get(p.jobs_id).set(key, p); }
    }
    // Keyed by crawl_page.id (the real FK - a vulnerable request's
    // target_url can differ from the crawl_page it was found on) - used
    // whenever a per-job detection exists; pageByJobUrl is only the
    // fallback for skipped/never-crawled rows with no detection at all.
    const pageById = new Map(pages.map(p => [p.id, p]));
    for (const d of detections) {
        if (d.jobs_id == null) continue;
        if (!byJob.has(d.jobs_id)) byJob.set(d.jobs_id, new Map());
        const key = gtNormalizeUrl(d.target_url);
        if (!key) continue;
        const vulnerable = d.is_vulnerable === 1 || d.is_vulnerable === true;
        const exploited = exploitedDetectorIds.has(d.id);
        const map = byJob.get(d.jobs_id);
        const existing = map.get(key);
        if (!existing
            || (exploited && !existing.exploited)
            || (vulnerable && !existing.vulnerable && !existing.exploited)) {
            map.set(key, { detection: d, exploited, vulnerable });
        }
    }

    const unionByUrl = gtBuildMatch(detections, exploitedDetectorIds);
    const crawledUnion = new Set(pages.map(p => gtNormalizeUrl(p.url)).filter(Boolean));
    const matchedKeys = new Set();
    let foundCount = 0;
    const coverageRows = GT_PAGES.map(gt => {
        const key = gtNormalizeUrl(gt.url);
        const perJob = {};
        const perJobPriority = {};
        for (const job of jobs) {
            const m = byJob.get(job.id)?.get(key);
            const crawled = crawledByJob.get(job.id)?.has(key);
            perJob[job.id] = gtCategory(m, crawled);
            const cpId = m?.detection?.crawl_page_id;
            const jobPage = pageByJobUrl.get(job.id)?.get(key);
            perJobPriority[job.id] = cpId != null
                ? (pageById.get(cpId)?.priority_level || null)
                : ((jobPage && jobPage.priority_level) || null);
        }
        const match = unionByUrl.get(key);
        const category = gtCategory(match, crawledUnion.has(key));
        if (GT_FOUND_CATEGORIES.has(category)) { matchedKeys.add(key); foundCount++; }
        return { ...gt, match, category, perJob, perJobPriority };
    });

    const extraRows = gtGroupExtraRows([...unionByUrl.entries()]
        .filter(([key, v]) => !matchedKeys.has(key) && (v.vulnerable || v.exploited))
        .map(([, v]) => v));

    gtSetSummary('All Jobs', foundCount);
    gtRenderCoverage(coverageRows, jobs);
    gtRenderAppSummary(coverageRows, jobs);
    gtRenderPriority(coverageRows, detections, pages, jobs);
    gtRenderExtra(extraRows, true);
    gtLastScope = 'All Jobs';
    gtLastCoverageRows = coverageRows;
    gtLastExtraRows = extraRows;
    gtLastJobs = jobs;
    gtLastShowJob = true;
    gtLastDetections = detections;
    gtLastPages = pages;
}

function gtSetSummary(scope, foundCount) {
    const summary = document.getElementById('gt-summary');
    if (!summary) return;
    const pct = GT_PAGES.length ? Math.round((foundCount / GT_PAGES.length) * 100) : 0;
    summary.textContent = `${scope} — ${foundCount}/${GT_PAGES.length} found (${pct}%)`;
}

const GT_STATUS_META = {
    exploited: { icon: '✅', label: 'Exploited',   cls: 'state-done' },
    detected:  { icon: '✅', label: 'Detected',    cls: 'state-pending' },
    safe:      { icon: '🟡', label: 'Marked Safe', cls: 'state-safe' },
    skipped:   { icon: '⏭️', label: 'Skipped',     cls: 'state-skipped' },
    not_found: { icon: '🔴', label: 'Not Found',   cls: 'state-error' },
};

/** Shared found/total(%) cell for the coverage tables' summary rows: color
 * (not just the number) signals none/partial/full, but the fraction+percent
 * text is always shown too — color is never the only carrier of meaning. */
function gtCoverageCell(found, total) {
    const pct = total ? Math.round((found / total) * 100) : 0;
    const cls = total === 0 ? 'gt-cov-none' : pct === 100 ? 'gt-cov-full' : pct === 0 ? 'gt-cov-none' : 'gt-cov-partial';
    return `<td class="${cls}"><strong>${found}/${total}</strong> <span>(${pct}%)</span></td>`;
}

function gtStatusBadge(category, compact) {
    const meta = GT_STATUS_META[category] || GT_STATUS_META.not_found;
    return { badge: compact ? meta.icon : `${meta.icon} ${meta.label}`, cls: meta.cls };
}

/** Builds the payload embedded in a coverage row's Details button — just
 * enough for the modal to render without a second round-trip, plus the
 * crawl_page_id needed to lazily fetch the sqlmap log. */
function gtDetailPayload(r) {
    const detection = r.match ? r.match.detection : null;
    const crawlPageId = detection ? detection.crawl_page_id : (r.page ? r.page.id : null);
    return {
        app: r.app, url: r.url, category: r.category,
        priority_score: r.page ? r.page.priority_score : null,
        priority_level: r.page ? r.page.priority_level : null,
        page_state: r.page ? r.page.state : null,
        page_error_message: r.page ? r.page.error_message : null,
        crawl_page_id: crawlPageId,
        detection,
    };
}

function gtPriorityLabel(page) {
    if (!page || page.priority_score === null || page.priority_score === undefined) return '—';
    return `${page.priority_score}${page.priority_level ? ` (${page.priority_level})` : ''}`;
}

/** `jobs`, when given (All Jobs mode), adds one status column per job plus a
 * combined "Any job" column instead of the single-job Priority/Status/Details
 * columns (per-job Priority/Details don't make sense in the matrix view). */
function gtRenderCoverage(rows, jobs) {
    const wrap = document.getElementById('gt-coverage-wrap');
    const count = document.getElementById('gt-coverage-count');
    if (count) count.textContent = `${rows.filter(r => GT_FOUND_CATEGORIES.has(r.category)).length}/${rows.length}`;
    if (!wrap) return;
    if (!rows.length) { wrap.innerHTML = '<p class="no-agents">No ground-truth pages configured</p>'; return; }

    const perJobMode = Array.isArray(jobs) && jobs.length > 0;
    const jobHeaders = perJobMode
        ? jobs.map(j => `<th title="${gtEsc(j.target_url || '')}">Job #${j.id}</th>`).join('')
        : '';

    // ZAP is a static, job-independent reference baseline - only meaningful
    // once you're comparing it against something, i.e. the All Jobs matrix.
    const zapKeys = zapDetectedKeys || new Set();
    const zapColHeader = perJobMode ? '<th title="Detected by OWASP ZAP in an independent baseline scan">ZAP</th>' : '';

    const totalRowHtml = perJobMode ? (() => {
        const total = rows.length;
        const zapFound = rows.filter(r => zapKeys.has(gtNormalizeUrl(r.url))).length;
        const jobTotals = jobs.map(j =>
            gtCoverageCell(rows.filter(r => GT_FOUND_CATEGORIES.has(r.perJob[j.id])).length, total)
        ).join('');
        const anyFound = rows.filter(r => GT_FOUND_CATEGORIES.has(r.category)).length;
        return `<tr class="gt-total-row">
            <td colspan="2"><strong>Total</strong></td>
            ${gtCoverageCell(zapFound, total)}
            ${jobTotals}
            ${gtCoverageCell(anyFound, total)}
        </tr>`;
    })() : '';

    wrap.innerHTML = `<table>
        <thead><tr>
            <th>App</th><th>URL</th>${zapColHeader}
            ${perJobMode ? jobHeaders + '<th>Any job</th>' : '<th>Priority</th><th>Status</th><th>Details</th>'}
        </tr></thead>
        <tbody>
            ${rows.map(r => {
                const noteHtml = r.note ? ` <span title="${gtEsc(r.note)}">📝</span>` : '';
                const zapHit = zapKeys.has(gtNormalizeUrl(r.url));
                const zapCell = perJobMode ? `<td>${zapHit ? '<span class="state-badge state-done">✓</span>' : '—'}</td>` : '';
                const jobCells = perJobMode ? jobs.map(j => {
                    const { badge, cls } = gtStatusBadge(r.perJob[j.id], true);
                    return `<td><span class="state-badge ${cls}" title="${gtEsc(GT_STATUS_META[r.perJob[j.id]]?.label || '')}">${badge}</span></td>`;
                }).join('') : '';
                const { badge, cls } = gtStatusBadge(r.category, false);
                let extraCells = '';
                if (!perJobMode) {
                    const payload = gtDetailPayload(r);
                    const detailsCell = payload.crawl_page_id != null
                        ? `<button type="button" class="page-btn gt-details-btn" data-json="${gtEsc(JSON.stringify(payload))}">🔍 Details</button>`
                        : `<span style="color:var(--text-secondary)" title="Never crawled">—</span>`;
                    extraCells = `<td>${gtEsc(gtPriorityLabel(r.page))}</td>
                        <td><span class="state-badge ${cls}">${badge}</span></td>
                        <td>${detailsCell}</td>`;
                }
                return `<tr>
                    <td>${gtEsc(r.app)}</td>
                    <td title="${gtEsc(r.url)}">${gtEsc(r.url)}${noteHtml}</td>
                    ${zapCell}
                    ${jobCells}
                    ${perJobMode ? `<td><span class="state-badge ${cls}">${badge}</span></td>` : ''}
                    ${extraCells}
                </tr>`;
            }).join('')}
            ${totalRowHtml}
        </tbody>
    </table>`;
}

/** Rolls coverage `rows` up one entry per App (shared by gtRenderAppSummary
 * and the CSV export, so the two never disagree). Each entry carries raw
 * found/total counts — not yet HTML or CSV — for `App`, `ZAP`, each job (if
 * `jobs` given) and `Any job`/`Found` (the union, or this job in single-job
 * mode; same field either way, mirroring how coverageRows.category works). */
function gtAppSummaryRows(rows, jobs) {
    const zapKeys = zapDetectedKeys || new Set();
    const perJobMode = Array.isArray(jobs) && jobs.length > 0;
    const byApp = new Map();
    for (const r of rows) {
        const app = r.app || '—';
        if (!byApp.has(app)) byApp.set(app, []);
        byApp.get(app).push(r);
    }
    return [...byApp.entries()].map(([app, appGtRows]) => {
        const total = appGtRows.length;
        const zapFound = appGtRows.filter(r => zapKeys.has(gtNormalizeUrl(r.url))).length;
        const anyFound = appGtRows.filter(r => GT_FOUND_CATEGORIES.has(r.category)).length;
        const perJob = {};
        if (perJobMode) {
            for (const j of jobs) {
                perJob[j.id] = appGtRows.filter(r => GT_FOUND_CATEGORIES.has(r.perJob[j.id])).length;
            }
        }
        return { app, total, zapFound, anyFound, perJob };
    });
}

/** Same coverage data as gtRenderCoverage, rolled up one row per App instead
 * of one row per URL — same columns (ZAP / per-job / Any job), each cell a
 * found/total (%) count across that app's GT rows. Reuses the same `rows`
 * (with .perJob/.category already computed) so the numbers always agree
 * with the per-URL table above it. */
function gtRenderAppSummary(rows, jobs) {
    const wrap = document.getElementById('gt-app-wrap');
    const count = document.getElementById('gt-app-count');
    if (!wrap) return;
    if (!rows.length) { wrap.innerHTML = '<p class="no-agents">No ground-truth pages configured</p>'; if (count) count.textContent = '0'; return; }

    const perJobMode = Array.isArray(jobs) && jobs.length > 0;
    const jobHeaders = perJobMode ? jobs.map(j => `<th title="${gtEsc(j.target_url || '')}">Job #${j.id}</th>`).join('') : '';
    const summary = gtAppSummaryRows(rows, jobs);
    if (count) count.textContent = String(summary.length);

    const appRows = summary.map(s => {
        const jobCells = perJobMode ? jobs.map(j => gtCoverageCell(s.perJob[j.id], s.total)).join('') : '';
        return `<tr>
            <td>${gtEsc(s.app)}</td>
            <td>${s.total}</td>
            ${gtCoverageCell(s.zapFound, s.total)}
            ${jobCells}
            ${gtCoverageCell(s.anyFound, s.total)}
        </tr>`;
    });

    const grandTotal = rows.length;
    const grandZap = summary.reduce((sum, s) => sum + s.zapFound, 0);
    const grandAny = summary.reduce((sum, s) => sum + s.anyFound, 0);
    const grandJobCells = perJobMode
        ? jobs.map(j => gtCoverageCell(summary.reduce((sum, s) => sum + s.perJob[j.id], 0), grandTotal)).join('')
        : '';
    const grandTotalRow = `<tr class="gt-total-row">
        <td colspan="2"><strong>Total URLs</strong></td>
        ${gtCoverageCell(grandZap, grandTotal)}
        ${grandJobCells}
        ${gtCoverageCell(grandAny, grandTotal)}
    </tr>`;

    // "Apps with >=1 finding" — one app with 20 URLs and one app with 1 URL
    // count the same here, unlike the URL-weighted Total row above.
    const appsTotal = summary.length;
    const appsZap = summary.filter(s => s.zapFound > 0).length;
    const appsAny = summary.filter(s => s.anyFound > 0).length;
    const appsJobCells = perJobMode
        ? jobs.map(j => gtCoverageCell(summary.filter(s => s.perJob[j.id] > 0).length, appsTotal)).join('')
        : '';
    const appsCoveredRow = `<tr class="gt-total-row">
        <td colspan="2"><strong>Apps with ≥1 finding</strong></td>
        ${gtCoverageCell(appsZap, appsTotal)}
        ${appsJobCells}
        ${gtCoverageCell(appsAny, appsTotal)}
    </tr>`;

    wrap.innerHTML = `<table>
        <thead><tr>
            <th>App</th><th>URLs</th><th title="Detected by OWASP ZAP in an independent baseline scan">ZAP</th>
            ${jobHeaders}<th>${perJobMode ? 'Any job' : 'Found'}</th>
        </tr></thead>
        <tbody>
            ${appRows.join('')}
            ${grandTotalRow}
            ${appsCoveredRow}
        </tbody>
    </table>`;
}

// Severity-descending, independent of Map insertion order. `range` documents
// WebScorer.py's actual threshold rule (modules/scoring/WebScorer.py): High
// requires score>=80 *and* an error-message indicator, Medium is score>=30
// (including a score>=80 page without that indicator), Low is everything
// else. Note this rule only applies to "Normal" jobs - "IA" jobs let the AI
// assign both the score and the level itself, with no fixed thresholds (see
// modules/scoring/WebScorerAIPromt.py), so its high/medium/low don't
// necessarily land in these same score ranges.
const GT_PRIORITY_LEVELS = [
    { key: 'high', label: 'High', range: 'score ≥ 80 + error indicators' },
    { key: 'medium', label: 'Medium', range: 'score 30–79 (or ≥80 without error indicators)' },
    { key: 'low', label: 'Low', range: 'score < 30' },
    { key: null, label: 'Unscored', range: 'never reached the Scorer' },
];

/** Whole-job (not GT-scoped) count of *non-vulnerable* detector rows by
 * priority level: "of every page tested in this run that came back clean,
 * how many were tagged each level". Joined via SqliDetector.crawl_page_id
 * (the real FK - a request's target_url, e.g. a form action, can differ
 * from the crawl_page it was found on), same as the found-count logic in
 * gtLoadAndRender's coverageRows. Returns Map<level, count>. */
function gtBuildSafeByPriority(detectionsScope, pageById) {
    const counts = new Map();
    for (const d of detectionsScope) {
        if (d.is_vulnerable === 1 || d.is_vulnerable === true) continue;
        const page = pageById.get(d.crawl_page_id);
        const level = (page && page.priority_level) || null;
        counts.set(level, (counts.get(level) || 0) + 1);
    }
    return counts;
}

/** {known_found, known_not_found, safe, total} for one priority level,
 * optionally scoped to one job (jobId given, All Jobs mode - reads
 * r.perJob[jobId]/r.perJobPriority[jobId]) or the row's merged
 * category/priority (jobId null, single-job mode). known_found/
 * known_not_found split the ~52-URL ground truth list (pages we know are
 * vulnerable) by whether that job actually caught them; safe comes from
 * safeCounts (gtBuildSafeByPriority - that job's whole run, not GT-limited)
 * since "how are non-vulnerable pages tagged" needs the full set to mean
 * anything (the GT list has no non-vulnerable entries to begin with).
 * total is literally found+missed+safe, mixed scopes and all, as asked. */
function gtPriorityRowCounts(coverageRows, key, jobId, safeCounts) {
    let known_found = 0, known_not_found = 0;
    for (const r of coverageRows) {
        const priority = jobId != null ? r.perJobPriority[jobId] : r.priority;
        if (priority !== key) continue;
        const category = jobId != null ? r.perJob[jobId] : r.category;
        if (GT_FOUND_CATEGORIES.has(category)) known_found++; else known_not_found++;
    }
    const safe = safeCounts.get(key) || 0;
    return { known_found, known_not_found, safe, total: known_found + known_not_found + safe };
}

/** One row per priority level, one column group per selected job (no merged
 * "All jobs" column - the Scorer re-tags every page from scratch each run,
 * so comparing jobs side by side is the point, not blending them into one
 * number): how many known (ground-truth) vulnerabilities tagged that level
 * were found vs. missed by that job, how many of that job's whole run (not
 * GT-limited) non-vulnerable pages were tagged that level, and Total
 * (found+missed+safe). Single-job view (jobs null) shows the same columns
 * without the job grouping. */
function gtRenderPriority(coverageRows, detections, pages, jobs) {
    const wrap = document.getElementById('gt-priority-wrap');
    const count = document.getElementById('gt-priority-count');
    if (!wrap) return;

    const pageById = new Map(pages.map(p => [p.id, p]));
    const perJobMode = Array.isArray(jobs) && jobs.length > 0;
    const cellsFor = (c) => `<td>${c.known_found}</td><td>${c.known_not_found}</td><td>${c.safe}</td><td><strong>${c.total}</strong></td>`;
    const sumField = (list, field) => list.reduce((s, c) => s + c[field], 0);

    if (perJobMode) {
        const safeByJob = new Map(jobs.map(j => [j.id, gtBuildSafeByPriority(detections.filter(d => d.jobs_id === j.id), pageById)]));

        const levels = GT_PRIORITY_LEVELS
            .map(({ key, label, range }) => {
                const perJob = new Map(jobs.map(j => [j.id, gtPriorityRowCounts(coverageRows, key, j.id, safeByJob.get(j.id))]));
                return { label, range, perJob };
            })
            .filter(l => [...l.perJob.values()].some(c => c.known_found + c.known_not_found + c.safe > 0));
        if (count) count.textContent = String(levels.length);
        if (!levels.length) { wrap.innerHTML = '<p class="no-agents">No detections yet</p>'; return; }

        const jobHeaders = jobs.map(j => `<th colspan="4" title="${gtEsc(j.target_url || '')}">Job #${j.id}</th>`).join('');
        const subHeaders = `<th title="Known-vulnerable GT pages at this priority, found">Found</th>
            <th title="Known-vulnerable GT pages at this priority, missed">Missed</th>
            <th title="This job's whole run: non-vulnerable pages tagged this priority">Safe</th>
            <th title="Found + Missed + Safe">Total</th>`;
        const bodyRows = levels.map(l => {
            const jobCells = jobs.map(j => cellsFor(l.perJob.get(j.id))).join('');
            return `<tr><td>${gtEsc(l.label)}<div class="gt-priority-range">${gtEsc(l.range)}</div></td>${jobCells}</tr>`;
        });
        const totalRow = `<tr class="gt-total-row"><td><strong>Total</strong></td>${jobs.map(j => {
            const jobLevels = levels.map(l => l.perJob.get(j.id));
            const f = sumField(jobLevels, 'known_found'), m = sumField(jobLevels, 'known_not_found'), s = sumField(jobLevels, 'safe');
            return `<td><strong>${f}</strong></td><td><strong>${m}</strong></td><td><strong>${s}</strong></td><td><strong>${f + m + s}</strong></td>`;
        }).join('')}</tr>`;

        wrap.innerHTML = `<table>
            <thead>
                <tr><th rowspan="2">Priority</th>${jobHeaders}</tr>
                <tr>${jobs.map(() => subHeaders).join('')}</tr>
            </thead>
            <tbody>${bodyRows.join('')}${totalRow}</tbody>
        </table>`;
        return;
    }

    const safeCounts = gtBuildSafeByPriority(detections, pageById);
    const levels = GT_PRIORITY_LEVELS
        .map(({ key, label, range }) => ({ label, range, ...gtPriorityRowCounts(coverageRows, key, null, safeCounts) }))
        .filter(l => l.known_found + l.known_not_found + l.safe > 0);
    if (count) count.textContent = String(levels.length);
    if (!levels.length) { wrap.innerHTML = '<p class="no-agents">No detections yet</p>'; return; }

    const bodyRows = levels.map(l => `<tr><td>${gtEsc(l.label)}<div class="gt-priority-range">${gtEsc(l.range)}</div></td>${cellsFor(l)}</tr>`);
    const f = sumField(levels, 'known_found'), m = sumField(levels, 'known_not_found'), s = sumField(levels, 'safe');
    const totalRow = `<tr class="gt-total-row"><td><strong>Total</strong></td>
        <td><strong>${f}</strong></td><td><strong>${m}</strong></td><td><strong>${s}</strong></td><td><strong>${f + m + s}</strong></td>
    </tr>`;

    wrap.innerHTML = `<table>
        <thead><tr>
            <th>Priority</th>
            <th title="Known-vulnerable GT pages at this priority, found">Found</th>
            <th title="Known-vulnerable GT pages at this priority, missed">Missed</th>
            <th title="Whole job (not limited to GT URLs): non-vulnerable pages tagged this priority">Safe</th>
            <th title="Found + Missed + Safe">Total</th>
        </tr></thead>
        <tbody>
            ${bodyRows.join('')}
            ${totalRow}
        </tbody>
    </table>`;
}

/** `showJob` adds a "Job" column identifying which job produced each finding
 * (only meaningful in All Jobs mode, where findings can come from any of them). */
function gtRenderExtra(rows, showJob) {
    const wrap = document.getElementById('gt-extra-wrap');
    const count = document.getElementById('gt-extra-count');
    if (count) count.textContent = rows.length;
    if (!wrap) return;
    if (!rows.length) { wrap.innerHTML = '<p class="no-agents">No extra findings outside the ground truth list</p>'; return; }
    wrap.innerHTML = `<table>
        <thead><tr>${showJob ? '<th>Job</th>' : ''}<th>URL</th><th>DBMS</th><th>Status</th></tr></thead>
        <tbody>
            ${rows.map(r => {
                const badge = r.exploited ? '✅ Exploited' : '⚠️ Vulnerable';
                const cls = r.exploited ? 'state-done' : 'state-pending';
                const jobTd = showJob ? `<td>#${gtEsc(r.detection.jobs_id ?? '—')}</td>` : '';
                return `<tr>
                    ${jobTd}
                    <td title="${gtEsc(r.detection.target_url)}">${gtEsc(r.detection.target_url)}</td>
                    <td>${gtEsc(r.detection.dbms || '—')}</td>
                    <td><span class="state-badge ${cls}">${badge}</span></td>
                </tr>`;
            }).join('')}
        </tbody>
    </table>`;
}

// ------------------------------------------------------------------
// Detail modal — sqlmap log + everything known about one GT row's page
// ------------------------------------------------------------------

let gtModalLogRequestSeq = 0;

async function gtOpenDetailModal(payload) {
    const modal    = document.getElementById('gt-detail-modal');
    const title    = document.getElementById('gt-modal-title');
    const fields   = document.getElementById('gt-modal-fields');
    const priority = document.getElementById('gt-modal-priority');
    const logSection = document.getElementById('gt-modal-log-section');
    const logPre   = document.getElementById('gt-modal-log');
    if (!modal || !fields) return;

    title.textContent = `${payload.app} — ${payload.url}`;

    if (priority) {
        if (payload.priority_score !== null && payload.priority_score !== undefined) {
            priority.textContent = `📊 Priority score: ${payload.priority_score}${payload.priority_level ? ` (${payload.priority_level})` : ''}`;
            priority.style.display = 'block';
        } else {
            priority.style.display = 'none';
        }
    }

    // Flatten the ground-truth status and the underlying sqli_detector row (if
    // any) into one field list. Detection fields win on key collision (e.g.
    // 'state' means more coming from the actual tested row than the page).
    const d = payload.detection || {};
    const rowData = {
        status: GT_STATUS_META[payload.category]?.label || payload.category,
        page_state: payload.page_state,
        page_error_message: payload.page_error_message,
        target_url: d.target_url,
        method: d.method,
        is_vulnerable: d.is_vulnerable,
        dbms: d.dbms,
        injection_points_json: d.injection_points_json,
        injection_types_json: d.injection_types_json,
        error_message: d.error_message,
        state: d.state,
    };
    let html = '';
    for (const [k, v] of Object.entries(rowData)) {
        if (v === null || v === undefined || v === '') continue;
        const value = typeof v === 'object' ? JSON.stringify(v) : String(v);
        html += `<dt>${gtEsc(k)}</dt><dd>${gtEsc(value)}</dd>`;
    }
    fields.innerHTML = html || '<dt>—</dt><dd>No data</dd>';
    modal.style.display = 'flex';

    if (logSection && logPre) {
        const requestId = ++gtModalLogRequestSeq;
        if (payload.crawl_page_id !== null && payload.crawl_page_id !== undefined) {
            logSection.style.display = 'block';
            logPre.textContent = 'Loading…';
            try {
                const { log } = await API.getV2Log('detector', payload.crawl_page_id);
                if (requestId === gtModalLogRequestSeq) logPre.textContent = log || '(no log captured)';
            } catch (err) {
                if (requestId === gtModalLogRequestSeq) logPre.textContent = `Could not load log: ${err.message}`;
            }
        } else {
            logSection.style.display = 'none';
            logPre.textContent = '';
        }
    }
}

document.getElementById('gt-coverage-wrap')?.addEventListener('click', (e) => {
    const btn = e.target.closest('.gt-details-btn');
    if (!btn) return;
    let payload;
    try { payload = JSON.parse(btn.dataset.json); } catch (err) { return; }
    gtOpenDetailModal(payload);
});

document.getElementById('gt-modal-close-btn')?.addEventListener('click', () => {
    document.getElementById('gt-detail-modal').style.display = 'none';
});

document.getElementById('gt-detail-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.style.display = 'none';
});

// ------------------------------------------------------------------
// CSV export — everything currently on screen (coverage + extra findings),
// built from the same row data the tables render from rather than scraped
// from the DOM, so it's accurate regardless of single-job/All-Jobs mode.
// ------------------------------------------------------------------

function gtCsvField(value) {
    const s = String(value ?? '');
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function gtCsvRow(fields) {
    return fields.map(gtCsvField).join(',');
}

function gtStatusLabel(category) {
    return GT_STATUS_META[category]?.label || category || '';
}

function gtBuildCsv() {
    const lines = [];
    const zapKeys = zapDetectedKeys || new Set();

    lines.push(`Ground truth coverage — ${gtLastScope}`);
    if (gtLastJobs) {
        lines.push(gtCsvRow(['App', 'URL', 'ZAP', ...gtLastJobs.map(j => `Job #${j.id}`), 'Any job']));
        for (const r of gtLastCoverageRows) {
            const zapHit = zapKeys.has(gtNormalizeUrl(r.url)) ? 'Yes' : 'No';
            const perJobLabels = gtLastJobs.map(j => gtStatusLabel(r.perJob[j.id]));
            lines.push(gtCsvRow([r.app, r.url, zapHit, ...perJobLabels, gtStatusLabel(r.category)]));
        }
    } else {
        lines.push(gtCsvRow(['App', 'URL', 'ZAP', 'Priority', 'Status']));
        for (const r of gtLastCoverageRows) {
            const zapHit = zapKeys.has(gtNormalizeUrl(r.url)) ? 'Yes' : 'No';
            lines.push(gtCsvRow([r.app, r.url, zapHit, gtPriorityLabel(r.page), gtStatusLabel(r.category)]));
        }
    }

    lines.push('');
    lines.push('Coverage by app');
    const appSummary = gtAppSummaryRows(gtLastCoverageRows, gtLastJobs);
    const appsTotal = appSummary.length;
    const appsHitCount = (getter) => appSummary.filter(s => getter(s) > 0).length;
    if (gtLastJobs) {
        lines.push(gtCsvRow(['App', 'URLs', 'ZAP', ...gtLastJobs.map(j => `Job #${j.id}`), 'Any job']));
        for (const s of appSummary) {
            lines.push(gtCsvRow([s.app, s.total, s.zapFound, ...gtLastJobs.map(j => s.perJob[j.id]), s.anyFound]));
        }
        lines.push(gtCsvRow([
            'Apps with ≥1 finding', appsTotal, appsHitCount(s => s.zapFound),
            ...gtLastJobs.map(j => appsHitCount(s => s.perJob[j.id])), appsHitCount(s => s.anyFound),
        ]));
    } else {
        lines.push(gtCsvRow(['App', 'URLs', 'ZAP', 'Found']));
        for (const s of appSummary) {
            lines.push(gtCsvRow([s.app, s.total, s.zapFound, s.anyFound]));
        }
        lines.push(gtCsvRow(['Apps with ≥1 finding', appsTotal, appsHitCount(s => s.zapFound), appsHitCount(s => s.anyFound)]));
    }

    lines.push('');
    lines.push('Vulnerabilities by priority (known-vulnerable GT pages found/missed per job, plus that job\'s whole-run safe pages by priority)');
    const csvPageById = new Map(gtLastPages.map(p => [p.id, p]));
    const csvCell = (c) => [c.known_found, c.known_not_found, c.safe, c.total];
    if (gtLastJobs) {
        const safeByJob = new Map(gtLastJobs.map(j => [j.id, gtBuildSafeByPriority(gtLastDetections.filter(d => d.jobs_id === j.id), csvPageById)]));
        const header = ['Priority'];
        for (const j of gtLastJobs) header.push(`Job #${j.id} Found`, `Job #${j.id} Missed`, `Job #${j.id} Safe`, `Job #${j.id} Total`);
        lines.push(gtCsvRow(header));
        for (const { key, label } of GT_PRIORITY_LEVELS) {
            const perJob = gtLastJobs.map(j => gtPriorityRowCounts(gtLastCoverageRows, key, j.id, safeByJob.get(j.id)));
            if (!perJob.some(c => c.known_found + c.known_not_found + c.safe > 0)) continue;
            const row = [label];
            for (const c of perJob) row.push(...csvCell(c));
            lines.push(gtCsvRow(row));
        }
    } else {
        const csvSafeCounts = gtBuildSafeByPriority(gtLastDetections, csvPageById);
        lines.push(gtCsvRow(['Priority', 'Found', 'Missed', 'Safe', 'Total']));
        for (const { key, label } of GT_PRIORITY_LEVELS) {
            const c = gtPriorityRowCounts(gtLastCoverageRows, key, null, csvSafeCounts);
            if (c.known_found + c.known_not_found + c.safe === 0) continue;
            lines.push(gtCsvRow([label, ...csvCell(c)]));
        }
    }

    lines.push('');
    lines.push('Extra findings (vulnerable, not in ground truth)');
    const extraHeader = gtLastShowJob ? ['Job', 'URL', 'DBMS', 'Status'] : ['URL', 'DBMS', 'Status'];
    lines.push(gtCsvRow(extraHeader));
    for (const r of gtLastExtraRows) {
        const status = r.exploited ? 'Exploited' : 'Vulnerable';
        const row = gtLastShowJob
            ? [`#${r.detection.jobs_id ?? '—'}`, r.detection.target_url, r.detection.dbms || '', status]
            : [r.detection.target_url, r.detection.dbms || '', status];
        lines.push(gtCsvRow(row));
    }

    return lines.join('\r\n');
}

function gtDownloadCsv() {
    if (!gtLastCoverageRows.length && !gtLastExtraRows.length) return;
    const csv = gtBuildCsv();
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const scopeSlug = gtLastScope.replace(/[^a-z0-9]+/gi, '-').toLowerCase();
    const a = document.createElement('a');
    a.href = url;
    a.download = `debug-gt-${scopeSlug}-${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

document.getElementById('gt-download-csv-btn')?.addEventListener('click', gtDownloadCsv);
