// Debug Timeline — cumulative distinct ground-truth pages found vulnerable
// vs. elapsed job time, one line per selected job (see tlBuildGtSeries),
// plus a second chart of cumulative distinct ground-truth *projects/apps*
// with >=1 vulnerability found (see tlBuildAppSeries). Both are derived
// client-side from the same raw per-event API response (GET
// /api/debug-gt/vuln-timeline, grouped by url_pattern/method/injection
// points, GT and non-GT alike) by matching each event's URL against
// debug_data/GT_URLS.json - this keeps both totals equal to Debug GT's
// "found/N" numbers for the same job, rather than the finer-grained,
// GT-unbounded count the raw API returns. Self-contained, mirrors
// debug_gt.js's structure (job picker + API calls + Chart.js render).

// Fixed categorical order, read from the CSS custom properties defined on
// .viz-root in styles.css — never cycled or reassigned per dataviz skill's
// color-formula.md. A 9th+ job simply can't be added (checkbox disabled)
// rather than reusing/generating a hue.
const TL_MAX_SERIES = 8;
let TL_SERIES_COLORS = [];

function tlSeriesColors() {
    if (TL_SERIES_COLORS.length) return TL_SERIES_COLORS;
    const root = document.querySelector('.viz-root');
    const style = root ? getComputedStyle(root) : getComputedStyle(document.documentElement);
    TL_SERIES_COLORS = Array.from({ length: TL_MAX_SERIES }, (_, i) =>
        style.getPropertyValue(`--series-${i + 1}`).trim() || '#888'
    );
    return TL_SERIES_COLORS;
}

let tlJobs = [];             // full job list from API.getJobs()
let tlSelectedIds = [];      // ordered list of selected job ids (order = color assignment)
let tlChart = null;
let tlSeries = {};           // job_id -> { start, finished_at, state, target_url, points }
let tlTableVisible = false;

// --- Ground-truth app lookup, for the "distinct projects found vulnerable"
// chart below. Same source Debug GT uses (debug_data/GT_URLS.json via
// GET /api/debug-gt/urls) and the same URL normalization, so a url_pattern
// variant of a GT page (different query string, same page) still resolves
// to its app. Findings outside the GT app list have nothing to attribute
// to and are skipped in that chart.
let tlAppsChart = null;
let tlAppByUrl = null;   // normalized url -> app name, once loaded
let tlTotalApps = 0;
let tlTotalGtUrls = 0;   // == Debug GT's GT_PAGES.length, so both totals mean the same thing
let tlGtAppsPromise = null;

function tlLoadGtApps() {
    if (tlGtAppsPromise) return tlGtAppsPromise;
    tlGtAppsPromise = (async () => {
        tlAppByUrl = new Map();
        try {
            const { gt_pages } = await API.getGtUrls();
            const apps = new Set();
            for (const gt of gt_pages || []) {
                tlAppByUrl.set(tlNormalizeUrl(gt.url), gt.app);
                apps.add(gt.app);
            }
            tlTotalApps = apps.size;
            tlTotalGtUrls = (gt_pages || []).length;
        } catch (err) {
            console.error('Debug Timeline: error loading GT apps', err);
        }
        return tlAppByUrl;
    })();
    return tlGtAppsPromise;
}

/** Same normalization as Debug GT's gtNormalizeUrl (duplicated here since
 * this page doesn't load debug_gt.js): strips query/fragment so different
 * parameter values for the same page resolve to one entry. */
function tlNormalizeUrl(url) {
    if (!url) return '';
    let u = String(url).trim();
    const qIdx = u.search(/[?#]/);
    if (qIdx !== -1) u = u.slice(0, qIdx);
    try { u = decodeURIComponent(u); } catch (e) { /* malformed escape, use as-is */ }
    return u.replace(/\/$/, '').toLowerCase();
}

/** Derives "cumulative distinct GT apps with >=1 vulnerability" from the
 * same per-URL detection events the main chart uses (tlSeries[id].points
 * already carries the url of each new vulnerability, in elapsed-time
 * order) - the first event whose URL belongs to a not-yet-seen app bumps
 * the count. No separate API call or backend support needed. */
function tlBuildAppSeries(id) {
    const s = tlSeries[id];
    if (!s || !tlAppByUrl) return null;
    const seenApps = new Set();
    const points = [{ t: 0, count: 0 }];
    let count = 0;
    for (const p of s.points) {
        if (!p.url) continue;
        const app = tlAppByUrl.get(tlNormalizeUrl(p.url));
        if (!app || seenApps.has(app)) continue;
        seenApps.add(app);
        count += 1;
        points.push({ t: p.t, count, app });
    }
    return { state: s.state, points };
}

/** Derives "cumulative distinct ground-truth PAGES with >=1 vulnerability"
 * - the same thing Debug GT's headline "found/N" counts - from the raw
 * per-event points, same way tlBuildAppSeries does it one level up (by app
 * instead of by page). The raw API data groups by (url_pattern, method,
 * injection_points) and includes pages outside the GT list, so its own
 * last count is a *different, larger* number than Debug GT's; this is what
 * makes the main chart's total actually equal Debug GT's for the same job. */
function tlBuildGtSeries(id) {
    const s = tlSeries[id];
    if (!s || !tlAppByUrl) return null;
    const seenUrls = new Set();
    const points = [{ t: 0, count: 0 }];
    let count = 0;
    for (const p of s.points) {
        if (!p.url) continue;
        const key = tlNormalizeUrl(p.url);
        if (!tlAppByUrl.has(key) || seenUrls.has(key)) continue;
        seenUrls.add(key);
        count += 1;
        points.push({ t: p.t, count, url: p.url });
    }
    return { state: s.state, points };
}

function tlEsc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function tlJobLabel(j) {
    const type = j.type || 'Normal';
    const ts = j.timestamp ? ' (' + String(j.timestamp).slice(0, 10) + ')' : '';
    const running = j.state === 'running' ? ' 🔄' : '';
    return `#${j.id}${running} ${type}${ts}`;
}

async function tlLoadJobsPicker() {
    const wrap = document.getElementById('tl-job-picker');
    if (!wrap) return;
    try {
        const data = await API.getJobs();
        tlJobs = (data.jobs || []).slice().sort((a, b) => b.id - a.id);
    } catch (err) {
        console.error('Debug Timeline: error loading jobs', err);
        wrap.innerHTML = '<p class="no-agents">Error loading jobs</p>';
        return;
    }
    if (!tlJobs.length) {
        wrap.innerHTML = '<p class="no-agents">No jobs yet</p>';
        return;
    }
    // Default selection: the most recent finished jobs, capped at the palette size.
    if (!tlSelectedIds.length) {
        tlSelectedIds = tlJobs.filter(j => j.state !== 'running').slice(0, 5).map(j => j.id);
    }
    tlRenderPicker();
    tlLoadAndRenderChart();
}

function tlRenderPicker() {
    const wrap = document.getElementById('tl-job-picker');
    if (!wrap) return;
    const colors = tlSeriesColors();
    wrap.innerHTML = tlJobs.map(j => {
        const idx = tlSelectedIds.indexOf(j.id);
        const checked = idx !== -1;
        const disabled = !checked && tlSelectedIds.length >= TL_MAX_SERIES;
        const swatch = checked
            ? `<span class="timeline-swatch" style="background:${colors[idx % colors.length]}"></span>`
            : `<span class="timeline-swatch" style="background:transparent;border-style:dashed"></span>`;
        return `<label class="timeline-job-chip${disabled ? ' disabled' : ''}" title="${tlEsc(j.target_url || '')}${j.comment ? ' — ' + tlEsc(j.comment) : ''}">
            <input type="checkbox" data-job-id="${j.id}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
            ${swatch}
            <span>${tlEsc(tlJobLabel(j))}</span>
        </label>`;
    }).join('');
}

function tlToggleJob(jobId, on) {
    if (on) {
        if (tlSelectedIds.includes(jobId) || tlSelectedIds.length >= TL_MAX_SERIES) return;
        tlSelectedIds.push(jobId);
    } else {
        tlSelectedIds = tlSelectedIds.filter(id => id !== jobId);
    }
    tlRenderPicker();
    tlLoadAndRenderChart();
}

document.getElementById('tl-job-picker')?.addEventListener('change', (e) => {
    const cb = e.target.closest('input[type="checkbox"][data-job-id]');
    if (!cb) return;
    tlToggleJob(parseInt(cb.dataset.jobId, 10), cb.checked);
});

document.getElementById('tl-table-toggle')?.addEventListener('click', () => {
    tlTableVisible = !tlTableVisible;
    const section = document.getElementById('tl-table-section');
    const btn = document.getElementById('tl-table-toggle');
    if (section) section.style.display = tlTableVisible ? 'block' : 'none';
    if (btn) btn.textContent = tlTableVisible ? '📋 Hide table' : '📋 Show table';
    if (tlTableVisible) tlRenderTable();
});

async function tlLoadAndRenderChart() {
    const summary = document.getElementById('tl-summary');
    const appsSummary = document.getElementById('tl-apps-summary');
    if (!tlSelectedIds.length) {
        tlSeries = {};
        if (summary) summary.textContent = '';
        if (appsSummary) appsSummary.textContent = '';
        tlRenderChart();
        tlRenderAppsChart();
        if (tlTableVisible) tlRenderTable();
        return;
    }
    try {
        const { series } = await API.getVulnTimeline(tlSelectedIds);
        tlSeries = series || {};
    } catch (err) {
        console.error('Debug Timeline: error loading vuln timeline', err);
        tlSeries = {};
    }
    await tlLoadGtApps();
    if (summary) {
        const totals = tlSelectedIds
            .map(id => ({ id, s: tlBuildGtSeries(id) }))
            .filter(({ s }) => s)
            .map(({ id, s }) => `#${id}: ${s.points[s.points.length - 1]?.count ?? 0}${tlTotalGtUrls ? `/${tlTotalGtUrls}` : ''}`);
        summary.textContent = totals.join('  ·  ');
    }
    if (appsSummary) {
        const totals = tlSelectedIds
            .map(id => ({ id, s: tlBuildAppSeries(id) }))
            .filter(({ s }) => s)
            .map(({ id, s }) => `#${id}: ${s.points[s.points.length - 1]?.count ?? 0}${tlTotalApps ? `/${tlTotalApps}` : ''}`);
        appsSummary.textContent = totals.join('  ·  ');
    }
    tlRenderChart();
    tlRenderAppsChart();
    if (tlTableVisible) tlRenderTable();
}

/** minutes look better than raw seconds on the axis for jobs running for hours */
function tlMinutes(seconds) {
    return Math.round((seconds / 60) * 10) / 10;
}

/** Draws each series' final count next to its last point — a selective
 * direct label (endpoint only, not every point), per dataviz skill's
 * marks-and-anatomy.md. Label text stays in ink (--text-primary), never the
 * series color: the colored endpoint marker right next to it already
 * carries identity. A simple vertical-collision pass nudges labels apart
 * when two jobs end at (near) the same count. */
const tlEndpointLabelsPlugin = {
    id: 'tlEndpointLabels',
    afterDatasetsDraw(chart) {
        const { ctx, chartArea } = chart;
        if (!chartArea) return;
        const textColor = (chart.options.plugins && chart.options.plugins.tlEndpointLabels
            && chart.options.plugins.tlEndpointLabels.color) || '#111';
        const placements = [];
        chart.data.datasets.forEach((dataset, i) => {
            const meta = chart.getDatasetMeta(i);
            if (!meta || meta.hidden || !dataset.data.length) return;
            const lastIndex = dataset.data.length - 1;
            const point = meta.data[lastIndex];
            if (!point) return;
            const value = dataset.data[lastIndex].y;
            const labelText = String(value);
            const rightFits = point.x + 10 + ctx.measureText(labelText).width + 4 <= chartArea.right;
            placements.push({ point, labelText, color: dataset.borderColor, alignRight: rightFits, y: point.y });
        });
        // Stack labels that would otherwise overlap vertically (within 14px).
        placements.sort((a, b) => a.y - b.y);
        for (let i = 1; i < placements.length; i++) {
            if (placements[i].y - placements[i - 1].y < 14) {
                placements[i].y = placements[i - 1].y + 14;
            }
        }
        ctx.save();
        ctx.font = '700 12px system-ui, -apple-system, "Segoe UI", sans-serif';
        ctx.textBaseline = 'middle';
        for (const p of placements) {
            ctx.fillStyle = textColor;
            ctx.textAlign = p.alignRight ? 'left' : 'right';
            const x = p.point.x + (p.alignRight ? 10 : -10);
            ctx.fillText(p.labelText, x, p.y);
        }
        ctx.restore();
    },
};
Chart.register(tlEndpointLabelsPlugin);

function tlRenderChart() {
    const canvas = document.getElementById('tl-chart');
    if (!canvas || typeof Chart === 'undefined') return;
    const colors = tlSeriesColors();

    const datasets = tlSelectedIds
        .map((id, i) => ({ id, i, s: tlBuildGtSeries(id) }))
        .filter(({ s }) => s)
        .map(({ id, i, s }) => {
            const color = colors[i % colors.length];
            return {
                label: `Job #${id}${s.state === 'running' ? ' (running)' : ''}`,
                data: s.points.map(p => ({ x: tlMinutes(p.t), y: p.count, url: p.url })),
                borderColor: color,
                backgroundColor: color,
                pointRadius: (ctx) => (ctx.dataIndex === ctx.dataset.data.length - 1 ? 4 : 2),
                pointHoverRadius: 5,
                borderWidth: 2,
                tension: 0,
                stepped: 'after', // counts only change at discrete detection events
                fill: false,
            };
        });

    const rootStyle = getComputedStyle(document.querySelector('.viz-root') || document.documentElement);
    const textPrimary = rootStyle.getPropertyValue('--text-primary').trim() || '#111';
    const textSecondary = rootStyle.getPropertyValue('--text-secondary').trim() || '#555';
    const gridColor = rootStyle.getPropertyValue('--border-color').trim() || '#ddd';

    const config = {
        type: 'line',
        data: { datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            layout: { padding: { right: 34 } },
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: {
                    type: 'linear',
                    title: { display: true, text: 'Elapsed time (minutes)', color: textSecondary },
                    ticks: { color: textSecondary },
                    grid: { color: gridColor },
                },
                y: {
                    beginAtZero: true,
                    suggestedMax: tlTotalGtUrls || undefined,
                    title: {
                        display: true,
                        text: `Cumulative ground-truth pages found vulnerable${tlTotalGtUrls ? ` (of ${tlTotalGtUrls})` : ''}`,
                        color: textSecondary,
                    },
                    ticks: { color: textSecondary, precision: 0 },
                    grid: { color: gridColor },
                },
            },
            plugins: {
                legend: {
                    display: datasets.length > 0,
                    position: 'top',
                    labels: { color: textPrimary, usePointStyle: true, boxWidth: 8 },
                },
                tooltip: {
                    callbacks: {
                        title: (items) => items.length ? `${items[0].parsed.x} min` : '',
                        label: (item) => {
                            const p = item.raw;
                            return p?.url ? `${item.dataset.label}: ${p.url}` : `${item.dataset.label}: ${item.parsed.y}`;
                        },
                    },
                },
                tlEndpointLabels: { color: textPrimary },
            },
        },
    };

    if (tlChart) {
        tlChart.data = config.data;
        tlChart.options = config.options;
        tlChart.update();
    } else {
        tlChart = new Chart(canvas.getContext('2d'), config);
    }
}

/** Same chart as tlRenderChart, but for tlBuildAppSeries's cumulative
 * distinct-apps-found series - kept as a second canvas/chart instead of a
 * second dataset on the same axes since the two counts are on unrelated
 * scales (URLs found vs. GT apps found, capped at tlTotalApps). Job colors
 * are kept in sync with the main chart (same tlSelectedIds index -> same
 * palette slot) so a job is visually the same line in both. */
function tlRenderAppsChart() {
    const canvas = document.getElementById('tl-chart-apps');
    if (!canvas || typeof Chart === 'undefined') return;
    const colors = tlSeriesColors();

    const datasets = tlSelectedIds
        .map((id, i) => ({ id, i, s: tlBuildAppSeries(id) }))
        .filter(({ s }) => s)
        .map(({ id, i, s }) => {
            const color = colors[i % colors.length];
            return {
                label: `Job #${id}${s.state === 'running' ? ' (running)' : ''}`,
                data: s.points.map(p => ({ x: tlMinutes(p.t), y: p.count, app: p.app })),
                borderColor: color,
                backgroundColor: color,
                pointRadius: (ctx) => (ctx.dataIndex === ctx.dataset.data.length - 1 ? 4 : 2),
                pointHoverRadius: 5,
                borderWidth: 2,
                tension: 0,
                stepped: 'after',
                fill: false,
            };
        });

    const rootStyle = getComputedStyle(document.querySelector('.viz-root') || document.documentElement);
    const textPrimary = rootStyle.getPropertyValue('--text-primary').trim() || '#111';
    const textSecondary = rootStyle.getPropertyValue('--text-secondary').trim() || '#555';
    const gridColor = rootStyle.getPropertyValue('--border-color').trim() || '#ddd';

    const config = {
        type: 'line',
        data: { datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            layout: { padding: { right: 34 } },
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: {
                    type: 'linear',
                    title: { display: true, text: 'Elapsed time (minutes)', color: textSecondary },
                    ticks: { color: textSecondary },
                    grid: { color: gridColor },
                },
                y: {
                    beginAtZero: true,
                    suggestedMax: tlTotalApps || undefined,
                    title: {
                        display: true,
                        text: `Cumulative projects found vulnerable${tlTotalApps ? ` (of ${tlTotalApps})` : ''}`,
                        color: textSecondary,
                    },
                    ticks: { color: textSecondary, precision: 0 },
                    grid: { color: gridColor },
                },
            },
            plugins: {
                legend: {
                    display: datasets.length > 0,
                    position: 'top',
                    labels: { color: textPrimary, usePointStyle: true, boxWidth: 8 },
                },
                tooltip: {
                    callbacks: {
                        title: (items) => items.length ? `${items[0].parsed.x} min` : '',
                        label: (item) => {
                            const p = item.raw;
                            return p?.app ? `${item.dataset.label}: ${p.app}` : `${item.dataset.label}: ${item.parsed.y}`;
                        },
                    },
                },
                tlEndpointLabels: { color: textPrimary },
            },
        },
    };

    if (tlAppsChart) {
        tlAppsChart.data = config.data;
        tlAppsChart.options = config.options;
        tlAppsChart.update();
    } else {
        tlAppsChart = new Chart(canvas.getContext('2d'), config);
    }
}

/** Mirrors the main chart's data (tlBuildGtSeries - ground-truth pages
 * only, same total as Debug GT), not the raw per-event API response, so
 * the table always agrees with what's plotted above it. */
function tlRenderTable() {
    const wrap = document.getElementById('tl-table-wrap');
    if (!wrap) return;
    const rows = tlSelectedIds
        .map(id => ({ id, s: tlBuildGtSeries(id) }))
        .filter(({ s }) => s);
    if (!rows.length) {
        wrap.innerHTML = '<p class="no-agents">No jobs selected</p>';
        return;
    }
    wrap.innerHTML = `<table>
        <thead><tr><th>Job</th><th>Elapsed (min)</th><th>Cumulative count</th><th>URL</th></tr></thead>
        <tbody>
            ${rows.map(({ id, s }) => s.points.map(p => `<tr>
                <td>#${id}</td>
                <td>${tlMinutes(p.t)}</td>
                <td>${p.count}</td>
                <td title="${tlEsc(p.url || '')}">${tlEsc(p.url || '—')}</td>
            </tr>`).join('')).join('')}
        </tbody>
    </table>`;
}

// --- SVG export -------------------------------------------------------
// Chart.js draws to <canvas> (raster only), so "download as SVG" means
// re-drawing the current series as a small hand-built vector chart rather
// than rasterizing the canvas - keeps it crisp/editable when dropped into
// a report, which is the point of asking for SVG instead of a screenshot.
// Always rendered on a white background with dark ink, independent of the
// page's current theme: it's a portable figure, not a dashboard snapshot.

function tlSvgEsc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** `datasets` is [{ label, color, points: [{x,y}] }], points already in
 * final axis units (minutes / count) and sorted by x. Steps 'after', same
 * as the on-screen Chart.js series: the line holds the previous y until
 * the next x, then jumps - counts only change at discrete events. */
function tlChartToSvgString({ title, datasets, xTitle, yTitle, yMax }) {
    const W = 900, H = 460;
    const marginLeft = 60, marginRight = 90, marginTop = 46, marginBottom = 56;
    const plotW = W - marginLeft - marginRight;
    const plotH = H - marginTop - marginBottom;

    const allX = datasets.flatMap(d => d.points.map(p => p.x));
    const allY = datasets.flatMap(d => d.points.map(p => p.y));
    const maxX = Math.max(1, ...(allX.length ? allX : [0]));
    const maxY = Math.max(1, yMax || 0, ...(allY.length ? allY : [0]));

    const xScale = (x) => marginLeft + (x / maxX) * plotW;
    const yScale = (y) => marginTop + plotH - (y / maxY) * plotH;

    const yTickCount = 5;
    const yTicks = Array.from({ length: yTickCount + 1 }, (_, i) => Math.round((maxY / yTickCount) * i));
    const xTickCount = 6;
    const xTicks = Array.from({ length: xTickCount + 1 }, (_, i) => Math.round(((maxX / xTickCount) * i) * 10) / 10);

    const ink = '#1a1a1a', sub = '#555', grid = '#ddd';

    const gridLines = yTicks.map(t => {
        const y = yScale(t);
        return `<line x1="${marginLeft}" y1="${y}" x2="${marginLeft + plotW}" y2="${y}" stroke="${grid}" stroke-width="1"/>
            <text x="${marginLeft - 8}" y="${y}" text-anchor="end" dominant-baseline="middle" font-size="11" fill="${sub}">${t}</text>`;
    }).join('\n');

    const xLabels = xTicks.map(t => {
        const x = xScale(t);
        return `<text x="${x}" y="${marginTop + plotH + 20}" text-anchor="middle" font-size="11" fill="${sub}">${t}</text>`;
    }).join('\n');

    const seriesSvg = datasets.map((d) => {
        const pts = d.points;
        if (!pts.length) return '';
        let path = `M ${xScale(pts[0].x)} ${yScale(pts[0].y)}`;
        for (let i = 1; i < pts.length; i++) {
            const prev = pts[i - 1], cur = pts[i];
            path += ` L ${xScale(cur.x)} ${yScale(prev.y)} L ${xScale(cur.x)} ${yScale(cur.y)}`;
        }
        const last = pts[pts.length - 1];
        const lastX = xScale(last.x), lastY = yScale(last.y);
        const labelRight = lastX + 34 <= marginLeft + plotW + marginRight - 4;
        const labelX = labelRight ? lastX + 8 : lastX - 8;
        const anchor = labelRight ? 'start' : 'end';
        return `<path d="${path}" fill="none" stroke="${d.color}" stroke-width="2"/>
            <circle cx="${lastX}" cy="${lastY}" r="3.5" fill="${d.color}"/>
            <text x="${labelX}" y="${lastY}" text-anchor="${anchor}" dominant-baseline="middle" font-size="12" font-weight="700" fill="${ink}">${last.y}</text>`;
    }).join('\n');

    const legendSvg = datasets.map((d, i) => {
        const lx = marginLeft + i * 150;
        const ly = 22;
        return `<rect x="${lx}" y="${ly - 8}" width="10" height="10" fill="${d.color}"/>
            <text x="${lx + 16}" y="${ly}" font-size="12" fill="${ink}" dominant-baseline="middle">${tlSvgEsc(d.label)}</text>`;
    }).join('\n');

    return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" font-family="system-ui, -apple-system, 'Segoe UI', sans-serif">
        <rect x="0" y="0" width="${W}" height="${H}" fill="#ffffff"/>
        ${title ? `<text x="${marginLeft}" y="16" font-size="13" font-weight="700" fill="${ink}">${tlSvgEsc(title)}</text>` : ''}
        ${legendSvg}
        ${gridLines}
        <line x1="${marginLeft}" y1="${marginTop}" x2="${marginLeft}" y2="${marginTop + plotH}" stroke="${ink}" stroke-width="1"/>
        <line x1="${marginLeft}" y1="${marginTop + plotH}" x2="${marginLeft + plotW}" y2="${marginTop + plotH}" stroke="${ink}" stroke-width="1"/>
        ${xLabels}
        <text x="${marginLeft + plotW / 2}" y="${H - 8}" text-anchor="middle" font-size="12" fill="${sub}">${tlSvgEsc(xTitle)}</text>
        <text x="14" y="${marginTop + plotH / 2}" text-anchor="middle" font-size="12" fill="${sub}" transform="rotate(-90 14 ${marginTop + plotH / 2})">${tlSvgEsc(yTitle)}</text>
        ${seriesSvg}
    </svg>`;
}

function tlDownloadSvg(svgString, slug) {
    const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const a = document.createElement('a');
    a.href = url;
    a.download = `debug-timeline-${slug}-${stamp}.svg`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

function tlDownloadMainChartSvg() {
    const colors = tlSeriesColors();
    const datasets = tlSelectedIds
        .map((id, i) => ({ id, i, s: tlBuildGtSeries(id) }))
        .filter(({ s }) => s)
        .map(({ id, i, s }) => ({
            label: `Job #${id}`,
            color: colors[i % colors.length],
            points: s.points.map(p => ({ x: tlMinutes(p.t), y: p.count })),
        }));
    tlDownloadSvg(tlChartToSvgString({
        title: 'Cumulative ground-truth pages found vulnerable vs. elapsed time',
        datasets,
        xTitle: 'Elapsed time (minutes)',
        yTitle: `Cumulative ground-truth pages found vulnerable${tlTotalGtUrls ? ` (of ${tlTotalGtUrls})` : ''}`,
        yMax: tlTotalGtUrls,
    }), 'vulnerabilities');
}

function tlDownloadAppsChartSvg() {
    const colors = tlSeriesColors();
    const datasets = tlSelectedIds
        .map((id, i) => ({ id, i, s: tlBuildAppSeries(id) }))
        .filter(({ s }) => s)
        .map(({ id, i, s }) => ({
            label: `Job #${id}`,
            color: colors[i % colors.length],
            points: s.points.map(p => ({ x: tlMinutes(p.t), y: p.count })),
        }));
    tlDownloadSvg(tlChartToSvgString({
        title: 'Distinct projects found vulnerable vs. elapsed time',
        datasets,
        xTitle: 'Elapsed time (minutes)',
        yTitle: `Cumulative projects found vulnerable${tlTotalApps ? ` (of ${tlTotalApps})` : ''}`,
        yMax: tlTotalApps,
    }), 'projects');
}

document.getElementById('tl-download-svg-btn')?.addEventListener('click', tlDownloadMainChartSvg);
document.getElementById('tl-apps-download-svg-btn')?.addEventListener('click', tlDownloadAppsChartSvg);

function tlStart() {
    tlLoadGtApps();
    tlLoadJobsPicker();
}
