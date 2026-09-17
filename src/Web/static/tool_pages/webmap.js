// WebMap - Tree visualization of crawled pages

let wmAutoRefreshInterval = null;
let wmNodeCounter = 0;
let wmUserCollapsed = false;

const WM_STATUS_COLORS = {
    pending:    '#888888',
    safe:       '#22c55e',
    discarded:  '#facc15',
    vulnerable: '#f59e0b',
    exploited:  '#ef4444',
};

function wmStatusPriority(status) {
    return ({ pending: 0, safe: 1, discarded: 2, vulnerable: 3, exploited: 4 })[status] ?? 0;
}

function wmStart() {
    if (wmAutoRefreshInterval) clearInterval(wmAutoRefreshInterval);
    wmLoadAndRender();
    wmAutoRefreshInterval = setInterval(wmLoadAndRender, 5000);
}

function wmStop() {
    if (wmAutoRefreshInterval) {
        clearInterval(wmAutoRefreshInterval);
        wmAutoRefreshInterval = null;
    }
}

/** Shows the page body only once a job is selected; otherwise shows the empty state. */
function wmUpdateBodyVisibility(jobId) {
    const body  = document.getElementById('wm-body');
    const empty = document.getElementById('wm-empty-state');
    if (!body || !empty) return;
    body.style.display  = jobId ? 'flex' : 'none';
    empty.style.display = jobId ? 'none' : 'flex';
}

async function wmLoadAndRender() {
    const jobId = (typeof selectedJobId !== 'undefined') ? selectedJobId : null;
    const indicator = document.getElementById('wm-refresh-indicator');
    const jobLabel  = document.getElementById('wm-job-label');

    wmUpdateBodyVisibility(jobId);
    if (!jobId) return;

    if (indicator) { indicator.textContent = '↻'; indicator.classList.add('spinning'); }
    if (jobLabel)  jobLabel.textContent = 'Job #' + jobId;

    try {
        const data  = await API.getWebmap(jobId);
        const pages = data.pages || [];

        // Save collapsed state before re-render (IDs are deterministic by render order)
        const collapsedIds = new Set();
        document.querySelectorAll('.wm-children').forEach(el => {
            if (el.style.display === 'none') collapsedIds.add(el.id);
        });
        const hadState = collapsedIds.size > 0 || document.querySelectorAll('.wm-children').length > 0;

        wmNodeCounter = 0;
        wmRenderTree(pages);

        // Restore collapsed state
        if (hadState) {
            document.querySelectorAll('.wm-children').forEach(el => {
                const btn = el.previousElementSibling;
                if (collapsedIds.has(el.id)) {
                    el.style.display = 'none';
                    if (btn && btn.classList.contains('wm-toggle')) btn.textContent = '▶';
                } else {
                    el.style.display = 'block';
                    if (btn && btn.classList.contains('wm-toggle')) btn.textContent = '▼';
                }
            });
        }

        if (wmUserCollapsed) wmCollapseAll();
    } catch (e) {
        const c = document.getElementById('wm-tree-container');
        if (c) c.innerHTML = '<p class="wm-empty wm-error">Error loading WebMap: ' + wmEscH(e.message) + '</p>';
    } finally {
        if (indicator) { indicator.textContent = ''; indicator.classList.remove('spinning'); }
    }
}

function wmRenderTree(pages) {
    const container = document.getElementById('wm-tree-container');
    if (!container) return;

    if (!pages.length) {
        container.innerHTML = '<p class="wm-empty">No crawled pages found for this job.</p>';
        return;
    }

    // Group: host_id -> webapp_id -> pages[]
    const hosts = {};
    for (const p of pages) {
        if (!hosts[p.host_id]) {
            hosts[p.host_id] = { target_host: p.target_host, webapps: {} };
        }
        const wa = hosts[p.host_id].webapps;
        if (!wa[p.webapp_id]) {
            wa[p.webapp_id] = { webapp_url: p.webapp_url, pages: [] };
        }
        wa[p.webapp_id].pages.push(p);
    }

    let html = '';
    for (const host of Object.values(hosts)) {
        html += '<div class="wm-host-block">';
        html += '<div class="wm-host-title">🖥️ ' + wmEscH(host.target_host) + '</div>';

        for (const webapp of Object.values(host.webapps)) {
            const total     = webapp.pages.length;
            const exploited  = webapp.pages.filter(function(p){ return p.status === 'exploited';  }).length;
            const vuln       = webapp.pages.filter(function(p){ return p.status === 'vulnerable'; }).length;
            const discarded  = webapp.pages.filter(function(p){ return p.status === 'discarded';  }).length;
            const safe       = webapp.pages.filter(function(p){ return p.status === 'safe';       }).length;
            const pending    = total - exploited - vuln - discarded - safe;

            const parts = [];
            if (exploited)  parts.push('<span style="color:#ef4444">&#9679; ' + exploited  + ' exploited</span>');
            if (vuln)       parts.push('<span style="color:#f59e0b">&#9679; ' + vuln       + ' vulnerable</span>');
            if (discarded)  parts.push('<span style="color:#facc15">&#9679; ' + discarded  + ' discarded</span>');
            if (safe)       parts.push('<span style="color:#22c55e">&#9679; ' + safe       + ' safe</span>');
            if (pending)    parts.push('<span style="color:#888">&#9679; '    + pending    + ' pending</span>');
            const summary = parts.join(' &nbsp; ');

            html += '<div class="wm-webapp-block">';
            html += '<div class="wm-webapp-title">';
            html += '🌐 <a href="' + wmEscH(webapp.webapp_url) + '" target="_blank" class="wm-webapp-link">' + wmEscH(webapp.webapp_url) + '</a>';
            if (summary) html += '<span class="wm-webapp-summary">' + summary + '</span>';
            html += '</div>';

            const trie = wmBuildTrie(webapp.pages, webapp.webapp_url);
            wmComputeMaxStatus(trie);
            html += '<div class="wm-tree">' + wmRenderNode(trie, true) + '</div>';

            html += '</div>';
        }

        html += '</div>';
    }

    container.innerHTML = html;
}

function wmBuildTrie(pages, webappUrl) {
    const root = { name: '', children: {}, page: null, maxStatus: 'pending' };

    let basePath = '';
    try { basePath = new URL(webappUrl).pathname.replace(/\/$/, ''); } catch(e) {}

    for (var i = 0; i < pages.length; i++) {
        var page = pages[i];
        try {
            var u    = new URL(page.page_url);
            var path = u.pathname;

            if (basePath && path.indexOf(basePath) === 0) {
                path = path.slice(basePath.length);
            }
            if (path.charAt(0) === '/') path = path.slice(1);

            var segments = path ? path.split('/') : [];
            var qs       = u.search;

            var node = root;
            for (var j = 0; j < segments.length - 1; j++) {
                var dirKey = segments[j] + '/';
                if (!node.children[dirKey]) {
                    node.children[dirKey] = { name: dirKey, children: {}, page: null, maxStatus: 'pending' };
                }
                node = node.children[dirKey];
            }

            var lastSeg = segments.length > 0 ? segments[segments.length - 1] : '';
            var leafKey = (lastSeg + qs) || '/';

            if (!node.children[leafKey]) {
                node.children[leafKey] = { name: leafKey, children: {}, page: null, maxStatus: 'pending' };
            }
            var leaf = node.children[leafKey];
            if (!leaf.page || wmStatusPriority(page.status) > wmStatusPriority(leaf.page.status)) {
                leaf.page = page;
            }
        } catch(e) {}
    }

    return root;
}

// Propagates the highest-priority status up through the trie.
// Returns the maxStatus of this node's subtree.
function wmComputeMaxStatus(node) {
    var maxPrio   = node.page ? wmStatusPriority(node.page.status) : 0;
    var maxStatus = node.page ? node.page.status : 'pending';

    var keys = Object.keys(node.children);
    for (var i = 0; i < keys.length; i++) {
        var childStatus = wmComputeMaxStatus(node.children[keys[i]]);
        var childPrio   = wmStatusPriority(childStatus);
        if (childPrio > maxPrio) {
            maxPrio   = childPrio;
            maxStatus = childStatus;
        }
    }

    node.maxStatus = maxStatus;
    return maxStatus;
}

function wmRenderNode(node, isRoot) {
    var childKeys = Object.keys(node.children);
    if (!childKeys.length) return '';

    var html = '<ul class="wm-ul">';
    for (var k = 0; k < childKeys.length; k++) {
        var child       = node.children[childKeys[k]];
        var hasChildren = Object.keys(child.children).length > 0;
        var isDir       = !child.page;
        var page        = child.page;
        var status      = page ? page.status : 'pending';
        var color       = WM_STATUS_COLORS[status] || '#888';

        var score = '';
        if (page && page.priority_score != null) {
            score = '<span class="wm-score" title="Priority score">' + page.priority_score + '</span>';
        }

        var dot = isDir
            ? '<span class="wm-dot wm-dot-dir" title="directory"></span>'
            : '<span class="wm-dot" style="background:' + color + '" title="' + wmEscH(status) + '"></span>';

        var toggleBtn    = '';
        var childrenHtml = '';
        if (hasChildren) {
            var nodeId    = 'wm-n-' + (++wmNodeCounter);
            var maxStatus = child.maxStatus || 'pending';
            toggleBtn     = '<button class="wm-toggle" onclick="wmToggle(\'' + nodeId + '\')">&#9660;</button>';
            childrenHtml  = '<div id="' + nodeId + '" class="wm-children" data-max-status="' + maxStatus + '">'
                          + wmRenderNode(child, false)
                          + '</div>';
        }

        var labelContent = wmEscH(child.name);
        var label = (page && !isDir)
            ? '<a class="wm-label" href="' + wmEscH(page.page_url) + '" target="_blank">' + labelContent + '</a>'
            : '<span class="wm-label wm-dir-label">' + labelContent + '</span>';

        html += '<li class="wm-li">' + toggleBtn + dot + label + score + childrenHtml + '</li>';
    }
    html += '</ul>';
    return html;
}

function wmToggle(nodeId) {
    var el  = document.getElementById(nodeId);
    if (!el) return;
    var btn = el.previousElementSibling;
    if (el.style.display === 'none') {
        el.style.display = 'block';
        if (btn && btn.classList.contains('wm-toggle')) btn.textContent = '▼';
        wmUserCollapsed = false;  // user is manually expanding — stop forcing collapse
    } else {
        el.style.display = 'none';
        if (btn && btn.classList.contains('wm-toggle')) btn.textContent = '▶';
    }
}

// Collapses all nodes; keeps expanded those whose subtree contains
// at least one vulnerable or exploited page.
function wmCollapseAll() {
    wmUserCollapsed = true;
    var nodes = document.querySelectorAll('.wm-children');
    for (var i = 0; i < nodes.length; i++) {
        var el        = nodes[i];
        var maxStatus = el.getAttribute('data-max-status') || 'pending';
        var keepOpen  = (maxStatus === 'vulnerable' || maxStatus === 'exploited');
        var btn       = el.previousElementSibling;

        if (keepOpen) {
            el.style.display = 'block';
            if (btn && btn.classList.contains('wm-toggle')) btn.textContent = '▼';
        } else {
            el.style.display = 'none';
            if (btn && btn.classList.contains('wm-toggle')) btn.textContent = '▶';
        }
    }
}

function wmEscH(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
