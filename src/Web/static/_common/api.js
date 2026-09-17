// API Communication Layer
// Manage all interactions with the backend

const API_BASE = '/websqli/api';

/**
 * API client for backend communication
 */
const API = {
    /**
     * Starts a scan with WebScanner
     * @param {string} ip - IP or URL to scan
     * @returns {Promise<ReadableStreamDefaultReader>} Stream of results
     */
    async startScanner(ip) {
        return this._startStream(`${API_BASE}/scan`, { ip });
    },

    /**
     * Starts a crawling with WebCrawler
     * @param {Object} params - Crawler parameters
     * @param {string} params.url - URL to crawl
     * @param {number} params.pages - Maximum number of pages
     * @param {number} params.depth - Maximum depth
     * @param {boolean} params.skip_nikto - Skip Nikto
     * @param {boolean} params.render - Render JS
     * @returns {Promise<ReadableStreamDefaultReader>} Stream of results
     */
    async startCrawler(params) {
        return this._startStream(`${API_BASE}/crawler`, params);
    },

    /**
     * Starts vulnerability detection with WebDetector
     * @param {Object} params - Detector parameters
     * @param {string} params.mode - Operation mode: 'url', 'webapp', or 'page'
     * @param {string} [params.url] - URL to analyze (mode 'url')
     * @param {number} [params.webapp_id] - Existing webapp ID (mode 'webapp')
     * @param {number} [params.page_id] - Crawled page ID (mode 'page')
     * @returns {Promise<ReadableStreamDefaultReader>} Stream of results
     */
    async startDetector(params) {
        return this._startStream(`${API_BASE}/detector`, params);
    },

    /**
     * Starts exploitation with SQLExploiter
     * @param {Object} params - Exploiter parameters
     * @param {number} params.sqli_id - ID of sqli_detector to exploit
     * @returns {Promise<ReadableStreamDefaultReader>} Stream of results
     */
    async startExploiter(params) {
        return this._startStream(`${API_BASE}/exploiter`, params);
    },

    /**
     * Gets the list of available databases in sqli_exploit_tables
     * @returns {Promise<Object>} {databases: string[]}
     */
    async getExploitDatabases(jobId = null) {
        const url = jobId
            ? `${API_BASE}/obtain-data/databases?job_id=${encodeURIComponent(jobId)}`
            : `${API_BASE}/obtain-data/databases`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Gets the tables of a specific database
     * @param {string} dbName - Database name
     * @returns {Promise<Object>} {tables: string[]}
     */
    async getExploitTablesForDb(dbName, jobId = null) {
        let url = `${API_BASE}/obtain-data/tables?db_name=${encodeURIComponent(dbName)}`;
        if (jobId) url += `&job_id=${encodeURIComponent(jobId)}`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Executes a dump of a specific table
     * @param {Object} params
     * @param {number} params.sqli_id
     * @param {string} params.db_name
     * @param {string} params.table_name
     * @returns {Promise<ReadableStreamDefaultReader>} Stream of results
     */
    async startDump(params) {
        return this._startStream(`${API_BASE}/dumper`, params);
    },

    /**
     * Gets the last saved data_json for a table dump
     * @param {string} dbName - Database name
     * @param {string} tableName - Table name
     * @returns {Promise<Object>} {data_json: string|null}
     */
    async getExploitDumpData(dbName, tableName, jobId = null) {
        let url = `${API_BASE}/obtain-data/result?db_name=${encodeURIComponent(dbName)}&table_name=${encodeURIComponent(tableName)}`;
        if (jobId) url += `&job_id=${encodeURIComponent(jobId)}`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Starts the WebSQLI pipeline (WebScanner + SQLiAgentOrchestrator)
     * @param {Object} params - WebSQLI parameters
     * @param {string} params.url - URL to analyze
     * @returns {Promise<ReadableStreamDefaultReader>} Stream of results
     */
    async startWebSQLI(params) {
        return this._startStream(`${API_BASE}/websqli/start`, params);
    },

    /**
     * Gets all jobs ordered by most recent first
     * @returns {Promise<Object>} {jobs: Array}
     */
    async getJobs() {
        const response = await fetch(`${API_BASE}/jobs`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Gets the status of the agents (scanners, crawlers, detectors, exploiters)
     * @param {number|null} jobId - Optional job filter (defaults to latest job)
     * @returns {Promise<Object>} Status of the agents
     */
    async getWebSQLIStatus(jobId = null) {
        const url = jobId
            ? `${API_BASE}/websqli/status?job_id=${jobId}`
            : `${API_BASE}/websqli/status`;
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    },

    /**
     * Lazily fetches the full captured log for one V2 kanban card.
     * @param {string} stage - scanner|crawler|detector|scorer|exploiter
     * @param {number} id - row id within that stage's table
     * @returns {Promise<Object>} { log: string|null }
     */
    async getV2Log(stage, id) {
        const url = `${API_BASE}/pipeline/log?stage=${encodeURIComponent(stage)}&id=${id}`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Frontend-facing config sourced from .env (e.g. the New Job modal's
     * default target URL).
     * @returns {Promise<Object>} { default_target_url: string }
     */
    async getConfig() {
        const response = await fetch(`${API_BASE}/config`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Static OWASP ZAP baseline scan results for Debug GT's ground-truth URLs.
     * @returns {Promise<Object>} { detected_urls: string[] }
     */
    async getZapBaseline() {
        const response = await fetch(`${API_BASE}/debug-gt/zap`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Debug GT's ground-truth URL list (app + url + optional note), served
     * from debug_data/GT_URLS.json.
     * @returns {Promise<Object>} { gt_pages: {app, url, note?}[] }
     */
    async getGtUrls() {
        const response = await fetch(`${API_BASE}/debug-gt/urls`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Reachability check for the Debug GT benchmark target VM, so the UI can
     * warn when it's saturated/unresponsive instead of the results looking
     * like a crawler/detector bug.
     * @returns {Promise<Object>} { saturated: bool, target: string, checks: object }
     */
    async getTargetHealth() {
        const response = await fetch(`${API_BASE}/debug-gt/target-health`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Cumulative vulnerabilities-found-over-elapsed-time series, one per job,
     * for the Debug Timeline chart.
     * @param {number[]} jobIds
     * @returns {Promise<Object>} { series: { [jobId]: {start, finished_at, state, target_url, points: [{t, count, url?}]} } }
     */
    async getVulnTimeline(jobIds) {
        const response = await fetch(`${API_BASE}/debug-gt/vuln-timeline?job_ids=${jobIds.join(',')}`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Gets all entries from crawl_page and crawl_page_details
     * @param {number|null} jobId - Optional job filter
     * @returns {Promise<Object>}
     */
    async getCrawlerStatus(jobId = null) {
        const url = jobId ? `${API_BASE}/crawler/status?job_id=${jobId}` : `${API_BASE}/crawler/status`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Gets all entries from sqli_detector
     * @param {number|null} jobId - Optional job filter
     * @returns {Promise<Object>}
     */
    async getDetectorStatus(jobId = null) {
        const url = jobId ? `${API_BASE}/detector/status?job_id=${jobId}` : `${API_BASE}/detector/status`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Gets the status of the scanner (jobs, hosts, webapps, nmap)
     * @param {number|null} jobId - Optional job filter
     * @returns {Promise<Object>} Status of the scanner
     */
    async getScannerStatus(jobId = null) {
        const url = jobId ? `${API_BASE}/scanner/status?job_id=${jobId}` : `${API_BASE}/scanner/status`;
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`HTTP error! statusS: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Gets aggregated statistics by job
     * @returns {Promise<Object>} {stats: Array}
     */
    async getStats(jobId = null) {
        const url = jobId ? `${API_BASE}/stats?job_id=${jobId}` : `${API_BASE}/stats`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Gets the list of jobs for the report generator
     * @returns {Promise<Object>} {jobs: Array}
     */
    async getReporterJobs() {
        const response = await fetch(`${API_BASE}/reporter/jobs`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Generates a PDF report for a job and returns the filename
     * @param {number} jobId
     * @returns {Promise<Object>} {filename, log}
     */
    async generateReport(jobId) {
        const response = await fetch(`${API_BASE}/reporter`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ job_id: jobId })
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP error! status: ${response.status}`);
        }
        return response.json();
    },

    /**
     * Downloads a previously generated PDF report
     * @param {string} filename - Name of the file to download
     */
    downloadReport(filename) {
        const a = document.createElement('a');
        a.href = `${API_BASE}/reporter/download?filename=${encodeURIComponent(filename)}`;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    },

    downloadCSVPages(jobId) {
        const a = document.createElement('a');
        a.href = `${API_BASE}/reporter/csv?job_id=${jobId}`;
        a.download = `pages_job${jobId}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    },

    /**
     * Gets the databases of a job for the DB Analyzer
     * @param {number} jobId - ID of the job
     * @returns {Promise<Object>} {databases: string[]}
     */
    async getDBAnalyzerDatabases(jobId) {
        const response = await fetch(`${API_BASE}/dbanalyzer/databases?job_id=${jobId}`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Executes the AI analysis of a database
     * @param {string} dbName
     * @returns {Promise<Object>} {output, result}
     */
    async analyseDB(dbName, jobId = null) {
        const body = { db_name: dbName };
        if (jobId) body.job_id = jobId;
        const response = await fetch(`${API_BASE}/dbanalyzer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP error! status: ${response.status}`);
        }
        return response.json();
    },

    /**
     * Runs DBCredentialHunter.py for a job
     * @param {number} jobId
     * @returns {Promise<Object>} {output}
     */
    async runCredentialHunter(jobId) {
        const response = await fetch(`${API_BASE}/dbcredentialhunter`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ job_id: jobId })
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP error! status: ${response.status}`);
        }
        return response.json();
    },

    /**
     * Runs DBAdminInyector.py for a job
     * @param {number} jobId
     * @returns {Promise<Object>} {output}
     */
    async runAdminInyector(jobId) {
        const response = await fetch(`${API_BASE}/dbadmininyector`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ job_id: jobId })
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP error! status: ${response.status}`);
        }
        return response.json();
    },

    /**
     * Gets all entries from sqli_exploit_data (Dumper)
     * @param {number|null} jobId - Optional job filter
     * @returns {Promise<Object>} {dumps: Array}
     */
    async getDumperStatus(jobId = null) {
        const url = jobId ? `${API_BASE}/dumper/status?job_id=${jobId}` : `${API_BASE}/dumper/status`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Gets all entries from sqli_exploit, sqli_exploit_tables, and sqli_exploit_columns
     * @param {number|null} jobId - Optional job filter
     * @returns {Promise<Object>}
     */
    async getExploiterStatus(jobId = null) {
        const url = jobId ? `${API_BASE}/exploiter/status?job_id=${jobId}` : `${API_BASE}/exploiter/status`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Gets pages for the WebMap tree visualization
     * @param {number|null} jobId - Optional job filter
     * @returns {Promise<Object>} {pages: Array}
     */
    async getWebmap(jobId = null) {
        const url = jobId ? `${API_BASE}/webmap?job_id=${jobId}` : `${API_BASE}/webmap`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Cancels an ongoing execution
     * @param {string} sessionId - ID of the session to cancel
     * @returns {Promise<Object>} Result of the cancellation
     */
    async cancelExecution(sessionId) {
        const response = await fetch(`${API_BASE}/cancel/${sessionId}`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Deletes a job and all its associated data
     * @param {number} jobId
     * @returns {Promise<Object>} {deleted: jobId}
     */
    async deleteJob(jobId) {
        const response = await fetch(`${API_BASE}/jobs/${jobId}`, { method: 'DELETE' });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP error! status: ${response.status}`);
        }
        return response.json();
    },

    /**
     * Checks the health status of the server
     * @returns {Promise<Object>} Server status
     */
    async checkHealth() {
        const response = await fetch(`${API_BASE}/health`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Checks whether SQLiAgentOrchestrator.py is currently running
     * @returns {Promise<Object>} {running: boolean}
     */
    async getOrchestratorStatus() {
        const response = await fetch(`${API_BASE}/sqli-agent-orchestrator/status`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    },

    /**
     * Internal method to start a stream
     * @private
     * @param {string} endpoint - API endpoint
     * @param {Object} data - Data to send
     * @returns {Promise<Object>} Object with reader and response
     */
    async _startStream(endpoint, data) {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return {
            reader: response.body.getReader(),
            response: response
        };
    }
};

/**
 * SSE (Server-Sent Events) stream processor
 */
class StreamProcessor {
    constructor() {
        this.decoder = new TextDecoder();
        this.sessionId = null;
        this.onSessionCallback = null;
        this.onDataCallback = null;
        this.onCompleteCallback = null;
        this.onCancelCallback = null;
        this.onErrorCallback = null;
    }

    /**
     * Sets the callback for when a session ID is received
     * @param {Function} callback - Function to execute (sessionId)
     */
    onSession(callback) {
        this.onSessionCallback = callback;
        return this;
    }

    /**
     * Sets the callback for when data is received
     * @param {Function} callback - Function to execute (data)
     */
    onData(callback) {
        this.onDataCallback = callback;
        return this;
    }

    /**
     * Sets the callback for when the stream is complete
     * @param {Function} callback - Function to execute ()
     */
    onComplete(callback) {
        this.onCompleteCallback = callback;
        return this;
    }

    /**
     * Sets the callback for when the stream is cancelled
     * @param {Function} callback - Function to execute (message)
     */
    onCancel(callback) {
        this.onCancelCallback = callback;
        return this;
    }

    /**
     * Sets the callback for when an error occurs
     * @param {Function} callback - Function to execute (errorMessage)
     */
    onError(callback) {
        this.onErrorCallback = callback;
        return this;
    }

    /**
     * Processes a data stream
     * @param {ReadableStreamDefaultReader} reader - Stream reader
     */
    async process(reader) {
        try {
            while (true) {
                const { value, done } = await reader.read();

                if (done) {
                    break;
                }

                const chunk = this.decoder.decode(value, { stream: true });
                const lines = chunk.split('\n');

                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = line.substring(6);

                        // Try to parse as JSON (for special messages)
                        try {
                            const jsonData = JSON.parse(data);
                            if (jsonData.type === 'session') {
                                this.sessionId = jsonData.session_id;
                                if (this.onSessionCallback) {
                                    this.onSessionCallback(this.sessionId);
                                }
                                continue;
                            }
                        } catch (e) {
                            // Not JSON, process as text
                        }

                        // Process special messages
                        if (data === '[DONE]') {
                            if (this.onCompleteCallback) {
                                this.onCompleteCallback();
                            }
                            break;
                        } else if (data.startsWith('[CANCELLED]')) {
                            if (this.onCancelCallback) {
                                this.onCancelCallback(data);
                            }
                            break;
                        } else if (data.startsWith('[ERROR]') || data.startsWith('ERROR:')) {
                            if (this.onErrorCallback) {
                                this.onErrorCallback(data);
                            }
                        } else if (data.trim()) {
                            // Normal data
                            if (this.onDataCallback) {
                                this.onDataCallback(data);
                            }
                        }
                    }
                }
            }
        } catch (error) {
            if (this.onErrorCallback) {
                this.onErrorCallback(`Stream error: ${error.message}`);
            }
            throw error;
        }
    }

    /**
     * Gets the current session ID
     * @returns {string|null} Session ID
     */
    getSessionId() {
        return this.sessionId;
    }
}

// Export for use in other modules
window.API = API;
window.StreamProcessor = StreamProcessor;

// ============================================================================
// SQLI AGENT ORCHESTRATOR STATUS — shown in the navbar on every page (this file is the
// only script every page includes), and disables "+ New Job" wherever it
// exists: launching a job without SQLiAgentOrchestrator running means nothing will
// ever pick it up and process it.
// ============================================================================

async function checkOrchestratorStatus() {
    try {
        const data = await API.getOrchestratorStatus();
        const running = !!data.running;
        const warning = document.getElementById('orchestrator-warning');
        if (warning) warning.style.display = running ? 'none' : 'inline-flex';
        document.querySelectorAll('.new-job-btn').forEach(btn => {
            btn.disabled = !running;
            btn.title = running ? '' : 'SQLi Agent Orchestrator is not running — new jobs would never be processed';
        });
    } catch (err) {
        console.error('Error checking SQLi Agent Orchestrator status:', err);
    }
}

checkOrchestratorStatus();
setInterval(checkOrchestratorStatus, 10000);
