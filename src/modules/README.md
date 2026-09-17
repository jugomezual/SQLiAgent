# `modules/` organization

The modules are grouped by the pentesting pipeline's **functional phase**.
Each module inherits from `core.BaseModule`.

```
modules/
├── recon/            Discovery of the target's surface
│   ├── WebScanner.py   ports (nmap) + fingerprint (whatweb) → creates job/host/webapp
│   └── WebCrawler.py   crawling + nikto → pages, forms, parameters
├── scoring/          Prioritization
│   └── WebScorer.py    scores the crawl_pages (local or AI) to decide what to attack
├── sqli/             SQL injection chain
│   ├── WebDetector.py   detects injection with sqlmap on the pages
│   ├── SQLExploiter.py  exploits (databases → tables → columns)
│   └── DBDumper.py      dumps a specific table
├── sqli_ai_attack/   AI-assisted DB post-exploitation
│   ├── DBSchemaAnalyzer.py (+ DBSchemaAnalyzerPromt.py)
│   ├── DBCredentialHunter.py (+ DBCredentialHunterPromt.py)
│   └── DBAdminInyector.py (+ DBAdminInyectorPromt.py)
└── reports/          Report generation
    ├── SQLWebReporter.py
    └── templates/report.html
```

Typical flow: **recon → scoring → sqli (detect → exploit → dump) → sqli_ai_attack → reports**.

> Note: `recon/` replaces the old `common/` folder (which described nothing)
> and the empty `sqli_analysis/` folder was removed.
