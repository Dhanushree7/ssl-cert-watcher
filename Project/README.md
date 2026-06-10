# ExpirySense — SSL Certificate Expiry Watcher

ExpirySense is an AI-powered SSL Certificate Monitoring and Renewal Recommendation Platform. It performs live socket connection queries on target servers to decode secure certificate metadata, calculate days remaining, and categorizes them into tiered alert severity groups. Using the modern **Model Context Protocol (MCP)** tool layer coupled with a **Groq AI Orchestrator (llama3-8b-8192)**, ExpirySense automatically compiles risk assessments, executive business impact briefs, remediation recipes, and publishes actionable email draft workbooks.

Target use cases include full-stack evaluations, technical portfolio showcases, cybersecurity demonstrations, and direct SOC audits.

---

## Technical Architecture Overview

ExpirySense implements a compliant full-stack design with dual-platform runtime support:
1. **Google AI Studio Runtime**: Powered by **Node.js Express + SQLite** (port 3000), utilizing native Node sockets and promises to provide instantaneous previews.
2. **Local Production Runtime**: Powered by **Python FastAPI + SQLite** (port 3000), using native socket/ssl connections.

```
                  ┌─────────────────────────────────────┐
                  │          Vanilla HTML/CSS/JS        │
                  │        Cybersecurity Dashboard      │
                  └──────────────────┬──────────────────┘
                                     │
                        ┌────────────┴────────────┐ (REST API)
                        ▼                         ▼
            ┌───────────────────────┐ ┌───────────────────────┐
            │   Express (Node.ts)   │ │    FastAPI (Python)   │
            │  AI Studio Container  │ │   Local Host Server   │
            └───────────┬───────────┘ └───────────┬───────────┘
                        │                         │
                        └────────────┬────────────┘
                                     ▼
                        ┌─────────────────────────┐
                        │    SQLite (expiry.db)   │
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │   MCP Server Dispatcher │
                        └────────────┬────────────┘
                                     │ (JSON-RPC stdio)
                ┌────────────────────┼────────────────────┐
                ▼                    ▼                    ▼
      ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
      │ ssl_scanner_tool │ │ ai_recom_tool   │ │ md_workbook_tool │
      └──────────────────┘ └──────────────────┘ └──────────────────┘
```

---

## Technology Stack

- **Frontend**: Single-Screen Vanilla HTML5, Tailwind CSS, Chart.js for adaptive metrics, and Lucide Vectors.
- **Backend (Node.js)**: Express REST Server, custom `tls` Socket Client, and `sqlite3` driver.
- **Backend (Python)**: FastAPI, native `socket` & `ssl` engines, and native `sqlite3`.
- **Database**: SQLite database with structural state retention.
- **AI Integration**: Groq API Client leveraging the **llama3-8b-8192** model.

---

## MCP Server Specifications

ExpirySense integrates a native Model Context Protocol (MCP) server layer to separate orchestrator logic from core capabilities. The AI-Agent executes commands purely through registered standard JSON-RPC schema calls:

1. **`ssl_scanner_tool`**: Performs raw socket connections on TCP port 443, returning host validation strings.
2. **`certificate_analyzer_tool`**: Assigns alert severity bounds based on certificate lifetime.
3. **`ai_recommendation_tool`**: Feeds context queries to Groq to generate business risk analyses and bulleted remedies.
4. **`markdown_report_generator_tool`**: Combines threat items into a fully formatted `.md` workbook file.
5. **`csv_export_tool`**: Formats database states into comma-separated columns.

---

## Setup & Running Instructions

### 1. Groq API Configuration

ExpirySense accesses Groq to build security assessments.
1. Obtain an API Key from the Console.
2. In Google AI Studio, add `GROQ_API_KEY` to the **Secrets** manager panel.
3. Locally, copy `.env.example` to `.env` and assign your token:
   ```env
   GROQ_API_KEY="gsk_..."
   ```

*Note: If no API key is specified, ExpirySense automatically activates a beautiful backup template generator utilizing offline compliance schemas, preventing any interface outages.*

---

### 2. Running Locally (Python Backend)

Follow these instructions to run the Python/FastAPI environment on your local server:

1. **Clone and Navigate**:
   ```bash
   cd ExpirySense
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Start FastAPI Backend**:
   ```bash
   python -m uvicorn backend.main:app --host 0.0.0.0 --port 3000 --reload
   ```

4. **Launch Dashboard**:
   Open your browser and navigate to `http://localhost:3000/`. The static frontend is served automatically!

---

### 3. Running Locally (Node.js Backend / AI Studio Preview)

Follow these directions to load the preview locally using Node.js:

1. **Install Packages**:
   ```bash
   npm install
   ```

2. **Boot Dev Server**:
   ```bash
   npm run dev
   ```
   *Express starts on `http://localhost:3000`, matching all endpoints perfectly.*

---

## Key App Features

- **Bulk Input Methods**: Type domains directly (one per line) or drop down target `.csv` logs possessing a `hostname` column header. Duplicates and schema formatting values are automatically standardized.
- **Offline Failure Code Attribution**: Unreachable servers are captured with specialized descriptions, including:
  - `DNS Resolution Failed`
  - `Connection Timeout`
  - `SSL Handshake Failed`
  - `Connection Refused`
- **Dynamic Chart Sync**: Seamlessly compiles pie graphs indicating severity allocations alongside histograms representing days left distribution ranges.
- **CSV Data Exporter**: Compiles clean tables of all monitored domain entities for offline analysis.
- **AI Expiry Workbooks**: Packages custom business emails warning managers of looming certificate expirations, strictly targeting **CRITICAL** (0-14 days) and **WARNING** (15-45 days) domains.

---

## Future Enhancements
- **Multi-port scanning**: Introduce selectable ports for custom microservices (e.g., port 8443, 9443).
- **Auto-scheduler cron alerts**: Integrate periodic silent checks linked to SMTP servers or Slack Webhooks for real-time channel warnings.
- **Custom Certificate Chain Inspections**: Inspect intermediate certificate authority links to isolate trust anchor issues.
