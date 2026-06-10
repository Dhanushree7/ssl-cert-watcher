/**
 * ExpirySense Full Stack Server Core (Node.js Express + TS)
 * Powers Google AI Studio preview & matches FastAPI backend feature-for-feature
 */
import express from "express";
import path from "path";
import fs from "fs";
import tls from "tls";
import dns from "dns";
import dotenv from "dotenv";

// Load Environment Keys
dotenv.config();

const app = express();
const PORT = 3000;

// Host JSON Parser
app.use(express.json());

// Pure TypeScript persistent database driver to bypass native GLIBC binary problems of sqlite3 package
class JsonDatabase {
  private filePath: string;
  private data: any[] = [];

  constructor(filePath: string) {
    this.filePath = filePath;
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, "utf-8");
        this.data = JSON.parse(raw);
        console.log(`Loaded ${this.data.length} records from persistent file: ${this.filePath}`);
      } else {
        this.data = [];
        this.save();
      }
    } catch (e) {
      console.error("Failed to load JSON database:", e);
      this.data = [];
    }
  }

  private save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), "utf-8");
    } catch (e) {
      console.error("Failed to save JSON database:", e);
    }
  }

  async run(query: string, params: any[] = []): Promise<any> {
    const trimmed = query.trim().toUpperCase();

    // 1. Initial schema table creation
    if (trimmed.startsWith("CREATE TABLE")) {
      return { lastID: 0, changes: 0 };
    }

    // 2. INSERT OR UPDATE (ON CONFLICT DO UPDATE)
    if (trimmed.startsWith("INSERT INTO")) {
      const hostname = params[0];
      const issuer = params[1];
      const expiry_date = params[2];
      const days_remaining = params[3];
      const tls_version = params[4];
      const status = params[5];
      const failure_reason = params[6];
      const last_scan = params[7];

      const existingIndex = this.data.findIndex(
        item => String(item.hostname).toLowerCase() === String(hostname).toLowerCase()
      );
      const nowStr = new Date().toISOString();

      if (existingIndex !== -1) {
        // Update
        this.data[existingIndex] = {
          ...this.data[existingIndex],
          issuer,
          expiry_date,
          days_remaining,
          tls_version,
          status,
          failure_reason,
          last_scan
        };
      } else {
        // Find next auto-incremental ID
        const nextId = this.data.reduce((max, item) => Math.max(max, item.id || 0), 0) + 1;
        this.data.push({
          id: nextId,
          hostname,
          issuer,
          expiry_date,
          days_remaining,
          tls_version,
          status,
          failure_reason,
          last_scan,
          created_at: nowStr
        });
      }
      this.save();
      return { lastID: 1, changes: 1 };
    }

    // 3. DELETE FROM
    if (trimmed.startsWith("DELETE FROM")) {
      const id = Number(params[0]);
      const initialLength = this.data.length;
      this.data = this.data.filter(item => Number(item.id) !== id);
      const deletedCount = initialLength - this.data.length;
      if (deletedCount > 0) {
        this.save();
      }
      return { lastID: 0, changes: deletedCount };
    }

    throw new Error("Query not supported in JSON engine: " + query);
  }

  async all(query: string, params: any[] = []): Promise<any[]> {
    const trimmed = query.trim().toUpperCase();

    if (trimmed.startsWith("SELECT * FROM SSL_CERTIFICATES")) {
      let results = [...this.data];

      if (trimmed.includes("ORDER BY")) {
        results.sort((a, b) => {
          const getStatusOrder = (status: string) => {
            const s = (status || "").toUpperCase();
            if (s === "CRITICAL") return 1;
            if (s === "WARNING") return 2;
            if (s === "HEALTHY") return 3;
            return 4;
          };

          const orderA = getStatusOrder(a.status);
          const orderB = getStatusOrder(b.status);

          if (orderA !== orderB) {
            return orderA - orderB;
          }

          const daysA = a.days_remaining ?? -1;
          const daysB = b.days_remaining ?? -1;
          return daysA - daysB;
        });
      }

      return results;
    }

    return [];
  }
}

// SQLite legacy config mapped to JSON file persistence safely
const dbPath = path.join(process.cwd(), "expiry_sense_db.json");
const db = new JsonDatabase(dbPath);

// Async Database Connection Helpers matching sqlite signatures
const dbRun = (query: string, params: any[] = []): Promise<any> => {
  return db.run(query, params);
};

const dbAll = (query: string, params: any[] = []): Promise<any[]> => {
  return db.all(query, params);
};

// Initialize database schema tables matching database.py
async function initSqliteSchema() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS ssl_certificates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hostname TEXT UNIQUE NOT NULL,
      issuer TEXT,
      expiry_date TEXT,
      days_remaining INTEGER,
      tls_version TEXT,
      status TEXT NOT NULL,
      failure_reason TEXT,
      last_scan TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
  console.log("Telemetry database initialized and ready at:", dbPath);
}
initSqliteSchema().catch(console.error);

// Clean hostname regex
const HOSTNAME_REGEX = /^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/;

interface ScanResult {
  hostname: string;
  issuer: string | null;
  expiry_date: string | null;
  days_remaining: number;
  tls_version: string | null;
  status: "CRITICAL" | "WARNING" | "HEALTHY" | "UNREACHABLE";
  failure_reason: string | null;
}

// Node.js SSL live socket scanning utility (No Dummy Data, authentic scans)
function scanSSLCertificate(hostname: string): Promise<ScanResult> {
  return new Promise((resolve) => {
    let host = hostname.trim().toLowerCase();
    if (host.includes("://")) {
      host = host.split("://")[1];
    }
    host = host.split("/")[0];
    host = host.split(":")[0];

    const result: ScanResult = {
      hostname: host,
      issuer: null,
      expiry_date: null,
      days_remaining: -1,
      tls_version: null,
      status: "UNREACHABLE",
      failure_reason: null
    };

    if (!HOSTNAME_REGEX.test(host)) {
      result.failure_reason = "DNS Resolution Failed";
      return resolve(result);
    }

    // 1. Resolve host IP to confirm DNS
    dns.lookup(host, (dnsErr) => {
      if (dnsErr) {
        result.failure_reason = "DNS Resolution Failed";
        return resolve(result);
      }

      // 2. Wrap Node.js tls socket
      let completed = false;
      const socket = tls.connect(443, host, {
        servername: host,
        rejectUnauthorized: false // Allow checking of invalid or expired certs
      });

      socket.setTimeout(6000);

      socket.on("secureConnect", () => {
        if (completed) return;
        completed = true;

        const cert = socket.getPeerCertificate();
        const tlsVersion = socket.getProtocol();
        socket.destroy();

        if (!cert || !cert.valid_to) {
          result.failure_reason = "No SSL Certificate Found";
          return resolve(result);
        }

        // Issuer CN or Organization parsing
        let issuerName = "Unknown Issuer";
        if (cert.issuer) {
          const rawCN = cert.issuer.CN;
          const rawO = cert.issuer.O;
          const cn = Array.isArray(rawCN) ? rawCN[0] : rawCN;
          const o = Array.isArray(rawO) ? rawO[0] : rawO;
          issuerName = cn || o || "Unknown Issuer";
        }

        const expiryDateStr = new Date(cert.valid_to).toISOString().replace("Z", "") + "Z";
        const expiryEpoch = new Date(cert.valid_to).getTime();
        const nowEpoch = Date.now();
        const daysRemaining = Math.floor((expiryEpoch - nowEpoch) / (1000 * 24 * 3600));

        let status: "CRITICAL" | "WARNING" | "HEALTHY" = "HEALTHY";
        if (daysRemaining <= 14) {
          status = "CRITICAL";
        } else if (daysRemaining <= 45) {
          status = "WARNING";
        }

        result.issuer = issuerName;
        result.expiry_date = expiryDateStr;
        result.days_remaining = daysRemaining;
        result.tls_version = tlsVersion;
        result.status = status;

        return resolve(result);
      });

      socket.on("timeout", () => {
        if (completed) return;
        completed = true;
        socket.destroy();
        result.failure_reason = "Connection Timeout";
        return resolve(result);
      });

      socket.on("error", (err: any) => {
        if (completed) return;
        completed = true;
        socket.destroy();

        if (err.code === "ECONNREFUSED") {
          result.failure_reason = "Connection Refused";
        } else {
          result.failure_reason = "SSL Handshake Failed";
        }
        return resolve(result);
      });
    });
  });
}

// AI recommendation service using Groq API or Local template fallback
async function generateAIRecommendation(cert: any): Promise<any> {
  const hostname = cert.hostname;
  const status = cert.status;
  const days = cert.days_remaining;
  const issuer = cert.issuer || "Unknown Certificate Authority";
  const expiryDate = cert.expiry_date || "N/A";

  const priority = status === "CRITICAL" ? "CRITICAL" : "MEDIUM";
  const dueDate = status === "CRITICAL" ? "Immediately or before expiry" : "At least 7 days before expiry";

  const apiKey = process.env.GROQ_API_KEY;

  if (apiKey && apiKey !== "MY_GEMINI_API_KEY") {
    try {
      const prompt = `
      You are a cybersecurity audit officer and assistant. Analyze this SSL certificate warning and generate a professional security assessment:
      Hostname: ${hostname}
      Status: ${status}
      Days Remaining: ${days}
      Issuer: ${issuer}
      Expiry Date: ${expiryDate}
      
      Format your entire answer as a single stringified JSON object containing these exact keys:
      "risk_summary": a business-friendly explanation of the security risk in exactly 3-4 sentences. Do not use complex technical jargon.
      "business_impact": a concise, bulleted list of 3-4 business consequences of letting this expire (e.g. browser warnings, transaction interruptions, trust damage).
      "recommended_actions": a numbered list of 4-5 recovery actions in professional enterprise phrasing.
      
      Ensure your response is raw JSON only. Do not wrap in markdown \`\`\`json blocks.
      `;

      const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: "llama3-8b-8192",
          messages: [{ role: "user", content: prompt }],
          temperature: 0.2
        })
      });

      if (response.ok) {
        const data = await response.json();
        let textContent = data.choices[0].message.content.trim();
        if (textContent.startsWith("```")) {
          textContent = textContent.replace(/```json/g, "").replace(/```/g, "").trim();
        }
        const parsed = JSON.parse(textContent);
        return {
          risk_summary: parsed.risk_summary || "",
          business_impact: parsed.business_impact || [],
          recommended_actions: parsed.recommended_actions || [],
          due_date: dueDate,
          priority: priority
        };
      }
    } catch (e) {
      console.warn("Groq API error. Activating beautiful local fallback:", e);
    }
  }

  // Pure Local Fallback Engine Matching database.py/mcp_tools.py 1-to-1
  if (status === "CRITICAL") {
    return {
      risk_summary: `The SSL certificate for ${hostname} is scheduled to expire in only ${days} days on ${expiryDate}. Once this certificate window expires, any incoming user browser requests will encounter secure HTTPS connection handshake errors. This will cause browsers to display red security warnings, completely blocking normal user navigation. Immediate renewal must be configured in your domain authority console as soon as possible.`,
      business_impact: [
        "Immediate customer navigation blocking via red web browser security alerts.",
        "Disruption of insecure transit lines, APIs, and transactional payment gateways.",
        "Severe public trust erosion and reputational damage.",
        "Loss of operational compliance and industry security standards."
      ],
      recommended_actions: [
        `Login into the certificate administrative console or active Certificate Authority (${issuer})`,
        "Generate a standard Certificate Signing Request (CSR) on your server host",
        "Submit renewal request and complete Domain Control Validation (DCV)",
        "Download newly minted server certificates containing full intermediate chains",
        "Install new certificates on webservers and restart load-balancer daemons"
      ],
      due_date: dueDate,
      priority: priority
    };
  } else {
    return {
      risk_summary: `The secure SSL socket certificate for ${hostname} is approaching its expiration marker in ${days} days on ${expiryDate}. While HTTPS encryption is currently active, early restoration checks are required to prevent emergency maintenance. Renewing the certificate prevents connection bottlenecks and safeguards business processes.`,
      business_impact: [
        "Risk of unplanned server outages and downtime outside of working shifts.",
        "Decline in search engine visibility (SEO) due to pending chain warnings.",
        "Subtle organizational bottlenecks during last-minute DNS validation shifts."
      ],
      recommended_actions: [
        "Schedule maintenance hours for security certificate validation and swap-outs",
        "Retrieve updated private keys or create a renewal ticket with your CA provider",
        "Acquire the renewed SSL certificate files from administrative panels",
        "Perform staging server trials before live production socket deployment",
        "Verify complete certificate path validation and browser handshakes"
      ],
      due_date: dueDate,
      priority: priority
    };
  }
}

// Dynamic Markdown Workbook Builder matches mcp_tools.py
async function generateMarkdownWorkbook(certificates: any[]): Promise<string> {
  const timestampNow = new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC";
  let reportMd = `# SSL Renewal Tasks Report\n\nGenerated On:\n${timestampNow}\n\n`;

  const targets = certificates.filter(c => c.status === "CRITICAL" || c.status === "WARNING");

  if (targets.length === 0) {
    reportMd += "No critical or warming expiring certificates require remediation at this time.\n";
    return reportMd;
  }

  for (const cert of targets) {
    const recs = await generateAIRecommendation(cert);
    const hostname = cert.hostname;
    const status = cert.status;
    const issuer = cert.issuer || "Unknown";
    const expiry_date = cert.expiry_date || "N/A";
    const days_remaining = cert.days_remaining ?? -1;

    let impactBullets = "";
    if (Array.isArray(recs.business_impact)) {
      recs.business_impact.forEach((imp: string) => {
        impactBullets += `* ${imp}\n`;
      });
    }

    let actionsList = "";
    if (Array.isArray(recs.recommended_actions)) {
      recs.recommended_actions.forEach((act: string, idx: number) => {
        actionsList += `${idx + 1}. ${act}\n`;
      });
    }

    let readableExpiry = expiry_date;
    try {
      const expDate = new Date(expiry_date);
      readableExpiry = expDate.toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric"
      });
    } catch {}

    const entryMd = `---

## [${status}] ${hostname}

### Certificate Details

Hostname:
${hostname}
Issuer:
${issuer}
Expiry Date:
${expiry_date}
Days Remaining:
${days_remaining}
Priority:
${recs.priority}

### Risk Summary

${recs.risk_summary}

### Business Impact

${impactBullets}
### Recommended Actions

${actionsList}
### Due Date

${recs.due_date}

### Email Draft

Subject:
SSL Certificate Renewal Required - ${hostname}

Hello Team,

The SSL certificate for ${hostname} is scheduled to expire on ${readableExpiry} and currently has ${days_remaining} days remaining.

Please initiate the renewal process and complete deployment before the expiry date to avoid service interruptions and browser security warnings.

Recommended completion date:
${recs.due_date}

Regards,
ExpirySense
`;
    reportMd += entryMd;
  }

  return reportMd;
}

// Tabular CSV log builder matches mcp_tools.py
function generateCSVReport(certificates: any[]): string {
  let lines = ["Hostname,Issuer,Expiry Date,Days Remaining,TLS Version,Status,Last Scan Time"];
  
  certificates.forEach(c => {
    const hostname = c.hostname;
    const issuer = `"${(c.issuer || "N/A").replace(/"/g, '""')}"`;
    const expiry_date = c.expiry_date || "N/A";
    const days_remaining = c.days_remaining ?? -1;
    const tls_version = c.tls_version || "N/A";
    const status = c.status;
    const last_scan = c.last_scan || "N/A";

    lines.push(`${hostname},${issuer},${expiry_date},${days_remaining},${tls_version},${status},${last_scan}`);
  });

  return lines.join("\n");
}

// --- API Router Endpoints ---

// POST /api/scan-hostnames
app.post("/api/scan-hostnames", async (req, res) => {
  const { hostnames } = req.body;

  if (!hostnames || !Array.isArray(hostnames) || hostnames.length === 0) {
    return res.status(400).json({ detail: "Hostnames query array cannot be empty." });
  }

  const validHostnames: string[] = [];
  const skipped: string[] = [];

  hostnames.forEach((raw: any) => {
    let host = String(raw).trim().toLowerCase();
    if (host.includes("://")) {
      host = host.split("://")[1];
    }
    host = host.split("/")[0];
    host = host.split(":")[0];

    if (HOSTNAME_REGEX.test(host)) {
      validHostnames.push(host);
    } else {
      skipped.push(raw);
    }
  });

  if (validHostnames.length === 0) {
    return res.status(400).json({ detail: "All provided hostnames failed layout verification regex filters." });
  }

  // Deduplicate
  const finalHosts = Array.from(new Set(validHostnames));
  const scanResults: ScanResult[] = [];

  for (const host of finalHosts) {
    try {
      const scan = await scanSSLCertificate(host);
      const nowStr = new Date().toISOString();

      await dbRun(`
        INSERT INTO ssl_certificates (
          hostname, issuer, expiry_date, days_remaining, tls_version, status, failure_reason, last_scan
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
          issuer=excluded.issuer,
          expiry_date=excluded.expiry_date,
          days_remaining=excluded.days_remaining,
          tls_version=excluded.tls_version,
          status=excluded.status,
          failure_reason=excluded.failure_reason,
          last_scan=excluded.last_scan
      `, [
        scan.hostname,
        scan.issuer,
        scan.expiry_date,
        scan.days_remaining,
        scan.tls_version,
        scan.status,
        scan.failure_reason,
        nowStr
      ]);

      scanResults.push(scan);
    } catch (err: any) {
      console.error("Scanning error host:", host, err);
      const unreachableRecord: ScanResult = {
        hostname: host,
        issuer: null,
        expiry_date: null,
        days_remaining: -1,
        tls_version: null,
        status: "UNREACHABLE",
        failure_reason: `System Outage (${err.message})`
      };
      scanResults.push(unreachableRecord);
    }
  }

  return res.json({
    message: `Resolved ${scanResults.length} domains.`,
    scanned: scanResults.map(r => r.hostname),
    skipped
  });
});

// GET /api/certificates
app.get("/api/certificates", async (req, res) => {
  try {
    const rows = await dbAll(`
      SELECT * FROM ssl_certificates 
      ORDER BY 
        CASE status
          WHEN 'CRITICAL' THEN 1
          WHEN 'WARNING' THEN 2
          WHEN 'HEALTHY' THEN 3
          ELSE 4
        END ASC,
        days_remaining ASC
    `);
    return res.json(rows);
  } catch (err: any) {
    return res.status(500).json({ detail: err.message });
  }
});

// DELETE /api/certificates/:id
app.delete("/api/certificates/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const result = await dbRun("DELETE FROM ssl_certificates WHERE id = ?", [id]);
    // dbRun resolver returns statement context
    return res.json({ message: "Hostname deleted successfully" });
  } catch (err: any) {
    return res.status(500).json({ detail: err.message });
  }
});

// GET /api/export/csv
app.get("/api/export/csv", async (req, res) => {
  try {
    const certs = await dbAll("SELECT * FROM ssl_certificates");
    const csvContent = generateCSVReport(certs);
    const timestamp = new Date().toISOString().replace(/[-:T]/g, "").substring(0, 14);
    const filename = `ssl_scan_report_${timestamp}.csv`;

    res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
    res.setHeader("Content-Type", "text/csv");
    return res.send(csvContent);
  } catch (err: any) {
    return res.status(500).send(err.message);
  }
});

// GET /api/export/markdown
app.get("/api/export/markdown", async (req, res) => {
  try {
    const certs = await dbAll("SELECT * FROM ssl_certificates");
    const mdContent = await generateMarkdownWorkbook(certs);
    
    // Save report in reports/renewal_tasks.md
    const reportsDir = path.join(process.cwd(), "reports");
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }
    fs.writeFileSync(path.join(reportsDir, "renewal_tasks.md"), mdContent, "utf-8");

    const timestamp = new Date().toISOString().replace(/[-:T]/g, "").substring(0, 14);
    const filename = `ssl_renewal_workbook_${timestamp}.md`;

    res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
    res.setHeader("Content-Type", "text/markdown");
    return res.send(mdContent);
  } catch (err: any) {
    return res.status(500).send(err.message);
  }
});

// Serving the static folder directly
const frontendPath = path.join(process.cwd(), "frontend");
app.use(express.static(frontendPath));

// Fallback all other client assets to index.html
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Express custom server running in AI Studio container on http://localhost:${PORT}`);
});
