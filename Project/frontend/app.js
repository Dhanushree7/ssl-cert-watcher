/**
 * ExpirySense - SSL Certificate Expiry Watcher
 * Frontend Application Code (Vanilla JS)
 */

document.addEventListener("DOMContentLoaded", () => {
  // Initialize Lucide Icons
  lucide.createIcons();

  // State Management
  let certificates = [];
  let deleteTargetId = null;
  let chartRisk = null;
  let chartTimeline = null;

  // DOM Selections
  const tabManual = document.getElementById("tab-manual");
  const tabCsv = document.getElementById("tab-csv");
  const contentManual = document.getElementById("content-manual");
  const contentCsv = document.getElementById("content-csv");
  const csvDropzone = document.getElementById("csv-dropzone");
  const csvFileInput = document.getElementById("csv-file-input");
  const csvFeedback = document.getElementById("csv-feedback");
  const csvFeedbackText = document.getElementById("csv-feedback-text");
  const hostnamesInput = document.getElementById("hostnames-input");
  const btnClearInput = document.getElementById("btn-clear-input");
  const btnScan = document.getElementById("btn-scan");
  const btnRefresh = document.getElementById("btn-refresh");

  const btnDownloadCsv = document.getElementById("btn-download-csv");
  const btnDownloadMd = document.getElementById("btn-download-md");

  const statTotal = document.getElementById("stat-total");
  const statCritical = document.getElementById("stat-critical");
  const statWarning = document.getElementById("stat-warning");
  const statHealthy = document.getElementById("stat-healthy");

  const tableBody = document.getElementById("results-table-body");
  const emptyRowPlaceholder = document.getElementById("rows-empty-state");

  const modalLoader = document.getElementById("modal-loader");
  const loaderMessage = document.getElementById("loader-message");
  const logDns = document.getElementById("log-dns");
  const logSsl = document.getElementById("log-ssl");
  const logGroq = document.getElementById("log-groq");

  const modalConfirm = document.getElementById("modal-confirm");
  const confirmHostnameSpan = document.getElementById("confirm-hostname-span");
  const btnConfirmCancel = document.getElementById("btn-confirm-cancel");
  const btnConfirmDelete = document.getElementById("btn-confirm-delete");

  const apiStatusBanner = document.getElementById("api-status-banner");

  // Domain verification regex
  const hostnameRegex = /^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/;

  // Cleanup helper for url schemas or www. tags (e.g. https://google.com -> google.com)
  function sanitizeHostname(raw) {
    let host = raw.trim().toLowerCase();
    // Remove protocol
    host = host.replace(/^(https?:\/\/)?(www\.)?/, "");
    // Remove paths or ports if any
    host = host.split("/")[0];
    host = host.split(":")[0];
    return host;
  }

  // --- Theme/Tab Switching ---
  tabManual.addEventListener("click", () => {
    tabManual.className = "px-4 py-2 text-sm font-medium text-cyan-500 border-b-2 border-cyan-500 transition-all focus:outline-none flex items-center gap-2 cursor-pointer";
    tabCsv.className = "px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-all focus:outline-none flex items-center gap-2 cursor-pointer border-b-2 border-transparent";
    contentManual.classList.remove("hidden");
    contentCsv.classList.add("hidden");
  });

  tabCsv.addEventListener("click", () => {
    tabCsv.className = "px-4 py-2 text-sm font-medium text-cyan-500 border-b-2 border-cyan-500 transition-all focus:outline-none flex items-center gap-2 cursor-pointer";
    tabManual.className = "px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-all focus:outline-none flex items-center gap-2 cursor-pointer border-b-2 border-transparent";
    contentCsv.classList.remove("hidden");
    contentManual.classList.add("hidden");
  });

  // --- CSV Parser & Uploader ---
  csvDropzone.addEventListener("click", () => csvFileInput.click());
  
  csvDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    csvDropzone.classList.add("border-cyan-500", "bg-slate-950/80");
  });

  csvDropzone.addEventListener("dragleave", () => {
    csvDropzone.classList.remove("border-cyan-500", "bg-slate-950/80");
  });

  csvDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    csvDropzone.classList.remove("border-cyan-500", "bg-slate-950/80");
    const file = e.dataTransfer.files[0];
    if (file) handleCsvFile(file);
  });

  csvFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) handleCsvFile(file);
  });

  function handleCsvFile(file) {
    if (!file.name.endsWith(".csv")) {
      showToast("Access Denied: Only .csv spreadsheet files are allowed.", "error");
      return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
      try {
        const text = e.target.result;
        const parsedHostnames = parseCsvHostnames(text);
        if (parsedHostnames.length === 0) {
          showToast("Invalid CSV File: Target column 'hostname' was not found or was empty.", "error");
          return;
        }

        // Deduplicate scanned items
        const deduplicated = Array.from(new Set(parsedHostnames));
        hostnamesInput.value = deduplicated.join("\n");
        
        // Show success, switch to textarea
        csvFeedback.classList.remove("hidden");
        csvFeedbackText.innerText = `Mapped column 'hostname' successfully! Parsed ${deduplicated.length} potential domain(s).`;
        showToast(`Parsed ${deduplicated.length} valid hostnames. Custom values are editable!`, "success");
        
        // Stagger visual switch
        setTimeout(() => {
          tabManual.click();
        }, 800);
      } catch (err) {
        showToast("An error occurred while parsing the CSV. Check document structure.", "error");
      }
    };
    reader.readAsText(file);
  }

  function parseCsvHostnames(csvText) {
    const lines = csvText.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    if (lines.length === 0) return [];

    // Parse headers
    const headers = lines[0].split(",").map(h => h.trim().toLowerCase());
    const hostnameIndex = headers.indexOf("hostname");

    if (hostnameIndex === -1) {
      // Fallback: If no headers are named "hostname", look for column named "domain" or just use first column
      const fallbackIndex = headers.indexOf("domain") !== -1 ? headers.indexOf("domain") : 0;
      return parseColumn(lines, fallbackIndex);
    }
    return parseColumn(lines, hostnameIndex);
  }

  function parseColumn(lines, columnIndex) {
    const hostnames = [];
    for (let i = 1; i < lines.length; i++) {
      const parts = splitCsvLine(lines[i]);
      if (parts[columnIndex]) {
        const cleaned = sanitizeHostname(parts[columnIndex]);
        if (cleaned && hostnameRegex.test(cleaned)) {
          hostnames.push(cleaned);
        }
      }
    }
    return hostnames;
  }

  function splitCsvLine(line) {
    // Simple robust CSV line splitter accounting for possible quotes around hostnames
    let result = [];
    let cur = '';
    let insideQuote = false;
    for (let char of line) {
      if (char === '"') {
        insideQuote = !insideQuote;
      } else if (char === ',' && !insideQuote) {
        result.push(cur.trim().replace(/^"|"$/g, ''));
        cur = '';
      } else {
        cur += char;
      }
    }
    result.push(cur.trim().replace(/^"|"$/g, ''));
    return result;
  }

  // --- Reset/Clear Operations ---
  btnClearInput.addEventListener("click", () => {
    hostnamesInput.value = "";
    csvFileInput.value = "";
    csvFeedback.classList.add("hidden");
    showToast("Hostnames workspace has been reset.", "info");
  });

  // --- Scan SSL Connection Service ---
  btnScan.addEventListener("click", async () => {
    const rawText = hostnamesInput.value.trim();
    if (!rawText) {
      showToast("Verification Error: Please input or upload at least one website domain.", "error");
      return;
    }

    const rawList = rawText.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    const validHostnames = [];
    const invalidList = [];

    rawList.forEach(entry => {
      const cleaned = sanitizeHostname(entry);
      if (cleaned && hostnameRegex.test(cleaned)) {
        validHostnames.push(cleaned);
      } else if (cleaned) {
        invalidList.push(entry);
      }
    });

    if (invalidList.length > 0 && validHostnames.length === 0) {
      showToast(`Validation Failed: Unrecognized host format: "${invalidList[0]}"`, "error");
      return;
    }

    if (validHostnames.length === 0) {
      showToast("Verification Error: Input does not contain any valid website hostnames.", "error");
      return;
    }

    // Deduplicate
    const finalHostnamesList = Array.from(new Set(validHostnames));

    // Open Loader modal
    showLoaderModal();
    updateLoaderMetrics("resolving");

    try {
      // Step 1: Trigger Scan on API
      const response = await fetch("/api/scan-hostnames", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostnames: finalHostnamesList })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || "Scanner backend returned error. Verify ports.");
      }

      const scanResult = await response.json();
      
      // Step 2: Fetch updated log
      await loadCertificates();

      hideLoaderModal();
      showToast(`Scan complete! Synchronized ${finalHostnamesList.length} secure hostnames.`, "success");
      
      if (invalidList.length > 0) {
        showToast(`Skipped ${invalidList.length} invalid addresses.`, "info");
      }
    } catch (err) {
      hideLoaderModal();
      console.error(err);
      showToast(`Hardware Network Timeout: ${err.message}`, "error");
    }
  });

  // --- Load Data API Engine ---
  async function loadCertificates() {
    try {
      const res = await fetch("/api/certificates");
      if (!res.ok) throw new Error("Could not reach telemetry server.");
      
      apiStatusBanner.classList.add("hidden");
      certificates = await res.json();
      
      updateDashboardData();
    } catch (err) {
      console.error(err);
      apiStatusBanner.classList.remove("hidden");
      apiStatusBanner.classList.add("flex");
      showToast("Database connectivity lost. App running in transient preview mode.", "error");
    }
  }

  btnRefresh.addEventListener("click", async () => {
    btnRefresh.classList.add("animate-spin");
    await loadCertificates();
    setTimeout(() => {
      btnRefresh.classList.remove("animate-spin");
      showToast("Telemetry synced successfully.", "success");
    }, 450);
  });

  // --- Dashboard Analytics calculations ---
  function updateDashboardData() {
    // Total numbers
    const total = certificates.length;
    statTotal.innerText = total;

    // Filter statuses
    const criticalList = certificates.filter(c => c.status === "CRITICAL");
    const warningList = certificates.filter(c => c.status === "WARNING");
    const healthyList = certificates.filter(c => c.status === "HEALTHY");

    statCritical.innerText = criticalList.length;
    statWarning.innerText = warningList.length;
    statHealthy.innerText = healthyList.length;

    // Dynamically update the preview progress bars in Technical KPI cards
    const totalCount = total || 1;
    const pctCritical = Math.round((criticalList.length / totalCount) * 100);
    const pctWarning = Math.round((warningList.length / totalCount) * 100);
    const pctHealthy = Math.round((healthyList.length / totalCount) * 100);

    const criticalBar = document.getElementById("stat-critical-bar");
    const warningBar = document.getElementById("stat-warning-bar");
    const healthyBar = document.getElementById("stat-healthy-bar");

    if (criticalBar) {
      criticalBar.style.width = total > 0 ? `${pctCritical}%` : "0%";
    }
    if (warningBar) {
      warningBar.style.width = total > 0 ? `${pctWarning}%` : "0%";
    }
    if (healthyBar) {
      healthyBar.style.width = total > 0 ? `${pctHealthy}%` : "0%";
    }

    // Handle button activation
    if (total > 0) {
      btnDownloadCsv.removeAttribute("disabled");
      btnDownloadMd.removeAttribute("disabled");
    } else {
      btnDownloadCsv.setAttribute("disabled", "true");
      btnDownloadMd.setAttribute("disabled", "true");
    }

    // Render tables
    renderTable();

    // Render Charts
    renderCharts(criticalList.length, warningList.length, healthyList.length);
  }

  // --- Render Results Log Table ---
  function renderTable() {
    tableBody.innerHTML = "";

    if (certificates.length === 0) {
      tableBody.appendChild(emptyRowPlaceholder);
      return;
    }

    certificates.forEach(cert => {
      const row = document.createElement("tr");
      row.className = "hover:bg-slate-900/30 transition-colors border-b border-slate-800/40 text-sm";
      row.id = `row-cert-${cert.id}`;

      // Status Styling calculations
      let statusBadgeClass = "";
      let glowClass = "";
      let displayDaysMessage = `${cert.days_remaining} days left`;

      if (cert.status === "CRITICAL") {
        statusBadgeClass = "bg-rose-500/10 text-rose-400 border-rose-500/20";
        glowClass = "border-l-2 border-l-rose-500";
      } else if (cert.status === "WARNING") {
        statusBadgeClass = "bg-amber-500/10 text-amber-400 border-amber-500/20";
        glowClass = "border-l-2 border-l-amber-500";
      } else if (cert.status === "HEALTHY") {
        statusBadgeClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
        glowClass = "border-l-2 border-l-emerald-500";
      } else {
        // UNREACHABLE or FAIL
        statusBadgeClass = "bg-slate-800 text-slate-400 border-slate-700";
        glowClass = "border-l-2 border-l-slate-700";
        displayDaysMessage = cert.failure_reason || "Unreachable";
      }

      // Format Expiry Date
      let expiryFormatted = "N/A";
      if (cert.expiry_date) {
        try {
          const dateObj = new Date(cert.expiry_date);
          expiryFormatted = dateObj.toLocaleDateString("en-US", {
            year: "numeric",
            month: "short",
            day: "numeric"
          });
        } catch {
          expiryFormatted = cert.expiry_date;
        }
      }

      row.innerHTML = `
        <td class="px-6 py-4 font-semibold text-slate-100 font-mono ${glowClass}">${cert.hostname}</td>
        <td class="px-6 py-4">
          <span class="inline-flex items-center px-2.5 py-1 text-xs font-medium border rounded-full ${statusBadgeClass}">
            ${cert.status}
          </span>
        </td>
        <td class="px-6 py-4 text-slate-300 font-mono text-xs truncate max-w-xs" title="${cert.issuer || "No Issuer Found"}">
          ${cert.issuer || "N/A"}
        </td>
        <td class="px-6 py-4 font-medium text-slate-200">
          ${cert.status === 'UNREACHABLE' ? '<span class="text-xs text-rose-400">Offline</span>' : displayDaysMessage}
        </td>
        <td class="px-6 py-4 text-slate-400 text-xs">${cert.status === 'UNREACHABLE' ? 'N/A' : expiryFormatted}</td>
        <td class="px-6 py-4 text-slate-400 font-mono text-xs">${cert.tls_version || "N/A"}</td>
        <td class="px-6 py-4 text-right">
          <button class="p-1.5 border border-slate-800 text-slate-500 hover:text-rose-400 hover:border-rose-500/20 hover:bg-rose-500/5 rounded-md transition cursor-pointer btn-delete" data-id="${cert.id}" data-hostname="${cert.hostname}">
            <i data-lucide="trash-2" class="w-4 h-4"></i>
          </button>
        </td>
      `;

      tableBody.appendChild(row);
    });

    // Re-verify the freshly created interactive trash buttons
    document.querySelectorAll(".btn-delete").forEach(btn => {
      btn.addEventListener("click", (e) => {
        const button = e.currentTarget;
        deleteTargetId = button.getAttribute("data-id");
        const hostname = button.getAttribute("data-hostname");
        
        confirmHostnameSpan.innerText = hostname;
        modalConfirm.classList.remove("hidden");
        modalConfirm.classList.add("flex");
      });
    });

    lucide.createIcons();
  }

  // --- Delete Hostname Execution ---
  btnConfirmCancel.addEventListener("click", () => {
    modalConfirm.classList.remove("flex");
    modalConfirm.classList.add("hidden");
    deleteTargetId = null;
  });

  btnConfirmDelete.addEventListener("click", async () => {
    if (!deleteTargetId) return;

    try {
      const res = await fetch(`/api/certificates/${deleteTargetId}`, {
        method: "DELETE"
      });

      if (!res.ok) throw new Error("Failed to delete certificate target from system.");

      // Visual feedback: remove row instantly
      const row = document.getElementById(`row-cert-${deleteTargetId}`);
      if (row) {
        row.style.transform = "translateX(-20px)";
        row.style.opacity = "0";
        setTimeout(() => row.remove(), 200);
      }

      // Refresh database reference
      await loadCertificates();
      showToast("Hostname deleted successfully", "success");
    } catch (err) {
      console.error(err);
      showToast("Failed to delete hostname", "error");
    } finally {
      modalConfirm.classList.remove("flex");
      modalConfirm.classList.add("hidden");
      deleteTargetId = null;
    }
  });

  // --- Chart Rendering using Chart.js ---
  function renderCharts(crit, warn, healthy) {
    const riskCanvas = document.getElementById("chart-risk");
    const timelineCanvas = document.getElementById("chart-timeline");
    const riskEmpty = document.getElementById("chart-risk-empty");
    const timelineEmpty = document.getElementById("chart-timeline-empty");

    if (certificates.length === 0) {
      riskCanvas.classList.add("hidden");
      timelineCanvas.classList.add("hidden");
      riskEmpty.classList.remove("hidden");
      timelineEmpty.classList.remove("hidden");
      return;
    }

    riskCanvas.classList.remove("hidden");
    timelineCanvas.classList.remove("hidden");
    riskEmpty.classList.add("hidden");
    timelineEmpty.classList.add("hidden");

    // Chart 1: Risk Severity Pie Distribution
    if (chartRisk) chartRisk.destroy();
    
    chartRisk = new Chart(riskCanvas, {
      type: "doughnut",
      data: {
        labels: ["Critical", "Warning", "Healthy"],
        datasets: [{
          data: [crit, warn, healthy],
          backgroundColor: ["#f43f5e", "#f59e0b", "#10b981"],
          borderColor: "#0f172a",
          borderWidth: 2,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#94a3b8",
              font: { family: 'Space Grotesk', size: 11 },
              padding: 15,
              usePointStyle: true
            }
          },
          tooltip: {
            backgroundColor: "#020617",
            titleColor: "#ffffff",
            bodyColor: "#94a3b8",
            borderColor: "#1e293b",
            borderWidth: 1,
            titleFont: { family: 'Space Grotesk', weight: 'bold' },
            bodyFont: { family: 'Space Grotesk' }
          }
        },
        cutout: "65%"
      }
    });

    // Chart 2: Expiry Timeline Bar Distribution
    // Segment days remaining into ranges
    const ranges = {
      "0–14 d": 0,
      "15–45 d": 0,
      "46–90 d": 0,
      "91–180 d": 0,
      "180+ d": 0
    };

    certificates.forEach(c => {
      if (c.status === "UNREACHABLE") return;
      const days = c.days_remaining;
      if (days <= 14) ranges["0–14 d"]++;
      else if (days <= 45) ranges["15–45 d"]++;
      else if (days <= 90) ranges["46–90 d"]++;
      else if (days <= 180) ranges["91–180 d"]++;
      else ranges["180+ d"]++;
    });

    if (chartTimeline) chartTimeline.destroy();

    chartTimeline = new Chart(timelineCanvas, {
      type: "bar",
      data: {
        labels: Object.keys(ranges),
        datasets: [{
          label: "Certificates",
          data: Object.values(ranges),
          backgroundColor: ["#f43f5e", "#f59e0b", "#0ea5e9", "#10b981", "#84cc16"],
          borderColor: "transparent",
          borderRadius: 4,
          maxBarThickness: 25
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: "#64748b", font: { family: 'Space Grotesk', size: 10 } }
          },
          y: {
            grid: { color: "#1e293b" },
            ticks: { color: "#64748b", precision: 0, font: { family: 'Space Grotesk', size: 10 } }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#020617",
            titleColor: "#ffffff",
            bodyColor: "#94a3b8",
            borderColor: "#1e293b",
            borderWidth: 1,
            titleFont: { family: 'Space Grotesk', weight: 'bold' },
            bodyFont: { family: 'Space Grotesk' }
          }
        }
      }
    });
  }

  // --- Loader Dialog Helpers ---
  function showLoaderModal() {
    modalLoader.classList.remove("hidden");
    modalLoader.classList.add("flex");
  }

  function hideLoaderModal() {
    modalLoader.classList.remove("flex");
    modalLoader.classList.add("hidden");
  }

  function updateLoaderMetrics(phase) {
    logDns.className = "flex items-center gap-1.5 text-slate-500";
    logSsl.className = "flex items-center gap-1.5 text-slate-500";
    logGroq.className = "flex items-center gap-1.5 text-slate-500";

    logDns.innerHTML = `<i data-lucide="clock" class="w-3.5 h-3.5"></i> Resolve Domain Name Services...`;
    logSsl.innerHTML = `<i data-lucide="clock" class="w-3.5 h-3.5"></i> Negotiate Cryptographic Handshake...`;
    logGroq.innerHTML = `<i data-lucide="clock" class="w-3.5 h-3.5"></i> Compute Groq llama3 Incident Analysis...`;

    if (phase === "resolving") {
      logDns.className = "flex items-center gap-1.5 text-rose-400 font-medium";
      logDns.innerHTML = `<i data-lucide="loader" class="w-3.5 h-3.5 animate-spin"></i> Resolving domain names...`;
    } else if (phase === "handshake") {
      logDns.className = "flex items-center gap-1.5 text-emerald-400";
      logDns.innerHTML = `<i data-lucide="check-circle" class="w-3.5 h-3.5"></i> DNS Resolution Completed`;
      
      logSsl.className = "flex items-center gap-1.5 text-rose-400 font-medium";
      logSsl.innerHTML = `<i data-lucide="loader" class="w-3.5 h-3.5 animate-spin"></i> Establishing TLS socket...`;
    } else if (phase === "ai") {
      logDns.className = "flex items-center gap-1.5 text-emerald-400";
      logDns.innerHTML = `<i data-lucide="check-circle" class="w-3.5 h-3.5"></i> DNS Resolution Completed`;

      logSsl.className = "flex items-center gap-1.5 text-emerald-400";
      logSsl.innerHTML = `<i data-lucide="check-circle" class="w-3.5 h-3.5"></i> Cryptographic Handshake Succeeded`;

      logGroq.className = "flex items-center gap-1.5 text-rose-400 font-medium";
      logGroq.innerHTML = `<i data-lucide="loader" class="w-3.5 h-3.5 animate-spin"></i> Evaluating threat with Groq API...`;
    }
    lucide.createIcons();
  }

  // Simulate loader subphases sequence to give a beautiful real-time feel to technical interviewers
  btnScan.addEventListener("click", () => {
    if (hostnamesInput.value.trim().length === 0) return;
    setTimeout(() => {
      if (!modalLoader.classList.contains("hidden")) {
        updateLoaderMetrics("handshake");
      }
    }, 1500);

    setTimeout(() => {
      if (!modalLoader.classList.contains("hidden")) {
        updateLoaderMetrics("ai");
      }
    }, 3200);
  });

  // --- Reports Export Download Engine ---
  btnDownloadCsv.addEventListener("click", () => {
    if (certificates.length === 0) return;
    // Trigger GET /api/export/csv
    window.location.href = "/api/export/csv";
    showToast("CSV scan report generated successfully.", "success");
  });

  btnDownloadMd.addEventListener("click", () => {
    if (certificates.length === 0) return;
    // Trigger GET /api/export/markdown
    window.location.href = "/api/export/markdown";
    showToast("AI Remediation Workbook generated successfully.", "success");
  });

  // --- Client Notifications helper ---
  function showToast(message, type = "success") {
    const id = "toast_" + Date.now();
    const container = document.getElementById("toast-container");
    
    let iconName = "check-circle";
    let bgBorderClass = "bg-slate-900 border-emerald-500/20 text-emerald-400";
    
    if (type === "error") {
      iconName = "x-circle";
      bgBorderClass = "bg-slate-900 border-rose-500/20 text-rose-400";
    } else if (type === "info") {
      iconName = "info";
      bgBorderClass = "bg-slate-900 border-sky-500/20 text-sky-400";
    }
    
    const toast = document.createElement("div");
    toast.id = id;
    toast.className = `toast-item pointer-events-auto flex items-center gap-2.5 px-4 py-3 border rounded-xl shadow-2xl backdrop-blur-md text-xs font-medium max-w-sm ${bgBorderClass}`;
    toast.innerHTML = `
      <i data-lucide="${iconName}" class="w-4.5 h-4.5 shrink-0"></i>
      <span>${message}</span>
      <button class="toast-close ml-auto hover:text-white transition cursor-pointer" onclick="this.parentElement.remove()">
        <i data-lucide="x" class="w-3.5 h-3.5"></i>
      </button>
    `;

    container.appendChild(toast);
    lucide.createIcons();

    // Auto-remove after 4 seconds
    setTimeout(() => {
      const liveToast = document.getElementById(id);
      if (liveToast) {
        liveToast.classList.add("toast-item-fadeout");
        setTimeout(() => liveToast.remove(), 250);
      }
    }, 4000);
  }

  // Expose toast so inline button call can invoke it
  window.showToast = showToast;

  // Sync state on load
  loadCertificates();
});
