// Global App State
let selectedFile = null;
let uploadedFileMeta = null;
let currentPage = 1;
const perPage = 25;
let charts = {};

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initDropzone();
    initOrgSelector();
    initProcessButton();
    loadFilterDropdowns();
    loadEvents(1);
    loadDashboardStats();
});

// Navigation Tab Switching
function initNavigation() {
    const tabs = document.querySelectorAll(".nav-tab");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

            tab.classList.add("active");
            const targetId = tab.getAttribute("data-tab");
            document.getElementById(targetId).classList.add("active");

            if (targetId === "dashboard-section") {
                loadDashboardStats();
            } else if (targetId === "events-section") {
                loadEvents(currentPage);
            }
        });
    });
}

// Drag & Drop File Handling
function initDropzone() {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => dropzone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => dropzone.classList.remove('dragover'), false);
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            handleFileSelected(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelected(e.target.files[0]);
        }
    });
}

function handleFileSelected(file) {
    selectedFile = file;
    document.getElementById("file-selected-name").innerText = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    document.getElementById("btn-process-log").disabled = false;
    
    // Auto populate source name if empty
    const srcInput = document.getElementById("source-input");
    if (!srcInput.value.trim()) {
        srcInput.value = file.name;
    }
}

// Organization Select Custom Input
function initOrgSelector() {
    const orgSelect = document.getElementById("org-select");
    const customInput = document.getElementById("org-custom-input");

    orgSelect.addEventListener("change", () => {
        if (orgSelect.value === "custom") {
            customInput.classList.remove("hidden");
            customInput.focus();
        } else {
            customInput.classList.add("hidden");
        }
    });
}

// Upload & Process Log Execution
function initProcessButton() {
    const btn = document.getElementById("btn-process-log");
    btn.addEventListener("click", async () => {
        if (!selectedFile) return;

        btn.disabled = true;
        btn.innerText = "⏳ Processing Log...";
        resetStepperUI();

        // Step 1: Upload File
        setStepActive(1);
        try {
            const formData = new FormData();
            formData.append("file", selectedFile);

            const uploadRes = await fetch("/api/upload", {
                method: "POST",
                body: formData
            });

            const uploadData = await uploadRes.json();
            if (!uploadRes.ok) {
                throw new Error(uploadData.error || "Upload failed");
            }

            uploadedFileMeta = uploadData;
            setStepCompleted(1);

            // Step 2 & Beyond: Process Pipeline
            setStepActive(2);
            animateStepperProgress();

            const orgSelect = document.getElementById("org-select");
            let orgVal = orgSelect.value;
            if (orgVal === "custom") {
                orgVal = document.getElementById("org-custom-input").value.trim() || "Custom Organization";
            }
            const sourceVal = document.getElementById("source-input").value.trim() || selectedFile.name;

            const processRes = await fetch("/api/process", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    filepath: uploadData.filepath,
                    filename: uploadData.filename,
                    stored_filename: uploadData.stored_filename,
                    organization: orgVal,
                    source: sourceVal
                })
            });

            const processResult = await processRes.json();
            if (!processRes.ok) {
                throw new Error(processResult.error || "Pipeline processing failed");
            }

            // Complete Stepper & Display Results
            completeAllSteps();
            displayProcessResults(processResult);
            loadFilterDropdowns();

        } catch (err) {
            alert(`Processing Error: ${err.message}`);
            document.getElementById("res-status-text").innerText = `ERROR: ${err.message}`;
            document.getElementById("res-status-text").style.color = "var(--accent-red)";
            document.getElementById("stepper-status-badge").className = "badge badge-danger";
            document.getElementById("stepper-status-badge").innerText = "FAILED";
        } finally {
            btn.disabled = false;
            btn.innerText = "⚡ [ PROCESS LOG ]";
        }
    });
}

// Stepper Helper Functions
function resetStepperUI() {
    for (let i = 1; i <= 8; i++) {
        const item = document.getElementById(`step-${i}`);
        item.classList.remove("active", "completed");
    }
    document.getElementById("stepper-status-badge").className = "badge badge-idle";
    document.getElementById("stepper-status-badge").innerText = "Processing...";
}

function setStepActive(stepNum) {
    const item = document.getElementById(`step-${stepNum}`);
    if (item) item.classList.add("active");
}

function setStepCompleted(stepNum) {
    const item = document.getElementById(`step-${stepNum}`);
    if (item) {
        item.classList.remove("active");
        item.classList.add("completed");
    }
}

function animateStepperProgress() {
    let currentStep = 2;
    const interval = setInterval(() => {
        if (currentStep <= 7) {
            setStepCompleted(currentStep - 1);
            setStepActive(currentStep);
            currentStep++;
        } else {
            clearInterval(interval);
        }
    }, 180);
}

function completeAllSteps() {
    for (let i = 1; i <= 8; i++) {
        setStepCompleted(i);
    }
}

function displayProcessResults(res) {
    document.getElementById("res-filename").innerText = res.filename || "-";
    document.getElementById("res-format").innerText = res.format_detected || "-";
    document.getElementById("res-received").innerText = res.events_received || 0;
    document.getElementById("res-parsed").innerText = res.events_parsed || 0;
    document.getElementById("res-normalized").innerText = res.events_normalized || 0;
    document.getElementById("res-stored").innerText = res.events_stored || 0;
    document.getElementById("res-warnings").innerText = res.warnings_count || 0;
    document.getElementById("res-duplicates").innerText = res.duplicate_count || 0;

    const statusBadge = document.getElementById("stepper-status-badge");
    const statusText = document.getElementById("res-status-text");

    if (res.warnings_count > 0) {
        statusBadge.className = "badge badge-warning";
        statusBadge.innerText = "Completed with Warnings";
        statusText.innerText = `Processing completed with warnings. ${res.warnings_count} record(s) logged warnings. ${res.events_stored} stored in SIEM.`;
        statusText.style.color = "var(--accent-amber)";
    } else {
        statusBadge.className = "badge badge-success";
        statusBadge.innerText = "SUCCESS";
        statusText.innerText = `SUCCESS! ${res.events_stored} events successfully parsed, normalized, and stored in SIEM.`;
        statusText.style.color = "var(--accent-green)";
    }
}

// Load Dropdown Options
async function loadFilterDropdowns() {
    try {
        const [orgRes, srcRes] = await Promise.all([
            fetch("/api/organizations"),
            fetch("/api/sources")
        ]);

        const orgData = await orgRes.json();
        const srcData = await srcRes.json();

        const orgSelect = document.getElementById("filter-org");
        orgSelect.innerHTML = `<option value="">All Organizations</option>` +
            (orgData.organizations || []).map(o => `<option value="${o}">${o}</option>`).join("");

        const srcSelect = document.getElementById("filter-source");
        srcSelect.innerHTML = `<option value="">All Sources</option>` +
            (srcData.sources || []).map(s => `<option value="${s}">${s}</option>`).join("");

    } catch (e) {
        console.error("Failed to load filter dropdowns", e);
    }
}

// Load SIEM Events Table
async function loadEvents(page = 1) {
    currentPage = page;
    const search = document.getElementById("filter-search").value.trim();
    const org = document.getElementById("filter-org").value;
    const source = document.getElementById("filter-source").value;
    const sourceType = document.getElementById("filter-source-type").value;
    const severity = document.getElementById("filter-severity").value;

    const params = new URLSearchParams({
        page: page,
        per_page: perPage,
        ...(search && { search }),
        ...(org && { organization: org }),
        ...(source && { source }),
        ...(sourceType && { source_type: sourceType }),
        ...(severity && { severity })
    });

    try {
        const res = await fetch(`/api/events?${params}`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);

        renderEventsTable(data.events || []);
        document.getElementById("events-total-count").innerText = data.total || 0;
        document.getElementById("page-info").innerText = `Page ${data.page} of ${data.total_pages || 1}`;

        document.getElementById("btn-prev-page").disabled = (data.page <= 1);
        document.getElementById("btn-next-page").disabled = (data.page >= data.total_pages);

    } catch (err) {
        console.error("Failed to load events", err);
    }
}

function resetFilters() {
    document.getElementById("filter-search").value = "";
    document.getElementById("filter-org").value = "";
    document.getElementById("filter-source").value = "";
    document.getElementById("filter-source-type").value = "";
    document.getElementById("filter-severity").value = "";
    loadEvents(1);
}

function prevPage() {
    if (currentPage > 1) loadEvents(currentPage - 1);
}

function nextPage() {
    loadEvents(currentPage + 1);
}

function renderEventsTable(events) {
    const tbody = document.getElementById("events-tbody");
    if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="12" class="text-center py-4">No events match criteria. Upload a log or adjust filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = events.map(ev => {
        const sevClass = getSeverityBadgeClass(ev.severity);
        const statusClass = ev.parser_status === "SUCCESS" ? "badge-success" : "badge-warning";
        return `
            <tr>
                <td>#${ev.id}</td>
                <td>${ev.timestamp || "-"}</td>
                <td>${ev.organization || "-"}</td>
                <td>${ev.source || "-"}</td>
                <td><span class="badge-chip">${ev.source_type || "-"}</span></td>
                <td>${ev.hostname || "-"}</td>
                <td>${ev.ip_address || "-"}</td>
                <td>${ev.destination_ip || "-"}</td>
                <td>${ev.event_type || "-"}</td>
                <td><span class="badge ${sevClass}">${ev.severity || "INFO"}</span></td>
                <td><span class="badge ${statusClass}">${ev.parser_status || "SUCCESS"}</span></td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="viewEventDetail(${ev.id})">🔍 View</button>
                </td>
            </tr>
        `;
    }).join("");
}

function getSeverityBadgeClass(sev) {
    switch (sev) {
        case "CRITICAL": return "badge-danger";
        case "HIGH": return "badge-danger";
        case "MEDIUM": return "badge-warning";
        case "LOW": return "badge-info";
        default: return "badge-idle";
    }
}

// Event Detail Modal Drawer
async function viewEventDetail(eventId) {
    try {
        const res = await fetch(`/api/events/${eventId}`);
        const ev = await res.json();
        if (!res.ok) throw new Error(ev.error);

        document.getElementById("modal-event-id").innerText = ev.id;
        const body = document.getElementById("modal-body-content");

        let rawDataFormatted = "-";
        if (ev.raw_data) {
            try {
                const parsedJSON = JSON.parse(ev.raw_data);
                rawDataFormatted = JSON.stringify(parsedJSON, null, 2);
            } catch (e) {
                rawDataFormatted = ev.raw_data;
            }
        }

        body.innerHTML = `
            <div class="detail-section">
                <h4>Normalized SIEM Schema Fields</h4>
                <div class="detail-grid">
                    <div><strong>ID:</strong> #${ev.id}</div>
                    <div><strong>Timestamp:</strong> ${ev.timestamp || "NULL"}</div>
                    <div><strong>Organization:</strong> ${ev.organization || "NULL"}</div>
                    <div><strong>Source:</strong> ${ev.source || "NULL"}</div>
                    <div><strong>Source Type:</strong> ${ev.source_type || "NULL"}</div>
                    <div><strong>Hostname:</strong> ${ev.hostname || "NULL"}</div>
                    <div><strong>IP Address:</strong> ${ev.ip_address || "NULL"}</div>
                    <div><strong>Destination IP:</strong> ${ev.destination_ip || "NULL"}</div>
                    <div><strong>Source Port:</strong> ${ev.source_port || "NULL"}</div>
                    <div><strong>Destination Port:</strong> ${ev.destination_port || "NULL"}</div>
                    <div><strong>User:</strong> ${ev.user || "NULL"}</div>
                    <div><strong>Event Type:</strong> ${ev.event_type || "NULL"}</div>
                    <div><strong>Event ID:</strong> ${ev.event_id || "NULL"}</div>
                    <div><strong>Provider:</strong> ${ev.provider || "NULL"}</div>
                    <div><strong>Protocol:</strong> ${ev.protocol || "NULL"}</div>
                    <div><strong>Status / Action:</strong> ${ev.status || "NULL"} / ${ev.action || "NULL"}</div>
                    <div><strong>Severity:</strong> ${ev.severity || "NULL"}</div>
                    <div><strong>Attack Type (Source Label):</strong> ${ev.attack_type || "Not Provided"}</div>
                    <div><strong>Suspicious (Source Flag):</strong> ${ev.suspicious || "Not Provided"}</div>
                    <div><strong>Is Duplicate:</strong> ${ev.is_duplicate ? "Yes (Flagged)" : "No"}</div>
                </div>
            </div>

            <div class="detail-section">
                <h4>Parser & Audit Meta</h4>
                <div><strong>Parser Status:</strong> ${ev.parser_status}</div>
                ${ev.parser_warning ? `<div class="warning-text"><strong>Warning:</strong> ${ev.parser_warning}</div>` : ""}
                <div><strong>SHA-256 Fingerprint:</strong> <code>${ev.fingerprint || "-"}</code></div>
                <div><strong>File Name:</strong> ${ev.log_file || "-"}</div>
            </div>

            <div class="detail-section">
                <h4>Original Raw Log</h4>
                <div class="code-block">${escapeHtml(ev.raw_log || "")}</div>
            </div>

            <div class="detail-section">
                <h4>Original Raw Structured Data (JSON)</h4>
                <div class="code-block">${escapeHtml(rawDataFormatted)}</div>
            </div>
        `;

        document.getElementById("event-modal").classList.add("active");
    } catch (err) {
        alert(`Failed to load event detail: ${err.message}`);
    }
}

function closeModal() {
    document.getElementById("event-modal").classList.remove("active");
}

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Load Dashboard Metrics & Render Chart.js
async function loadDashboardStats() {
    try {
        const res = await fetch("/api/stats");
        const stats = await res.json();
        if (!res.ok) throw new Error(stats.error);

        document.getElementById("stat-total-events").innerText = stats.total_events || 0;
        document.getElementById("stat-total-sources").innerText = stats.total_sources || 0;
        document.getElementById("stat-total-systems").innerText = stats.total_systems || 0;
        document.getElementById("stat-total-orgs").innerText = stats.total_organizations || 0;
        document.getElementById("stat-files-processed").innerText = stats.files_processed || 0;
        document.getElementById("stat-high-sev").innerText = stats.high_severity_events || 0;
        document.getElementById("stat-warnings").innerText = stats.parser_warnings || 0;

        renderCharts(stats);

    } catch (e) {
        console.error("Failed to load dashboard stats", e);
    }
}

function renderCharts(stats) {
    if (typeof Chart === "undefined") return;

    // Helper to destroy old chart before re-creating
    function createChart(ctxId, type, data, options) {
        if (charts[ctxId]) charts[ctxId].destroy();
        const ctx = document.getElementById(ctxId);
        if (!ctx) return;
        charts[ctxId] = new Chart(ctx, { type, data, options });
    }

    // Chart 1: Sources
    const srcLabels = (stats.by_source || []).map(s => s.source);
    const srcData = (stats.by_source || []).map(s => s.count);
    createChart("chart-sources", "bar", {
        labels: srcLabels,
        datasets: [{
            label: "Events",
            data: srcData,
            backgroundColor: "#00f2fe"
        }]
    }, { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } });

    // Chart 2: Source Types
    const typeLabels = (stats.by_source_type || []).map(st => st.source_type);
    const typeData = (stats.by_source_type || []).map(st => st.count);
    createChart("chart-source-types", "doughnut", {
        labels: typeLabels,
        datasets: [{
            data: typeData,
            backgroundColor: ["#00f2fe", "#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#ef4444"]
        }]
    }, { responsive: true, maintainAspectRatio: false });

    // Chart 3: Organizations
    const orgLabels = (stats.by_organization || []).map(o => o.organization);
    const orgData = (stats.by_organization || []).map(o => o.count);
    createChart("chart-orgs", "pie", {
        labels: orgLabels,
        datasets: [{
            data: orgData,
            backgroundColor: ["#3b82f6", "#10b981", "#8b5cf6", "#f59e0b"]
        }]
    }, { responsive: true, maintainAspectRatio: false });

    // Chart 4: Severity
    const sevLabels = (stats.by_severity || []).map(sv => sv.severity || "UNKNOWN");
    const sevData = (stats.by_severity || []).map(sv => sv.count);
    createChart("chart-severity", "bar", {
        labels: sevLabels,
        datasets: [{
            label: "Count",
            data: sevData,
            backgroundColor: ["#ef4444", "#f59e0b", "#3b82f6", "#10b981", "#6b7280"]
        }]
    }, { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } });
}
