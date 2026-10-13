/* ==========================================================================
   DYNAMIC NETWORK AUDIT LOGIC
   ========================================================================== */

let dynamicAuditPollInterval = null;
let currentDynamicReportData = null;
let dynamicMode = "launch"; // "launch" | "attach"

function setupDynamicAudit() {
    const tabBtnStatic = document.getElementById("tab-btn-static");
    const tabBtnDynamic = document.getElementById("tab-btn-dynamic");
    const viewStaticAudit = document.getElementById("view-static-audit");
    const viewDynamicAudit = document.getElementById("view-dynamic-audit");

    // Tab switching
    tabBtnStatic.addEventListener("click", () => {
        tabBtnStatic.classList.add("active");
        tabBtnDynamic.classList.remove("active");
        viewStaticAudit.classList.remove("hidden");
        viewDynamicAudit.classList.add("hidden");
    });

    tabBtnDynamic.addEventListener("click", () => {
        tabBtnDynamic.classList.add("active");
        tabBtnStatic.classList.remove("active");
        viewDynamicAudit.classList.remove("hidden");
        viewStaticAudit.classList.add("hidden");
        fetchRunningProcesses();
    });

    // Mode switching
    const btnModeLaunch = document.getElementById("btn-mode-launch");
    const btnModeAttach = document.getElementById("btn-mode-attach");
    const dynamicLaunchFields = document.getElementById("dynamic-launch-fields");
    const dynamicAttachFields = document.getElementById("dynamic-attach-fields");

    btnModeLaunch.addEventListener("click", () => {
        dynamicMode = "launch";
        btnModeLaunch.classList.add("active");
        btnModeAttach.classList.remove("active");
        dynamicLaunchFields.classList.remove("hidden");
        dynamicAttachFields.classList.add("hidden");
    });

    btnModeAttach.addEventListener("click", () => {
        dynamicMode = "attach";
        btnModeAttach.classList.add("active");
        btnModeLaunch.classList.remove("active");
        dynamicAttachFields.classList.remove("hidden");
        dynamicLaunchFields.classList.add("hidden");
        fetchRunningProcesses();
    });

    // Quick chips
    const chipOpenpeek = document.getElementById("chip-openpeek");
    if (chipOpenpeek) {
        chipOpenpeek.addEventListener("click", () => {
            document.getElementById("dynamic-exe-input").value = "C:\\Users\\ash\\AppData\\Local\\OpenPeek\\openpeek.exe";
        });
    }

    const chipNetworkTest = document.getElementById("chip-network-test");
    if (chipNetworkTest) {
        chipNetworkTest.addEventListener("click", () => {
            document.getElementById("dynamic-exe-input").value = "C:\\Python314\\python.exe";
            document.getElementById("dynamic-args-input").value = "samples/network_test_app.py";
        });
    }

    // Refresh PIDs
    document.getElementById("btn-refresh-pids").addEventListener("click", fetchRunningProcesses);

    // Launch & Stop buttons
    document.getElementById("btn-run-dynamic").addEventListener("click", startDynamicAudit);
    document.getElementById("btn-stop-dynamic").addEventListener("click", stopDynamicAudit);

    // Export Dynamic JSON
    document.getElementById("btn-export-dynamic-json").addEventListener("click", () => {
        if (!currentDynamicReportData) return;
        const blob = new Blob([JSON.stringify(currentDynamicReportData, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `vibe-network-audit-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    });
}

async function fetchRunningProcesses() {
    const select = document.getElementById("dynamic-pid-select");
    select.innerHTML = '<option value="">-- Chargement des processus actifs... --</option>';
    try {
        const res = await fetch("/api/dynamic/processes");
        const data = await res.json();
        const procs = data.processes || [];
        if (procs.length === 0) {
            select.innerHTML = '<option value="">Aucun processus utilisateur détecté</option>';
            return;
        }

        select.innerHTML = '<option value="">-- Sélectionner un processus à auditer --</option>';
        procs.forEach(p => {
            const opt = document.createElement("option");
            opt.value = p.pid;
            opt.textContent = `[PID ${p.pid}] ${p.name}`;
            if (p.name.toLowerCase().includes("openpeek")) {
                opt.selected = true;
            }
            select.appendChild(opt);
        });
    } catch (e) {
        select.innerHTML = '<option value="">Erreur lors de la récupération des processus</option>';
    }
}

async function startDynamicAudit() {
    const exeInput = document.getElementById("dynamic-exe-input").value.trim();
    const pidSelect = document.getElementById("dynamic-pid-select").value;
    const timeout = parseInt(document.getElementById("dynamic-timeout-select").value, 10);
    const args = document.getElementById("dynamic-args-input").value.trim();

    const payload = {
        timeout: timeout,
        args: args
    };

    if (dynamicMode === "launch") {
        if (!exeInput) {
            alert("Veuillez renseigner le chemin d'un exécutable .exe ou cliquer sur un exemple rapide.");
            return;
        }
        payload.exe_path = exeInput;
    } else {
        if (!pidSelect) {
            alert("Veuillez sélectionner un processus actif dans la liste.");
            return;
        }
        payload.pid = parseInt(pidSelect, 10);
    }

    try {
        const res = await fetch("/api/dynamic/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.error) {
            alert("Erreur : " + data.error);
            return;
        }

        // Toggle buttons
        document.getElementById("btn-run-dynamic").classList.add("hidden");
        document.getElementById("btn-stop-dynamic").classList.remove("hidden");

        // Show live banner
        const banner = document.getElementById("dynamic-live-banner");
        banner.classList.remove("hidden");
        document.getElementById("dynamic-results-view").classList.add("hidden");

        document.getElementById("live-target-title").textContent = `Audit en cours sur ${data.process_name} (PID: ${data.pid})`;
        document.getElementById("live-target-meta").textContent = `Interception de l'arbre des sockets, résolutions DNS et flux distants`;

        // Start polling status
        startDynamicStatusPolling(timeout);

    } catch (e) {
        alert("Erreur réseau : " + e.message);
    }
}

function startDynamicStatusPolling(timeout) {
    if (dynamicAuditPollInterval) {
        clearInterval(dynamicAuditPollInterval);
    }

    dynamicAuditPollInterval = setInterval(async () => {
        try {
            const res = await fetch("/api/dynamic/status");
            const data = await res.json();

            // Update live banner
            const elapsed = Math.round(data.elapsed || 0);
            const total = data.timeout > 0 ? `${data.timeout}s` : "En continu";
            document.getElementById("live-timer-text").textContent = `${elapsed}s / ${total}`;

            const rep = data.report;
            if (rep) {
                document.getElementById("live-count-conns").textContent = rep.total_connections || 0;
                document.getElementById("live-count-procs").textContent = (rep.processes_monitored || []).length || 1;
            }

            // Check if finished
            if (!data.is_running && rep) {
                clearInterval(dynamicAuditPollInterval);
                dynamicAuditPollInterval = null;
                finishDynamicAudit(rep);
            }
        } catch (e) {
            console.error("Polling error:", e);
        }
    }, 500);
}

async function stopDynamicAudit() {
    try {
        const res = await fetch("/api/dynamic/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        if (dynamicAuditPollInterval) {
            clearInterval(dynamicAuditPollInterval);
            dynamicAuditPollInterval = null;
        }
        if (data.report) {
            finishDynamicAudit(data.report);
        }
    } catch (e) {
        alert("Erreur lors de l'arrêt : " + e.message);
    }
}

function finishDynamicAudit(report) {
    // Reset buttons
    document.getElementById("btn-run-dynamic").classList.remove("hidden");
    document.getElementById("btn-stop-dynamic").classList.add("hidden");
    document.getElementById("dynamic-live-banner").classList.add("hidden");

    currentDynamicReportData = report;
    renderDynamicResults(report);
}

function renderDynamicResults(report) {
    const resultsView = document.getElementById("dynamic-results-view");
    resultsView.classList.remove("hidden");

    // 1. Score & Gauge
    const score = report.score || 0;
    const scoreNum = document.getElementById("net-score-num");
    const gaugeFill = document.getElementById("net-gauge-fill");
    const badgeLevel = document.getElementById("net-badge-level");
    const verdictText = document.getElementById("net-verdict");

    // Animate score counter
    let currentScore = 0;
    const scoreStep = Math.max(1, Math.floor(score / 30));
    const scoreInterval = setInterval(() => {
        currentScore += scoreStep;
        if (currentScore >= score) {
            currentScore = score;
            clearInterval(scoreInterval);
        }
        scoreNum.textContent = currentScore;
    }, 20);

    // Gauge circle animation (circumference = 2 * PI * 58 = 364.4)
    const maxOffset = 364.4;
    const fillOffset = maxOffset - (score / 100) * maxOffset;
    gaugeFill.style.strokeDashoffset = fillOffset;

    if (score >= 90) {
        gaugeFill.className = "gauge-fill gauge-fill-success";
        badgeLevel.className = "status-badge badge-success";
        badgeLevel.textContent = "🛡️ 100% OFFLINE";
    } else if (score >= 75) {
        gaugeFill.className = "gauge-fill gauge-fill-warning";
        badgeLevel.className = "status-badge badge-warning";
        badgeLevel.textContent = "⚠️ TÉLÉMÉTRIE DÉTECTÉE";
    } else {
        gaugeFill.className = "gauge-fill gauge-fill-danger";
        badgeLevel.className = "status-badge badge-danger";
        badgeLevel.textContent = "🚨 TRAFIC EXTERNE NON VÉRIFIÉ";
    }

    verdictText.textContent = report.verdict_description || "Audit terminé.";

    // 2. Metrics Card
    document.getElementById("stat-net-conns").textContent = report.total_connections || 0;
    document.getElementById("stat-net-dests").textContent = (report.unique_destinations || []).length;
    document.getElementById("stat-net-procs").textContent = (report.processes_monitored || []).length || 1;

    let totalReadKb = 0;
    let totalWriteKb = 0;
    (report.processes_monitored || []).forEach(p => {
        totalReadKb += (p.read_bytes || 0) / 1024;
        totalWriteKb += (p.write_bytes || 0) / 1024;
    });
    document.getElementById("stat-net-io").textContent = `${totalReadKb.toFixed(1)} KB / ${totalWriteKb.toFixed(1)} KB`;

    // 3. Category Breakdown
    const catContainer = document.getElementById("net-category-bars");
    catContainer.innerHTML = "";
    const catSummary = report.categories_summary || {};
    const catKeys = Object.keys(catSummary);

    if (catKeys.length === 0) {
        catContainer.innerHTML = '<div style="color: var(--emerald); font-size: 0.9rem; padding: 12px 0;">✓ Aucun paquet sortant enregistré (Zero Leaks).</div>';
    } else {
        const catLabels = {
            "telemetry": "Télémétrie & Analytics",
            "cloud_ai": "APIs Cloud / LLM",
            "code_distribution": "Distribution de Code & CDN",
            "cdn_infrastructure": "Infrastructure CDN / Cloud",
            "unknown_external": "Adresses Externes Inconnues",
            "pending": "En cours de résolution"
        };
        catKeys.forEach(k => {
            const count = catSummary[k];
            const name = catLabels[k] || k;
            const barItem = document.createElement("div");
            barItem.className = "category-bar-item";
            barItem.innerHTML = `
                <div class="cat-label-row">
                    <span class="cat-name">${escapeHtml(name)}</span>
                    <span class="cat-score">${count} trame${count > 1 ? 's' : ''}</span>
                </div>
                <div class="progress-track">
                    <div class="progress-fill" style="width: ${Math.min(100, count * 20)}%; background: ${k === 'unknown_external' ? 'var(--rose)' : k === 'telemetry' ? 'var(--amber)' : 'var(--accent-primary)'};"></div>
                </div>
            `;
            catContainer.appendChild(barItem);
        });
    }

    // 4. Process Tree Cards
    const treeContainer = document.getElementById("net-process-tree-container");
    treeContainer.innerHTML = "";
    const procs = report.processes_monitored || [];
    document.getElementById("net-process-tree-summary").textContent = `${procs.length} processus surveillé${procs.length > 1 ? 's' : ''} dans l'arbre`;

    procs.forEach((p, idx) => {
        const node = document.createElement("div");
        node.className = "proc-node-card";
        const isParent = idx === 0;
        node.innerHTML = `
            <div class="proc-node-title">
                <span>${isParent ? '👑' : '↳'}</span>
                <span>${escapeHtml(p.name)}</span>
            </div>
            <div class="proc-node-stats">
                Lecture: ${(p.read_bytes / 1024).toFixed(1)} KB | Écriture: ${(p.write_bytes / 1024).toFixed(1)} KB
            </div>
        `;
        treeContainer.appendChild(node);
    });

    // 5. Destinations Explorer Table
    const destContainer = document.getElementById("net-destinations-table-container");
    const dests = report.unique_destinations || [];
    document.getElementById("net-dest-count").textContent = dests.length;

    if (dests.length === 0) {
        destContainer.innerHTML = `
            <div style="padding: 24px; text-align: center; color: var(--emerald); font-size: 0.95rem;">
                🛡️ <strong>Application 100% Offline :</strong> Aucune socket réseau externe n'a été ouverte vers Internet.
            </div>
        `;
    } else {
        let tableHtml = `
            <table class="destinations-table">
                <thead>
                    <tr>
                        <th>Processus</th>
                        <th>Protocole</th>
                        <th>IP Cible : Port</th>
                        <th>Nom d'hôte résolu</th>
                        <th>Organisation / Pays</th>
                        <th>Catégorie</th>
                    </tr>
                </thead>
                <tbody>
        `;
        dests.forEach(d => {
            const catBadgeClass = `badge-cat-${d.category || 'unknown_external'}`;
            const orgDisplay = d.org ? `${escapeHtml(d.org)} (${d.country || 'N/A'})` : 'N/A';
            tableHtml += `
                <tr>
                    <td><strong>${escapeHtml(d.process_name)}</strong></td>
                    <td><span class="badge-proto">${d.protocol || 'TCP'}</span></td>
                    <td style="font-family: var(--font-mono); color: #93c5fd;">${escapeHtml(d.ip)}:${d.port}</td>
                    <td style="font-family: var(--font-mono);">${escapeHtml(d.hostname)}</td>
                    <td>${orgDisplay}</td>
                    <td><span class="badge-cat ${catBadgeClass}">${escapeHtml(d.category)}</span></td>
                </tr>
            `;
        });
        tableHtml += `</tbody></table>`;
        destContainer.innerHTML = tableHtml;
    }

    // 6. Timeline Stream
    const timelineContainer = document.getElementById("net-timeline-container");
    timelineContainer.innerHTML = "";
    const timeline = (currentDynamicReportData && currentDynamicReportData.timeline) || report.unique_destinations || [];
    document.getElementById("net-timeline-count").textContent = timeline.length;

    if (timeline.length === 0) {
        timelineContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 0.85rem; padding: 10px;">Aucun événement réseau enregistré.</p>';
    } else {
        timeline.slice(-30).forEach(ev => {
            const row = document.createElement("div");
            row.className = "timeline-event-row";
            row.innerHTML = `
                <span class="timeline-time">${ev.first_seen || ev.time || ''}</span>
                <span class="badge-proto">${ev.proto || ev.protocol || 'TCP'}</span>
                <span class="timeline-proc">${escapeHtml(ev.process_name || 'exe')}</span>
                <span>-></span>
                <span class="timeline-dest">${escapeHtml(ev.remote_ip || ev.ip)}:${ev.remote_port || ev.port}</span>
                <span class="timeline-host">${escapeHtml(ev.hostname || '')}</span>
            `;
            timelineContainer.appendChild(row);
        });
    }

    // 7. Static URLs Detected in Binary
    const staticUrls = report.static_detected_urls || [];
    const staticCard = document.getElementById("net-static-urls-card");
    const staticList = document.getElementById("net-static-urls-list");
    document.getElementById("net-static-urls-count").textContent = `${staticUrls.length} URLs`;

    if (staticUrls.length === 0) {
        staticCard.classList.add("hidden");
    } else {
        staticCard.classList.remove("hidden");
        staticList.innerHTML = "";
        staticUrls.forEach(u => {
            const chip = document.createElement("div");
            chip.className = "url-item-card";
            chip.textContent = u;
            staticList.appendChild(chip);
        });
    }
}

// Fullscreen Toggle Handler
const btnFullscreen = document.getElementById("btn-fullscreen-toggle");
if (btnFullscreen) {
    btnFullscreen.addEventListener("click", () => {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(() => {});
            btnFullscreen.querySelector("span").textContent = "Fenêtré";
        } else {
            if (document.exitFullscreen) {
                document.exitFullscreen().catch(() => {});
            }
            btnFullscreen.querySelector("span").textContent = "Plein écran";
        }
    });

    document.addEventListener("fullscreenchange", () => {
        if (btnFullscreen.querySelector("span")) {
            btnFullscreen.querySelector("span").textContent = document.fullscreenElement ? "Fenêtré" : "Plein écran";
        }
    });
}
