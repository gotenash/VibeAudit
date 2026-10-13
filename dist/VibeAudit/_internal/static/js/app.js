/**
 * Vibe Audit Frontend Application Logic
 */

// Application State
const state = {
    allRules: [],
    enabledRules: new Set(),
    samples: [],
    currentReport: null,
    activeSeverityFilter: "ALL"
};

// DOM Elements
const sampleSelect = document.getElementById("sample-select");
const targetPathInput = document.getElementById("target-path-input");
const btnRunAudit = document.getElementById("btn-run-audit");
const btnOpenConfig = document.getElementById("btn-open-config");
const btnCloseModal = document.getElementById("btn-close-modal");
const btnSaveTests = document.getElementById("btn-save-tests");
const testsModal = document.getElementById("tests-modal");
const rulesListContainer = document.getElementById("rules-list-container");
const activeTestsCount = document.getElementById("active-tests-count");
const selectedSummaryText = document.getElementById("selected-summary-text");

const heroWelcome = document.getElementById("hero-welcome");
const loadingState = document.getElementById("loading-state");
const loadingStepText = document.getElementById("loading-step-text");
const resultsDashboard = document.getElementById("results-dashboard");

// Dashboard Elements
const vibeScoreNum = document.getElementById("vibe-score-num");
const gaugeCircleFill = document.getElementById("gauge-circle-fill");
const badgeLevel = document.getElementById("badge-level");
const vibeVerdict = document.getElementById("vibe-verdict");

const statFiles = document.getElementById("stat-files");
const statLines = document.getElementById("stat-lines");
const statCritical = document.getElementById("stat-critical");
const statHigh = document.getElementById("stat-high");

const categoryBarsList = document.getElementById("category-bars-list");
const actionPlanItems = document.getElementById("action-plan-items");
const findingsContainer = document.getElementById("findings-container");
const findingsTotalCount = document.getElementById("findings-total-count");

// Initialize on page load
document.addEventListener("DOMContentLoaded", async () => {
    await fetchRules();
    await fetchSamples();
    setupEventListeners();
});

async function fetchRules() {
    try {
        const res = await fetch("/api/tests");
        const data = await res.json();
        state.allRules = data.tests || [];
        // Enable default ones
        state.enabledRules = new Set(
            state.allRules.filter(r => r.enabled_by_default).map(r => r.id)
        );
        updateActiveCountBadge();
        renderRulesModal();
    } catch (e) {
        console.error("Failed to load rules:", e);
    }
}

async function fetchSamples() {
    try {
        const res = await fetch("/api/samples");
        const data = await res.json();
        state.samples = data.samples || [];

        // Populate sample dropdown
        sampleSelect.innerHTML = '<option value="">-- Choisir un projet d\'exemple --</option>';
        state.samples.forEach(s => {
            const opt = document.createElement("option");
            opt.value = s.path;
            opt.textContent = s.name;
            sampleSelect.appendChild(opt);
        });
    } catch (e) {
        console.error("Failed to load samples:", e);
    }
}

function updateActiveCountBadge() {
    const count = state.enabledRules.size;
    activeTestsCount.textContent = count;
    selectedSummaryText.textContent = `${count} test${count > 1 ? 's' : ''} activé${count > 1 ? 's' : ''} sur ${state.allRules.length}`;
}

function renderRulesModal() {
    rulesListContainer.innerHTML = "";

    state.allRules.forEach(rule => {
        const isChecked = state.enabledRules.has(rule.id);
        const item = document.createElement("div");
        item.className = "rule-card-item";

        let sevBadgeClass = "badge-danger";
        if (rule.default_severity === "HIGH") sevBadgeClass = "badge-warning";
        else if (rule.default_severity === "MEDIUM") sevBadgeClass = "badge-cyan";
        else if (rule.default_severity === "LOW") sevBadgeClass = "badge-success";

        item.innerHTML = `
            <div class="rule-card-info">
                <div class="rule-card-top">
                    <span class="status-badge ${sevBadgeClass}">${rule.default_severity}</span>
                    <span class="rule-card-name">${escapeHtml(rule.name)}</span>
                </div>
                <p class="rule-card-desc">${escapeHtml(rule.description)}</p>
            </div>
            <label class="switch">
                <input type="checkbox" data-rule-id="${rule.id}" ${isChecked ? "checked" : ""}>
                <span class="slider"></span>
            </label>
        `;

        const checkbox = item.querySelector("input[type='checkbox']");
        checkbox.addEventListener("change", (e) => {
            if (e.target.checked) {
                state.enabledRules.add(rule.id);
            } else {
                state.enabledRules.delete(rule.id);
            }
            updateActiveCountBadge();
        });

        rulesListContainer.appendChild(item);
    });
}

function applyPreset(presetName) {
    state.enabledRules.clear();
    if (presetName === "all") {
        state.allRules.forEach(r => state.enabledRules.add(r.id));
    } else if (presetName === "security") {
        state.allRules.forEach(r => {
            if (["vibe_hardcoded_secrets", "vibe_security_holes", "vibe_dep_vulnerabilities"].includes(r.id)) {
                state.enabledRules.add(r.id);
            }
        });
    } else if (presetName === "hygiene") {
        state.allRules.forEach(r => {
            if (["vibe_lazy_errors", "vibe_architecture_bloat", "vibe_ghost_deps"].includes(r.id)) {
                state.enabledRules.add(r.id);
            }
        });
    } else if (presetName === "prod") {
        state.allRules.forEach(r => state.enabledRules.add(r.id));
    }

    updateActiveCountBadge();
    renderRulesModal();
}

function setupEventListeners() {
    // Modal open / close
    btnOpenConfig.addEventListener("click", () => testsModal.classList.remove("hidden"));
    btnCloseModal.addEventListener("click", () => testsModal.classList.add("hidden"));
    btnSaveTests.addEventListener("click", () => testsModal.classList.add("hidden"));

    // Close modal on click outside
    testsModal.addEventListener("click", (e) => {
        if (e.target === testsModal) testsModal.classList.add("hidden");
    });

    // Presets
    document.querySelectorAll(".preset-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            applyPreset(btn.dataset.preset);
        });
    });

    // Sample select changed
    sampleSelect.addEventListener("change", (e) => {
        if (e.target.value) {
            targetPathInput.value = e.target.value;
            triggerAudit(e.target.value);
        }
    });

    // Hero buttons
    const btnHeroChaos = document.getElementById("btn-hero-demo-chaos");
    if (btnHeroChaos) {
        btnHeroChaos.addEventListener("click", () => {
            const chaosSample = state.samples.find(s => s.id === "chaos_saas");
            if (chaosSample) {
                targetPathInput.value = chaosSample.path;
                sampleSelect.value = chaosSample.path;
                triggerAudit(chaosSample.path);
            }
        });
    }

    const btnHeroClean = document.getElementById("btn-hero-demo-clean");
    if (btnHeroClean) {
        btnHeroClean.addEventListener("click", () => {
            const cleanSample = state.samples.find(s => s.id === "hardened_app");
            if (cleanSample) {
                targetPathInput.value = cleanSample.path;
                sampleSelect.value = cleanSample.path;
                triggerAudit(cleanSample.path);
            }
        });
    }

    // Run audit button
    btnRunAudit.addEventListener("click", () => {
        const path = targetPathInput.value.trim();
        if (!path) {
            alert("Veuillez renseigner un chemin de dossier ou sélectionner un échantillon.");
            return;
        }
        triggerAudit(path);
    });

    // Target input enter key
    targetPathInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            const path = targetPathInput.value.trim();
            if (path) triggerAudit(path);
        }
    });

    // Severity filters in findings list
    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            state.activeSeverityFilter = btn.dataset.severity;
            renderFindingsList();
        });
    });

    // Export buttons
    document.getElementById("btn-export-markdown").addEventListener("click", exportMarkdown);
    document.getElementById("btn-export-json").addEventListener("click", exportJson);

    // Initialize Dynamic Network Audit handlers
    setupDynamicAudit();
}

async function triggerAudit(targetPath) {
    if (state.enabledRules.size === 0) {
        alert("Veuillez sélectionner au moins un test dans la configuration.");
        testsModal.classList.remove("hidden");
        return;
    }

    // UI Loading state
    heroWelcome.classList.add("hidden");
    resultsDashboard.classList.add("hidden");
    loadingState.classList.remove("hidden");
    btnRunAudit.disabled = true;

    // Cycle animated steps
    const steps = [
        "Parcours des fichiers sources du projet...",
        "Inspection de l'AST et détection des 'except: pass'...",
        "Vérification des tokens OpenAI, Google et AWS...",
        "Analyse de cohérence des dépendances package.json / requirements...",
        "Calcul du Vibe Score et synthèse des correctifs..."
    ];
    let stepIdx = 0;
    const stepInterval = setInterval(() => {
        stepIdx = (stepIdx + 1) % steps.length;
        loadingStepText.textContent = steps[stepIdx];
    }, 450);

    try {
        const res = await fetch("/api/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target_path: targetPath,
                enabled_rules: Array.from(state.enabledRules)
            })
        });

        clearInterval(stepInterval);
        const report = await res.json();

        if (report.error) {
            alert("Erreur lors de l'audit : " + report.error);
            loadingState.classList.add("hidden");
            heroWelcome.classList.remove("hidden");
            btnRunAudit.disabled = false;
            return;
        }

        state.currentReport = report;
        renderDashboard(report);
    } catch (e) {
        clearInterval(stepInterval);
        alert("Erreur de communication avec le serveur : " + e.message);
        loadingState.classList.add("hidden");
        heroWelcome.classList.remove("hidden");
    } finally {
        btnRunAudit.disabled = false;
    }
}

function renderDashboard(report) {
    loadingState.classList.add("hidden");
    resultsDashboard.classList.remove("hidden");

    const score = report.score;
    const stats = report.stats;

    // 1. Animate Gauge & Score
    animateScoreNumber(score.vibe_score);
    updateGaugeSvg(score.vibe_score, score.badge_color);

    badgeLevel.textContent = `${score.badge_icon} ${score.badge_label}`;
    badgeLevel.className = `status-badge badge-${score.badge_color === 'emerald' ? 'success' : score.badge_color === 'cyan' ? 'cyan' : score.badge_color === 'amber' ? 'warning' : 'danger'}`;
    vibeVerdict.textContent = score.verdict;

    // 2. Stats
    statFiles.textContent = stats.total_files;
    statLines.textContent = stats.total_lines.toLocaleString();
    statCritical.textContent = stats.severity_counts.CRITICAL || 0;
    statHigh.textContent = (stats.severity_counts.HIGH || 0) + (stats.severity_counts.MEDIUM || 0);

    // 3. Category Breakdown Bars
    renderCategoryBars(score.category_scores);

    // 4. Tech Stack & Languages Detection
    renderTechStack(report.tech_stack);

    // 5. Action Plan Checklist
    renderActionPlan(report.action_plan);

    // 6. Findings
    renderFindingsList();

    // Smooth scroll to dashboard
    resultsDashboard.scrollIntoView({ behavior: "smooth", block: "start" });
}

function animateScoreNumber(finalScore) {
    let current = 0;
    const duration = 1000;
    const startTime = performance.now();

    function step(now) {
        const progress = Math.min((now - startTime) / duration, 1);
        current = Math.floor(progress * finalScore);
        vibeScoreNum.textContent = current;
        if (progress < 1) {
            requestAnimationFrame(step);
        } else {
            vibeScoreNum.textContent = finalScore;
        }
    }
    requestAnimationFrame(step);
}

function updateGaugeSvg(scoreValue, colorKey) {
    // Total circumference = 2 * PI * 58 ≈ 364.4
    const circumference = 364.4;
    const offset = circumference - (scoreValue / 100) * circumference;
    gaugeCircleFill.style.strokeDashoffset = offset;

    const colors = {
        emerald: "#10b981",
        cyan: "#06b6d4",
        amber: "#f59e0b",
        rose: "#f43f5e"
    };
    gaugeCircleFill.style.stroke = colors[colorKey] || "#6366f1";
}

function renderCategoryBars(catScores) {
    categoryBarsList.innerHTML = "";
    const categoryLabels = {
        SECRETS: "🔑 Clés & Secrets",
        GHOST_DEPS: "👻 Dépendances Fantômes",
        LAZY_ERRORS: "🙈 Erreurs Paresseuses",
        ARCHITECTURE: "🏛️ Architecture & Bloat",
        SECURITY: "🛡️ Sécurité & Injections",
        TESTS_DOCS: "🧪 Tests & Documentation",
        DEPENDENCY_VULNS: "📦 Failles de Dépendances (CVE)"
    };

    for (const [cat, val] of Object.entries(catScores)) {
        const item = document.createElement("div");
        item.className = "category-bar-item";

        let color = "#10b981";
        if (val < 50) color = "#f43f5e";
        else if (val < 75) color = "#f59e0b";
        else if (val < 90) color = "#06b6d4";

        item.innerHTML = `
            <div class="cat-label-row">
                <span class="cat-name">${categoryLabels[cat] || cat}</span>
                <span class="cat-score" style="color: ${color}">${val}%</span>
            </div>
            <div class="progress-track">
                <div class="progress-fill" style="width: ${val}%; background-color: ${color}"></div>
            </div>
        `;
        categoryBarsList.appendChild(item);
    }
}

function renderTechStack(techStack) {
    const card = document.getElementById("tech-stack-card");
    if (!card) return;

    if (!techStack || (!techStack.languages?.length && !techStack.frameworks?.length)) {
        card.classList.add("hidden");
        return;
    }
    card.classList.remove("hidden");

    // 1. Primary language & total code lines badge
    const primaryBadge = document.getElementById("primary-lang-badge");
    const totalLinesBadge = document.getElementById("total-code-lines-badge");
    if (primaryBadge) {
        primaryBadge.textContent = `Langage principal : ${techStack.primary_language || "Inconnu"}`;
    }
    if (totalLinesBadge) {
        totalLinesBadge.textContent = `${(techStack.total_code_lines || 0).toLocaleString()} lignes de code`;
    }

    // 2. Language distribution bar & legend
    const progressBar = document.getElementById("lang-progress-bar");
    const legendList = document.getElementById("lang-legend-list");
    if (progressBar && legendList) {
        progressBar.innerHTML = "";
        legendList.innerHTML = "";

        (techStack.languages || []).forEach(lang => {
            // Segment
            const seg = document.createElement("div");
            seg.className = "lang-progress-segment";
            seg.style.width = `${lang.percentage}%`;
            seg.style.backgroundColor = lang.color;
            seg.title = `${lang.name} : ${lang.percentage}% (${lang.lines} lignes, ${lang.files} fichier${lang.files > 1 ? 's' : ''})`;
            progressBar.appendChild(seg);

            // Legend item
            const item = document.createElement("div");
            item.className = "lang-legend-item";
            item.innerHTML = `
                <span class="lang-dot" style="background-color: ${lang.color}"></span>
                <span class="lang-name">${escapeHtml(lang.name)}</span>
                <span class="lang-pct">${lang.percentage}%</span>
            `;
            legendList.appendChild(item);
        });
    }

    // 3. Frameworks, Tools, and Package Managers
    const frameworksContainer = document.getElementById("frameworks-container");
    if (frameworksContainer) {
        frameworksContainer.innerHTML = "";

        // Group frameworks by category
        const byCategory = {};
        (techStack.frameworks || []).forEach(fw => {
            if (!byCategory[fw.category]) byCategory[fw.category] = [];
            byCategory[fw.category].push(fw);
        });

        // Add package managers as a category if any
        if (techStack.package_managers?.length) {
            byCategory["Gestionnaires de Paquets"] = techStack.package_managers.map(pm => ({
                name: pm,
                icon: "📦",
                detected_via: "manifeste"
            }));
        }

        // Add tools / env as a category if any
        if (techStack.tools?.length) {
            byCategory["Outils & Configuration"] = techStack.tools.map(t => ({
                name: t,
                icon: "⚙️",
                detected_via: "structure"
            }));
        }

        const categories = Object.keys(byCategory);
        if (categories.length === 0) {
            frameworksContainer.innerHTML = `<p class="empty-hint" style="color: var(--text-muted); font-size: 0.85rem;">Aucun framework spécifique détecté (code script pur ou standard).</p>`;
        } else {
            categories.forEach(catName => {
                const items = byCategory[catName];
                const row = document.createElement("div");
                row.className = "fw-category-row";

                const tag = document.createElement("span");
                tag.className = "fw-category-tag";
                tag.textContent = catName;
                row.appendChild(tag);

                const pillsList = document.createElement("div");
                pillsList.className = "fw-pills-list";

                items.forEach(item => {
                    const pill = document.createElement("div");
                    const isTool = catName.includes("Configuration") || catName.includes("Gestionnaires");
                    pill.className = `fw-pill ${isTool ? "tool-pill" : ""}`;
                    pill.innerHTML = `
                        <span class="fw-icon">${item.icon}</span>
                        <span class="fw-name">${escapeHtml(item.name)}</span>
                        ${item.detected_via ? `<span class="fw-via">(${escapeHtml(item.detected_via)})</span>` : ""}
                    `;
                    pillsList.appendChild(pill);
                });

                row.appendChild(pillsList);
                frameworksContainer.appendChild(row);
            });
        }
    }
}

function renderActionPlan(actions) {
    actionPlanItems.innerHTML = "";
    if (!actions || actions.length === 0) {
        actionPlanItems.innerHTML = `
            <div style="grid-column: 1/-1; text-align: center; color: var(--emerald); padding: 20px;">
                ✨ Félicitations ! Aucune action critique n'a été détectée. Votre projet passe les tests avec brio.
            </div>
        `;
        return;
    }

    actions.forEach(act => {
        const item = document.createElement("div");
        item.className = "action-item-card";
        item.innerHTML = `
            <div class="action-step-num">${act.step}</div>
            <div class="action-content">
                <div class="action-title">${escapeHtml(act.title)}</div>
                <div class="action-loc">${escapeHtml(act.file)}${act.line ? `:${act.line}` : ''}</div>
                <div class="action-recommendation">💡 <strong>Action :</strong> ${escapeHtml(act.action)}</div>
            </div>
        `;
        actionPlanItems.appendChild(item);
    });
}

function renderFindingsList() {
    findingsContainer.innerHTML = "";
    if (!state.currentReport) return;

    let allFindings = [];
    state.currentReport.rule_results.forEach(r => {
        allFindings.push(...r.findings);
    });

    // Filter by severity if selected
    if (state.activeSeverityFilter !== "ALL") {
        allFindings = allFindings.filter(f => f.severity === state.activeSeverityFilter);
    }

    findingsTotalCount.textContent = allFindings.length;

    if (allFindings.length === 0) {
        findingsContainer.innerHTML = `
            <div style="text-align: center; color: var(--text-muted); padding: 30px;">
                Aucune anomalie pour ce filtre de sévérité.
            </div>
        `;
        return;
    }

    allFindings.forEach(f => {
        const card = document.createElement("div");
        card.className = `finding-card sev-${f.severity}`;

        let sevBadgeClass = "badge-danger";
        if (f.severity === "HIGH") sevBadgeClass = "badge-warning";
        else if (f.severity === "MEDIUM") sevBadgeClass = "badge-cyan";
        else if (f.severity === "LOW" || f.severity === "INFO") sevBadgeClass = "badge-success";

        card.innerHTML = `
            <div class="finding-top-row">
                <div class="finding-badges">
                    <span class="status-badge ${sevBadgeClass}">${f.severity}</span>
                    <span style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(f.rule_name)}</span>
                </div>
                <span class="finding-file">${escapeHtml(f.file_path)}${f.line_number ? `:${f.line_number}` : ''}</span>
            </div>
            <div class="finding-message">${escapeHtml(f.message)}</div>
            ${f.code_snippet ? `<pre class="code-snippet-box"><code>${escapeHtml(f.code_snippet)}</code></pre>` : ''}
            <div class="ai-diagnosis-box">
                <div class="diagnosis-col diagnosis-why">
                    <h5>🤖 Pourquoi l'IA a fait cela</h5>
                    <p>${escapeHtml(f.ai_rationale || "Raccourci typique lors de la complétion par modèle de langage.")}</p>
                </div>
                <div class="diagnosis-col diagnosis-fix">
                    <h5>💡 Comment corriger</h5>
                    <p>${escapeHtml(f.fix_recommendation || "Appliquer les bonnes pratiques d'ingénierie logicielle.")}</p>
                </div>
            </div>
        `;
        findingsContainer.appendChild(card);
    });
}

async function exportMarkdown() {
    if (!state.currentReport) return;
    try {
        const res = await fetch("/api/export", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ report: state.currentReport })
        });
        const data = await res.json();
        if (data.markdown) {
            await navigator.clipboard.writeText(data.markdown);
            alert("Rapport Markdown copié dans le presse-papier !");
        }
    } catch (e) {
        alert("Erreur lors de l'export Markdown : " + e.message);
    }
}

function exportJson() {
    if (!state.currentReport) return;
    const blob = new Blob([JSON.stringify(state.currentReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vibe-audit-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

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

