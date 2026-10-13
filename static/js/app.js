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

