const API_BASE = "/api";


const form =
    document.getElementById("analyze-form");

const urlInput =
    document.getElementById("url-input");

const analyzeButton =
    document.getElementById("analyze-button");

const loading =
    document.getElementById("loading");

const resultSection =
    document.getElementById("result-section");

const errorMessage =
    document.getElementById("error-message");

const historyList =
    document.getElementById("history-list");


let currentScanId = null;


/* =========================
   Helpers
========================= */


function showLoading(show) {

    loading.classList.toggle(
        "hidden",
        !show,
    );


    if (show) {

        resultSection.classList.add(
            "hidden",
        );

        analyzeButton.disabled = true;

        analyzeButton.textContent =
            "Analyzing...";

    } else {

        analyzeButton.disabled = false;

        analyzeButton.textContent =
            "Analyze URL";
    }
}


function showError(message) {

    errorMessage.textContent =
        message || "Something went wrong.";
}


function clearError() {

    errorMessage.textContent = "";
}


function formatProbability(value) {

    const probability =
        Number(value);

    if (
        !Number.isFinite(probability)
    ) {
        return "0.00%";
    }

    return `${(
        probability * 100
    ).toFixed(2)}%`;
}


function normalizeSeverity(value) {

    return String(
        value || "Low",
    ).toLowerCase();
}


function getRiskClass(score) {

    if (score < 20) {
        return "risk-safe";
    }

    if (score < 50) {
        return "risk-suspicious";
    }

    return "risk-high";
}


function getRiskSummary(score) {

    if (score < 20) {

        return (
            "This URL shows few or no "
            + "suspicious indicators."
        );
    }


    if (score < 50) {

        return (
            "This URL contains suspicious "
            + "indicators. Review it carefully "
            + "before entering sensitive "
            + "information."
        );
    }


    return (
        "This URL contains multiple "
        + "high-risk phishing indicators. "
        + "Avoid entering sensitive "
        + "information."
    );
}


/* =========================
   Risk Theme
========================= */


function setRiskTheme(score) {

    const card =
        document.getElementById(
            "risk-card",
        );

    const riskLevel =
        document.getElementById(
            "risk-level",
        );


    card.classList.remove(
        "risk-safe",
        "risk-suspicious",
        "risk-high",
    );


    const riskClass =
        getRiskClass(score);


    card.classList.add(
        riskClass,
    );


    if (score < 20) {

        riskLevel.style.color =
            "var(--success)";

    } else if (score < 50) {

        riskLevel.style.color =
            "var(--warning)";

    } else {

        riskLevel.style.color =
            "var(--danger)";
    }
}


/* =========================
   Reasons
========================= */


function renderReasons(reasons) {

    const container =
        document.getElementById(
            "reasons-list",
        );


    container.innerHTML = "";


    if (
        !Array.isArray(reasons) ||
        reasons.length === 0
    ) {

        const item =
            document.createElement("div");

        item.className =
            "reason-item safe";

        item.textContent =
            "No suspicious indicators were detected.";

        container.appendChild(item);

        return;
    }


    for (const reason of reasons) {

        const item =
            document.createElement("div");

        item.className =
            "reason-item";

        item.textContent =
            reason;

        container.appendChild(item);
    }
}


/* =========================
   Indicators
========================= */


function renderIndicators(indicators) {

    const container =
        document.getElementById(
            "indicators-list",
        );


    container.innerHTML = "";


    if (
        !Array.isArray(indicators) ||
        indicators.length === 0
    ) {

        const item =
            document.createElement("div");

        item.className =
            "reason-item safe";

        item.textContent =
            "No suspicious indicators were detected.";

        container.appendChild(item);

        return;
    }


    for (
        const indicator of indicators
    ) {

        const item =
            document.createElement("div");

        item.className =
            "indicator-item";


        const severity =
            normalizeSeverity(
                indicator.severity,
            );


        const badge =
            document.createElement("span");

        badge.className =
            "severity-badge";


        if (severity === "high") {

            badge.classList.add(
                "severity-high",
            );

        } else if (
            severity === "medium"
        ) {

            badge.classList.add(
                "severity-medium",
            );

        } else {

            badge.classList.add(
                "severity-low",
            );
        }


        badge.textContent =
            severity.toUpperCase();


        const score =
            document.createElement("span");

        score.className =
            "indicator-score";

        score.textContent =
            `${Number(indicator.score) || 0} pts`;


        const reason =
            document.createElement("span");

        reason.className =
            "indicator-reason";

        reason.textContent =
            indicator.reason ||
            "Suspicious indicator detected.";


        item.appendChild(badge);

        item.appendChild(score);

        item.appendChild(reason);


        container.appendChild(item);
    }
}


/* =========================
   Render Analysis
========================= */


function renderResult(data) {

    currentScanId =
        data.id;


    document.getElementById(
        "result-url",
    ).textContent =
        data.url || "—";


    const score =
        Math.max(
            0,
            Math.min(
                100,
                Number(data.risk_score) || 0,
            ),
        );


    document.getElementById(
        "risk-score",
    ).textContent =
        score;


    document.getElementById(
        "risk-level",
    ).textContent =
        data.risk_level || "Unknown";


    document.getElementById(
        "risk-summary",
    ).textContent =
        getRiskSummary(score);


    document.getElementById(
        "ml-prediction",
    ).textContent =
        data.ml_prediction || "Unknown";


    const probability =
        Number(data.ml_probability) || 0;


    document.getElementById(
        "ml-probability",
    ).textContent =
        formatProbability(probability);


    document.getElementById(
        "probability-fill",
    ).style.width =
        `${Math.min(
            Math.max(
                probability * 100,
                0,
            ),
            100,
        )}%`;


    document.getElementById(
        "hostname",
    ).textContent =
        data.hostname || "—";


    document.getElementById(
        "registered-domain",
    ).textContent =
        data.registered_domain || "—";


    document.getElementById(
        "domain",
    ).textContent =
        data.domain || "—";


    document.getElementById(
        "suffix",
    ).textContent =
        data.suffix || "—";


    document.getElementById(
        "protocol",
    ).textContent =
        data.protocol
            ? data.protocol.toUpperCase()
            : "—";


    document.getElementById(
        "subdomain",
    ).textContent =
        data.subdomain || "(none)";


    document.getElementById(
        "subdomain-levels",
    ).textContent =
        data.subdomain_levels ?? 0;


    document.getElementById(
        "path",
    ).textContent =
        data.path || "/";


    document.getElementById(
        "query-count",
    ).textContent =
        data.query_parameter_count ?? 0;


    setRiskTheme(score);


    renderReasons(
        data.reasons,
    );


    renderIndicators(
        data.indicators,
    );


    resultSection.classList.remove(
        "hidden",
    );


    resultSection.scrollIntoView({
        behavior: "smooth",
        block: "start",
    });
}


/* =========================
   Analyze API
========================= */


async function analyzeUrl(url) {

    const response =
        await fetch(
            `${API_BASE}/analyze`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json",
                },

                body: JSON.stringify({
                    url: url,
                }),
            },
        );


    let data = null;


    try {

        data =
            await response.json();

    } catch {

        throw new Error(
            "Server returned an invalid response.",
        );
    }


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "URL analysis failed.",
        );
    }


    return data;
}


/* =========================
   Analyze Form
========================= */


form.addEventListener(
    "submit",
    async (event) => {

        event.preventDefault();


        const url =
            urlInput.value.trim();


        if (!url) {

            showError(
                "Please enter a URL.",
            );

            return;
        }


        clearError();

        showLoading(true);


        try {

            const result =
                await analyzeUrl(url);


            renderResult(result);


            await loadHistory();

        } catch (error) {

            showError(
                error.message ||
                "Unable to analyze the URL.",
            );

        } finally {

            showLoading(false);
        }
    },
);


/* =========================
   New Scan
========================= */


document
    .getElementById("new-scan-button")
    .addEventListener(
        "click",
        () => {

            resultSection.classList.add(
                "hidden",
            );

            clearError();

            urlInput.focus();

            window.scrollTo({
                top: 0,
                behavior: "smooth",
            });
        },
    );


/* =========================
   Report
========================= */


document
    .getElementById("report-button")
    .addEventListener(
        "click",
        () => {

            if (!currentScanId) {
                return;
            }


            window.open(
                `${API_BASE}/report/${currentScanId}`,
                "_blank",
            );
        },
    );


/* =========================
   PDF
========================= */


document
    .getElementById("pdf-button")
    .addEventListener(
        "click",
        () => {

            if (!currentScanId) {
                return;
            }


            window.open(
                `${API_BASE}/report/${currentScanId}/pdf`,
                "_blank",
            );
        },
    );


/* =========================
   History
========================= */


async function loadHistory() {

    try {

        const response =
            await fetch(
                `${API_BASE}/history?limit=20`,
            );


        if (!response.ok) {

            throw new Error(
                "Unable to load history.",
            );
        }


        const scans =
            await response.json();


        renderHistory(scans);

    } catch {

        historyList.innerHTML = `
            <div class="empty-history">
                Unable to load scan history.
            </div>
        `;
    }
}


function renderHistory(scans) {

    if (
        !Array.isArray(scans) ||
        scans.length === 0
    ) {

        historyList.innerHTML = `
            <div class="empty-history">
                No scans yet.
            </div>
        `;

        return;
    }


    historyList.innerHTML = "";


    for (const scan of scans) {

        const item =
            document.createElement("div");

        item.className =
            "history-item";


        const url =
            document.createElement("div");

        url.className =
            "history-url";

        url.textContent =
            scan.url || "—";


        const domain =
            document.createElement("div");

        domain.className =
            "history-domain";

        domain.textContent =
            scan.registered_domain ||
            scan.hostname ||
            "";


        const risk =
            document.createElement("div");

        risk.className =
            "history-risk";

        risk.textContent =
            `${scan.risk_level || "Unknown"} · `
            + `${scan.risk_score ?? 0}/100`;


        const openButton =
            document.createElement("button");

        openButton.type =
            "button";

        openButton.className =
            "history-open";

        openButton.textContent =
            "Open";


        openButton.addEventListener(
            "click",
            () => {
                loadHistoryItem(scan.id);
            },
        );


        item.appendChild(url);

        item.appendChild(domain);

        item.appendChild(risk);

        item.appendChild(openButton);


        historyList.appendChild(item);
    }
}


/* =========================
   Open History Item
========================= */


async function loadHistoryItem(id) {

    try {

        const response =
            await fetch(
                `${API_BASE}/history/${id}`,
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Scan not found.",
            );
        }


        urlInput.value =
            data.url;


        showLoading(true);

        clearError();


        const analysis =
            await analyzeUrl(
                data.url,
            );


        renderResult(
            analysis,
        );

    } catch (error) {

        showError(
            error.message ||
            "Unable to open scan.",
        );

    } finally {

        showLoading(false);
    }
}


/* =========================
   Refresh History
========================= */


document
    .getElementById("refresh-history")
    .addEventListener(
        "click",
        loadHistory,
    );


/* =========================
   Educational Email
========================= */


const emailForm =
    document.getElementById(
        "email-form",
    );


const emailStatus =
    document.getElementById(
        "email-status",
    );


emailForm.addEventListener(
    "submit",
    async (event) => {

        event.preventDefault();


        emailStatus.classList.add(
            "hidden",
        );

        emailStatus.classList.remove(
            "email-error",
        );


        const recipient =
            document
                .getElementById(
                    "recipient-input",
                )
                .value
                .trim();


        const subject =
            document
                .getElementById(
                    "subject-input",
                )
                .value
                .trim();


        const body =
            document
                .getElementById(
                    "body-input",
                )
                .value
                .trim();


        try {

            const response =
                await fetch(
                    `${API_BASE}/email/send-awareness`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json",
                        },

                        body: JSON.stringify({
                            recipient:
                                recipient,

                            subject:
                                subject,

                            body:
                                body,
                        }),
                    },
                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(
                    data.detail ||
                    "Unable to send email.",
                );
            }


            emailStatus.textContent =
                data.message ||
                "Educational email sent successfully.";


            emailStatus.classList.remove(
                "hidden",
            );

        } catch (error) {

            emailStatus.textContent =
                error.message ||
                "Unable to send the email.";


            emailStatus.classList.add(
                "email-error",
            );


            emailStatus.classList.remove(
                "hidden",
            );
        }
    },
);


/* =========================
   Initial Load
========================= */


loadHistory();