console.log("Phishing Tool JavaScript Loaded!");


const form = document.getElementById("analyzeForm");

const urlInput = document.getElementById("urlInput");

const loading = document.getElementById("loading");

const result = document.getElementById("result");

const error = document.getElementById("error");

const errorMessage = document.getElementById("errorMessage");


const riskScore = document.getElementById("riskScore");

const riskLevel = document.getElementById("riskLevel");

const riskBar = document.getElementById("riskBar");

const riskSummary = document.getElementById("riskSummary");

const riskCircle = document.querySelector(
    ".risk-score-circle"
);


const hostname = document.getElementById(
    "hostname"
);

const registeredDomain = document.getElementById(
    "registeredDomain"
);

const subdomain = document.getElementById(
    "subdomain"
);

const protocol = document.getElementById(
    "protocol"
);

const subdomainLevels = document.getElementById(
    "subdomainLevels"
);

const tld = document.getElementById(
    "tld"
);

const queryParameterCount = document.getElementById(
    "queryParameterCount"
);


const reasonsList = document.getElementById(
    "reasonsList"
);


form.addEventListener(
    "submit",
    async function (event) {

        event.preventDefault();


        // ---------------------------
        // Get URL
        // ---------------------------

        const url = urlInput.value.trim();

        if (!url) {
            return;
        }


        // ---------------------------
        // Reset previous state
        // ---------------------------

        result.classList.add("hidden");

        error.classList.add("hidden");

        loading.classList.remove("hidden");


        try {

            // ---------------------------
            // Send request
            // ---------------------------

            const response = await fetch(
                "/analyze",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );


            if (!response.ok) {

                throw new Error(
                    "Server returned an error."
                );

            }


            const data = await response.json();


            console.log(
                "API response:",
                data
            );


            // ---------------------------
            // Hide loading
            // ---------------------------

            loading.classList.add("hidden");


            // ---------------------------
            // Risk Score
            // ---------------------------

            const score = Math.max(
                0,
                Math.min(
                    100,
                    Number(
                        data.risk_score
                    ) || 0
                )
            );


            riskScore.textContent = score;


            // ---------------------------
            // Risk Circle Colors
            // ---------------------------

            riskCircle.classList.remove(
                "risk-safe",
                "risk-suspicious",
                "risk-high"
            );


            riskBar.classList.remove(
                "bar-safe",
                "bar-suspicious",
                "bar-high"
            );


            riskLevel.classList.remove(
                "badge-safe",
                "badge-suspicious",
                "badge-high"
            );


            // ---------------------------
            // Dynamic Risk Summary
            // ---------------------------

            if (score < 20) {

                riskCircle.classList.add(
                    "risk-safe"
                );

                riskBar.classList.add(
                    "bar-safe"
                );

                riskLevel.classList.add(
                    "badge-safe"
                );

                riskSummary.textContent =
                    "This URL shows only a few or no suspicious indicators.";

            }

            else if (score < 50) {

                riskCircle.classList.add(
                    "risk-suspicious"
                );

                riskBar.classList.add(
                    "bar-suspicious"
                );

                riskLevel.classList.add(
                    "badge-suspicious"
                );

                riskSummary.textContent =
                    "This URL contains suspicious indicators. Review it carefully before entering sensitive information.";

            }

            else {

                riskCircle.classList.add(
                    "risk-high"
                );

                riskBar.classList.add(
                    "bar-high"
                );

                riskLevel.classList.add(
                    "badge-high"
                );

                riskSummary.textContent =
                    "This URL contains multiple high-risk phishing indicators. Avoid entering sensitive information.";

            }


            // ---------------------------
            // Risk Level
            // ---------------------------

            riskLevel.textContent =
                data.risk_level ||
                "Unknown";


            // ---------------------------
            // Risk Bar
            // ---------------------------

            riskBar.style.width =
                score + "%";


            // ---------------------------
            // URL Information
            // ---------------------------

            hostname.textContent =
                data.hostname ||
                "-";


            registeredDomain.textContent =
                data.registered_domain ||
                "-";


            subdomain.textContent =
                data.subdomain ||
                "(none)";


            protocol.textContent =
                data.protocol
                    ? data.protocol.toUpperCase()
                    : "-";


            subdomainLevels.textContent =
                data.subdomain_levels ?? 0;


            tld.textContent =
                data.suffix ||
                "-";


            queryParameterCount.textContent =
                data.query_parameter_count ?? 0;


            // ---------------------------
            // Clear old indicators
            // ---------------------------

            reasonsList.innerHTML = "";


            // ---------------------------
            // No indicators
            // ---------------------------

            if (
                !data.indicators ||
                data.indicators.length === 0
            ) {

                const li =
                    document.createElement("li");

                li.textContent =
                    "No suspicious indicators were detected.";

                reasonsList.appendChild(li);

            }


            // ---------------------------
            // Display indicators
            // ---------------------------

            else {

                data.indicators.forEach(
                    function (indicator) {

                        const li =
                            document.createElement("li");


                        li.classList.add(
                            "indicator-item"
                        );


                        // Severity badge

                        const badge =
                            document.createElement("span");


                        badge.classList.add(
                            "severity-badge"
                        );


                        const severity =
                            indicator.severity ||
                            "Low";


                        badge.textContent =
                            severity.toUpperCase();


                        if (
                            severity === "High"
                        ) {

                            badge.classList.add(
                                "severity-high"
                            );

                        }

                        else if (
                            severity === "Medium"
                        ) {

                            badge.classList.add(
                                "severity-medium"
                            );

                        }

                        else {

                            badge.classList.add(
                                "severity-low"
                            );

                        }


                        // Indicator reason

                        const reason =
                            document.createElement("span");


                        reason.classList.add(
                            "indicator-reason"
                        );


                        reason.textContent =
                            indicator.reason;


                        // Add elements

                        li.appendChild(
                            badge
                        );


                        li.appendChild(
                            reason
                        );


                        reasonsList.appendChild(
                            li
                        );

                    }
                );

            }


            // ---------------------------
            // Show result
            // ---------------------------

            result.classList.remove(
                "hidden"
            );


        }


        // ---------------------------
        // Error handling
        // ---------------------------

        catch (err) {

            console.error(
                "Analysis error:",
                err
            );


            loading.classList.add(
                "hidden"
            );


            let message =
                "Unable to analyze the URL. Please try again.";

            try {
                const errorData = await response.json();
                if (errorData.detail) {
                    message = errorData.detail;
                }
            } catch (parseError) {
                console.warn("Could not parse server error:", parseError);
            }

            errorMessage.textContent = message;


            error.classList.remove(
                "hidden"
            );

        }

    }
);

const emailForm = document.getElementById("emailForm");
const emailStatus = document.getElementById("emailStatus");

if (emailForm) {

    emailForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();

            emailStatus.classList.add("hidden");

            const recipient =
                document
                    .getElementById("recipientInput")
                    .value
                    .trim();

            const subject =
                document
                    .getElementById("subjectInput")
                    .value
                    .trim();

            const body =
                document
                    .getElementById("bodyInput")
                    .value
                    .trim();

            try {

                const response = await fetch(
                    "/send-awareness-email",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            recipient: recipient,
                            subject: subject,
                            body: body
                        })
                    }
                );

                const data =
                    await response.json();

                emailStatus.textContent =
                    data.message;

                emailStatus.classList.remove(
                    "hidden"
                );

                if (!data.success) {
                    emailStatus.classList.add(
                        "email-error"
                    );
                }

            } catch (error) {

                console.error(
                    "Email error:",
                    error
                );

                emailStatus.textContent =
                    "Unable to send the email.";

                emailStatus.classList.remove(
                    "hidden"
                );

                emailStatus.classList.add(
                    "email-error"
                );
            }
        }
    );
}

