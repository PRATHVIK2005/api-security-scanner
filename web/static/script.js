document.addEventListener("DOMContentLoaded", () => {
    // ==========================================
    // 1. SCAN FORM & PROGRESS OVERLAY
    // ==========================================
    const scanForm = document.getElementById("scan-form");
    const scanButton = document.getElementById("scan-button");
    const buttonText = document.getElementById("button-text");
    const loader = document.getElementById("loader");
    const scanOverlay = document.getElementById("scan-overlay");
    const overlayTargetUrl = document.getElementById("overlay-target-url");
    const scanProgressFill = document.getElementById("scan-progress-fill");
    const scanLogFeed = document.getElementById("scan-log-feed");

    const telemetrySteps = [
        "Resolving host target and validating connectivity...",
        "Crawling routes & parsing OpenAPI / Swagger specifications...",
        "Probing endpoints for Broken Object Level Authorization (BOLA)...",
        "Analyzing authentication mechanisms and authorization headers...",
        "Auditing Cross-Origin Resource Sharing (CORS) configurations...",
        "Testing HTTP method tampering (OPTIONS, HEAD, PUT, DELETE)...",
        "Inspecting response bodies for JWT tokens & API key exposure...",
        "Scanning for sensitive data disclosure and stack trace leaks...",
        "Checking security headers (HSTS, CSP, X-Content-Type, Framing)...",
        "Computing OWASP risk weights and generating CVSS security score..."
    ];

    if (scanForm) {
        scanForm.addEventListener("submit", (e) => {
            const urlInput = document.getElementById("input-url");
            if (!urlInput || !urlInput.value.trim()) {
                return;
            }

            if (overlayTargetUrl) {
                overlayTargetUrl.textContent = urlInput.value.trim();
            }

            // Reveal cyber scan overlay
            if (scanOverlay) {
                scanOverlay.classList.remove("hidden");
            }

            if (scanButton) {
                scanButton.disabled = true;
            }
            if (buttonText) {
                buttonText.textContent = "AUDITING SECURITY POSTURE...";
            }
            if (loader) {
                loader.classList.remove("hidden");
            }

            // Simulate progressive scanning telemetry
            let stepIndex = 0;
            let progress = 18;

            const progressInterval = setInterval(() => {
                stepIndex++;
                progress = Math.min(94, progress + Math.floor(Math.random() * 12) + 6);

                if (scanProgressFill) {
                    scanProgressFill.style.width = `${progress}%`;
                }

                if (stepIndex < telemetrySteps.length && scanLogFeed) {
                    // Mark previous active line as done
                    const activeLines = scanLogFeed.querySelectorAll(".log-line.active");
                    activeLines.forEach((line) => {
                        line.classList.remove("active");
                        line.classList.add("done");
                        const prefix = line.querySelector(".log-prefix");
                        if (prefix) prefix.textContent = "✓";
                    });

                    // Add new active step
                    const newLine = document.createElement("p");
                    newLine.className = "log-line active";
                    newLine.innerHTML = `<span class="log-prefix">◈</span> ${telemetrySteps[stepIndex]}`;
                    scanLogFeed.appendChild(newLine);
                    scanLogFeed.scrollTop = scanLogFeed.scrollHeight;
                }
            }, 750);
        });
    }

    // ==========================================
    // 2. BEARER TOKEN VISIBILITY TOGGLE & ACTIVE MODE WARNING
    // ==========================================
    const tokenToggleBtn = document.getElementById("toggle-token-visibility");
    const tokenInput = document.getElementById("input-token");
    if (tokenToggleBtn && tokenInput) {
        tokenToggleBtn.addEventListener("click", () => {
            if (tokenInput.type === "password") {
                tokenInput.type = "text";
                tokenToggleBtn.textContent = "🔒";
                tokenToggleBtn.title = "Hide token";
            } else {
                tokenInput.type = "password";
                tokenToggleBtn.textContent = "👁";
                tokenToggleBtn.title = "Show token";
            }
        });
    }

    const modeSelect = document.getElementById("input-mode");
    const activeWarning = document.getElementById("active-mode-warning");
    if (modeSelect && activeWarning) {
        modeSelect.addEventListener("change", () => {
            if (modeSelect.value === "active") {
                activeWarning.classList.remove("hidden");
            } else {
                activeWarning.classList.add("hidden");
            }
        });
    }

    // ==========================================
    // 3. EXPANDABLE FINDINGS TABLE ROWS
    // ==========================================
    const findingRows = document.querySelectorAll(".finding-row");

    findingRows.forEach((row) => {
        row.addEventListener("click", (e) => {
            // Ignore if clicked directly on copy button
            if (e.target.closest(".copy-endpoint-btn")) {
                return;
            }

            const index = row.dataset.index;
            const detailRow = document.getElementById(`detail-${index}`);
            if (!detailRow) return;

            const isExpanded = row.classList.contains("expanded");

            if (isExpanded) {
                row.classList.remove("expanded");
                detailRow.classList.add("hidden");
                const toggleBtn = row.querySelector(".row-toggle-btn");
                if (toggleBtn) toggleBtn.setAttribute("aria-expanded", "false");
                const inspectBtn = row.querySelector(".inspect-btn");
                if (inspectBtn) inspectBtn.textContent = "View ▾";
            } else {
                row.classList.add("expanded");
                detailRow.classList.remove("hidden");
                const toggleBtn = row.querySelector(".row-toggle-btn");
                if (toggleBtn) toggleBtn.setAttribute("aria-expanded", "true");
                const inspectBtn = row.querySelector(".inspect-btn");
                if (inspectBtn) inspectBtn.textContent = "Hide ▴";
            }
        });
    });

    // ==========================================
    // 4. EXPAND ALL / COLLAPSE ALL
    // ==========================================
    const toggleAllBtn = document.getElementById("toggle-all-details-btn");
    const toggleAllText = document.getElementById("toggle-all-text");

    if (toggleAllBtn) {
        let allExpanded = false;

        toggleAllBtn.addEventListener("click", () => {
            allExpanded = !allExpanded;

            findingRows.forEach((row) => {
                // Only toggle if currently visible under filters
                if (row.style.display !== "none") {
                    const index = row.dataset.index;
                    const detailRow = document.getElementById(`detail-${index}`);
                    const toggleBtn = row.querySelector(".row-toggle-btn");
                    const inspectBtn = row.querySelector(".inspect-btn");

                    if (allExpanded) {
                        row.classList.add("expanded");
                        if (detailRow) detailRow.classList.remove("hidden");
                        if (toggleBtn) toggleBtn.setAttribute("aria-expanded", "true");
                        if (inspectBtn) inspectBtn.textContent = "Hide ▴";
                    } else {
                        row.classList.remove("expanded");
                        if (detailRow) detailRow.classList.add("hidden");
                        if (toggleBtn) toggleBtn.setAttribute("aria-expanded", "false");
                        if (inspectBtn) inspectBtn.textContent = "View ▾";
                    }
                }
            });

            if (toggleAllText) {
                toggleAllText.textContent = allExpanded ? "COLLAPSE ALL" : "EXPAND ALL";
            }
        });
    }

    // ==========================================
    // 5. SEARCH & SEVERITY FILTERING
    // ==========================================
    let currentSeverityFilter = "ALL";
    const searchInput = document.getElementById("findings-search");
    const clearSearchBtn = document.getElementById("clear-search-btn");
    const filterChips = document.querySelectorAll(".filter-chip");
    const severityCards = document.querySelectorAll(".severity-card");
    const visibleCountSpan = document.getElementById("visible-count");
    const noResultsDiv = document.getElementById("no-filter-results");
    const resetFiltersBtn = document.getElementById("reset-filters-btn");
    const activeFilterIndicator = document.getElementById("active-filter-indicator");

    function applyFilters() {
        const query = (searchInput?.value || "").trim().toLowerCase();
        let visibleCount = 0;

        findingRows.forEach((row) => {
            const index = row.dataset.index;
            const detailRow = document.getElementById(`detail-${index}`);
            const rowSeverity = (row.dataset.severity || "").toUpperCase();
            const rowEndpoint = (row.dataset.endpoint || "").toLowerCase();
            const rowTitle = (row.dataset.title || "").toLowerCase();
            const rowOwasp = (row.dataset.owasp || "").toLowerCase();
            const rowMethod = (row.dataset.method || "").toLowerCase();

            // Check severity filter
            const matchesSeverity = currentSeverityFilter === "ALL" || rowSeverity === currentSeverityFilter;

            // Check search query
            const matchesSearch =
                !query ||
                rowEndpoint.includes(query) ||
                rowTitle.includes(query) ||
                rowOwasp.includes(query) ||
                rowMethod.includes(query);

            if (matchesSeverity && matchesSearch) {
                row.style.display = "";
                visibleCount++;
                // If it was previously expanded, keep detail row visible
                if (detailRow) {
                    detailRow.style.display = row.classList.contains("expanded") ? "" : "none";
                }
            } else {
                row.style.display = "none";
                if (detailRow) {
                    detailRow.style.display = "none";
                }
            }
        });

        // Update count indicator
        if (visibleCountSpan) {
            visibleCountSpan.textContent = visibleCount;
        }

        // Show/hide empty state
        if (noResultsDiv) {
            if (visibleCount === 0 && findingRows.length > 0) {
                noResultsDiv.classList.remove("hidden");
            } else {
                noResultsDiv.classList.add("hidden");
            }
        }

        // Toggle clear search button
        if (clearSearchBtn) {
            if (query.length > 0) {
                clearSearchBtn.classList.remove("hidden");
            } else {
                clearSearchBtn.classList.add("hidden");
            }
        }

        // Update active filter text
        if (activeFilterIndicator) {
            if (currentSeverityFilter === "ALL" && !query) {
                activeFilterIndicator.textContent = "Showing All Findings";
            } else if (currentSeverityFilter !== "ALL" && !query) {
                activeFilterIndicator.textContent = `Severity: ${currentSeverityFilter}`;
            } else if (currentSeverityFilter === "ALL" && query) {
                activeFilterIndicator.textContent = `Search: "${query}"`;
            } else {
                activeFilterIndicator.textContent = `${currentSeverityFilter} + "${query}"`;
            }
        }
    }

    // Set Severity Filter helper
    function setSeverityFilter(severity) {
        currentSeverityFilter = severity.toUpperCase();

        // Sync filter chips
        filterChips.forEach((chip) => {
            if (chip.dataset.severity === currentSeverityFilter) {
                chip.classList.add("active");
            } else {
                chip.classList.remove("active");
            }
        });

        // Sync severity cards
        severityCards.forEach((card) => {
            if (card.dataset.filter === currentSeverityFilter) {
                card.classList.add("active");
            } else {
                card.classList.remove("active");
            }
        });

        applyFilters();
    }

    // Filter Chips click
    filterChips.forEach((chip) => {
        chip.addEventListener("click", () => {
            const severity = chip.dataset.severity || "ALL";
            setSeverityFilter(severity);
        });
    });

    // Severity Cards click
    severityCards.forEach((card) => {
        card.addEventListener("click", () => {
            const severity = card.dataset.filter || "ALL";
            if (currentSeverityFilter === severity) {
                // Clicking again resets to ALL
                setSeverityFilter("ALL");
            } else {
                setSeverityFilter(severity);
            }
        });
    });

    // Search input typing
    if (searchInput) {
        searchInput.addEventListener("input", () => {
            applyFilters();
        });
    }

    // Clear search button
    if (clearSearchBtn) {
        clearSearchBtn.addEventListener("click", () => {
            if (searchInput) {
                searchInput.value = "";
                searchInput.focus();
            }
            applyFilters();
        });
    }

    // Reset filters button in empty state
    if (resetFiltersBtn) {
        resetFiltersBtn.addEventListener("click", () => {
            if (searchInput) searchInput.value = "";
            setSeverityFilter("ALL");
        });
    }

    // ==========================================
    // 6. COPY TO CLIPBOARD HELPER & TOAST
    // ==========================================
    const toast = document.getElementById("cyber-toast");
    let toastTimeout = null;

    function showToast(message) {
        if (!toast) return;
        toast.textContent = message;
        toast.classList.remove("hidden");

        if (toastTimeout) clearTimeout(toastTimeout);
        toastTimeout = setTimeout(() => {
            toast.classList.add("hidden");
        }, 2500);
    }

    document.querySelectorAll(".copy-endpoint-btn").forEach((btn) => {
        btn.addEventListener("click", async (e) => {
            e.stopPropagation();
            const textToCopy = btn.dataset.copy;
            if (!textToCopy) return;

            try {
                await navigator.clipboard.writeText(textToCopy);
                showToast(`✓ Copied: ${textToCopy}`);
                btn.textContent = "✓";
                setTimeout(() => {
                    btn.textContent = "📋";
                }, 1500);
            } catch (err) {
                // Fallback
                const tempInput = document.createElement("input");
                tempInput.value = textToCopy;
                document.body.appendChild(tempInput);
                tempInput.select();
                document.execCommand("copy");
                document.body.removeChild(tempInput);
                showToast(`✓ Copied: ${textToCopy}`);
            }
        });
    });
});