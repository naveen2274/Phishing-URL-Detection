
const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");

const loading = document.getElementById("loading");
const resultBox = document.getElementById("resultBox");


// --------------------------------------------------
// INITIAL DASHBOARD LOAD
// --------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
    loadDashboard();
    loadHistory();
});


// --------------------------------------------------
// SCAN FORM
// --------------------------------------------------

scanForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) return;

    resultBox.classList.add("hidden");
    loading.classList.remove("hidden");
    scanButton.disabled = true;

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to scan URL.");
        }

        showResult(data);

        // Refresh dashboard after every successful scan.
        await Promise.all([
            loadDashboard(),
            loadHistory()
        ]);

    } catch (error) {
        resultBox.className = "result-box error";

        document.getElementById("resultTitle").textContent =
            "Scanner unavailable";

        document.getElementById("resultMessage").textContent =
            error.message;

        document.getElementById("confidence").textContent = "";

    } finally {
        loading.classList.add("hidden");
        resultBox.classList.remove("hidden");
        scanButton.disabled = false;
    }
});


// --------------------------------------------------
// DISPLAY SCAN RESULT
// --------------------------------------------------

function showResult(data) {
    const isPhishing = data.prediction === "Phishing";

    resultBox.className = isPhishing
        ? "result-box phishing"
        : "result-box legitimate";

    document.getElementById("resultTitle").textContent =
        isPhishing
            ? "⚠ Phishing Website Detected"
            : "✓ Legitimate Website";

    document.getElementById("resultMessage").textContent =
        data.message || "URL analysis completed.";

    document.getElementById("confidence").textContent =
        "Model confidence: " +
        Number(data.confidence).toFixed(2) + "%";
}


// --------------------------------------------------
// LOAD DASHBOARD STATISTICS
// --------------------------------------------------

async function loadDashboard() {
    try {
        const response = await fetch("/api/dashboard");
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Dashboard loading failed.");
        }

        const stats = data.stats;

        document.getElementById("totalScans").textContent =
            stats.total_scans;

        document.getElementById("phishingCount").textContent =
            stats.phishing_count;

        document.getElementById("legitimateCount").textContent =
            stats.legitimate_count;

        document.getElementById("detectionRate").textContent =
            Number(stats.detection_rate).toFixed(2) + "%";

        renderAnalytics(data.analytics);

    } catch (error) {
        console.error("Dashboard error:", error);
    }
}


// --------------------------------------------------
// LOAD SCAN HISTORY
// --------------------------------------------------

async function loadHistory() {
    try {
        const response = await fetch("/api/history");
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "History loading failed.");
        }

        renderHistory(data.history);

    } catch (error) {
        console.error("History error:", error);
    }
}


// --------------------------------------------------
// DISPLAY HISTORY TABLE
// --------------------------------------------------

function renderHistory(history) {
    const historyBody = document.getElementById("historyBody");

    historyBody.replaceChildren();

    if (!history || history.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 4;
        cell.className = "empty-state";
        cell.textContent = "No scan history available yet.";

        row.appendChild(cell);
        historyBody.appendChild(row);
        return;
    }

    history.forEach(scan => {
        const row = document.createElement("tr");

        const urlCell = document.createElement("td");
        urlCell.textContent = scan.url;
        urlCell.title = scan.url;

        const resultCell = document.createElement("td");
        resultCell.textContent = scan.prediction;

        const confidenceCell = document.createElement("td");
        confidenceCell.textContent =
            Number(scan.confidence).toFixed(2) + "%";

        const dateCell = document.createElement("td");

        const date = new Date(scan.scanned_at);

        dateCell.textContent = isNaN(date.getTime())
            ? scan.scanned_at
            : date.toLocaleString();

        resultCell.style.fontWeight = "600";

        resultCell.style.color =
            scan.prediction === "Phishing"
                ? "#ef4444"
                : "#22c55e";

        row.append(
            urlCell,
            resultCell,
            confidenceCell,
            dateCell
        );

        historyBody.appendChild(row);
    });
}


// --------------------------------------------------
// DISPLAY ANALYTICS
// --------------------------------------------------

function renderAnalytics(analytics) {
    const analyticsCard =
        document.querySelector(".analytics-card");

    if (!analyticsCard) return;

    analyticsCard.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = "Daily Scan Analytics";
    heading.style.marginBottom = "20px";

    analyticsCard.appendChild(heading);

    if (!analytics || analytics.length === 0) {
        const message = document.createElement("p");
        message.textContent = "No analytics data available yet.";
        analyticsCard.appendChild(message);
        return;
    }

    const maxScans = Math.max(
        1,
        ...analytics.map(day => Number(day.total))
    );

    analytics.forEach(day => {
        const wrapper = document.createElement("div");
        wrapper.style.marginBottom = "20px";

        const dateLabel = document.createElement("div");
        dateLabel.style.display = "flex";
        dateLabel.style.justifyContent = "space-between";
        dateLabel.style.marginBottom = "7px";
        dateLabel.style.fontSize = "13px";

        const date = new Date(day.date + "T00:00:00");

        const dateText = document.createElement("span");
        dateText.textContent = date.toLocaleDateString(
            undefined,
            { day: "numeric", month: "short" }
        );

        const countText = document.createElement("strong");
        countText.textContent = `${day.total} scans`;

        dateLabel.append(dateText, countText);

        const track = document.createElement("div");
        track.style.display = "flex";
        track.style.width = "100%";
        track.style.height = "13px";
        track.style.background = "#e5e7eb";
        track.style.borderRadius = "20px";
        track.style.overflow = "hidden";

        const phishingBar = document.createElement("div");
        phishingBar.style.width =
            (Number(day.phishing) / maxScans * 100) + "%";
        phishingBar.style.background = "#ef4444";

        const legitimateBar = document.createElement("div");
        legitimateBar.style.width =
            (Number(day.legitimate) / maxScans * 100) + "%";
        legitimateBar.style.background = "#22c55e";

        track.append(phishingBar, legitimateBar);

        wrapper.append(dateLabel, track);
        analyticsCard.appendChild(wrapper);
    });

    // Chart legend
    const legend = document.createElement("div");
    legend.style.display = "flex";
    legend.style.gap = "20px";
    legend.style.flexWrap = "wrap";
    legend.style.marginTop = "18px";
    legend.style.fontSize = "13px";

    const phishingLegend = document.createElement("span");
    phishingLegend.textContent = "🔴 Phishing";

    const legitimateLegend = document.createElement("span");
    legitimateLegend.textContent = "🟢 Legitimate";

    legend.append(phishingLegend, legitimateLegend);
    analyticsCard.appendChild(legend);
}
