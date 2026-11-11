
const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");

const loading = document.getElementById("loading");
const resultBox = document.getElementById("resultBox");

scanForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        return;
    }

    resultBox.classList.add("hidden");
    loading.classList.remove("hidden");
    scanButton.disabled = true;

    try {

        // Flask API will be implemented in the next stage.
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to scan URL.");
        }

        showResult(data);

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
        "Model confidence: " + Number(data.confidence).toFixed(2) + "%";

}
