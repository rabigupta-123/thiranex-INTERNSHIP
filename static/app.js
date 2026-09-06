const passwordInput = document.getElementById("password");
const toggleBtn = document.getElementById("toggle");
const meterBar = document.getElementById("meterBar");
const labelEl = document.getElementById("label");
const scoreText = document.getElementById("scoreText");
const insights = document.getElementById("insights");
const historyMsg = document.getElementById("historyMsg");

function badgeClass(name) {
    return name.toLowerCase().replace(/\s+/g, "");
}

function meterColor(score) {
    if (score >= 80) return "#2ecc71";
    if (score >= 60) return "#27ae60";
    if (score >= 40) return "#f1c40f";
    if (score >= 20) return "#f39c12";
    return "#e74c3c";
}

async function analyze(showToast = true) {
    const pw = passwordInput.value;
    if (!pw) {
        meterBar.style.width = "0%";
        labelEl.textContent = "Waiting for input...";
        labelEl.className = "badge";
        scoreText.textContent = "";
        insights.innerHTML = "";
        return;
    }
    const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw }),
    }).then(r => r.json());

    meterBar.style.width = res.score + "%";
    meterBar.style.background = meterColor(res.score);

    labelEl.textContent = res.label + " (" + res.score + "/100)";
    labelEl.className = "badge " + badgeClass(res.label);

    scoreText.textContent =
        "Entropy ~" + res.entropy + " bits · Estimated crack time: " + res.crack_time;

    insights.innerHTML = "";
    res.checks.forEach(c => {
        const div = document.createElement("div");
        div.className = "check-item " + (c.passed ? "pass" : "fail");
        div.innerHTML = '<div class="chk-name">' + c.name +
            ' <span>(' + c.score + "/" + c.max + ")</span></div>" +
            '<div class="chk-msg">' + c.message + "</div>";
        insights.appendChild(div);
    });

    const sugg = document.createElement("div");
    res.suggestions.forEach(s => {
        const p = document.createElement("div");
        p.className = "suggestion";
        p.textContent = s;
        sugg.appendChild(p);
    });
    insights.appendChild(sugg);

    historyMsg.textContent = res.reused
        ? "Warning: this password was already used before. Choose a new one."
        : "Stored passwords in history: " + res.history_count + ".";

    // Brute-force resistance table
    const bfEl = document.getElementById("bruteForce");
    const bfTbody = document.querySelector("#bfTable tbody");
    const bfVerdict = document.getElementById("bfVerdict");
    if (res.brute_force && res.brute_force.scenarios) {
        bfTbody.innerHTML = "";
        Object.entries(res.brute_force.scenarios).forEach(([name, time]) => {
            const tr = document.createElement("tr");
            const tdName = document.createElement("td");
            tdName.textContent = name;
            const tdTime = document.createElement("td");
            tdTime.textContent = time;
            tr.appendChild(tdName);
            tr.appendChild(tdTime);
            bfTbody.appendChild(tr);
        });
        bfVerdict.textContent = res.brute_force.recommended
            ? "This password holds up well against brute force (" + res.entropy + " bits entropy)."
            : "Increase length and complexity to improve brute-force resistance.";
        bfVerdict.className = "verdict " + (res.brute_force.recommended ? "strong" : "weak");
        bfEl.hidden = false;
    } else {
        bfEl.hidden = true;
    }
}

async function savePassword() {
    const pw = passwordInput.value;
    if (!pw) return;
    const res = await fetch("/api/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw }),
    }).then(r => r.json());
    historyMsg.textContent = "Saved. Passwords in history: " + res.history_count + ".";
    analyze(false);
}

async function generate() {
    const length = document.getElementById("length").value;
    const res = await fetch("/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ length: parseInt(length, 10) }),
    }).then(r => r.json());
    const generated = document.getElementById("generated");
    generated.textContent = "";
    const randomLabel = document.createElement("strong");
    randomLabel.textContent = "Random: ";
    const randomText = document.createTextNode(res.strong + " ");
    const entropy = document.createElement("span");
    entropy.className = "entropy";
    entropy.textContent = "~" + res.entropy_estimate + " bits";
    const passphraseLabel = document.createElement("strong");
    passphraseLabel.textContent = "Passphrase: ";
    generated.append(randomLabel, randomText, entropy,
        document.createElement("br"), passphraseLabel,
        document.createTextNode(res.passphrase));
}

async function showHashes() {
    const pw = passwordInput.value;
    if (!pw) return;
    const res = await fetch("/api/hash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw }),
    }).then(r => r.json());
    document.getElementById("hashes").textContent =
        "SHA-256 : " + res.sha256 + "\n" +
        "SHA-512 : " + res.sha512 + "\n" +
        "PBKDF2  : " + res.pbkdf2_600k + "\n" +
        "         (" + res.iterations.toLocaleString() + " iterations - slows brute force)\n" +
        "HMAC    : " + res.hmac_sha256;
}

toggleBtn.addEventListener("click", () => {
    const isPw = passwordInput.type === "password";
    passwordInput.type = isPw ? "text" : "password";
    toggleBtn.textContent = isPw ? "\uD83D\uDE11" : "\uD83D\uDC41";
});

passwordInput.addEventListener("input", () => analyze());
document.getElementById("checkBtn").addEventListener("click", () => analyze());
document.getElementById("saveBtn").addEventListener("click", savePassword);
document.getElementById("generateBtn").addEventListener("click", generate);
document.getElementById("hashBtn").addEventListener("click", showHashes);
