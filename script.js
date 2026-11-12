
const input = document.getElementById("threatInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const resultPanel = document.getElementById("resultPanel");

let currentMode = "url";
let latestReport = null;

const STORAGE_KEY = "threatlens-history-v1";

function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
  } catch {
    return [];
  }
}

function saveHistory(history) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(0, 20)));
}

function updateDashboard() {
  const history = getHistory();

  document.getElementById("scanCount").textContent = history.length;
  document.getElementById("threatCount").textContent =
    history.filter(item => item.score >= 60).length;

  const historyList = document.getElementById("historyList");

  if (!history.length) {
    historyList.innerHTML =
      '<p class="empty-state">No scans yet. Run your first analysis above.</p>';
    return;
  }

  historyList.innerHTML = history.map(item => `
    <div class="history-entry">
      <div>
        <strong>${escapeHTML(item.target)}</strong>
        <small>${escapeHTML(item.date)} · ${escapeHTML(item.type)}</small>
      </div>
      <span class="history-risk" style="color:${getRiskColor(item.score)}">
        ${item.score}/100
      </span>
    </div>
  `).join("");
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[character]);
}

function getRiskColor(score) {
  if (score >= 60) return "#ff637c";
  if (score >= 30) return "#f5bd57";
  return "#40d6a0";
}

function analyzeURL(value) {
  const indicators = [];
  let score = 0;

  let parsedURL;

  try {
    parsedURL = new URL(value);
  } catch {
    return {
      score: 0,
      indicators: ["Invalid URL format. Include a complete address such as https://example.com."],
      recommendation: "Check the address and try again.",
      invalid: true
    };
  }

  const hostname = parsedURL.hostname.toLowerCase();
  const fullURL = value.toLowerCase();

  if (parsedURL.protocol !== "https:") {
    score += 15;
    indicators.push("The URL does not use HTTPS encryption.");
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 25;
    indicators.push("The website uses a direct IP address instead of a recognizable domain.");
  }

  if (hostname.includes("xn--")) {
    score += 25;
    indicators.push("The domain contains encoded characters that may disguise its appearance.");
  }

  if (hostname.split(".").length >= 5) {
    score += 10;
    indicators.push("The domain contains an unusually large number of subdomains.");
  }

  if (hostname.includes("@")) {
    score += 20;
    indicators.push("The URL contains an @ symbol in its hostname.");
  }

  const suspiciousWords = [
    "login", "verify", "secure", "account", "update",
    "password", "wallet", "banking", "confirm"
  ];

  const matches = suspiciousWords.filter(word => hostname.includes(word));

  if (matches.length) {
    score += Math.min(matches.length * 8, 24);
    indicators.push("Potentially sensitive account-related wording appears in the domain.");
  }

  if (fullURL.includes("bit.ly") || fullURL.includes("tinyurl") ||
      fullURL.includes("t.co") || fullURL.includes("is.gd")) {
    score += 15;
    indicators.push("A URL-shortening service is being used, hiding the final destination.");
  }

  if (hostname.length > 35) {
    score += 10;
    indicators.push("The domain name is unusually long.");
  }

  if (parsedURL.port && !["80", "443"].includes(parsedURL.port)) {
    score += 10;
    indicators.push("The URL uses a non-standard web port.");
  }

  if (parsedURL.username || parsedURL.password) {
    score += 20;
    indicators.push("The URL contains embedded username or password information.");
  }

  if (!indicators.length) {
    indicators.push("No configured suspicious URL patterns were detected.");
  }

  score = Math.min(score, 100);

  return {
    score,
    indicators,
    recommendation: getRecommendation(score),
    invalid: false
  };
}

function analyzeMessage(value) {
  const indicators = [];
  let score = 0;
  const message = value.toLowerCase();

  const patterns = [
    {
      regex: /\b(urgent|immediately|act now|within 24 hours|final warning)\b/,
      points: 18,
      description: "Urgency or pressure tactics detected."
    },
    {
      regex: /\b(password|ssn|social security|credit card|bank details|pin number)\b/,
      points: 25,
      description: "The message requests or references sensitive personal information."
    },
    {
      regex: /\b(account suspended|account locked|account compromised)\b/,
      points: 20,
      description: "The message uses an account suspension or compromise warning."
    },
    {
      regex: /\b(click here|open this link|verify now|login here)\b/,
      points: 15,
      description: "The message encourages clicking a link or logging in."
    },
    {
      regex: /\b(winner|prize|free money|claim your reward|lottery)\b/,
      points: 18,
      description: "The message uses prize or reward language."
    },
    {
      regex: /\b(gift card|wire transfer|send money|payment required)\b/,
      points: 20,
      description: "The message includes potentially risky payment instructions."
    },
    {
      regex: /\b(otp|one-time password|verification code)\b/,
      points: 20,
      description: "The message references authentication or verification codes."
    }
  ];

  patterns.forEach(pattern => {
    if (pattern.regex.test(message)) {
      score += pattern.points;
      indicators.push(pattern.description);
    }
  });

  const links = value.match(/https?:\/\/[^\s]+/gi) || [];

  if (links.length) {
    indicators.push(`${links.length} web link(s) found. Inspect destinations carefully.`);
    score += Math.min(links.length * 8, 16);
  }

  if (!indicators.length) {
    indicators.push("No configured suspicious message patterns were detected.");
  }

  score = Math.min(score, 100);

  return {
    score,
    indicators,
    recommendation: getRecommendation(score),
    invalid: false
  };
}

function getRecommendation(score) {
  if (score >= 60) {
    return "HIGH RISK: Avoid interacting with this content. Do not share personal information, passwords, or payment details.";
  }

  if (score >= 30) {
    return "MODERATE RISK: Investigate the indicators carefully. Verify the sender or website through an independent trusted channel.";
  }

  return "LOWER RISK: Few configured warning patterns were detected. This is not proof that the content is safe.";
}

function displayResult(target, result) {
  resultPanel.hidden = false;

  const score = result.score;
  const title = score >= 60
    ? "High Risk Detected"
    : score >= 30
      ? "Moderate Risk Detected"
      : "Lower Risk Assessment";

  document.getElementById("resultTitle").textContent =
    result.invalid ? "Input Needs Attention" : title;

  document.getElementById("riskScore").innerHTML =
    `${score}<span>/100</span>`;

  const riskBar = document.getElementById("riskBar");
  riskBar.style.width = score + "%";
  riskBar.style.background = getRiskColor(score);

  document.getElementById("riskDescription").textContent =
    result.invalid
      ? "The submitted URL could not be parsed."
      : `Risk assessment: ${score >= 60 ? "High" : score >= 30 ? "Moderate" : "Lower"} based on configured heuristic indicators.`;

  const indicatorList = document.getElementById("indicatorList");
  indicatorList.replaceChildren();

  result.indicators.forEach(indicator => {
    const li = document.createElement("li");
    li.textContent = indicator;
    indicatorList.appendChild(li);
  });

  document.getElementById("recommendation").textContent =
    result.recommendation;

  latestReport = {
    target,
    type: currentMode.toUpperCase(),
    score,
    indicators: result.indicators,
    recommendation: result.recommendation,
    date: new Date().toLocaleString()
  };
}

function runAnalysis() {
  const value = input.value.trim();

  if (!value) {
    alert("Please enter a URL or message to analyze.");
    input.focus();
    return;
  }

  const result = currentMode === "url"
    ? analyzeURL(value)
    : analyzeMessage(value);

  displayResult(value, result);

  if (!result.invalid) {
    const history = getHistory();

    history.unshift({
      target: value.length > 100 ? value.slice(0, 100) + "..." : value,
      type: currentMode.toUpperCase(),
      score: result.score,
      date: new Date().toLocaleString()
    });

    saveHistory(history);
    updateDashboard();
  }
}

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(item =>
      item.classList.remove("active")
    );

    tab.classList.add("active");
    currentMode = tab.dataset.mode;

    const isURL = currentMode === "url";

    document.getElementById("inputLabel").textContent =
      isURL ? "Suspicious URL" : "Suspicious message";

    input.placeholder = isURL
      ? "https://example.com/login"
      : "Paste a suspicious email, text message, or notification here...";

    document.getElementById("inputHint").textContent = isURL
      ? "Paste a URL you want to inspect. Do not visit suspicious links."
      : "Paste message text for a local heuristic phishing assessment.";

    resultPanel.hidden = true;
  });
});

analyzeBtn.addEventListener("click", runAnalysis);

clearBtn.addEventListener("click", () => {
  input.value = "";
  resultPanel.hidden = true;
  latestReport = null;
  input.focus();
});

document.getElementById("exportBtn").addEventListener("click", () => {
  if (!latestReport) return;

  const report = [
    "THREATLENS AI - ANALYSIS REPORT",
    "================================",
    `Target: ${latestReport.target}`,
    `Type: ${latestReport.type}`,
    `Risk Score: ${latestReport.score}/100`,
    `Date: ${latestReport.date}`,
    "",
    "DETECTED INDICATORS",
    ...latestReport.indicators.map(item => "- " + item),
    "",
    "RECOMMENDATION",
    latestReport.recommendation,
    "",
    "DISCLAIMER: Educational heuristic analysis only. This report does not guarantee safety or maliciousness."
  ].join("\n");

  const blob = new Blob([report], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = "ThreatLens-Analysis-Report.txt";
  link.click();

  URL.revokeObjectURL(url);
});

document.getElementById("clearHistoryBtn").addEventListener("click", () => {
  if (!confirm("Clear all saved scan history on this device?")) return;

  localStorage.removeItem(STORAGE_KEY);
  updateDashboard();
});

input.addEventListener("keydown", event => {
  if (event.key === "Enter" && event.ctrlKey) {
    runAnalysis();
  }
});

updateDashboard();
