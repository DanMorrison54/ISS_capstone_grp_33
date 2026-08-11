const senderInput = document.getElementById("sender");
const subjectInput = document.getElementById("subject");
const bodyInput = document.getElementById("body");
const attachmentsInput = document.getElementById("attachments");
const resultBox = document.getElementById("result");
const sourceBox = document.getElementById("source");
const readButton = document.getElementById("readEmail");
const analyzeButton = document.getElementById("analyze");

function setResult(message, type = "") {
  resultBox.className = type;
  resultBox.textContent = message;
}

function setBusy(button, busy, busyText, normalText) {
  button.disabled = busy;
  button.textContent = busy ? busyText : normalText;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[character]);
}

function extractOpenEmail() {
  const clean = (value) => (value || "").replace(/\s+/g, " ").trim();

  const firstText = (selectors) => {
    for (const selector of selectors) {
      const element = document.querySelector(selector);
      if (element) {
        const value = clean(
          element.getAttribute("email") ||
          element.getAttribute("data-email-address") ||
          element.getAttribute("title") ||
          element.getAttribute("aria-label") ||
          element.innerText ||
          element.textContent
        );
        if (value) return value;
      }
    }
    return "";
  };

  const largestVisibleText = (selectors) => {
    const candidates = [];
    for (const selector of selectors) {
      document.querySelectorAll(selector).forEach((element) => {
        const rect = element.getBoundingClientRect();
        const style = window.getComputedStyle(element);
        const text = clean(element.innerText || element.textContent);
        if (
          text &&
          text.length >= 10 &&
          rect.width > 0 &&
          rect.height > 0 &&
          style.display !== "none" &&
          style.visibility !== "hidden"
        ) {
          candidates.push({ text, size: text.length, top: rect.top });
        }
      });
    }
    candidates.sort((a, b) => b.size - a.size || a.top - b.top);
    return candidates[0]?.text || "";
  };

  const extractAttachmentNames = (selectors) => {
    const candidates = [];
    const filenamePattern = /([^\\/:*?"<>|\n\r]{1,180}\.(?:pdf|docx?|docm|xlsx?|xlsm|pptx?|pptm|zip|rar|7z|gz|tar|iso|img|exe|msi|scr|bat|cmd|com|js|jse|vbs|vbe|wsf|hta|lnk|apk|dmg|pkg|jar|html?|svg|rtf|txt|csv|jpg|jpeg|png|gif|webp))/ig;

    const normalizeFilename = (raw) => {
      const value = clean(raw)
        .replace(/\b(?:preview|download)\s+attachment\b/ig, " ")
        .replace(/\battachment\b/ig, " ")
        .replace(/\s+/g, " ")
        .trim();

      const matches = [...value.matchAll(filenamePattern)]
        .map((match) => clean(match[1]))
        .filter(Boolean);

      if (!matches.length) return "";

      matches.sort((a, b) => a.length - b.length || a.localeCompare(b));
      return matches[0];
    };

    for (const selector of selectors) {
      document.querySelectorAll(selector).forEach((element) => {
        const rect = element.getBoundingClientRect();
        const style = window.getComputedStyle(element);

        if (
          rect.width <= 0 ||
          rect.height <= 0 ||
          style.display === "none" ||
          style.visibility === "hidden"
        ) return;

        const values = [
          element.getAttribute("download"),
          element.getAttribute("data-tooltip"),
          element.getAttribute("data-tooltip-text"),
          element.getAttribute("aria-label"),
          element.getAttribute("title"),
          element.getAttribute("data-file-name"),
          element.innerText,
          element.textContent
        ].filter(Boolean);

        for (const value of values) {
          const filename = normalizeFilename(value);
          if (filename) candidates.push(filename);
        }
      });
    }

    const unique = [];
    const seen = new Set();

    candidates
      .sort((a, b) => a.length - b.length || a.localeCompare(b))
      .forEach((filename) => {
        const key = filename.toLowerCase();

        if (seen.has(key)) return;

        // Ignore a longer Gmail UI string when it contains a filename
        // already captured in a shorter, cleaner form.
        const isDuplicateContainer = unique.some(
          (existing) => key.includes(existing.toLowerCase())
        );

        if (!isDuplicateContainer) {
          seen.add(key);
          unique.push(filename);
        }
      });

    return unique.slice(0, 20);
  };

  const host = location.hostname;
  let provider = "Unsupported website";
  let sender = "";
  let subject = "";
  let body = "";
  let attachments = [];

  if (host === "mail.google.com") {
    provider = "Gmail";

    sender = firstText([
      "div.adn span.gD[email]",
      "span.gD[email]",
      "div.adn span[email]",
      "span[email][name]"
    ]);

    subject = firstText([
      "h2.hP",
      "div[role='main'] h2",
      "h2[data-thread-perm-id]"
    ]);

    body = largestVisibleText([
      "div.adn div.a3s.aiL",
      "div.a3s.aiL",
      "div[role='main'] div.a3s"
    ]);

    attachments = extractAttachmentNames([
      "div[role='main'] [download]",
      "div[role='main'] [data-tooltip*='.']",
      "div[role='main'] [data-tooltip-text*='.']",
      "div[role='main'] [aria-label*='attachment' i]",
      "div[role='main'] [aria-label*='download' i]",
      "div[role='main'] [title*='.']",
      "div[role='main'] a",
      "div[role='main'] span"
    ]);
  } else if (
    host === "outlook.live.com" ||
    host === "outlook.office.com" ||
    host === "outlook.office365.com"
  ) {
    provider = "Outlook";

    sender = firstText([
      "div[role='main'] button[aria-label*='From']",
      "div[role='main'] span[title*='@']",
      "div[role='main'] div[title*='@']",
      "div[role='main'] [data-email-address]"
    ]);

    subject = firstText([
      "div[role='main'] h1",
      "div[role='main'] h2",
      "div[role='heading'][aria-level='2']",
      "div[role='main'] [role='heading']"
    ]);

    body = largestVisibleText([
      "div[role='main'] div[aria-label='Message body']",
      "div[role='main'] div[aria-label*='Message body']",
      "div[role='main'] div[role='document']",
      "div[role='main'] div[contenteditable='false']"
    ]);

    attachments = extractAttachmentNames([
      "div[role='main'] [aria-label*='attachment' i]",
      "div[role='main'] [aria-label*='download' i]",
      "div[role='main'] [data-file-name]",
      "div[role='main'] [title*='.']",
      "div[role='main'] button",
      "div[role='main'] a",
      "div[role='main'] span"
    ]);
  }

  return {
    provider,
    sender: clean(sender),
    subject: clean(subject),
    body: clean(body),
    attachments,
    url: location.href
  };
}

async function readCurrentEmail() {
  setBusy(readButton, true, "Reading...", "Read Open Email");
  setResult("Reading the currently opened email...");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) throw new Error("No active browser tab was found.");

    const supported = [
      "https://mail.google.com/",
      "https://outlook.live.com/",
      "https://outlook.office.com/",
      "https://outlook.office365.com/"
    ].some((prefix) => tab.url?.startsWith(prefix));

    if (!supported) {
      throw new Error("Open an email in Gmail or Outlook before using this button.");
    }

    const injectionResults = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: extractOpenEmail
    });

    const email = injectionResults?.[0]?.result;
    if (!email) throw new Error("The page did not return any email information.");

    senderInput.value = email.sender || "";
    subjectInput.value = email.subject || "";
    bodyInput.value = email.body || "";
    attachmentsInput.value = (email.attachments || []).join("\n");
    sourceBox.textContent =
      `Source: ${email.provider} · ${(email.attachments || []).length} attachment name(s) found`;

    const missing = [];
    if (!email.sender) missing.push("sender");
    if (!email.subject) missing.push("subject");
    if (!email.body) missing.push("body");

    if (missing.length) {
      setResult(
        `Email partially read from ${email.provider}. Missing: ${missing.join(", ")}. You can fill in the missing field manually.`,
        "error"
      );
    } else {
      setResult(
        `Email read from ${email.provider}. Attachment metadata was inspected without downloading any file.`,
        "success"
      );
    }
    return email;
  } catch (error) {
    sourceBox.textContent = "No email was read.";
    setResult(`Read error: ${error.message}`, "error");
    return null;
  } finally {
    setBusy(readButton, false, "Reading...", "Read Open Email");
  }
}

async function analyzeEmail() {
  setBusy(analyzeButton, true, "Analyzing...", "Analyze Email");
  setResult("Analyzing...");

  const sender = senderInput.value.trim();
  const subject = subjectInput.value.trim();
  const body = bodyInput.value.trim();
  const attachments = attachmentsInput.value
    .split(/\n|,/)
    .map((name) => name.trim())
    .filter(Boolean);

  if (!sender && !subject && !body && attachments.length === 0) {
    setResult("Read an open email or enter email information before analyzing.", "error");
    setBusy(analyzeButton, false, "Analyzing...", "Analyze Email");
    return;
  }

  try {
    const response = await fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender, subject, body, attachments })
    });

    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error(`The Flask server returned an invalid response (HTTP ${response.status}).`);
    }

    if (!response.ok) throw new Error(data.error || `Server error (HTTP ${response.status}).`);
    if (data.error) throw new Error(data.error);

    const rawLabel = String(data.label ?? "unknown").trim().toLowerCase();
    const labelText = rawLabel === "phishing" ? "Phishing" : rawLabel === "legitimate" ? "Legitimate" : rawLabel;

    const confidence = Number(data.confidence ?? data.score);
    const confidencePercent = Number.isFinite(confidence)
      ? `${(confidence * 100).toFixed(2)}%`
      : "Not provided";

    const riskScore = Number(data.risk_score);
    const riskPercent = Number.isFinite(riskScore)
      ? `${riskScore.toFixed(1)}%`
      : "Not provided";

    const riskLevel = String(data.risk_level || "medium").toLowerCase();
    const safeRiskLevel = ["low", "medium", "high"].includes(riskLevel) ? riskLevel : "medium";
    const icon = safeRiskLevel === "high" ? "!" : safeRiskLevel === "medium" ? "⚠" : "✓";
    const reasons = Array.isArray(data.reasons) && data.reasons.length
      ? data.reasons
      : ["No additional risk indicators were returned."];

    resultBox.className = `result-card ${safeRiskLevel}`;
    resultBox.innerHTML = `
      <div class="result-heading">
        <span class="result-icon">${icon}</span>
        <span class="result-badge">${escapeHtml(labelText)} · ${escapeHtml(safeRiskLevel.toUpperCase())} RISK</span>
      </div>
      <div class="metric-row">
        <span>Overall risk score</span>
        <strong>${escapeHtml(riskPercent)}</strong>
      </div>
      <div class="metric-row">
        <span>Model confidence</span>
        <strong>${escapeHtml(confidencePercent)}</strong>
      </div>
      <div style="margin-top:8px;font-weight:700;">Why this result</div><ul class="reasons">
        ${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}
      </ul>
    `;
  } catch (error) {
    setResult(
      `Connection or analysis error: ${error.message}. Make sure the updated Flask server is running at http://127.0.0.1:5000.`,
      "error"
    );
  } finally {
    setBusy(analyzeButton, false, "Analyzing...", "Analyze Email");
  }
}

readButton.addEventListener("click", readCurrentEmail);
analyzeButton.addEventListener("click", analyzeEmail);
