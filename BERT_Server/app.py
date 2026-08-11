from pathlib import Path
from typing import Iterable
import re

import torch
from flask import Flask, jsonify, request
from flask_cors import CORS
from transformers import AutoModelForSequenceClassification, AutoTokenizer


app = Flask(__name__)
CORS(app)

MODEL_DIR = Path("bert_phishing_model")

if not MODEL_DIR.exists():
    raise FileNotFoundError(
        "The 'bert_phishing_model' folder was not found. "
        "Place it in the same folder as app.py."
    )

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
model.eval()


FILENAME_PATTERN = re.compile(
    r'([^\\/:*?"<>|\n\r]{1,180}\.'
    r'(?:pdf|docx?|docm|xlsx?|xlsm|pptx?|pptm|zip|rar|7z|gz|tar|'
    r'iso|img|exe|msi|scr|bat|cmd|com|js|jse|vbs|vbe|wsf|hta|lnk|'
    r'apk|dmg|pkg|jar|html?|svg|rtf|txt|csv|jpg|jpeg|png|gif|webp))',
    re.IGNORECASE
)

HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".msi", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".hta", ".lnk", ".iso", ".img", ".apk",
    ".dmg", ".pkg", ".jar"
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".tar",
    ".docm", ".xlsm", ".pptm", ".rtf", ".html", ".htm", ".svg"
}

COMMON_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".webp"
}

SUSPICIOUS_FILENAME_TERMS = {
    "invoice", "payment", "payroll", "password", "verify", "verification",
    "account", "secure", "security", "urgent", "statement", "receipt",
    "refund", "remittance", "wire", "bank", "document", "scan", "voicemail",
    "purchase", "order", "delivery", "tax", "salary"
}

MEDIUM_COMBINATIONS = [
    {"payment", "receipt"},
    {"purchase", "receipt"},
    {"order", "confirmation"},
    {"account", "statement"},
    {"refund", "receipt"}
]

HIGH_COMBINATIONS = [
    {"invoice", "payment"},
    {"verify", "account"},
    {"verification", "account"},
    {"password", "document"},
    {"payroll", "document"},
    {"bank", "statement"}
]

URGENT_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
    r"\bwithin 24 hours\b", r"\bfinal warning\b",
    r"\baccount (?:will be )?(?:closed|suspended|locked)\b"
]

CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\blog[ -]?in\b", r"\bsign[ -]?in\b",
    r"\bverify your account\b", r"\bconfirm your identity\b",
    r"\bcredentials?\b", r"\bone[- ]time code\b", r"\botp\b"
]

PAYMENT_PATTERNS = [
    r"\bgift card\b", r"\bwire transfer\b", r"\bcrypto(?:currency)?\b",
    r"\bbitcoin\b", r"\bpayment required\b", r"\bpay immediately\b",
    r"\bbank transfer\b", r"\brefund\b"
]

LINK_PATTERN = re.compile(r"https?://|www\.", re.IGNORECASE)
SHORTENER_PATTERN = re.compile(
    r"\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly)/",
    re.IGNORECASE
)


def clean_filename(value: str) -> str:
    value = re.sub(
        r"\b(?:preview|download)\s+attachment\b",
        " ",
        value,
        flags=re.IGNORECASE
    )
    value = re.sub(r"\battachment\b", " ", value, flags=re.IGNORECASE)
    value = re.sub(r"\s+", " ", value).strip(" -:;|")

    matches = [match.group(1).strip() for match in FILENAME_PATTERN.finditer(value)]
    if not matches:
        return ""

    matches.sort(key=lambda item: (len(item), item.lower()))
    return matches[0]


def normalize_attachments(value) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        raw_items = value.replace(",", "\n").splitlines()
    elif isinstance(value, Iterable):
        raw_items = value
    else:
        raw_items = [value]

    output = []
    seen = set()

    for item in raw_items:
        raw_text = str(item).strip()

        # Explicitly reject email addresses accidentally captured by Gmail selectors.
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", raw_text):
            continue

        candidates = [
            clean_filename(match.group(1))
            for match in FILENAME_PATTERN.finditer(raw_text)
        ]

        if not candidates:
            cleaned = clean_filename(raw_text)
            candidates = [cleaned] if cleaned else []

        for filename in candidates:
            # Reject anything that is actually an email address.
            if "@" in filename:
                continue

            key = filename.lower()
            if filename and key not in seen:
                seen.add(key)
                output.append(filename)

    return output[:20]


def any_pattern(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def analyze_text_indicators(
    sender: str,
    subject: str,
    body: str
) -> tuple[int, list[str]]:
    combined = f"{sender} {subject} {body}"
    points = 0
    reasons = []

    if any_pattern(combined, URGENT_PATTERNS):
        points += 7
        reasons.append("Urgent or threatening language was detected.")

    if any_pattern(combined, CREDENTIAL_PATTERNS):
        points += 9
        reasons.append(
            "The email contains credential or identity-verification language."
        )

    if any_pattern(combined, PAYMENT_PATTERNS):
        points += 8
        reasons.append(
            "Payment, transfer, refund, gift-card, or cryptocurrency language was detected."
        )

    if SHORTENER_PATTERN.search(combined):
        points += 8
        reasons.append("A shortened URL was detected.")
    elif LINK_PATTERN.search(combined):
        points += 2
        reasons.append("The email contains one or more web links.")

    return min(points, 15), reasons


def analyze_attachment_metadata(
    attachments: list[str]
) -> tuple[int, list[str], str | None]:
    points = 0
    reasons = []
    minimum_level = None

    if not attachments:
        return 0, ["No visible attachment filenames were detected."], minimum_level

    reasons.append(
        f"Inspected {len(attachments)} visible attachment filename(s) "
        "without downloading files."
    )

    for filename in attachments:
        lower = filename.lower()
        extension = Path(lower).suffix
        suffixes = Path(lower).suffixes
        words = set(re.findall(r"[a-z0-9]+", lower))

        if extension in HIGH_RISK_EXTENSIONS:
            points += 50
            minimum_level = "high"
            reasons.append(
                f"High-risk attachment extension detected: {filename} ({extension})."
            )
        elif extension in MEDIUM_RISK_EXTENSIONS:
            points += 28
            minimum_level = minimum_level or "medium"
            reasons.append(
                f"Potentially risky attachment extension detected: {filename} ({extension})."
            )
        elif extension in COMMON_EXTENSIONS:
            reasons.append(
                f"Common attachment type detected: {filename} ({extension})."
            )
        else:
            points += 10
            reasons.append(
                f"Unknown or uncommon attachment type detected: {filename}."
            )

        matched_terms = sorted(
            term for term in SUSPICIOUS_FILENAME_TERMS
            if term in words
        )

        if matched_terms:
            points += min(18, len(matched_terms) * 6)
            reasons.append(
                f"Suspicious filename wording detected in {filename}: "
                + ", ".join(matched_terms[:4])
                + "."
            )

        if any(required.issubset(words) for required in HIGH_COMBINATIONS):
            points += 40
            minimum_level = "high"
            reasons.append(
                f"High-risk filename combination detected in {filename}."
            )
        elif any(required.issubset(words) for required in MEDIUM_COMBINATIONS):
            points += 28
            if minimum_level != "high":
                minimum_level = "medium"
            reasons.append(
                f"Suspicious filename combination detected in {filename}; manual review is recommended."
            )

        if len(suffixes) >= 2 and suffixes[-1] in HIGH_RISK_EXTENSIONS:
            points += 50
            minimum_level = "high"
            reasons.append(
                f"Double-extension pattern detected in {filename}."
            )

    return min(points, 100), reasons, minimum_level


@app.route("/")
def home():
    return "BERT Phishing Detector API Running"


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        sender = str(data.get("sender", ""))
        subject = str(data.get("subject", ""))
        body = str(data.get("body", ""))
        attachments = normalize_attachments(
            data.get("attachments", [])
        )

        if not any([
            sender.strip(),
            subject.strip(),
            body.strip(),
            attachments
        ]):
            return jsonify({"error": "No email content received"}), 400

        attachment_text = (
            " | ".join(attachments)
            if attachments
            else "No visible attachments"
        )

        text = (
            f"Sender: {sender} "
            f"Subject: {subject} "
            f"Body: {body} "
            f"Attachments: {attachment_text}"
        )

        encoded = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=256
        )
        encoded = {
            key: value.to(device)
            for key, value in encoded.items()
        }

        with torch.no_grad():
            logits = model(**encoded).logits
            probabilities = torch.softmax(logits, dim=-1)[0]

        predicted_id = int(torch.argmax(probabilities).item())
        confidence = float(probabilities[predicted_id].item())
        phishing_probability = float(probabilities[1].item())

        text_rule_points, text_reasons = analyze_text_indicators(
            sender,
            subject,
            body
        )

        (
            attachment_points,
            attachment_reasons,
            minimum_attachment_level
        ) = analyze_attachment_metadata(attachments)

        # Practical demo weighting:
        # 55% BERT, 15% email indicators, 30% attachment metadata.
        bert_component = phishing_probability * 55.0
        text_component = float(text_rule_points)
        attachment_component = min(
            30.0,
            attachment_points * 0.30
        )

        overall_risk_score = min(
            100.0,
            bert_component + text_component + attachment_component
        )

        # Safety floors for strong attachment indicators.
        if minimum_attachment_level == "medium":
            overall_risk_score = max(overall_risk_score, 45.0)
        elif minimum_attachment_level == "high":
            overall_risk_score = max(overall_risk_score, 75.0)

        if overall_risk_score >= 70:
            risk_level = "high"
        elif overall_risk_score >= 35:
            risk_level = "medium"
        else:
            risk_level = "low"

        label = (
            "phishing"
            if overall_risk_score >= 50
            else "legitimate"
        )

        # Medium-risk results are intentionally shown as "suspicious"
        # rather than falsely claiming the message is definitely phishing.
        display_label = (
            "suspicious"
            if risk_level == "medium"
            else label
        )

        reasons = [
            (
                "BERT analyzed the sender, subject, body, "
                "and visible attachment filename(s)."
            ),
            (
                "BERT phishing probability: "
                f"{phishing_probability * 100:.2f}%."
            )
        ]
        reasons.extend(text_reasons)
        reasons.extend(attachment_reasons)

        if minimum_attachment_level == "medium":
            reasons.append(
                "Attachment metadata set a minimum Medium Risk level; manual review is recommended."
            )
        elif minimum_attachment_level == "high":
            reasons.append(
                "Attachment metadata set a minimum High Risk level."
            )

        if not text_reasons:
            reasons.append(
                "No explicit urgency, credential, payment, "
                "or shortened-link rule was triggered."
            )

        return jsonify({
            "label": display_label,
            "score": round(confidence, 4),
            "confidence": round(confidence, 4),
            "phishing_probability": round(phishing_probability, 4),
            "risk_score": round(overall_risk_score, 1),
            "risk_level": risk_level,
            "risk_components": {
                "bert_text_and_filenames": round(bert_component, 1),
                "email_indicators": round(text_component, 1),
                "attachment_allow_block_rules": round(attachment_component, 1)
            },
            "attachments": attachments,
            "reasons": reasons[:10],
            "analysis_scope": (
                "BERT analyzed email text plus visible attachment filenames. "
                "Allow/block-list rules also checked filename metadata. "
                "Attachment contents were not opened or downloaded."
            )
        })

    except Exception as error:
        print("ERROR:", error)
        return jsonify({"error": str(error)}), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
