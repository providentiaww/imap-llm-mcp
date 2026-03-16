#!/usr/bin/env python3
"""Risa — Standalone IMAP spam triage cron job.

Connects to an IMAP server, classifies unseen messages using denylist/allowlist
rules, and moves spam to a triage folder. Optionally learns from a training
folder where the user drags false positives.

Designed to run as a K8s CronJob on aequor (arm64).

Environment variables:
    IMAP_HOST          IMAP server hostname
    IMAP_PORT          IMAP server port (default: 993)
    IMAP_USER          IMAP username
    IMAP_PASS          IMAP password
    IMAP_USE_SSL       Use SSL (default: true)
    TRIAGE_FOLDER      Destination folder for spam (default: INBOX/Zora-Triage)
    TRAINING_FOLDER    Folder for user feedback (default: INBOX/Zora-imap-training)
    DENYLIST_PATH      Path to denylist file (default: /config/denylist.md)
    ALLOWLIST_PATH     Path to allowlist file (default: /config/allowlist.md)
    LOG_LEVEL          Logging level (default: INFO)
    METRICS_FILE       Path to write Prometheus metrics (default: /tmp/risa-metrics.prom)
    DRY_RUN            If "true", classify but don't move (default: false)
"""

import imaplib
import email
import os
import re
import sys
import json
import time
import logging
from email.header import decode_header
from collections import Counter
from datetime import datetime

# --- Config from env ---
IMAP_HOST = os.environ.get("IMAP_HOST", "cslewis.phaedo.com")
IMAP_PORT = int(os.environ.get("IMAP_PORT", "993"))
IMAP_USER = os.environ.get("IMAP_USER", "rquick")
IMAP_PASS = os.environ.get("IMAP_PASS", "")
IMAP_USE_SSL = os.environ.get("IMAP_USE_SSL", "true").lower() == "true"
TRIAGE_FOLDER = os.environ.get("TRIAGE_FOLDER", "INBOX/Zora-Triage")
TRAINING_FOLDER = os.environ.get("TRAINING_FOLDER", "INBOX/Zora-imap-training")
DENYLIST_PATH = os.environ.get("DENYLIST_PATH", "/config/denylist.md")
ALLOWLIST_PATH = os.environ.get("ALLOWLIST_PATH", "/config/allowlist.md")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
METRICS_FILE = os.environ.get("METRICS_FILE", "/tmp/risa-metrics.prom")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("risa")

# --- Scam TLDs ---
SCAM_TLDS = {".click", ".store", ".fun", ".shop", ".biz.id", ".za.com",
             ".digital", ".name", ".living", ".sa.com", ".ru.com"}

# --- Health scam subject patterns ---
HEALTH_SCAM_PATTERNS = [
    r"blood pressure", r"blood sugar", r"joint pain", r"nerve pain",
    r"dementia risk", r"alzheimer", r"blindness", r"olive oil",
    r"common veggie", r"common food", r"hemorrhoid", r"prostate",
    r"ear noise", r"ringing.*ear", r"tinnitus", r"dark spot",
    r"stubborn fat", r"weight loss.*sleep", r"digestive system",
    r"A1C", r"1 simple.*trick", r"weird.*patch", r"mineral drink",
    r"knee.*pain", r"memory loss", r"posture.*sleep", r"brain fog",
    r"back pain.*fix", r"pins.*needles", r"belly fat", r"flat tummy",
    r"nail fungus", r"thinning brow", r"senior moment", r"speech test.*memory",
    r"gelatin.*trick", r"baking soda.*coffee", r"car scratch",
]


def load_domain_list(path):
    """Load domains from a markdown file (one per line, skip comments/headers)."""
    domains = set()
    if not os.path.exists(path):
        log.warning(f"Domain list not found: {path}")
        return domains
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("---") and "." in line:
                domains.add(line.lower())
    log.info(f"Loaded {len(domains)} domains from {path}")
    return domains


def decode_subject(raw):
    if not raw:
        return ""
    parts = decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded).replace("\r\n", " ").replace("\n", " ")


def get_domain(from_header):
    match = re.search(r"<([^>]+)>", from_header)
    addr = match.group(1) if match else from_header.strip()
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip()
    return ""


def domain_match(domain, domain_set):
    if domain in domain_set:
        return True
    for d in domain_set:
        if domain.endswith("." + d):
            return True
    return False


def is_scam_tld(domain):
    return any(domain.endswith(tld) for tld in SCAM_TLDS)


def is_health_scam(subject):
    sl = subject.lower()
    return any(re.search(p, sl, re.IGNORECASE) for p in HEALTH_SCAM_PATTERNS)


def is_non_latin(subject):
    if not subject:
        return False
    non_latin = sum(1 for c in subject if ord(c) > 0x024F and not c.isspace())
    return non_latin > len(subject) * 0.3


def is_wrong_recipient(to_header):
    to_lower = to_header.lower() if to_header else ""
    return any(n in to_lower for n in ["amanda adkins", "amanda l adkins", "sterling quick"])


def classify(from_header, to_header, subject, domain, denylist, allowlist):
    """Classify a message. Returns (should_move, reason)."""
    if domain_match(domain, allowlist):
        return False, "allowlisted"
    if domain_match(domain, denylist):
        return True, f"denylist:{domain}"
    if is_scam_tld(domain):
        return True, f"scam_tld:{domain}"
    if is_health_scam(subject):
        return True, "health_scam_subject"
    if is_non_latin(subject):
        return True, "non_latin"
    if is_wrong_recipient(to_header):
        return True, "wrong_recipient"
    # Marketing heuristics
    marketing_signals = ["email.", "mail.", "em.", "marketing.", "promo",
                        "newsletter", "rewards", "offers", "sale",
                        "donotreply", "noreply@", "no-reply@"]
    from_lower = from_header.lower()
    for sig in marketing_signals:
        if sig in domain:
            return True, f"marketing:{domain}"
    return False, "not_spam"


def learn_from_training(conn, denylist, denylist_path):
    """Check training folder for user feedback, extract new domains, update denylist."""
    try:
        status, data = conn.select(TRAINING_FOLDER)
        if status != "OK":
            log.info(f"Training folder not accessible: {TRAINING_FOLDER}")
            return 0
    except Exception as e:
        log.info(f"Training folder not found: {e}")
        return 0

    status, data = conn.search(None, "ALL")
    uids = data[0].split() if data[0] else []
    if not uids:
        return 0

    log.info(f"Training folder has {len(uids)} messages")
    new_domains = []

    for uid_bytes in uids:
        uid = uid_bytes.decode()
        status, msg_data = conn.fetch(uid, "(BODY.PEEK[HEADER.FIELDS (FROM)])")
        if status != "OK" or not msg_data or not msg_data[0]:
            continue
        msg = email.message_from_bytes(msg_data[0][1])
        domain = get_domain(msg.get("From", ""))
        if domain and domain not in denylist:
            new_domains.append(domain)
            denylist.add(domain)

    if new_domains:
        log.info(f"Learned {len(new_domains)} new domains from training: {new_domains}")
        # Append to denylist file
        with open(denylist_path, "a") as f:
            f.write(f"\n## Learned from training folder ({datetime.now().strftime('%Y-%m-%d %H:%M')})\n")
            for d in new_domains:
                f.write(f"{d}\n")

    # Move processed training messages to triage (so they don't get re-learned)
    for uid_bytes in uids:
        uid = uid_bytes.decode()
        conn.copy(uid, TRIAGE_FOLDER)
        conn.store(uid, "+FLAGS", "\\Deleted")
    conn.expunge()
    log.info(f"Moved {len(uids)} training messages to {TRIAGE_FOLDER}")

    return len(new_domains)


def triage_inbox(conn, denylist, allowlist):
    """Scan INBOX for unseen messages, classify, and move spam."""
    conn.select("INBOX")
    status, data = conn.search(None, "UNSEEN")
    uids = data[0].split() if data[0] else []

    if not uids:
        log.info("No unseen messages in INBOX")
        return {"total": 0, "moved": 0, "kept": 0, "categories": {}}

    log.info(f"Processing {len(uids)} unseen messages")

    moved = 0
    kept = 0
    categories = Counter()

    for uid_bytes in uids:
        uid = uid_bytes.decode()
        status, msg_data = conn.fetch(uid, "(BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT)])")
        if status != "OK" or not msg_data or not msg_data[0]:
            kept += 1
            continue

        msg = email.message_from_bytes(msg_data[0][1])
        from_h = msg.get("From", "")
        to_h = msg.get("To", "")
        subject = decode_subject(msg.get("Subject", ""))
        domain = get_domain(from_h)

        should_move, reason = classify(from_h, to_h, subject, domain, denylist, allowlist)

        if should_move:
            if not DRY_RUN:
                result = conn.copy(uid, TRIAGE_FOLDER)
                if result[0] == "OK":
                    conn.store(uid, "+FLAGS", "\\Deleted")
                    moved += 1
                    categories[reason.split(":")[0]] += 1
                else:
                    log.warning(f"Failed to move UID {uid}: {result}")
                    kept += 1
            else:
                log.info(f"DRY RUN: would move UID {uid} ({reason}): {subject[:60]}")
                moved += 1
                categories[reason.split(":")[0]] += 1
        else:
            kept += 1

    if not DRY_RUN:
        conn.expunge()

    return {"total": len(uids), "moved": moved, "kept": kept, "categories": dict(categories)}


def write_metrics(results, learned, duration):
    """Write Prometheus text exposition format metrics."""
    lines = [
        "# HELP risa_triage_total Total messages processed",
        "# TYPE risa_triage_total counter",
        f'risa_triage_total {results["total"]}',
        "# HELP risa_triage_moved Messages moved to triage",
        "# TYPE risa_triage_moved counter",
        f'risa_triage_moved {results["moved"]}',
        "# HELP risa_triage_kept Messages kept in inbox",
        "# TYPE risa_triage_kept counter",
        f'risa_triage_kept {results["kept"]}',
        "# HELP risa_training_learned New domains learned from training",
        "# TYPE risa_training_learned counter",
        f"risa_training_learned {learned}",
        "# HELP risa_run_duration_seconds Duration of triage run",
        "# TYPE risa_run_duration_seconds gauge",
        f"risa_run_duration_seconds {duration:.2f}",
        "# HELP risa_last_run_timestamp Unix timestamp of last run",
        "# TYPE risa_last_run_timestamp gauge",
        f"risa_last_run_timestamp {time.time():.0f}",
    ]
    for category, count in results.get("categories", {}).items():
        lines.append(f'risa_triage_by_category{{category="{category}"}} {count}')

    try:
        with open(METRICS_FILE, "w") as f:
            f.write("\n".join(lines) + "\n")
        log.info(f"Metrics written to {METRICS_FILE}")
    except Exception as e:
        log.warning(f"Failed to write metrics: {e}")


def main():
    if not IMAP_PASS:
        log.error("IMAP_PASS not set")
        sys.exit(1)

    start = time.time()
    log.info(f"Risa triage starting — host={IMAP_HOST} user={IMAP_USER} dry_run={DRY_RUN}")

    # Load lists
    denylist = load_domain_list(DENYLIST_PATH)
    allowlist = load_domain_list(ALLOWLIST_PATH)

    # Connect
    if IMAP_USE_SSL:
        conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    else:
        conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
    conn.login(IMAP_USER, IMAP_PASS)
    log.info(f"Connected to {IMAP_HOST}")

    # Learn from training folder first
    learned = learn_from_training(conn, denylist, DENYLIST_PATH)

    # Triage inbox
    results = triage_inbox(conn, denylist, allowlist)

    # Disconnect
    conn.logout()

    duration = time.time() - start
    log.info(
        f"Risa triage complete — "
        f"processed={results['total']} moved={results['moved']} kept={results['kept']} "
        f"learned={learned} duration={duration:.1f}s"
    )
    if results["categories"]:
        log.info(f"Categories: {json.dumps(results['categories'])}")

    # Write metrics
    write_metrics(results, learned, duration)


if __name__ == "__main__":
    main()
