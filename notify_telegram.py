"""
Post a single clean change-summary message to a Telegram channel and
attach latest_changes.html (the full side-by-side diff) as a document.

Design goal: keep the channel readable even when many pages change.
ONE message per run, regardless of how many pages changed. Researchers
who want detail download the attached HTML — opens directly in a browser
with diff colors.

Required env vars:
  TELEGRAM_BOT_TOKEN   from @BotFather
  TELEGRAM_CHAT_ID     channel id (e.g. @my_channel or -1001234567890)

Skips gracefully if either is missing or the changes files don't exist.
"""

import html
import json
import os
import sys

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_FILE = os.path.join(SCRIPT_DIR, "latest_changes.json")
HTML_FILE = os.path.join(SCRIPT_DIR, "latest_changes.html")
TG_API = "https://api.telegram.org"
# Telegram caption hard limit is 1024 chars for documents.
CAPTION_LIMIT = 1024


def build_caption(data):
    changes = data["changes"]
    lines = [f"🚨 <b>Android Bug Bounty docs — {len(changes)} page(s) updated</b>", ""]
    for c in changes:
        lines.append(
            f"• <a href=\"{html.escape(c['url'], quote=True)}\">"
            f"{html.escape(c['name'])}</a> "
            f"(+{c['added']} / -{c['removed']})"
        )
    lines.append("")
    lines.append("<i>Open the attached HTML for the full side-by-side diff.</i>")
    caption = "\n".join(lines)
    if len(caption) > CAPTION_LIMIT:
        caption = caption[: CAPTION_LIMIT - 1] + "…"
    return caption


def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("TELEGRAM_BOT_TOKEN/CHAT_ID not set — skipping Telegram notification.")
        return 0

    if not os.path.exists(JSON_FILE) or not os.path.exists(HTML_FILE):
        print("No latest_changes.{json,html} — nothing to post.")
        return 0

    with open(JSON_FILE) as f:
        data = json.load(f)
    if not data.get("changes"):
        print("Changes file is empty — nothing to post.")
        return 0

    caption = build_caption(data)
    with open(HTML_FILE, "rb") as f:
        html_bytes = f.read()

    resp = requests.post(
        f"{TG_API}/bot{token}/sendDocument",
        data={
            "chat_id": chat_id,
            "caption": caption,
            "parse_mode": "HTML",
        },
        files={"document": ("changes.html", html_bytes, "text/html")},
        timeout=30,
    )
    if resp.status_code >= 300:
        print(f"❌ Telegram failed: {resp.status_code} {resp.text[:300]}")
        return 1

    print(f"✅ Posted summary + HTML for {len(data['changes'])} change(s) to Telegram")
    return 0


if __name__ == "__main__":
    sys.exit(main())
