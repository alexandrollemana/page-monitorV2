"""
🔍 Android VRP Page Monitor — PRODUCTION
================================================================
WHAT THIS DOES (plain English):
  1. Opens 3 Google security pages in a real headless browser
     (Playwright + Chromium) so that JavaScript-rendered content
     is fully loaded — a plain `requests.get()` would miss it.
  2. Takes the visible text of each page and hashes it (SHA256).
  3. Compares each hash with the value stored last time in
     page_hashes.json.
  4. If a page changed, it writes three artifacts:
       - latest_changes.md   (unified-diff markdown, for Discord)
       - latest_changes.html (side-by-side HTML, for Telegram attachment)
       - latest_changes.json (per-page +/- counts, for caption building)
  5. If NOTHING changed, it deletes those files so downstream
     notifiers know there is nothing to send.

This script does NOT talk to Discord or Telegram. Separate scripts
(notify_discord.py, notify_telegram.py) read the artifacts above
and post to their respective platforms. Keeping the jobs separate
makes this script deterministic and free.
================================================================
"""

import difflib
import hashlib
import html as html_lib
import json
import os
from datetime import datetime, timezone

from playwright.sync_api import sync_playwright

# ─── CONFIG ───────────────────────────────────────────────────────
# The pages we watch. The KEY is a friendly name (also used as the
# snapshot filename); the VALUE is the URL.
PAGES = {
    "Android VRP Rules": "https://bughunters.google.com/about/rules/android-friends/android-and-google-devices-security-reward-program-rules",
    "Severity Ratings": "https://source.android.com/docs/security/overview/updates-resources#severity",
    "About Rules": "https://bughunters.google.com/about/rules/about-this-section",
    "ASB Overview": "https://source.android.com/docs/security/bulletin/asb-overview",
    "Bug Hunters Leaderboard": "https://bughunters.google.com/leaderboard",
    "Bug Hunters Blog": "https://bughunters.google.com/blog",
}

# All paths are relative to this file's folder, so the script works
# no matter which directory you run it from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HASHES_FILE = os.path.join(SCRIPT_DIR, "page_hashes.json")
SNAPSHOTS_DIR = os.path.join(SCRIPT_DIR, "snapshots")
CHANGES_FILE = os.path.join(SCRIPT_DIR, "latest_changes.md")
CHANGES_HTML_FILE = os.path.join(SCRIPT_DIR, "latest_changes.html")
CHANGES_JSON_FILE = os.path.join(SCRIPT_DIR, "latest_changes.json")

# OPTIONAL: if the CHROME_PATH environment variable is set, use that
# Chromium/Chrome binary instead of the one `playwright install`
# downloads. This is only needed in locked-down environments where the
# Playwright browser CDN is blocked. In a normal Routine run this stays
# unset and Playwright uses its own browser automatically.
CHROME_PATH = os.environ.get("CHROME_PATH")

# Make sure the snapshots/ folder exists.
os.makedirs(SNAPSHOTS_DIR, exist_ok=True)


# Selectors tried in order to isolate the *article* content and strip away
# site chrome (top nav, side menus, footers). First match with enough text
# wins. `body` is the safety net so we never return nothing.
CONTENT_SELECTORS = [
    "article",
    "main",
    "[role='main']",
    ".devsite-article-body",
    ".devsite-article",
    "body",
]
MIN_CONTENT_CHARS = 500


# ─── FETCH ONE PAGE (WAITING FOR JAVASCRIPT) ──────────────────────
def fetch_page_content(url, browser):
    """Open `url` in the headless browser, wait for JS, return article text."""
    page = browser.new_page()
    try:
        page.goto(url, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(3000)
        for selector in CONTENT_SELECTORS:
            try:
                element = page.query_selector(selector)
            except Exception:
                continue
            if not element:
                continue
            text = (element.inner_text() or "").strip()
            if len(text) >= MIN_CONTENT_CHARS:
                print(f"   ↳ extracted via '{selector}' ({len(text)} chars)")
                return text
        # Fallback: nothing met the threshold — return whatever body has.
        return page.inner_text("body").strip()
    except Exception as e:
        print(f"⚠️ Error fetching {url}: {e}")
        return None
    finally:
        page.close()


# ─── SMALL HELPERS ────────────────────────────────────────────────
def hash_content(text):
    """SHA256 fingerprint of the page text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_filename(name):
    """Turn a friendly page name into a safe file name."""
    return "".join(c if c.isalnum() else "_" for c in name)


def load_hashes():
    """Read the previous run's hashes (empty dict on first run)."""
    if os.path.exists(HASHES_FILE):
        with open(HASHES_FILE, "r") as f:
            return json.load(f)
    return {}


def save_hashes(hashes):
    """Persist the current hashes for next time."""
    with open(HASHES_FILE, "w") as f:
        json.dump(hashes, f, indent=2)


def load_snapshot(page_name):
    """Read the last saved text of a page (empty string if none)."""
    path = os.path.join(SNAPSHOTS_DIR, f"{safe_filename(page_name)}.txt")
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return ""


def save_snapshot(page_name, content):
    """Save the current text of a page for future diffing."""
    path = os.path.join(SNAPSHOTS_DIR, f"{safe_filename(page_name)}.txt")
    with open(path, "w") as f:
        f.write(content)


def count_diff_lines(diff_text):
    """Return (added, removed) line counts from a unified diff."""
    added = 0
    removed = 0
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


def build_html_report(change_records, timestamp):
    """Build a single self-contained HTML doc with side-by-side diffs
    for every changed page. Designed to be downloaded once from a
    Telegram message and opened in a browser."""
    differ = difflib.HtmlDiff(wrapcolumn=80)
    # difflib ships its own CSS for the diff table (diff_add / diff_chg / diff_sub).
    diff_styles = difflib.HtmlDiff._styles
    sections = []
    for rec in change_records:
        table = differ.make_table(
            rec["old"].splitlines(),
            rec["new"].splitlines(),
            fromdesc=html_lib.escape(f"{rec['name']} — before"),
            todesc=html_lib.escape(f"{rec['name']} — after"),
            context=True,
            numlines=3,
        )
        sections.append(
            f'<section>'
            f'<h2>{html_lib.escape(rec["name"])}</h2>'
            f'<p><a href="{html_lib.escape(rec["url"], quote=True)}" target="_blank" rel="noopener">'
            f'{html_lib.escape(rec["url"])}</a></p>'
            f'{table}'
            f'</section>'
        )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        f"<title>Page Changes — {html_lib.escape(timestamp)}</title>"
        "<style>"
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
        "max-width:1200px;margin:2em auto;padding:0 1em;color:#222}"
        "h1{color:#c1121f}"
        "h2{border-bottom:2px solid #ddd;padding-bottom:.3em;margin-top:2em}"
        "section{margin-bottom:3em}"
        "table.diff{font-family:ui-monospace,Menlo,Consolas,monospace;"
        "font-size:13px;width:100%;border-collapse:collapse}"
        f"{diff_styles}"
        "</style></head><body>"
        f"<h1>Page Changes Detected</h1>"
        f"<p><b>{len(change_records)} page(s) changed</b> · {html_lib.escape(timestamp)}</p>"
        f"<hr>{''.join(sections)}</body></html>"
    )


def generate_diff(old_text, new_text, page_name):
    """Build a unified diff (the +/- lines) between old and new text."""
    # splitlines() WITHOUT keepends + lineterm="" keeps every diff line on its
    # own row, even when the page's last line has no trailing newline.
    diff = difflib.unified_diff(
        old_text.splitlines(),
        new_text.splitlines(),
        fromfile=f"{page_name} (before)",
        tofile=f"{page_name} (after)",
        n=2,  # show 2 lines of context around each change
        lineterm="",
    )
    return "\n".join(diff)


def launch_browser(p):
    """Launch headless Chromium, honouring the optional CHROME_PATH override."""
    launch_args = {
        "headless": True,
        # These flags are required to run Chromium inside containers/CI.
        "args": ["--no-sandbox", "--disable-dev-shm-usage"],
    }
    if CHROME_PATH:
        launch_args["executable_path"] = CHROME_PATH
    return p.chromium.launch(**launch_args)


# ─── MAIN ─────────────────────────────────────────────────────────
def main():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"🔍 Page Monitor — {now}")
    print("=" * 60)

    old_hashes = load_hashes()
    new_hashes = {}
    # Each entry: {name, url, old, new, diff}
    changes = []
    first_run = len(old_hashes) == 0

    with sync_playwright() as p:
        browser = launch_browser(p)

        for name, url in PAGES.items():
            print(f"\n📄 {name}...")
            content = fetch_page_content(url, browser)

            if content is None:
                # Fetch failed — keep the old hash so we don't lose state
                # or raise a false "changed" alarm next time.
                print("   ⏭️ Skipped (fetch failed)")
                if name in old_hashes:
                    new_hashes[name] = old_hashes[name]
                continue

            current_hash = hash_content(content)
            new_hashes[name] = current_hash

            if first_run or name not in old_hashes:
                # No baseline yet → just store it, never alert.
                save_snapshot(name, content)
                print("   📝 Baseline saved")
            elif old_hashes[name] != current_hash:
                # Hash differs → real change. Diff against last snapshot.
                print("   🚨 CHANGE DETECTED")
                old_content = load_snapshot(name)
                diff = generate_diff(old_content, content, name)
                changes.append({
                    "name": name,
                    "url": url,
                    "old": old_content,
                    "new": content,
                    "diff": diff,
                })
                save_snapshot(name, content)
            else:
                print("   ✅ No change")

        browser.close()

    save_hashes(new_hashes)

    # ─── WRITE OR CLEAR THE CHANGES FILES ─────────────────────────
    output_files = (CHANGES_FILE, CHANGES_HTML_FILE, CHANGES_JSON_FILE)
    if changes:
        # 1. Markdown unified-diff (for Discord chunked text post).
        with open(CHANGES_FILE, "w") as f:
            f.write(f"# 🚨 Page Changes Detected — {now}\n\n")
            f.write(f"**{len(changes)} page(s) changed.**\n\n")
            for rec in changes:
                f.write(f"---\n\n## 📄 {rec['name']}\n\n")
                f.write(f"🔗 {rec['url']}\n\n")
                f.write(f"### Diff:\n\n```diff\n{rec['diff']}\n```\n\n")

        # 2. Side-by-side HTML (for Telegram attachment).
        with open(CHANGES_HTML_FILE, "w") as f:
            f.write(build_html_report(changes, now))

        # 3. Structured JSON summary (for notifiers to build captions).
        with open(CHANGES_JSON_FILE, "w") as f:
            summary = []
            for rec in changes:
                added, removed = count_diff_lines(rec["diff"])
                summary.append({
                    "name": rec["name"],
                    "url": rec["url"],
                    "added": added,
                    "removed": removed,
                })
            json.dump({"timestamp": now, "changes": summary}, f, indent=2)

        print(f"\n📋 Wrote {len(changes)} change(s) to .md / .html / .json")
    else:
        # No changes → make sure no stale changes files are left behind.
        for path in output_files:
            if os.path.exists(path):
                os.remove(path)
        print(f"\n✅ No changes — output files not created")


if __name__ == "__main__":
    main()
