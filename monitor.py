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
  4. If a page changed, it writes a human-readable "unified diff"
     (old vs new text) into latest_changes.md.
  5. If NOTHING changed, it deletes latest_changes.md (if present)
     so the Claude Routine knows there is nothing to report.

This script does NOT talk to Discord. A separate step
(notify_discord.py) reads latest_changes.md and posts it to a
Discord webhook. Keeping the two jobs separate makes this
script deterministic and free.
================================================================
"""

import difflib
import hashlib
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
}

# All paths are relative to this file's folder, so the script works
# no matter which directory you run it from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HASHES_FILE = os.path.join(SCRIPT_DIR, "page_hashes.json")
SNAPSHOTS_DIR = os.path.join(SCRIPT_DIR, "snapshots")
CHANGES_FILE = os.path.join(SCRIPT_DIR, "latest_changes.md")

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
    changes = []  # list of (name, url, diff_text) for pages that changed
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
                changes.append((name, url, diff))
                save_snapshot(name, content)
            else:
                print("   ✅ No change")

        browser.close()

    save_hashes(new_hashes)

    # ─── WRITE OR CLEAR THE CHANGES FILE ──────────────────────────
    if changes:
        with open(CHANGES_FILE, "w") as f:
            f.write(f"# 🚨 Page Changes Detected — {now}\n\n")
            f.write(f"**{len(changes)} page(s) changed.**\n\n")
            for name, url, diff in changes:
                f.write(f"---\n\n## 📄 {name}\n\n")
                f.write(f"🔗 {url}\n\n")
                f.write(f"### Diff:\n\n```diff\n{diff}\n```\n\n")
        print(f"\n📋 Wrote {CHANGES_FILE} ({len(changes)} change(s))")
    else:
        # No changes → make sure no stale changes file is left behind.
        if os.path.exists(CHANGES_FILE):
            os.remove(CHANGES_FILE)
        print(f"\n✅ No changes — {CHANGES_FILE} not created")


if __name__ == "__main__":
    main()
