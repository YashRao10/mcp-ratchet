#!/usr/bin/env python3
"""Render a Hummingbird-template HTML doc to PDF via headless Chrome/Edge,
then verify it (page count, page-1 text, footer-gap scan).

Encodes two bug-prone steps from the PACT doc-render recipe so they don't
have to be re-derived (or silently mis-derived) by hand each time:
  1. file:// URL construction. Edge/Chrome do NOT error on a malformed
     POSIX-style path (e.g. produced by Git Bash auto-conversion) -- they
     silently render their own "file not found" page and print THAT as a
     plausible-looking 1-page PDF. This script always builds the URL from
     an explicit drive letter with forward slashes and %20-encoded spaces,
     regardless of what shell invoked it.
  2. Post-render verification. "N bytes written" from the browser is not
     proof the export worked. This script opens the resulting PDF with
     PyMuPDF and reports page count, page-1 text, and a footer-gap scan
     (flags any page where the gap between the last body text and the
     footer zone is under ~5pt).

Usage:
  python render_pdf.py --html "C:\\path\\to\\doc.html" --out "C:\\path\\to\\doc.pdf" [--browser chrome|edge]
"""

import argparse
import os
import subprocess
import sys
import tempfile

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]
EDGE_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def find_browser(preferred):
    order = CHROME_CANDIDATES + EDGE_CANDIDATES if preferred == "chrome" else EDGE_CANDIDATES + CHROME_CANDIDATES
    for path in order:
        if os.path.isfile(path):
            return path
    return None


def to_file_url(win_path):
    """Build a file:// URL the way headless Chrome/Edge actually need it:
    explicit drive letter, forward slashes, three slashes after 'file:',
    spaces manually %20-encoded. Never derive this from a POSIX-style path."""
    abs_path = os.path.abspath(win_path)
    if len(abs_path) >= 2 and abs_path[1] == ":":
        drive = abs_path[0].upper()
        rest = abs_path[2:].replace("\\", "/").lstrip("/")
        forward = f"{drive}:/{rest}"
    else:
        forward = abs_path.replace("\\", "/")
    encoded = forward.replace(" ", "%20")
    return f"file:///{encoded}"


def render(html_path, out_path, browser_pref):
    browser = find_browser(browser_pref)
    if not browser:
        print(f"ERROR: no {browser_pref} (or fallback) executable found in known locations.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(html_path):
        print(f"ERROR: input HTML not found: {html_path}", file=sys.stderr)
        sys.exit(1)

    url = to_file_url(html_path)
    out_abs = os.path.abspath(out_path)
    profile_dir = os.path.join(tempfile.gettempdir(), "chrome-print-profile")

    cmd = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--user-data-dir={profile_dir}",
        f"--print-to-pdf={out_abs}",
        url,
    ]
    print(f"Rendering with: {os.path.basename(browser)}")
    print(f"  URL: {url}")
    print(f"  Out: {out_abs}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        print(f"ERROR: browser exited {result.returncode}\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(out_abs) or os.path.getsize(out_abs) == 0:
        print("ERROR: no PDF (or empty PDF) was produced.", file=sys.stderr)
        sys.exit(1)
    return out_abs


def verify(pdf_path, footer_zone_pt=120, gap_threshold_pt=5):
    import fitz

    doc = fitz.open(pdf_path)
    print(f"\n--- Verification: {os.path.basename(pdf_path)} ---")
    print(f"Page count: {doc.page_count}")
    print(f"File size: {os.path.getsize(pdf_path):,} bytes")

    page1_text = doc[0].get_text()[:200].replace("\n", " ")
    print(f"Page 1 text sample: {page1_text!r}")
    if "not found" in page1_text.lower() or "file not found" in page1_text.lower():
        print("WARNING: page 1 text looks like a browser error page, not real content. "
              "This is the silent-404 failure mode -- check the file:// URL.")

    flagged = []
    for i, page in enumerate(doc):
        page_height = page.rect.height
        zone_top = page_height - footer_zone_pt
        blocks = page.get_text("blocks")
        candidates = [b for b in blocks if b[1] >= zone_top - 40]
        if len(candidates) < 2:
            continue
        candidates.sort(key=lambda b: b[3])
        body_bottoms = [b[3] for b in candidates[:-1]]
        footer_top = candidates[-1][1]
        if not body_bottoms:
            continue
        gap = footer_top - max(body_bottoms)
        if gap < gap_threshold_pt:
            flagged.append((i + 1, round(gap, 1)))

    if flagged:
        print(f"FLAGGED pages (footer-gap < {gap_threshold_pt}pt) -- render to PNG and eyeball these:")
        for page_num, gap in flagged:
            print(f"  page {page_num}: gap={gap}pt")
    else:
        print("No footer-gap collisions flagged by the heuristic.")
        print("Still spot-check visually -- the heuristic has missed real collisions before.")

    doc.close()
    return flagged


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--html", required=True, help="Path to source HTML file")
    parser.add_argument("--out", required=True, help="Path to write output PDF")
    parser.add_argument("--browser", choices=["chrome", "edge"], default="chrome", help="Preferred browser (falls back to the other if not found)")
    args = parser.parse_args()

    out_abs = render(args.html, args.out, args.browser)
    verify(out_abs)


if __name__ == "__main__":
    main()
