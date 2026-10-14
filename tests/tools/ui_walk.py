"""Walk every section of a running console in a real browser and report what a
person would trip on.

    python tests/tools/ui_walk.py https://host:8787 <password> [--out DIR]

Against a throwaway node only. For each tab it takes a screenshot (desktop and
phone width) and reports:

* a script error, a failed request or a CSP violation;
* a visible paragraph longer than `--long` characters (the text blocks a
  product page should not have);
* horizontal scrolling at phone width;
* a button or input with no accessible name.

Needs Playwright and its Chromium; nothing else.
"""
from __future__ import annotations

import argparse
import os
import sys

from playwright.sync_api import sync_playwright

_LONG = 220


def _text_blocks(page, limit: int) -> list[str]:
    return page.evaluate("""(limit) => {
      const out = [];
      for (const el of document.querySelectorAll('p, .sub, .lede, li')) {
        const box = el.getBoundingClientRect();
        if (!box.width || !box.height || getComputedStyle(el).visibility === 'hidden') continue;
        if (el.closest('[hidden], details:not([open]) > :not(summary)')) continue;
        const text = (el.innerText || '').trim().replace(/\\s+/g, ' ');
        if (text.length > limit) out.push(text.slice(0, 90) + '… (' + text.length + ')');
      }
      return out;
    }""", limit)


def _unnamed(page) -> list[str]:
    return page.evaluate("""() => {
      const out = [];
      for (const el of document.querySelectorAll('button, input, select, textarea, a[href]')) {
        const box = el.getBoundingClientRect();
        if (!box.width || !box.height || el.closest('[hidden]')) continue;
        if (el.type === 'hidden') continue;
        const name = (el.getAttribute('aria-label') || el.innerText || el.value || el.title || '').trim();
        const labelled = el.labels && el.labels.length;
        if (!name && !labelled && !el.getAttribute('aria-labelledby'))
          out.push(el.tagName.toLowerCase() + '#' + (el.id || el.className || '?'));
      }
      return out.slice(0, 12);
    }""")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("password")
    ap.add_argument("--out", default="ui-walk")
    ap.add_argument("--long", type=int, default=_LONG)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    findings: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for label, size in (("desktop", {"width": 1280, "height": 800}),
                            ("phone", {"width": 390, "height": 800})):
            context = browser.new_context(ignore_https_errors=True, viewport=size)
            page = context.new_page()
            problems: list[str] = []
            page.on("pageerror", lambda e: problems.append(f"script error: {str(e)[:120]}"))
            page.on("console", lambda m: problems.append(f"console {m.type}: {m.text[:120]}")
                    if m.type in ("error", "warning") else None)
            page.on("requestfailed", lambda r: problems.append(f"request failed: {r.url[-60:]}"))
            page.goto(args.base)
            page.fill("#password", args.password)
            page.press("#password", "Enter")
            page.wait_for_selector("#nav", state="visible", timeout=15000)
            tabs = page.eval_on_selector_all("#nav [data-tab]", "els => els.map(e => e.dataset.tab)")
            for tab in tabs:
                page.click(f'#nav [data-tab="{tab}"]')
                page.wait_for_timeout(600)
                page.screenshot(path=os.path.join(args.out, f"{label}-{tab}.png"), full_page=True)
                for text in _text_blocks(page, args.long):
                    findings.append(f"[{label}/{tab}] long text: {text}")
                for name in _unnamed(page):
                    findings.append(f"[{label}/{tab}] no accessible name: {name}")
                if label == "phone" and page.evaluate(
                        "document.documentElement.scrollWidth > innerWidth + 1"):
                    findings.append(f"[{label}/{tab}] scrolls sideways")
            findings += [f"[{label}] {p}" for p in dict.fromkeys(problems)]
            context.close()
        browser.close()
    print(f"{len(findings)} findings")
    for line in findings:
        print("  ", line)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
