#!/usr/bin/env python3
"""Send a session progress message to Telegram (optional)."""
from __future__ import annotations

import os
import sys

import requests


def main() -> int:
    message = " ".join(sys.argv[1:]) or "WraithWall OSS session update"
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat:
        print("telegram skipped (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)")
        return 0
    response = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat, "text": message, "disable_web_page_preview": True},
        timeout=15,
    )
    print("telegram", response.status_code, response.json().get("ok", False))
    return 0 if response.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())