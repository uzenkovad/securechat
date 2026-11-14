"""Консольний застосунок: вводиш повідомлення — воно йде на сервер зашифрованим."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, TextIO

import httpx

from .channel import SecureChannelClient, SecureChannelError

EXIT_WORDS = {"exit", "quit", "q", "вихід"}


def run_console(
    channel: SecureChannelClient,
    read: Callable[[str], str] = input,
    out: TextIO = sys.stdout,
) -> int:
    """Цикл «введи повідомлення → отримай відповідь». Повертає код завершення."""
    print("Захищений клієнт. Введіть повідомлення для сервера (порожній рядок або 'exit' — вихід).", file=out)
    while True:
        try:
            text = read("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(file=out)
            return 0
        if not text or text.lower() in EXIT_WORDS:
            return 0
        try:
            result = channel.send_message(text)
        except SecureChannelError as exc:
            print(f"Помилка: {exc}", file=out)
            continue
        print(f"Відповідь сервера: {result.reply}", file=out)
        print(f"Номер сесії: {result.session_id}", file=out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securechat-client", description="Клієнт шифрованого каналу (лабораторна №6)")
    parser.add_argument(
        "--server",
        default=os.environ.get("SERVER_URL", "http://127.0.0.1:8000"),
        help="адреса сервера (за замовчуванням http://127.0.0.1:8000 або змінна SERVER_URL)",
    )
    parser.add_argument(
        "--reuse-session",
        action="store_true",
        help="не створювати нову сесію для кожного повідомлення (за замовчуванням — як на діаграмі: нова сесія щоразу)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="не показувати кроки протоколу")
    args = parser.parse_args(argv)

    def show_step(message: str) -> None:
        if not args.quiet:
            print(f"  · {message}")

    with httpx.Client(base_url=args.server, timeout=10.0) as http:
        channel = SecureChannelClient(http, reuse_session=args.reuse_session, on_step=show_step)
        return run_console(channel)


if __name__ == "__main__":
    raise SystemExit(main())
