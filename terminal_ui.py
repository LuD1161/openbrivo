"""Small dependency-free terminal styling helpers for OpenBrivo."""
from __future__ import annotations

import os
import sys
from typing import TextIO


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"


def supports_color(stream: TextIO | None = None) -> bool:
    stream = stream or sys.stdout
    return (
        os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
        and hasattr(stream, "isatty")
        and stream.isatty()
    )


def paint(text: object, *styles: str, stream: TextIO | None = None) -> str:
    value = str(text)
    return "".join(styles) + value + RESET if styles and supports_color(stream) else value


def banner() -> None:
    print()
    print(paint("  OPENBRIVO", BOLD, CYAN))
    print(paint("  Secure local access for Allegion XE360", DIM))
    print(paint("  ─────────────────────────────────────", BLUE))
    print()


def status(icon: str, label: str, value: object, color: str = WHITE, *, stream: TextIO | None = None) -> None:
    target = stream or sys.stdout
    print(
        f"  {icon}  {paint(f'{label:<18}', BOLD, stream=target)} {paint(value, color, stream=target)}",
        file=target,
    )


def prompt(text: str) -> str:
    return paint(text, BOLD, CYAN)
