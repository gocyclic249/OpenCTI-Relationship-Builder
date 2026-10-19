"""`python -m octirb` entry point; the TUI launches every step this way."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
