from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Prefer Typer when available (better UX + completion), but fall back to
    # argparse when Typer/Click isn't installed.
    from marvain_cli.argparse_app import run as run_argparse

    try:
        from marvain_cli.typer_app import run as run_typer

        return run_typer(argv)
    except ModuleNotFoundError as e:
        # Only fall back for missing Typer/Click. Other missing modules should
        # still surface as real errors.
        if getattr(e, "name", None) not in ("typer", "click"):
            raise
        return run_argparse(argv)
    except ImportError:
        return run_argparse(argv)


if __name__ == "__main__":
    raise SystemExit(main())
