import logging


def configure_logging(verbose: int | str = 0) -> None:
    """Configure root logger verbosity.

    - verbose >= 1 -> DEBUG
    - else -> INFO
    """
    level = logging.INFO
    try:
        v = int(verbose)
        if v >= 1:
            level = logging.DEBUG
    except Exception:
        pass

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    logging.getLogger().setLevel(level)
