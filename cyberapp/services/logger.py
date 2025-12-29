import logging
import os

from flask import g, has_request_context


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        if has_request_context() and hasattr(g, "request_id"):
            record.request_id = g.request_id
        else:
            record.request_id = "-"
        return True


def get_logger(name="monolith"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level_name = os.getenv("MONOLITH_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)

    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s: %(message)s"
    )
    handler.setFormatter(formatter)
    handler.addFilter(RequestIdFilter())
    logger.addHandler(handler)

    return logger
