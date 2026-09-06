"""Small, provider-agnostic retry classification helpers.

SDKs expose different exception classes, so retry decisions use the stable
parts of their contract: HTTP status codes, well-known transport exception
names, and transient socket errno values. Unknown failures are deliberately
not retried; that avoids multiplying authentication and invalid-request
failures while still allowing a caller-configured retry budget for outages.
"""

import errno


_RETRYABLE_STATUS_CODES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
_RETRYABLE_NAMES = (
    "timeout", "timedout", "connection", "connecterror", "readerror",
    "writeerror", "ratelimit", "serviceunavailable", "internalserver",
    "badgateway", "gatewaytimeout", "remoteprotocol",
)
_RETRYABLE_ERRNOS = frozenset({
    errno.ECONNABORTED, errno.ECONNREFUSED, errno.ECONNRESET,
    errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT, errno.EPIPE,
})
_PERMANENT_MESSAGE_MARKERS = (
    "model_not_found", "model does not exist", "does not exist or you do not have access",
    "invalid api key", "incorrect api key", "authentication failed",
    "permission denied", "invalid request",
)


def _status_code(error):
    for name in ("status_code", "status"):
        value = getattr(error, name, None)
        if isinstance(value, int):
            return value
    response = getattr(error, "response", None)
    value = getattr(response, "status_code", None)
    return value if isinstance(value, int) else None


def is_retryable_error(error) -> bool:
    """Return whether a provider failure is safe to retry."""

    message = str(error).lower()
    if any(marker in message for marker in _PERMANENT_MESSAGE_MARKERS):
        return False
    status = _status_code(error)
    if status in _RETRYABLE_STATUS_CODES:
        return True
    if isinstance(error, (TimeoutError, ConnectionError)):
        return True
    error_name = type(error).__name__.lower()
    if any(marker in error_name for marker in _RETRYABLE_NAMES):
        return True
    # A few test doubles and lightweight adapters surface only a message,
    # rather than an HTTP status attribute. Keep this fallback narrow.
    if any(marker in message for marker in (
        "429", "rate limit", "too many requests", "503 service unavailable",
        "temporarily unavailable",
    )):
        return True
    error_number = getattr(error, "errno", None)
    return isinstance(error_number, int) and error_number in _RETRYABLE_ERRNOS
