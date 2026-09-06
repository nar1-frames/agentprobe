import errno

from agentprobe.reliability import is_retryable_error


class RateLimitError(Exception):
    status_code = 429


class AuthError(Exception):
    status_code = 401


class ReadTimeoutError(Exception):
    pass


def test_retry_classifier_accepts_transient_http_and_transport_failures():
    assert is_retryable_error(RateLimitError()) is True
    assert is_retryable_error(ReadTimeoutError()) is True
    assert is_retryable_error(OSError(errno.ECONNRESET, "reset")) is True


def test_retry_classifier_rejects_permanent_authentication_failures():
    assert is_retryable_error(AuthError()) is False
    assert is_retryable_error(ValueError("invalid model request")) is False
