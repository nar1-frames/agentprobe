import io
import sys

from agentprobe import termstyle


class _Stream(io.StringIO):
    def __init__(self, encoding):
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self):
        return self._encoding


def test_glyph_falls_back_on_non_unicode_console(monkeypatch):
    monkeypatch.setattr(sys, "stdout", _Stream("cp1252"))
    assert termstyle.console_is_unicode() is False
    assert termstyle.glyph("\U0001f534", "[VULNERABLE]") == "[VULNERABLE]"
    assert termstyle.glyph("—", "-") == "-"

    monkeypatch.setattr(sys, "stdout", _Stream("utf-8"))
    assert termstyle.console_is_unicode() is True
    assert termstyle.glyph("\U0001f534", "[VULNERABLE]") == "\U0001f534"
    assert termstyle.glyph("—", "-") == "—"

    monkeypatch.setattr(sys, "stdout", _Stream("UTF-16"))
    assert termstyle.console_is_unicode() is True

    # No encoding attribute at all (some capture objects): treat as non-unicode.
    monkeypatch.setattr(sys, "stdout", _Stream(None))
    assert termstyle.console_is_unicode() is False
    assert termstyle.console_is_unicode(_Stream("utf-8")) is True
