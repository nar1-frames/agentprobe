"""Scan an agent by calling a Python function directly, with no HTTP wrapper.

An agent built in Python (LangChain, LlamaIndex, a hand-rolled loop) usually
has a function that takes a user message and returns the reply. This adapter
imports that function into the scanner process and makes it look like a
chat-completions client, so the scanner, the record/replay layer, and the
reports work unchanged. Configuration (all under ``target.python``):

- ``callable`` (required): ``"package.module:function"``. The part after the
  colon may be a dotted attribute path, for example ``"app:agent.answer"``.
- ``cwd`` (optional): a directory put first on ``sys.path`` before the import.
  A relative path is resolved next to the config file, and the default is the
  config file's own directory. The scanner's working directory never changes.
- ``messages`` (optional, default false): false calls ``function(prompt)``
  with the attack text; true calls ``function(messages)`` with the
  chat-completions message list, including the system message when
  ``target.system_prompt`` is set. Either way the function returns ``str``.

The function may be ``async``. It runs in the scanner process with the
scanner's permissions, so a config that names a python target is code: scan
only configs you trust. An exception from the function, or a reply that is not
text, becomes that attack's operational error and never stops the scan. A
function that cannot be imported stops the scan before any attack is sent.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import inspect
import os
import re
import sys
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Optional

from agentprobe.detection import sanitize_error


_CALLABLE_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_KEYS = frozenset({"callable", "cwd", "messages"})


class PythonTargetError(RuntimeError):
    """The target function failed in a way the scanner records as an operational error."""


def validate_python_block(block: Any, name: str = "target.python") -> dict:
    """Validate the ``python`` settings and return a normalized copy."""

    if not isinstance(block, Mapping):
        raise ValueError(f"{name} must be a mapping")
    unknown = sorted(str(key) for key in set(block) - _KEYS)
    if unknown:
        raise ValueError(f"{name} has unknown keys: {unknown} (allowed: callable, cwd, messages)")
    spec = block.get("callable")
    if not isinstance(spec, str) or not _CALLABLE_RE.match(spec.strip()):
        raise ValueError(f'{name}.callable must look like "package.module:function"')
    cwd = block.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
        raise ValueError(f"{name}.cwd must be a non-empty directory path or null")
    messages = block.get("messages", False)
    if not isinstance(messages, bool):
        raise ValueError(f"{name}.messages must be true or false")
    return {"callable": spec.strip(), "cwd": cwd.strip() if cwd else None, "messages": messages}


def load_callable(spec: str, cwd: Optional[str] = None) -> Callable[[Any], Any]:
    """Import ``package.module:function`` with ``cwd`` first on ``sys.path``."""

    if not isinstance(spec, str) or not _CALLABLE_RE.match(spec.strip()):
        raise ValueError(f'python target callable must look like "package.module:function", '
                         f"not {spec!r}")
    module_name, _, attribute_path = spec.strip().partition(":")
    if cwd is not None:
        cwd = os.path.abspath(cwd)
        if not os.path.isdir(cwd):
            raise ValueError(f"python target cwd is not a directory: {cwd}")
        if cwd not in sys.path:
            sys.path.insert(0, cwd)
    try:
        target: Any = importlib.import_module(module_name)
        for part in attribute_path.split("."):
            target = getattr(target, part)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # noqa: BLE001 - importing runs the module's code, even sys.exit()
        raise ValueError(
            f"python target could not load {spec!r}: {type(exc).__name__}: {sanitize_error(exc)}"
        ) from None
    if not callable(target):
        raise ValueError(f"python target {spec!r} is not callable")
    try:
        inspect.signature(target).bind("attack text")
    except TypeError:
        raise ValueError(
            f"python target {spec!r} must accept one positional argument "
            "(the prompt, or the message list with python.messages: true)"
        ) from None
    except ValueError:
        pass  # no introspectable signature (some builtins); the first call will tell
    return target


def _last_user_message(messages: Any) -> str:
    if not isinstance(messages, (list, tuple)) or not messages:
        raise ValueError("python target request must include messages")
    prompt = None
    for message in messages:
        if not isinstance(message, Mapping):
            raise ValueError("python target messages must be objects")
        if message.get("role") == "user" and isinstance(message.get("content"), str):
            prompt = message["content"]  # the last user turn is the attack
    if prompt is None:
        raise ValueError("python target request has no user message to send")
    return prompt


async def _await(awaitable: Any) -> Any:
    return await awaitable


class _PythonCompletions:
    def __init__(self, client: "PythonTargetClient"):
        self._client = client

    def create(self, **request: Any) -> SimpleNamespace:
        text = self._client.call(request)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


class PythonTargetClient:
    """Drive a Python function through the chat-completions shape.

    There is deliberately no ``models`` attribute: the scanner's model
    preflight skips clients without one, because a function does not
    advertise which model it calls.
    """

    def __init__(self, function: Callable[[Any], Any], *, messages: bool = False,
                 spec: str = "<function>"):
        if not callable(function):
            raise ValueError("python target function must be callable")
        self.function = function
        self.messages = bool(messages)
        self.spec = spec
        self.chat = SimpleNamespace(completions=_PythonCompletions(self))

    def argument(self, chat_request: Mapping[str, Any]) -> Any:
        """Return what the function is called with. Pure; used by tests."""

        messages = chat_request.get("messages")
        if self.messages:
            _last_user_message(messages)  # same shape check as prompt mode
            # A copy, so the function cannot change the request a recording keys on.
            return [dict(message) for message in copy.deepcopy(list(messages))]
        return _last_user_message(messages)

    def call(self, chat_request: Mapping[str, Any]) -> str:
        argument = self.argument(chat_request)
        try:
            result = self.function(argument)
            if inspect.isawaitable(result):
                result = asyncio.run(_await(result))
        except (KeyboardInterrupt, Exception):
            # Exceptions pass through unchanged, so the scanner's retry policy
            # can classify a provider's rate limit or timeout raised inside the
            # function; send_prompt records the rest as operational errors.
            raise
        except BaseException as exc:  # noqa: BLE001 - sys.exit() in a target must not end the scan
            raise PythonTargetError(
                f"target function raised {type(exc).__name__}: {sanitize_error(exc)}"
            ) from None
        if not isinstance(result, str):
            raise PythonTargetError(
                f"target function returned {type(result).__name__}, expected str"
            )
        return result


def build_python_target(provider_config: Mapping[str, Any]) -> PythonTargetClient:
    """Import the function named by a validated ``target`` block."""

    settings = validate_python_block(provider_config.get("python"))
    function = load_callable(settings["callable"], settings["cwd"])
    return PythonTargetClient(function, messages=settings["messages"], spec=settings["callable"])
