from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def load_pin_store(path: str | Path) -> dict:
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("pins"), dict):
        raise ValueError("pin store must be an object with pins")
    for host, ips in data["pins"].items():
        if not isinstance(host, str) or not isinstance(ips, list):
            raise ValueError("pins must map host to a list of ip strings")
        if not all(isinstance(item, str) for item in ips):
            raise ValueError("pin addresses must be strings")
    return data


def load_resolver(path: str | Path) -> dict:
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("answers"), dict):
        raise ValueError("resolver snapshot must be an object with answers")
    return data


def load_policy(path: str | Path) -> dict:
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError("policy must be an object")
    return data
