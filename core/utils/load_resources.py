from __future__ import annotations
import json
from pathlib import Path

BASE = Path(__file__).absolute().parent.parent.parent

def resources_credential_path(filename):
    return BASE / "resources" / "credentials" / filename

def load_credential_resource(filename):
    path = resources_credential_path(filename)
    with path.open() as f:
        return json.load(f)