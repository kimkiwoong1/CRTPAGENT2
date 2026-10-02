"""
bh_loader.py — SOAPHound / BloodHound JSON loader & normalizer.

SOAPHound exports BloodHound-compatible JSON (SharpHound-style):
  *_users.json, *_groups.json, *_computers.json, *_domains.json,
  *_gpos.json, *_ous.json, *_containers.json

This module reads any/all of those from an input directory and returns a
single normalized in-memory model that the CRTP analyzer consumes.

It tolerates BloodHound legacy (v3) and CE/v4-v5 layouts:
  - top-level "data" list vs. type-named list (e.g. "users")
  - "Properties" nested vs. flat
  - ACEs under "Aces" with ("PrincipalSID","RightName","IsInherited")

No external dependencies. Python 3.9+.
"""

from __future__ import annotations
import json
import glob
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# BloodHound "type" tokens we care about, mapped to file glob hints.
OBJECT_TYPES = ["users", "groups", "computers", "domains", "gpos", "ous", "containers"]


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8-sig") as fh:  # utf-8-sig handles BOM
        return json.load(fh)


def _extract_list(blob: Any, type_hint: str) -> List[dict]:
    """BloodHound files wrap records under 'data' (v3/CE) or a type key."""
    if isinstance(blob, list):
        return blob
    if isinstance(blob, dict):
        if isinstance(blob.get("data"), list):
            return blob["data"]
        if isinstance(blob.get(type_hint), list):
            return blob[type_hint]
        # last resort: first list value found
        for v in blob.values():
            if isinstance(v, list):
                return v
    return []


def _props(rec: dict) -> dict:
    """Return the Properties dict (case-insensitive-ish), flat-fallback."""
    p = rec.get("Properties") or rec.get("properties")
    if isinstance(p, dict):
        return {k.lower(): v for k, v in p.items()}
    # some exports keep props flat on the record
    return {k.lower(): v for k, v in rec.items() if not isinstance(v, (dict, list))}


def _aces(rec: dict) -> List[dict]:
    out = []
    for ace in rec.get("Aces") or rec.get("aces") or []:
        if not isinstance(ace, dict):
            continue
        out.append({
            "principal_sid": ace.get("PrincipalSID") or ace.get("principalSID"),
            "principal_type": ace.get("PrincipalType") or ace.get("principalType"),
            "right": ace.get("RightName") or ace.get("rightName"),
            "inherited": ace.get("IsInherited", ace.get("isInherited", False)),
        })
    return out


@dataclass
class ADObject:
    kind: str                    # user | group | computer | domain | gpo | ou | container
    sid: Optional[str]
    name: Optional[str]          # UPN / samaccountname / dns
    props: Dict[str, Any] = field(default_factory=dict)
    aces: List[dict] = field(default_factory=list)     # who has rights OVER this object
    raw: dict = field(default_factory=dict)

    def p(self, key: str, default=None):
        return self.props.get(key.lower(), default)


@dataclass
class Model:
    domain: Optional[str] = None
    domain_sid: Optional[str] = None
    users: Dict[str, ADObject] = field(default_factory=dict)
    groups: Dict[str, ADObject] = field(default_factory=dict)
    computers: Dict[str, ADObject] = field(default_factory=dict)
    domains: Dict[str, ADObject] = field(default_factory=dict)
    gpos: Dict[str, ADObject] = field(default_factory=dict)
    ous: Dict[str, ADObject] = field(default_factory=dict)
    containers: Dict[str, ADObject] = field(default_factory=dict)
    sid_index: Dict[str, ADObject] = field(default_factory=dict)  # sid -> object (any kind)
    warnings: List[str] = field(default_factory=list)

    def all_objects(self):
        for bucket in (self.users, self.groups, self.computers, self.domains,
                       self.gpos, self.ous, self.containers):
            yield from bucket.values()

    def name_for(self, sid: Optional[str]) -> str:
        if not sid:
            return "<unknown>"
        obj = self.sid_index.get(sid)
        return obj.name if obj and obj.name else sid


def _mk(kind: str, rec: dict) -> ADObject:
    p = _props(rec)
    sid = rec.get("ObjectIdentifier") or rec.get("objectid") or p.get("objectid") or p.get("sid")
    name = (p.get("name") or p.get("distinguishedname") or p.get("samaccountname")
            or rec.get("Properties", {}).get("name") if isinstance(rec.get("Properties"), dict) else None)
    name = name or p.get("name") or sid
    return ADObject(kind=kind, sid=sid, name=name, props=p, aces=_aces(rec), raw=rec)


def load(input_dir: str) -> Model:
    """Load every *_<type>.json under input_dir into a normalized Model."""
    m = Model()
    found_any = False

    for t in OBJECT_TYPES:
        # match  something_users.json / users.json / 20250101_users.json
        matches = sorted(set(
            glob.glob(os.path.join(input_dir, f"*{t}.json"))
            + glob.glob(os.path.join(input_dir, f"*_{t}.json"))
        ))
        bucket = getattr(m, t)
        for path in matches:
            try:
                blob = _read_json(path)
            except Exception as e:  # noqa
                m.warnings.append(f"failed to read {os.path.basename(path)}: {e}")
                continue
            found_any = True
            singular = {
                "users": "user", "groups": "group", "computers": "computer",
                "domains": "domain", "gpos": "gpo", "ous": "ou",
                "containers": "container",
            }[t]
            for rec in _extract_list(blob, t):
                if not isinstance(rec, dict):
                    continue
                obj = _mk(singular, rec)
                key = obj.sid or obj.name or str(len(bucket))
                bucket[key] = obj
                if obj.sid:
                    m.sid_index[obj.sid] = obj

    if not found_any:
        m.warnings.append(f"no BloodHound JSON files found under {input_dir}")

    # derive domain identity
    if m.domains:
        dom = next(iter(m.domains.values()))
        m.domain = dom.name
        m.domain_sid = dom.sid
    elif m.users:
        # infer from a user SID (strip RID)
        any_sid = next((u.sid for u in m.users.values() if u.sid and u.sid.startswith("S-1-5-21")), None)
        if any_sid:
            m.domain_sid = "-".join(any_sid.split("-")[:7])

    return m


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    model = load(d)
    print(f"domain={model.domain} sid={model.domain_sid}")
    print(f"users={len(model.users)} groups={len(model.groups)} "
          f"computers={len(model.computers)} domains={len(model.domains)} "
          f"gpos={len(model.gpos)} ous={len(model.ous)} containers={len(model.containers)}")
    for w in model.warnings:
        print("WARN:", w)
