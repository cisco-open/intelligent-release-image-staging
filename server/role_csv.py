# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Role-definition CSV grammar shared by ``iris-role`` and the Console.

One parser and one writer, so a file exported from either surface imports
unchanged in the other. Lists use semicolons, rates are bytes/second,
``*_s`` fields are seconds, and a blank cell inherits the default.
"""
import csv
import io
import ipaddress

import peer_policy


ROLE_QOS_FIELDS = (
    "max_peers", "per_peer_bps", "fanout", "seed_up_bps",
    "seed_down_bps", "leech_up_bps", "leech_down_bps", "overall_up_bps",
    "overall_down_bps", "max_concurrent", "request_peer_speed_limit_bps",
    "announce_min_interval_s", "numwant", "handout_budget",
    "catalog_tick_s", "telemetry_every_ticks", "telemetry_pause")
ROLE_CSV_FIELDS = (
    "role", "restricted", "peers", "origin", "nets", "on_stale",
    *ROLE_QOS_FIELDS)


class RolesCsvError(ValueError):
    """The CSV text cannot describe a role set; the message names the cell."""


def parse_bool(value, field, blank=None):
    value = str(value or "").strip().lower()
    if not value and blank is not None:
        return blank
    if value == "true":
        return True
    if value == "false":
        return False
    raise RolesCsvError("%s must be true or false" % field)


def parse_qos_value(name, value):
    if name == "telemetry_pause":
        return parse_bool(value, name)
    try:
        if not str(value).strip() or any(c in str(value) for c in ".eE"):
            raise ValueError
        return int(value)
    except (TypeError, ValueError):
        raise RolesCsvError("%s must be an integer" % name) from None


def parse_nets(values):
    result = []
    seen = set()
    for value in values or ():
        try:
            canonical = str(ipaddress.IPv4Network(value, strict=False))
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError,
                ValueError):
            raise RolesCsvError("invalid role network: %s" % value) from None
        if canonical in seen:
            raise RolesCsvError("duplicate role network: %s" % canonical)
        seen.add(canonical)
        result.append(value)
    return result


def parse_roles_csv(text):
    """Return ``{name: definition}`` for a complete, cross-validated role set.

    Raises :class:`RolesCsvError` for a grammar problem (the message names
    the row or field) and :class:`peer_policy.PolicyError` for a policy
    refusal such as an unknown peer, so callers can keep the two apart.
    """
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "role" not in reader.fieldnames:
        raise RolesCsvError("roles CSV requires a role header")
    unknown = set(reader.fieldnames) - set(ROLE_CSV_FIELDS)
    if unknown:
        raise RolesCsvError("unknown roles CSV field: %s" % sorted(unknown)[0])
    definitions = {}
    for number, row in enumerate(reader, 2):
        name = str(row.get("role") or "").strip()
        if not name:
            if any(str(value or "").strip() for value in row.values()):
                raise RolesCsvError("row %d has no role" % number)
            continue
        peer_policy.validate_role_name(name)
        if name in definitions:
            raise RolesCsvError("duplicate role: %s" % name)
        definition = {
            "restricted": parse_bool(row.get("restricted"), "restricted", False)}
        peers = [item.strip() for item in
                 str(row.get("peers") or "").split(";") if item.strip()]
        definition["peers"] = peers or [name]
        origin = str(row.get("origin") or "").strip()
        if origin:
            definition["origin"] = parse_bool(origin, "origin")
        nets = [item.strip() for item in
                str(row.get("nets") or "").split(";") if item.strip()]
        if nets:
            definition["nets"] = parse_nets(nets)
        on_stale = str(row.get("on_stale") or "").strip()
        if on_stale:
            definition["on_stale"] = on_stale
        qos = {}
        for field in ROLE_QOS_FIELDS:
            value = row.get(field)
            if value is not None and str(value).strip():
                qos[field] = parse_qos_value(field, value)
        if qos:
            definition["qos"] = qos
        definitions[name] = definition
    # Validate all cross-role references before a store exists or changes.
    candidate = peer_policy.base_document()
    candidate["roles"] = {"defs": definitions, "role_of": {},
                          "qos_default": {}, "qos_device": {}}
    candidate["roles_present"] = True
    peer_policy.validate_document(candidate)
    return definitions


def export_roles_csv(document):
    """Render the document's role definitions in the import grammar."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=ROLE_CSV_FIELDS,
                            lineterminator="\n")
    writer.writeheader()
    definitions = document.get("roles", {}).get("defs", {})
    for name in sorted(definitions):
        definition = definitions[name]
        row = {
            "role": name,
            "restricted": str(bool(definition.get("restricted", False))).lower(),
            "peers": ";".join(definition.get("peers", [name])),
            "origin": (str(definition["origin"]).lower()
                       if "origin" in definition else ""),
            "nets": ";".join(definition.get("nets", [])),
            "on_stale": definition.get("on_stale", ""),
        }
        for key, value in definition.get("qos", {}).items():
            if key in ROLE_QOS_FIELDS:
                row[key] = str(value).lower() if isinstance(value, bool) else value
        writer.writerow(row)
    return output.getvalue()
