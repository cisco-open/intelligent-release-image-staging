# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Structural contract for the agent-distribution exemption.

Enrollment and delivery of the agent must remain reachable before a device has
role, peer-policy, or QoS state.  These tests inspect executable structure and
validated interfaces rather than comments or broad source substrings.

Instruction parsing, agent cadence, and peer hand-out budgets do not exist in
Phase 0.  Their exemption checks belong to the tasks that introduce them.
"""
import ast
from dataclasses import fields
from pathlib import Path
import re
import shlex

import pytest

import api_routes
import peer_policy


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_ROOT = REPO_ROOT / "server"

PYTHON_DISTRIBUTION_ROOTS = (
    SERVER_ROOT / "artifact_server.py",
    SERVER_ROOT / "iris-mint-enrollment",
)

SHELL_DISTRIBUTION_ROOTS = tuple(REPO_ROOT / name for name in (
    "server/pack-agent-bundle.sh",
    "server/provision-served.sh",
    "tools/make-agent-bundle.sh",
    "tools/gen-device-installers.sh",
    "device/device-install.sh",
    "device/router-install.sh",
    "device/iox/install.sh",
    "device/xr-install.sh",
    "device/bootstrap.sh",
    "device/guestshell-start.sh",
))

# Phase-0 policy implementations that agent distribution must not import,
# directly or through a local helper.  origin_qos is added by Task 5; naming it
# here ensures that merge cannot quietly put the artifact path behind shaping.
FORBIDDEN_LOCAL_MODULES = frozenset(("peer_policy", "origin_qos"))

# Exact executable identifiers and configuration keys, not English substrings.
# Deriving the QoS portion from the production grammar keeps all 21 Phase-0
# controls covered as that grammar is integrated across branches.
PHASE0_QOS_KEYS = frozenset(peer_policy.QOS_DEFAULTS)
FORBIDDEN_CONTROL_KEYS = frozenset((
    "peer_policy", "origin_qos", "role", "roles", "role_of", "qos",
    "qos_default", "qos_device", "compile_roles", "compile_qos",
    "compile_origin_qos", "instructions", "get_instructions",
)) | PHASE0_QOS_KEYS

FORBIDDEN_QOS_KEY_STEMS = (
    "http", "https", "artifact", "artifact_server", "onboard", "onboarding",
    "enroll", "enrollment", "token_refresh", "token-refresh",
)

FORBIDDEN_SHELL_VARIABLES = frozenset((
    "ROLE", "ROLES", "QOS", "INSTRUCTIONS", "PEER_POLICY", "ORIGIN_QOS",
    "IRIS_ROLE", "IRIS_ROLES", "IRIS_QOS", "IRIS_INSTRUCTIONS",
    "IRIS_PEER_POLICY", "IRIS_ORIGIN_QOS",
)) | frozenset("IRIS_" + key.upper() for key in peer_policy.QOS_DEFAULTS)

FORBIDDEN_SHELL_OPTIONS = frozenset((
    "--max-overall-upload-limit", "--max-overall-download-limit",
    "--max-upload-limit", "--max-download-limit",
    "--bt-request-peer-speed-limit", "--bt-tracker-interval",
))

FORBIDDEN_ENDPOINT_PATTERNS = (
    re.compile(r"/(?:api/|internal/)?v1/peer-policy(?:[/?]|$)"),
    re.compile(r"/api/peer-policy(?:[/?]|$)"),
    re.compile(r"/v1/devices/[^/\s]+/instructions(?:[/?]|$)"),
)


def _tree(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _server_modules():
    """Map flat local import names to the source file Python executes."""
    modules = {path.stem: path for path in SERVER_ROOT.glob("*.py")}
    modules["iris-mint-enrollment"] = SERVER_ROOT / "iris-mint-enrollment"
    return modules


def _imported_modules(path):
    found = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".", 1)[0])
    return found


def _local_imports(path, module_names):
    return _imported_modules(path) & module_names


def _reachable_local_modules(start, modules):
    reached = set()
    pending = [start]
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        pending.extend(_local_imports(modules[name], set(modules)) - reached)
    return reached


def _identifiers(node):
    names = ({item.id for item in ast.walk(node)
              if isinstance(item, ast.Name)} |
             {item.attr for item in ast.walk(node)
              if isinstance(item, ast.Attribute)} |
             {item.arg for item in ast.walk(node) if isinstance(item, ast.arg)} |
             {item.arg for item in ast.walk(node)
              if isinstance(item, ast.keyword) and item.arg is not None})
    return names


def _literal_string(node):
    return node.value if isinstance(node, ast.Constant) \
        and isinstance(node.value, str) else None


def _configuration_keys(node):
    """Return exact keys used in executable mapping/key contexts."""
    keys = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Dict):
            keys.update(value for value in map(_literal_string, item.keys)
                        if value is not None)
        elif isinstance(item, ast.MatchMapping):
            keys.update(value for value in map(_literal_string, item.keys)
                        if value is not None)
        elif isinstance(item, ast.Subscript):
            value = _literal_string(item.slice)
            if value is not None:
                keys.add(value)
        elif isinstance(item, ast.Compare) and any(
                isinstance(operator, (ast.In, ast.NotIn))
                for operator in item.ops):
            value = _literal_string(item.left)
            if value is not None:
                keys.add(value)
        elif isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) \
                and item.func.attr in ("get", "setdefault", "pop") \
                and item.args:
            value = _literal_string(item.args[0])
            if value is not None:
                keys.add(value)
    return keys


def _docstring_nodes(node):
    ignored = set()
    for item in ast.walk(node):
        if isinstance(item, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)) and item.body:
            first = item.body[0]
            if isinstance(first, ast.Expr) and isinstance(
                    first.value, ast.Constant) and isinstance(
                        first.value.value, str):
                ignored.add(id(first.value))
    return ignored


def _endpoint_literals(node):
    """Inspect executable string constants, excluding all AST docstrings."""
    ignored = _docstring_nodes(node)
    return {
        item.value for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
        and id(item) not in ignored
        and any(pattern.search(item.value)
                for pattern in FORBIDDEN_ENDPOINT_PATTERNS)
    }


def _control_violations(node, inspect_endpoints=True):
    used = _identifiers(node) | _configuration_keys(node)
    violations = used & FORBIDDEN_CONTROL_KEYS
    if inspect_endpoints:
        violations |= _endpoint_literals(node)
    return violations


def _function(tree, name, class_name=None):
    scope = tree
    if class_name is not None:
        scope = next(node for node in tree.body
                     if isinstance(node, ast.ClassDef) and node.name == class_name)
    matches = [node for node in scope.body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == name]
    assert len(matches) == 1, "%s must have exactly one definition" % name
    return matches[0]


def _dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _calls(node, dotted_name):
    return [item for item in ast.walk(node)
            if isinstance(item, ast.Call)
            and _dotted_name(item.func) == dotted_name]


def _reachable_local_callables(tree, roots, class_name):
    """Walk only helpers called by the named functions, not all of catalog."""
    module_functions = {
        node.name: node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == class_name)
    class_methods = {
        "self." + node.name: node for node in cls.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    local = dict(module_functions)
    local.update(class_methods)
    reached = []
    pending = list(roots)
    seen = set()
    while pending:
        node = pending.pop()
        marker = (node.lineno, node.name)
        if marker in seen:
            continue
        seen.add(marker)
        reached.append(node)
        aliases = {}
        changed = True
        while changed:
            changed = False
            for assignment in (item for item in ast.walk(node)
                               if isinstance(item, (ast.Assign, ast.AnnAssign))):
                targets = (assignment.targets if isinstance(assignment, ast.Assign)
                           else [assignment.target])
                source = _dotted_name(assignment.value)
                source = aliases.get(source, source)
                if source not in local:
                    continue
                for target in targets:
                    if isinstance(target, ast.Name) \
                            and aliases.get(target.id) != source:
                        aliases[target.id] = source
                        changed = True
        for call in (item for item in ast.walk(node)
                     if isinstance(item, ast.Call)):
            called = _dotted_name(call.func)
            target = local.get(aliases.get(called, called))
            if target is not None:
                pending.append(target)
    return reached


def _contains(container, child):
    return any(item is child for item in ast.walk(container))


def _shell_tokens(path):
    lexer = shlex.shlex(path.read_text(encoding="utf-8"), posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def _shell_variables(tokens):
    found = set()
    for token in tokens:
        assigned = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", token)
        if assigned:
            found.add(assigned.group(1))
        found.update(re.findall(
            r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", token))
    return found


def _shell_control_violations(tokens):
    variables = _shell_variables(tokens)
    options = {token.split("=", 1)[0] for token in tokens
               if token.startswith("--")}
    violations = ((variables & FORBIDDEN_SHELL_VARIABLES) |
                  (options & FORBIDDEN_SHELL_OPTIONS))
    for token in tokens:
        if "aria2.changeGlobalOption" in token \
                or "aria2.changeOption" in token \
                or any(pattern.search(token)
                       for pattern in FORBIDDEN_ENDPOINT_PATTERNS):
            violations.add(token)
    return violations


def _qos_document(scope, key):
    doc = peer_policy.base_document()
    doc["roles"] = {
        "defs": {"fleet": {"restricted": False, "peers": ["fleet"]}},
        "role_of": {"device-1": "fleet"},
        "qos_default": {},
        "qos_device": {},
    }
    if scope == "global":
        doc["roles"]["qos_default"][key] = 1
    elif scope == "role":
        doc["roles"]["defs"]["fleet"]["qos"] = {key: 1}
    else:
        doc["roles"]["qos_device"]["device-1"] = {key: 1}
    return doc


def test_distribution_python_roots_cannot_reach_policy_modules():
    modules = _server_modules()
    for path in PYTHON_DISTRIBUTION_ROOTS:
        start = path.stem if path.suffix else path.name
        reached = _reachable_local_modules(start, modules)
        assert not reached & FORBIDDEN_LOCAL_MODULES, (path, sorted(reached))
        for name in reached:
            forbidden_imports = (_imported_modules(modules[name]) &
                                 FORBIDDEN_LOCAL_MODULES)
            assert not forbidden_imports, (
                modules[name], sorted(forbidden_imports))


def test_all_reachable_distribution_modules_reference_no_policy_controls():
    modules = _server_modules()
    for path in PYTHON_DISTRIBUTION_ROOTS:
        start = path.stem if path.suffix else path.name
        reached = _reachable_local_modules(start, modules)
        for name in reached:
            # api_routes is a shared registry and legitimately declares policy
            # routes for another service. Artifact route metadata has its own
            # scoped assertion below; do not mistake unrelated route literals
            # for an artifact-server dependency.
            inspect_endpoints = name != "api_routes"
            violations = _control_violations(
                _tree(modules[name]), inspect_endpoints=inspect_endpoints)
            assert not violations, (modules[name], sorted(violations))


def test_token_refresh_scope_is_independent_of_policy_controls():
    tree = _tree(SERVER_ROOT / "catalog.py")
    resolver = _function(tree, "_resolve_refresh_auth")
    handler = _function(tree, "_handle_token_refresh", class_name="Catalog")
    scoped = _reachable_local_callables(
        tree, (resolver, handler), class_name="Catalog")
    for node in scoped:
        violations = _control_violations(node)
        assert not violations, (node.name, sorted(violations))
    assert len(_calls(handler, "_resolve_refresh_auth")) == 1


def test_token_refresh_dispatches_to_the_scoped_handler():
    tree = _tree(SERVER_ROOT / "catalog.py")
    route_post = _function(tree, "_route_post", class_name="Catalog")
    calls = _calls(route_post, "self._handle_token_refresh")
    assert len(calls) == 1
    enclosing = [node for node in ast.walk(route_post)
                 if isinstance(node, ast.If) and _contains(node, calls[0])]
    assert any("token-refresh" in {
        item.value for item in ast.walk(node.test)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    } for node in enclosing)


def test_shell_distribution_roots_reference_no_phase0_controls():
    for path in SHELL_DISTRIBUTION_ROOTS:
        tokens = _shell_tokens(path)
        violations = _shell_control_violations(tokens)
        assert not violations, (path, sorted(violations))


def test_artifact_routes_have_no_policy_or_qos_metadata():
    artifact_routes = [route for route in api_routes.ROUTES
                       if route.service == "artifact"]
    assert artifact_routes
    metadata = {field.name for field in fields(api_routes.Route)}
    forbidden = FORBIDDEN_CONTROL_KEYS
    assert not metadata & forbidden
    for route in artifact_routes:
        assert not set(vars(route)) & forbidden


@pytest.mark.parametrize("scope", ("global", "role", "device"))
@pytest.mark.parametrize("stem", FORBIDDEN_QOS_KEY_STEMS)
def test_qos_grammar_rejects_distribution_control_keys(scope, stem):
    with pytest.raises(peer_policy.PolicyError, match="unknown qos key"):
        peer_policy.validate_document(_qos_document(scope, stem + "_bps"))


def test_agent_refresh_precedes_first_catalog_policy_read():
    tree = _tree(REPO_ROOT / "device/agent/iris_agent.py")
    run_once = _function(tree, "run_once")
    refresh_calls = _calls(run_once, "deps.refresh")
    policy_calls = _calls(run_once, "deps.catalog.get_policy")
    assert len(refresh_calls) == 1
    assert len(policy_calls) == 1
    refresh_call = refresh_calls[0]
    policy_call = policy_calls[0]
    assert refresh_call.end_lineno < policy_call.lineno
    refresh_statement = next(index for index, statement in enumerate(run_once.body)
                             if _contains(statement, refresh_call))
    policy_statement = next(index for index, statement in enumerate(run_once.body)
                            if _contains(statement, policy_call))
    assert refresh_statement < policy_statement


# Negative controls for the structural helpers. These source snippets live only
# in pytest's temporary directory; comments/docstrings are deliberate controls
# proving that executable inspection does not degrade into source grep.
def test_graph_scans_local_controls_in_a_transitive_helper(tmp_path):
    root = tmp_path / "root.py"
    helper = tmp_path / "helper.py"
    root.write_text("import helper\nhelper.deliver({})\n", encoding="utf-8")
    helper.write_text(
        '"""role qos max_peers are harmless here in documentation."""\n'
        "# role = qos = max_peers\n"
        "def deliver(config):\n"
        "    role = config.get('origin_up_bps')\n"
        "    return role\n",
        encoding="utf-8")
    modules = {"root": root, "helper": helper}
    reached = _reachable_local_modules("root", modules)
    assert reached == {"root", "helper"}
    assert _control_violations(_tree(helper)) == {
        "role", "origin_up_bps"}


def test_scanner_detects_exact_config_keys_and_endpoint_literals():
    tree = ast.parse(
        '"""config.get("max_peers") and instructions in documentation."""\n'
        "def fetch(config, request):\n"
        "    return (config.get('max_peers'), config['qos'],\n"
        "            request('/v1/devices/device-1/instructions'))\n")
    assert _control_violations(tree) == {
        "max_peers", "qos", "/v1/devices/device-1/instructions"}


def test_token_refresh_callable_walk_resolves_a_simple_local_alias():
    tree = ast.parse(
        "def _resolve_refresh_auth():\n"
        "    return True\n"
        "def _policy_helper(config):\n"
        "    return config.get('numwant')\n"
        "class Catalog:\n"
        "    def _handle_token_refresh(self, config):\n"
        "        callback = _policy_helper\n"
        "        return callback(config)\n")
    resolver = _function(tree, "_resolve_refresh_auth")
    handler = _function(tree, "_handle_token_refresh", class_name="Catalog")
    reached = _reachable_local_callables(
        tree, (resolver, handler), class_name="Catalog")
    assert {node.name for node in reached} == {
        "_resolve_refresh_auth", "_handle_token_refresh", "_policy_helper"}
    assert "numwant" in set().union(
        *(_control_violations(node) for node in reached))


def test_shell_scanner_detects_tracker_cadence_option_without_comments():
    tokens = ["aria2c", "--bt-tracker-interval=60"]
    assert _shell_control_violations(tokens) == {"--bt-tracker-interval"}
