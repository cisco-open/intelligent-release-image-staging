# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local Console Swagger static-serving boundary."""

import http.client
from pathlib import Path
import posixpath
import re
import socket
import threading

import pytest

import gui_server


def _request(port, method, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, headers=headers or {})
    response = conn.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    conn.close()
    return result


def _raw_request(port, method, path, headers=()):
    """Bytes after the header block, read from the socket until EOF.

    http.client returns b"" for every HEAD or 304 without looking at the wire,
    so only a raw read proves the server wrote nothing after the headers."""
    request = "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n" % (
        method, path)
    request += "".join("%s: %s\r\n" % header for header in headers) + "\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request.encode("ascii"))
        raw = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
    head, separator, body = raw.partition(b"\r\n\r\n")
    assert separator, raw
    status = int(head.split(b" ", 2)[1])
    return status, head, body


@pytest.fixture
def console_swagger(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    server = gui_server.make_server(
        "127.0.0.1", 0, "https://127.0.0.1:9",
        str(tmp_path / "unused-tier-token"), str(tmp_path / "unused-ca"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("path, relative, content_type", [
    ("/swagger/", "swagger/index.html", "text/html"),
    ("/swagger/index.html", "swagger/index.html", "text/html"),
    ("/swagger/swagger-ui.css", "swagger/swagger-ui.css", "text/css"),
    ("/swagger/iris-swagger.css", "swagger/iris-swagger.css", "text/css"),
    ("/swagger/swagger-ui-bundle.js", "swagger/swagger-ui-bundle.js",
     "application/javascript"),
    ("/swagger/iris-openapi32.js", "swagger/iris-openapi32.js",
     "application/javascript"),
    ("/swagger/swagger-initializer.js", "swagger/swagger-initializer.js",
     "application/javascript"),
    ("/openapi.yaml", "openapi.yaml", "application/yaml"),
])
def test_console_serves_only_the_bundled_swagger_documents_exactly(
        console_swagger, path, relative, content_type):
    status, headers, body = _request(console_swagger, "GET", path)

    assert status == 200
    assert headers["Content-Type"].startswith(content_type)
    assert headers["Cache-Control"] == "no-cache"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert body == (Path(gui_server.DOCSROOT) / relative).read_bytes()


def test_console_swagger_redirect_and_head_are_canonical(console_swagger):
    status, headers, body = _request(console_swagger, "GET", "/swagger")
    assert status == 308
    assert headers["Location"] == "/swagger/"
    assert headers["Cache-Control"] == "no-cache"
    assert body == b""

    status, headers, body = _request(console_swagger, "HEAD", "/swagger/")
    expected = (Path(gui_server.DOCSROOT) / "swagger/index.html").read_bytes()
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert "img-src 'self' data:" in headers["Content-Security-Policy"]
    assert int(headers["Content-Length"]) == len(expected)
    assert body == b""

    status, headers, body = _request(console_swagger, "HEAD", "/openapi.yaml")
    expected = (Path(gui_server.DOCSROOT) / "openapi.yaml").read_bytes()
    assert status == 200
    assert headers["Content-Type"] == "application/yaml"
    assert int(headers["Content-Length"]) == len(expected)
    assert body == b""


@pytest.mark.parametrize("method, path, headers, expected_status", [
    ("HEAD", "/swagger/", (), 200),
    ("HEAD", "/openapi.yaml", (), 200),
    ("HEAD", "/swagger", (), 308),
    ("GET", "/swagger", (), 308),
    ("HEAD", "/swagger/not-an-asset.js", (), 404),
    ("HEAD", "/swagger/", (("If-Modified-Since", "future"),), 200),
])
def test_console_swagger_writes_no_body_after_headerless_responses(
        console_swagger, method, path, headers, expected_status):
    """HEAD, redirect and 304 responses must end at the header block on the
    wire; a stray body would desynchronise the next response on a connection."""
    if headers and headers[0][1] == "future":
        _, fresh, _ = _request(console_swagger, "GET", path)
        headers = (("If-Modified-Since", fresh["Last-Modified"]),)
        expected_status = 304
    status, head, body = _raw_request(console_swagger, method, path, headers)

    assert status == expected_status
    assert body == b""
    if expected_status == 200:
        assert b"Content-Length: " in head


def test_console_swagger_assets_revalidate_without_an_upstream(console_swagger):
    status, headers, body = _request(console_swagger, "GET", "/swagger/")
    assert status == 200 and body
    status, cached_headers, cached_body = _request(
        console_swagger, "GET", "/swagger/",
        {"If-Modified-Since": headers["Last-Modified"]})
    assert status == 304
    assert cached_headers["Cache-Control"] == "no-cache"
    assert cached_headers["X-Content-Type-Options"] == "nosniff"
    assert "img-src 'self' data:" in cached_headers["Content-Security-Policy"]
    assert cached_body == b""


def test_swagger_document_alone_allows_data_images(console_swagger):
    status, headers, swagger = _request(console_swagger, "GET", "/swagger/")
    assert status == 200
    assert "img-src 'self' data:" in swagger.decode("utf-8")
    assert "img-src 'self' data:" in headers["Content-Security-Policy"]

    status, headers, console = _request(console_swagger, "GET", "/")
    assert status == 200
    assert b"data:" not in console
    assert "data:" not in headers["Content-Security-Policy"]
    assert "default-src 'self'" in headers["Content-Security-Policy"]


@pytest.mark.parametrize("path", [
    "/swagger/not-an-asset.js",
    "/swagger/swagger-ui-bundle.js.LICENSE.txt",
    "/swagger/../openapi.yaml",
    "/swagger/%2e%2e/openapi.yaml",
    "/openapi.yaml/extra",
    "/docs/zensical/openapi.yaml",
])
def test_console_swagger_does_not_expose_unlisted_or_traversal_paths(
        console_swagger, path):
    status, headers, body = _request(console_swagger, "GET", path)

    assert status == 404
    assert headers["Content-Type"] == "application/problem+json"
    assert headers["Cache-Control"] == "no-store"
    assert b"route-not-found" in body


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@pytest.mark.parametrize("path", ["/swagger", "/swagger/", "/swagger/index.html",
                                  "/openapi.yaml"])
def test_console_swagger_serves_nothing_on_other_methods(console_swagger, method,
                                                         path):
    """The documented contract: only GET and HEAD are public documentation.

    Every other method keeps the Console's unknown-route handling. The fixture's
    upstream is unreachable, so a 404 (not 503) proves no proxy request left."""
    status, headers, body = _request(console_swagger, method, path,
                                     {"Content-Length": "0"})

    assert status == 404
    assert headers["Content-Type"] == "application/problem+json"
    assert headers["Cache-Control"] == "no-store"
    assert b"route-not-found" in body


def test_console_swagger_redirect_carries_security_headers(console_swagger):
    status, headers, body = _request(console_swagger, "GET", "/swagger")
    assert status == 308
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "data:" not in headers["Content-Security-Policy"]

    status, headers, body = _request(console_swagger, "HEAD", "/swagger")
    assert status == 308
    assert headers["Location"] == "/swagger/"
    assert body == b""

    status, headers, body = _request(console_swagger, "HEAD",
                                     "/swagger/not-an-asset.js")
    assert status == 404
    assert headers["Content-Type"] == "application/problem+json"
    assert body == b""


def test_console_streams_large_documents_in_chunks(console_swagger, monkeypatch):
    """Serving must not depend on holding a whole file: force many small chunks
    and require the exact bytes and Content-Length of the largest documents."""
    monkeypatch.setattr(gui_server, "_STATIC_CHUNK_BYTES", 4096)
    for path, relative in (("/openapi.yaml", "openapi.yaml"),
                           ("/swagger/swagger-ui-bundle.js",
                            "swagger/swagger-ui-bundle.js")):
        expected = (Path(gui_server.DOCSROOT) / relative).read_bytes()
        assert len(expected) > 4096 * 8, relative
        status, headers, body = _request(console_swagger, "GET", path)
        assert status == 200
        assert int(headers["Content-Length"]) == len(expected)
        assert body == expected


def _local_references(text):
    """href/src/url targets in a page or initializer that point at local files."""
    found = []
    for value in re.findall(r"""(?:href|src|url)\s*[=:]\s*["']([^"']+)["']""",
                            text):
        if re.match(r"[a-z][a-z0-9+.-]*:", value) or value.startswith(("#", "//")):
            continue
        found.append(value.split("#")[0].split("?")[0])
    return found


def test_swagger_page_assets_route_table_and_image_contents_agree():
    """Three hand-kept lists must describe the same files: what the page loads,
    what the Console routes, and what .dockerignore lets into the image.

    A checkout serves any file under DOCSROOT, so only this cross-check catches
    an asset that renders locally but is missing from the built Console image."""
    import test_dockerignore
    docsroot = Path(gui_server.DOCSROOT)
    swagger_dir = docsroot / "swagger"
    patterns = test_dockerignore.load_patterns()

    # (a) every local reference the page and initializer make is routed
    referenced = set()
    for name in ("swagger/index.html", "swagger/swagger-initializer.js"):
        for target in _local_references((docsroot / name).read_text("utf-8")):
            referenced.add(posixpath.normpath(posixpath.join("/swagger/", target)))
    assert referenced, "no local references found"
    unrouted = referenced - set(gui_server._SWAGGER_STATIC_FILES)
    assert not unrouted, unrouted

    # (b) every routed file exists and survives the build context filter
    for route, relative in gui_server._SWAGGER_STATIC_FILES.items():
        assert (docsroot / relative).is_file(), route
        assert not test_dockerignore.excluded("docs/zensical/" + relative,
                                              patterns), route

    # (c) the directory on disk is exactly the reviewed, image-bound file set
    on_disk = {entry.name for entry in swagger_dir.iterdir()
               if not entry.name.startswith((".", "__"))}
    assert on_disk == set(test_dockerignore.SWAGGER_FILES)
    assert all((swagger_dir / name).is_file() for name in on_disk)
