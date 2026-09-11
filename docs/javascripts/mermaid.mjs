// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
// Runtime dependency: Mermaid, MIT License. See NOTICE.
//
// PINNED TO AN EXACT VERSION, deliberately. The import used to read `mermaid@11`
// -- a floating range jsDelivr resolved at request time, so every reader of the
// published site executed whatever that range returned that day, two builds of
// the same commit could render with different Mermaid versions, and a breaking
// change inside 11.x would silently alter every diagram with no repo change.
// The rest of this repository pins exactly (zensical==0.0.51, the aria2c
// sha256, the ioxclient sha256, the XR base image by digest); this now matches.
//
//   Version:  11.17.2
//   Entry:    https://cdn.jsdelivr.net/npm/mermaid@11.17.2/dist/mermaid.esm.min.mjs
//   sha256:   462d6f73fc9833044bca6dc08e62e0ee83f5a2b09583f588f95d5fd91b1960ed
//   sha384:   WpV0mnoAILtx5vne0am/qjdpWLSB/nef78GMd221pz6JKoZNgONGZbSu4ppDDPx/
//             (base64, i.e. the SRI digest, recorded so a reviewer can verify
//             the bytes this site loads; a bare ES-module `import` cannot carry
//             an integrity attribute, which is why the version pin -- not SRI --
//             is what actually constrains what runs here.)
//
// The entry module imports its chunks by RELATIVE path, so pinning the entry
// pins the whole dist tree at the same version. To move versions: fetch the new
// entry, record its digests above, and update all three of the version, the URL
// and the digests together.
//
// Air-gapped and proxied deployments: this import is the ONLY network fetch the
// documentation site makes. Where it cannot be reached, every diagram degrades
// to its raw code block and the failure is visible only in the browser console
// (see the catch below). Vendoring the whole dist tree would remove that, at the
// cost of carrying Mermaid's chunk set in-repo.

import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11.17.2/dist/mermaid.esm.min.mjs";

mermaid.initialize({
  startOnLoad: false,
  securityLevel: "strict",
});

window.mermaid = mermaid;

let renderQueued = false;

function normalizeMermaidBlocks() {
  const normalized = [];

  for (const block of document.querySelectorAll("pre.mermaid")) {
    const source = block.querySelector("code")?.textContent || block.textContent;
    const diagram = document.createElement("div");
    diagram.className = "mermaid";
    diagram.textContent = source.trim();
    block.replaceWith(diagram);
    normalized.push(diagram);
  }

  return normalized;
}

function queueMermaidRender() {
  if (renderQueued) return;

  renderQueued = true;

  window.requestAnimationFrame(() => {
    renderQueued = false;

    const normalized = normalizeMermaidBlocks();
    const existing = Array.from(
      document.querySelectorAll(".mermaid:not([data-processed])"),
    ).filter((node) => node.textContent.trim().length > 0);
    const nodes = [...new Set([...normalized, ...existing])];

    if (!nodes.length) return;

    mermaid.run({ nodes }).catch((error) => {
      console.error("Mermaid render failed", error?.message || error);
    });
  });
}

if (window.document$) {
  window.document$.subscribe(queueMermaidRender);
} else {
  window.addEventListener("DOMContentLoaded", queueMermaidRender);
}

queueMermaidRender();
