// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
// Runtime dependency: Mermaid, MIT License. See NOTICE.

import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";

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
