/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

(() => {
  "use strict";

  const operationMethods = new Set([
    "get", "put", "post", "delete", "options", "head", "patch", "trace", "query",
  ]);

  const appendText = (parent, tagName, value, className) => {
    const node = document.createElement(tagName);
    if (className) node.className = className;
    node.textContent = value;
    parent.appendChild(node);
    return node;
  };

  const pointerToken = (value) => String(value).replaceAll("~", "~0").replaceAll("/", "~1");

  const appendCanonicalDetails = (parent, label, pointer, value, searchText) => {
    const details = document.createElement("details");
    details.dataset.search = searchText.toLowerCase();
    appendText(details, "summary", label);
    appendText(details, "p", `JSON Pointer: ${pointer}`, "iris-json-pointer");

    const renderValue = () => {
      if (!details.open || details.querySelector("pre")) return;
      appendText(details, "pre", JSON.stringify(value, null, 2));
      details.removeEventListener("toggle", renderValue);
    };
    details.addEventListener("toggle", renderValue);
    parent.appendChild(details);
  };

  const appendStreamingResponses = (parent, operations) => {
    const streams = [];
    operations.forEach(({ path, method, operation }) => {
      Object.entries(operation.responses || {}).forEach(([status, response]) => {
        Object.entries((response && response.content) || {}).forEach(([mediaType, media]) => {
          const serialized = Object.entries((media && media.examples) || {})
            .filter(([, example]) => example && Object.hasOwn(example, "serializedValue"));
          if (media && (Object.hasOwn(media, "itemSchema") || serialized.length)) {
            streams.push({ path, method, operation, status, mediaType, media, serialized });
          }
        });
      });
    });
    if (!streams.length) return;

    appendText(parent, "h3", "OpenAPI 3.2 streaming response details");
    appendText(
      parent,
      "p",
      "Swagger UI 5.32.15 does not yet render Media Type Object itemSchema or serializedValue. These values come directly from the loaded canonical contract.",
    );
    streams.forEach(({ path, method, operation, status, mediaType, media, serialized }) => {
      const article = document.createElement("article");
      appendText(article, "h4", `${method.toUpperCase()} ${path} — ${status} ${mediaType}`);
      if (operation.summary) appendText(article, "p", operation.summary);
      const basePointer = `/paths/${pointerToken(path)}/${method}/responses/${pointerToken(status)}/content/${pointerToken(mediaType)}`;
      if (Object.hasOwn(media, "itemSchema")) {
        appendText(article, "p", `JSON Pointer: ${basePointer}/itemSchema`, "iris-json-pointer");
        appendText(article, "pre", JSON.stringify(media.itemSchema, null, 2));
      }
      serialized.forEach(([name, example]) => {
        appendText(
          article,
          "p",
          `Serialized example ${name} — JSON Pointer: ${basePointer}/examples/${pointerToken(name)}/serializedValue`,
          "iris-json-pointer",
        );
        appendText(article, "pre", String(example.serializedValue));
      });
      parent.appendChild(article);
    });
  };

  window.renderIrisOpenAPI32 = (spec) => {
    const target = document.getElementById("iris-streaming-responses");
    if (!target || !spec || !spec.paths) return;
    // Swagger may complete more than once (for example after reloading a spec).
    // Replace the previous explorer and its listeners instead of appending it.
    target.replaceChildren();

    const operations = [];
    Object.entries(spec.paths).forEach(([path, pathItem]) => {
      Object.entries(pathItem || {}).forEach(([method, operation]) => {
        if (operationMethods.has(method.toLowerCase()) && operation) {
          operations.push({ path, method: method.toLowerCase(), operation });
        }
      });
    });

    appendText(target, "h2", "Endpoint and schema definitions");
    appendText(
      target,
      "p",
      "Exact definitions from the OpenAPI 3.2 contract. Includes JSON Schema 2020-12 conditionals and streaming examples that Swagger previews may omit.",
    );
    const rawLink = document.createElement("a");
    rawLink.href = "../openapi.yaml";
    rawLink.textContent = "Open the complete raw OpenAPI 3.2 contract";
    target.appendChild(rawLink);

    const filterLabel = document.createElement("label");
    filterLabel.className = "iris-schema-filter";
    filterLabel.append("Find an endpoint or schema ");
    const filter = document.createElement("input");
    filter.type = "search";
    filter.placeholder = "path, method, operation ID, or component";
    filterLabel.appendChild(filter);
    target.appendChild(filterLabel);
    const searchStatus = appendText(target, "p", "", "iris-search-status");
    searchStatus.setAttribute("role", "status");

    appendText(target, "h3", `Operations (${operations.length})`);
    const operationList = document.createElement("div");
    operationList.className = "iris-canonical-list";
    operations.forEach(({ path, method, operation }) => {
      const operationId = operation.operationId || "unnamed";
      appendCanonicalDetails(
        operationList,
        `${method.toUpperCase()} ${path} — ${operationId}`,
        `/paths/${pointerToken(path)}/${method}`,
        operation,
        `${method} ${path} ${operationId} ${(operation.tags || []).join(" ")}`,
      );
    });
    target.appendChild(operationList);

    const componentEntries = [];
    Object.entries(spec.components || {}).forEach(([category, members]) => {
      Object.entries(members || {}).forEach(([name, value]) => {
        componentEntries.push({ category, name, value });
      });
    });
    appendText(target, "h3", `Components (${componentEntries.length})`);
    const componentList = document.createElement("div");
    componentList.className = "iris-canonical-list";
    componentEntries.forEach(({ category, name, value }) => {
      appendCanonicalDetails(
        componentList,
        `${category}.${name}`,
        `/components/${pointerToken(category)}/${pointerToken(name)}`,
        value,
        `${category} ${name}`,
      );
    });
    target.appendChild(componentList);

    const updateSearch = () => {
      const query = filter.value.trim().toLowerCase();
      let matches = 0;
      target.querySelectorAll(".iris-canonical-list details").forEach((details) => {
        details.hidden = query !== "" && !details.dataset.search.includes(query);
        if (!details.hidden) matches++;
      });
      searchStatus.textContent = matches
        ? `${matches} matching endpoints and components across all services.`
        : "No matching endpoints or schemas. Try a path, HTTP method, operation ID or component name.";
    };
    filter.addEventListener("input", updateSearch);
    updateSearch();
    appendStreamingResponses(target, operations);
    target.hidden = false;
  };
})();
