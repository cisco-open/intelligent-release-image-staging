/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

window.addEventListener("load", () => {
  const nonConsoleLink = () => location.hash.startsWith("#/") && location.hash.split("/")[1] !== "console";
  const initialScope = nonConsoleLink() ? "" : "console";
  const showScope = (scope) => {
    document.querySelectorAll("[data-iris-service]").forEach((choice) => {
      choice.setAttribute("aria-pressed", String(choice.dataset.irisService === scope));
    });
    document.getElementById("iris-service-status").textContent = scope
      ? "Console endpoints. All services includes management, catalog, tracker, telemetry and artifacts."
      : "All services. Check each endpoint's server and authentication requirements before using an API client.";
  };
  showScope(initialScope);
  window.ui = SwaggerUIBundle({
    url: "../openapi.yaml",
    dom_id: "#swagger-ui",
    deepLinking: true,
    // Keep bookmarked operations from other services visible on first load.
    filter: initialScope || true,
    docExpansion: "list",
    supportedSubmitMethods: [],
    validatorUrl: null,
    persistAuthorization: false,
    presets: [SwaggerUIBundle.presets.apis],
    layout: "BaseLayout",
    onComplete: () => {
      window.renderIrisOpenAPI32(window.ui.specSelectors.specJson().toJS());
    },
  });
  document.querySelectorAll("[data-iris-service]").forEach((button) => {
    button.addEventListener("click", () => {
      // Swagger's native filter selects service tags without rewriting the spec.
      window.ui.layoutActions.updateFilter(button.dataset.irisService);
      showScope(button.dataset.irisService);
    });
  });
  window.addEventListener("hashchange", () => {
    if (nonConsoleLink() && window.ui.layoutSelectors.currentFilter() === "console") {
      window.ui.layoutActions.updateFilter("");
      showScope("");
    }
  });
});
