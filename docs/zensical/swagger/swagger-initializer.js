/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

window.addEventListener("load", () => {
  window.ui = SwaggerUIBundle({
    url: "../openapi.yaml",
    dom_id: "#swagger-ui",
    deepLinking: true,
    filter: true,
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
});
