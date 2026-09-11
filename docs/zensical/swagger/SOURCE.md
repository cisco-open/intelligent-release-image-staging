# Swagger UI vendored source

This directory vendors `swagger-ui-dist` version **5.32.15** from the npm
registry. It is used only to render the checked-in IRIS OpenAPI contract as a
read-only static page.

- Upstream: <https://github.com/swagger-api/swagger-ui>
- Release: <https://github.com/swagger-api/swagger-ui/releases/tag/v5.32.15>
- Registry artifact: <https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-5.32.15.tgz>
- npm integrity: `sha512-TSFER+rFQlf1nzk6WvKkMaHTxAPQ3eAAxigFThnxQedSREanfZgSbJFayZVs/ULnSbNdrJOb99vLD6xpb3R3eg==`
- Archive SHA-512: `4d214447eac54257f59f393a5af2a431a1d3c403d0dde000c628054e19f141e7524446a77d98126c915ac9956cfd42e749b35dac939bf7dbcb0fac696f74777a`
- Archive SHA-1 published by npm: `0bbaa62695104dbf2db06ad9bbbaaa127d830614`
- License: Apache-2.0; see `LICENSE` and upstream `NOTICE` in this directory.

The checked-in files `swagger-ui.css`, `swagger-ui-bundle.js`,
`swagger-ui-bundle.js.LICENSE.txt`, `LICENSE`, `NOTICE`, and `package.json` are
extracted without modification. Recreate them with `tools/vendor-swagger-ui.sh`.

To update Swagger UI, review the upstream release, then update the version and
both archive checksums in `tools/vendor-swagger-ui.sh` and every version,
artifact, integrity, and checksum field above. Run the helper and review the
updated package metadata, licenses, notice, and generated assets together. Do
not change the OpenAPI `info.version` as part of this dependency update: that
field is the API major version, not the IRIS CalVer release.

IRIS's `swagger-initializer.js` disables request submission, external schema
validation, and persisted authorization. `iris-swagger.css` hides authorization
controls because the public documentation must not collect credentials.
`iris-openapi32.js` supplements Swagger UI's documented basic OpenAPI 3.2 support
with a canonical explorer. It displays every operation and component directly
from the loaded contract as deferred, exact JSON, and calls out streaming
`itemSchema` and serialized examples. It does not transform the OpenAPI document.
Swagger UI's dialect warning remains visible because its renderer does not claim
full support for IRIS's explicitly declared generic JSON Schema draft 2020-12
dialect.
