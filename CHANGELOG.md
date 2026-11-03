# Changelog

## 2.0.4 — 2026-11-03

The panel follows Kiro's language, with a Chinese / English switch at the top and a `kiroGateway.language` setting (`auto`, `zh`, `en`). The two buttons at the top only change the page. The route that is running stays until you confirm; confirming stops that route and reloads the window. Cancel leaves it running. Code comments in `extension.js` and `relay.js` are English.

## 2.0.3 — 2026-11-03

The Open VSX namespace is `tesbo`. The extension id is `tesbo.kiro-gateway`. Commands, settings, and saved state still use the `kiroGateway` prefix. The panel footer still shows the release date `2026-11-03`.

## 2.0.2 — 2026-11-03

The Open VSX namespace is `kiro-gateway`. The extension id is `kiro-gateway.kiro-gateway`. The `local` namespace already belonged to someone else, so 2.0.1 could not be published there.

Commands, settings, and saved state still use the `kiroGateway` prefix. The panel footer still shows the release date `2026-11-03`.

## 2.0.1 — 2026-11-03

Extension updates are left to Kiro. Install the extension from the Extensions view so Kiro can list a new version there and apply it with Restart Extensions. The extension no longer scans the local install every 10 seconds, and the panel no longer has an update banner or an auto-reload switch.

The panel footer still shows the release date `2026-11-03`.

## 2.0.0 — 2026-11-03

First public release of Kiro Gateway. The extension id is `local.kiro-gateway`. Commands, settings, and saved state use the `kiroGateway` prefix.

This repository starts at 2.0.0. It is the open-source line of the plugin that was previously installed as 1.1.46. Builds numbered 1.1.47 through 1.1.52 are not part of this repository and should not be installed over it.

The panel footer shows the version from `package.json` and the release date `2026-11-03`.
