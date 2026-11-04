# Changelog

## 2.0.7 — 2026-11-04

JSON BuilderId now uses Kiro's fixed profile `arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX`. Github and Google use the other fixed profile unless the credential already has one. That replaces the IDE login's profile on proxied usage, models, chat, and MCP. A JSON key no longer keeps the official `/mcp` passthrough, and a window without this credential no longer restores official endpoints while the gateway is still on. The imported FREE / used / total chip is shown from the snapshot until live usage returns. The panel footer shows `2026-11-04`.

## 2.0.6 — 2026-11-03

The relay fallback-model field is gone. It was replacing the model selected in chat, so a Haiku turn still went out as whatever id was filled in there. The model id Kiro sends is now forwarded as-is, unless `kiroGateway.relayModelMapping` has an entry for it. A saved fallback value is cleared on startup. The panel footer still shows `2026-11-03`.

## 2.0.5 — 2026-11-03

Relay mode now tells Kiro when a reply has finished. Anthropic `stop_reason` is forwarded as `metadataEvent.stopReason` (`END_TURN`, `MAX_TOKENS`, `TOOL_USE`, and the other reasons Kiro already understands). A completed relay answer is no longer treated as truncated, so Kiro does not retry that turn or append a `Continue` user message. The panel footer still shows `2026-11-03`.

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
