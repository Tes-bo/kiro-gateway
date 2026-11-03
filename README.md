# Kiro Gateway

English | [中文](README.zh-CN.md)

A Kiro extension that routes the built-in chat through a local gateway.

Two modes:

- **API key direct.** Use a Kiro API key (`ksk_`) or a JSON login (`refreshToken`) against Kiro's own service. No protocol translation. Supports several credentials, health checks, and automatic failover.
- **Relay.** Translate chat requests into Anthropic Messages and forward them to an Anthropic-compatible endpoint that you configure. The model list comes from that endpoint.

Each mode uses its own local ports. Direct mode uses `19820` and `19821`. Relay mode uses `19830` and `19831`. Credentials for one mode are not overwritten when you edit the other.

The extension id is `local.kiro-gateway`. Commands and settings use the `kiroGateway` prefix, for example `kiroGateway.enabled`.

## Install

Kiro checks [Open VSX](https://open-vsx.org) for extension updates. Once Kiro Gateway is listed there, install it from Kiro's Extensions view. A new version shows up in the Extensions view, under Updates. With **Extensions: Auto Update** turned on, Kiro downloads it for you. After it is installed, the extension entry shows **Restart Extensions**. That restarts the extension host when you choose. The extension does not scan its own install folder and does not ask you to reload for an update.

A copy installed from a VSIX file stays outside that update list. Use the Extensions view if you want later versions to show up there.

Kiro reads the gateway endpoints once, when the window starts. After you turn the gateway on, or after you change mode, reload the window.

## Publishing

Publish each release to Open VSX. Kiro can then update it from the Extensions view. The extension id stays `local.kiro-gateway`, so the Open VSX namespace is `local`. That namespace already exists and has no extensions yet. The publishing account has to be a member of it.

Create an access token at [open-vsx.org](https://open-vsx.org) after signing the publisher agreement, then either:

```bash
npm run package
npx --yes ovsx publish *.vsix -p "$OVSX_PAT"
```

or add the token as the `OVSX_PAT` repository secret. The publish workflow runs when a GitHub release is published.

## API key direct

1. Open the **Kiro Gateway** sidebar.
2. Choose **API key direct**.
3. Add a `ksk_` key, or import a JSON credential.
4. Turn the gateway on and reload the window.

A JSON credential needs a `refreshToken`. Builder ID and IAM Identity Center credentials also need `clientId` and `clientSecret`. The same refresh token must not be used by both the plugin and Kiro's own login at the same time. Kiro rotates the refresh token on every successful refresh, and a second refresh of the old token invalidates the account.

The plugin stores JSON secrets in the extension's private state, not in `settings.json`. Exports from the panel contain the full credential. Do not commit those files.

## Relay

1. Choose **Relay**.
2. Enter the Anthropic base URL and the relay API key. A missing `/v1` is added automatically.
3. Test the connection. The test only lists models.
4. Save, turn the gateway on, and reload the window.

Saved relay settings are restored when the panel is opened again.

## Theme and language

The panel follows Kiro's light and dark theme. The interface text is still Chinese. An English interface is not in 2.0.0 yet.

## Known limit

The two buttons at the top of the panel change the live mode, not just the page you are looking at. If the gateway switch is on, choosing the other mode starts that mode and stops the one that was running. A later version will keep page navigation separate from the mode that is actually in use, and will ask before switching.

## Development

`extension.js` and `relay.js` are the extension source. `webview-ui/dist` is the built panel. The Vue project that produced that bundle is not in this repository yet.

Do not commit API keys, refresh tokens, or account export files.

## License

MIT. See [LICENSE](LICENSE).
