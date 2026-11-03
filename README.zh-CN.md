# Kiro Gateway

[English](README.md) | 中文

一个 Kiro 插件，把自带对话接到本机网关。

两种模式：

- **API Key 直连。** 用 Kiro API Key（`ksk_`）或 JSON 登录（`refreshToken`）连接 Kiro 官方服务，不做协议翻译。可以放多把凭证，并做状态检查和自动切换。
- **中转站。** 把对话请求翻译成 Anthropic Messages，转发到你填写的 Anthropic 兼容地址。模型列表由该地址提供。

两种模式各用一组本地端口。直连是 `19820` 和 `19821`，中转站是 `19830` 和 `19831`。编辑一边的凭证不会覆盖另一边。

扩展 id 是 `local.kiro-gateway`。命令和设置使用 `kiroGateway` 前缀，例如 `kiroGateway.enabled`。

## 安装

还没有发布到扩展市场。在本仓库打包 VSIX，再装进 Kiro：

```bash
npx --yes @vscode/vsce@latest package --allow-star-activation --skip-license --allow-missing-repository
```

在 Kiro 里用 **Extensions: Install from VSIX** 安装生成的 `.vsix`。

Kiro 只在窗口启动时读取网关端点。打开网关或切换模式之后，需要重新加载窗口。

## API Key 直连

1. 打开侧边栏 **Kiro Gateway**。
2. 选择 **API Key 直连**。
3. 添加 `ksk_` 密钥，或导入 JSON 凭证。
4. 打开网关并重新加载窗口。

JSON 凭证必须有 `refreshToken`。Builder ID 和 IAM Identity Center 还需要 `clientId` 和 `clientSecret`。同一把 refresh token 不能同时交给插件和 Kiro 自己的登录。Kiro 每次刷新成功都会轮换 refresh token，再用旧的那把刷新会使账号失效。

JSON 密钥存在插件自己的私有状态里，不写进 `settings.json`。从面板导出的文件包含完整凭证，不要提交这些文件。

## 中转站

1. 选择 **中转站**。
2. 填写 Anthropic 基地址和中转站 API Key。没写 `/v1` 时会自动补上。
3. 测试连接。测试只拉取模型列表。
4. 保存，打开网关，然后重新加载窗口。

再次打开面板时，会填回已保存的中转站设置。

## 主题和语言

面板跟随 Kiro 的浅色和深色主题。界面文字目前仍是中文，2.0.0 还没有英文界面。

## 已知限制

面板顶部的两个按钮会切换正在使用的模式，不只是切换正在查看的页面。网关开关开着时，点另一个模式会启动那个模式，并停掉当前模式。后续版本会把翻页和生效模式分开，切换前先询问。

## 开发

`extension.js` 和 `relay.js` 是扩展源码。`webview-ui/dist` 是已构建的面板。生成这份面板的 Vue 工程还不在本仓库里。

不要提交 API Key、refresh token 或账号导出文件。

## 许可

MIT。见 [LICENSE](LICENSE)。
