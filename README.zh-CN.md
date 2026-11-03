# Kiro Gateway

[English](README.md) | 中文

一个 Kiro 插件，把自带对话接到本机网关。

两种模式：

- **API Key 直连。** 用 Kiro API Key（`ksk_`）或 JSON 登录（`refreshToken`）连接 Kiro 官方服务，不做协议翻译。可以放多把凭证，并做状态检查和自动切换。
- **中转站。** 把对话请求翻译成 Anthropic Messages，转发到你填写的 Anthropic 兼容地址。模型列表由该地址提供。

两种模式各用一组本地端口。直连是 `19820` 和 `19821`，中转站是 `19830` 和 `19831`。编辑一边的凭证不会覆盖另一边。

扩展 id 是 `tesbo.kiro-gateway`。命令和设置使用 `kiroGateway` 前缀，例如 `kiroGateway.enabled`。

## 安装

Kiro 向 [Open VSX](https://open-vsx.org) 查询扩展更新。Kiro Gateway 出现在那里之后，从 Kiro 的扩展中心安装。有新版本时，扩展中心的 Updates 里会出现条目。打开 **Extensions: Auto Update** 后，Kiro 会自己下载。装完后，扩展条目上是 **Restart Extensions**，由你决定什么时候重启扩展宿主。插件不再扫描自己的安装目录，也不会为了更新另弹重载窗口。

从 VSIX 文件装进去的那一份不进这个更新列表。想让以后的版本出现在扩展中心，就从扩展中心安装。

Kiro 只在窗口启动时读取网关端点。打开网关或切换模式之后，需要重新加载窗口。

## 发布

每个版本发到 Open VSX 之后，Kiro 才能按扩展中心的方式更新。Open VSX 上的命名空间是 `tesbo`。

在 [open-vsx.org](https://open-vsx.org) 签好发布协议并创建访问令牌，然后可以：

```bash
npm run package
npx --yes ovsx publish *.vsix -p "$OVSX_PAT"
```

也可以把令牌存成仓库密钥 `OVSX_PAT`。GitHub Release 发布时会走自动发布流程。

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

面板跟随 Kiro 的浅色和深色主题，文字也跟随 Kiro 的语言。中文和英文都有。`kiroGateway.language` 可以强制指定（`auto`、`zh`、`en`）。面板顶部的按钮可以在中文和 EN 之间切换。

## 线路

顶部的两个按钮只改正在看的页面。正在跑的线路继续跑，包括本窗口处于待命、端口归另一个窗口的时候。按钮下面会写明当前生效的线路。「改用此页线路并重载」会先询问。取消则当前线路继续跑。确认之后才写入模式、重绑端口，并重新加载窗口。网关开关仍然只控制正在生效的那条线路。

## 开发

`extension.js` 和 `relay.js` 是扩展源码。`webview-ui/dist` 是已构建的面板。生成这份面板的 Vue 工程还不在本仓库里。

不要提交 API Key、refresh token 或账号导出文件。

## 许可

MIT。见 [LICENSE](LICENSE)。
