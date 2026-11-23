# ArFS Key Web v1.5 — 全面复盘与代码审计

**审计基准**：本轮实读的 `/mnt/data/ArFS-key-web-v1.5.html`，45,855 字节，SHA-256：`1b56ecc5723553fa5aed492283bb316915238d2b07abf6445faf718bc2de5c77`。  
**日期**：2026-11-23。  
**操作边界**：仅对源文件进行静态分析、自动化离线测试、模拟请求和外部文档交叉核查；没有修改 v1.5，也没有读取真实钱包或执行新的主网交易。

## 总体判定

- **功能性基线**：可以保留 v1.5 作为已成功实测的限定场景版本（自己控制的 Public ArFS File、可信网关、输入来源有效）。
- **无逻辑漏洞的最终安全冻结**：**不能认定通过**。实际源码存在来源正文未与指定交易 ID 进行独立绑定验证的缺口；有可复现的异常网关数据导致原 `dataTxId` 被替换的路径。ArFS 文件 JSON 完整字段校验也不充分。
- **对已有真实交易的判断**：之前 v1.2 和 v1.5 的实际回执/截图支持正常发布和检索；没有证据表明真实网关篡改了用户记录，也不能将模拟攻击等同于真实攻击。

## 一、版本演进与确认过的用户需求

| 版本 | 变化 | 审计背景 |
|---|---|---|
| CLI v0.1.2 | 读取来源 Public File Metadata，重发 Metadata-only，按 `key` 反查 | 历史工具已实现基本功能，曾带有强制最新版检查 |
| Web v1.2 | 单 HTML 中实现浏览器签名、Turbo 上传、关键词与时间检索 | 真实交易 `Y7AJ0Ft...` 成功，之前的 ANS-104 签名错误已修复 |
| Web v1.3 | 增加常用网关预设 | 不自动切换服务 |
| Web v1.4 | 修复预检和发布异步状态、增加可关闭的收费查询 | 保留上传结果、不自动重试 |
| Web v1.5 | 移除强制“来源是最新 Metadata Tx ID” | 允许历史来源 ID；**不代表自动找最新版本** |

已确定的最小目标：浏览器本地选择 JWK；按给定历史或当前 Metadata ID 读取相应 Public ArFS File Metadata；验证来源交易的 Owner 与钱包地址相同；原正文二进制原样重新签名；新交易标签恰好为 `ArFS`、`Content-Type`、`Drive-Id`、`Entity-Type`、`File-Id`、`Parent-Folder-Id`、新 `Unix-Time` 及 N 条同名 `key`；默认不继承旧自定义标签；查询只按 `key` 标签，时间过滤以 `block.timestamp` 为准。收费查询可关闭、接口可配置、不自动上传重试。

## 二、源码逐层审计

| 层 | 直接源代码证据（JS 行号） | 判定 |
|---|---|---|
| 端点配置 | 8–18 | 可配置，HTTP/HTTPS 输入验证；扩展了网关信任面 |
| 密钥读取 | 40–50 | 本地选择 JWK，导入不可导出的 RSA-PSS CryptoKey；未发现直接上传原 JWK 的代码 |
| 标签构造 | 51–65、101–108 | 7 个协议字段 + N 个输入的 `key`，旧标签不继承；数量/字节限制合理 |
| 来源查询/读取 | 68–79 | GraphQL 元信息和 JSON 字节分别从可配置端点获取；**无源码认证关联** |
| 关键词与时间查询 | 80–99 | `key` 专用过滤；按区块时间筛选；有时间条件时分页，无时间条件只取一页 |
| ANS-104 签名 | 100–120 | RSA-4096、RSA-PSS SHA256、Avro Tags、Data Item ID = SHA256(signature) |
| 上传/状态 | 121–133、220–267 | 区分 HTTP 拒绝和接口未知；本地签名 ID 可追溯，无自动重试；成功处理先展示 ID |
| 费用 | 134–174 | 可开关、URL 可自定义、报价与免费剩余额度重新查询；不是最终扣费保证 |
| 异步状态 | 175–176、189–219、220–267、283–303 | 预检版本号、发布快照、发布期间禁用输入、之前结果保留；未发现重现旧版的简单状态空引用路径 |
| 回执与单项查询 | 178–188、276–280 | 可下载本地 JSON；`verify` 为网关结果展示，不是完整链上证明 |

静态 HTML 包含单个内联脚本，无外部脚本标签，无重复 HTML ID。CSP 的网络白名单为全部 HTTP(S) 域名，这是“任意手动配置网关”决定的技术结果，不是仅固定访问官方地址。用户输入展示主要使用 `textContent`，未在检查到的核心结果呈现路径中使用不可信字符串拼接 HTML。

## 三、已复现的实质性缺口

### F01：来源 Metadata 正文未绑定到真实交易（**高；限定于错误/不可信来源网关**）

代码：`byId()` 取 GraphQL `tx.id` / Owner / 标签；`readMetadata()` 独立从数据网关下载 JSON；`validateSource()` 检查字段结构、Wallet Owner；之后 `preview()` 直接保留 `data.raw`，`publish()` 将其签名发布。没有验证 `data.raw` 的内容确实属于 `sourceId`。

**隔离复现**：

1. 保持 GraphQL 的来源 ID、Owner、File-Id 等信息正确。
2. 模拟读取网关返回另一份格式合法的 JSON，把 `dataTxId` 替换为另一个 43 位值。
3. v1.5 的 `preview()` 仍通过。
4. 发布路径把被替换的 JSON 原样交给签名器和上传器。

影响：对不可靠数据来源，“保持原文件 `dataTxId`”不再有程序级保障。此测试**没有证明任何真实网关正在篡改数据**。这是代码未自行认证交易与正文对应关系所产生的信任边界。

### F02：ArFS File Metadata JSON 结构校验不完整（**中**）

代码：`validateSource()` 55–65 行只实质检查 `body.dataTxId`（合法 Tx ID）和 `body.name`（非空字符串），没有检查 `size`、`lastModifiedDate`、`dataContentType` 的存在及格式。隔离测试中缺少这些字段的 JSON 仍会通过预检。

协议文档的 File JSON 结构列出 `name`、`size`、`lastModifiedDate`、`dataTxId`、`dataContentType` 等关键字段。这个缺口主要影响错误源文件或不可信数据网关，正常 ArDrive File Metadata 的既有实测数据并未出现该问题。

### F03：显示文字不够严谨（**低，不阻断使用**）

`verify()` 的状态写“单个网关读取完成”，但索引与正文实际上可能由两个分别配置的网关返回。该措辞会低估跨网关数据一致性问题；页面同时明确说“不进行完整签名链验证”。

## 四、已知且由需求决定的边界（不要私自重新增加功能）

1. **历史 ID**：允许复用历史来源，且不合并其他版本 Metadata，符合用户明确要求。它不是“自动寻找最新版本”。
2. **Drive 所有权**：仅比对来源 Metadata Owner 与钱包地址，没有追溯创建 Drive 的第一条交易；这是之前已经明确不添加的功能范围，不能冒充完整 Drive 权限验证。参考 ArFS Reading Data 官方文档。
3. **收费 API**：预检和签名前各查询一次；可关闭，关闭后不连接费用 API。报价是标价，免费判断受单次尺寸、钱包余额以及网段/服务端规则影响；回执 `winc` 才是服务报告的实际收费。
4. **检索**：无时间范围时默认只返回 `limit` 条，无完整性声明；有范围时逐页取同一 `key` 交易再按 `block.timestamp` 过滤，可能读取许多页面。返回的是所有命中的历史与当前交易，不自动去重为一个 File-Id 的最新版。
5. **响应与上链**：HTTP 200 + 匹配的 ID 只证明服务返回接收声明，不等于网关全网同步或终局验证；页面不会自动验证 Turbo 回执的服务端数字签名，也不验证长期可用性。
6. **页面本地运行**：file://、CORS、网关状态、浏览器 WebCrypto 支持是外部运行条件；没有 Node.js 运行依赖，不等于没有网络依赖。
7. **输入变换**：关键词会 `trim()` 并去空行，不是严格逐字节保留用户原始文本；这继承了先前设计，已被本次审计明确识别。
8. **下载体积**：2 MiB 上限在 `response.arrayBuffer()` 之后检查，对异常巨大的网络响应不构成下载前内存限制。

## 五、测试证据与不可证之处

- v1.5 文件通过 Node.js 语法检查；HTML 静态检查 42 个元素 ID 均唯一、无外部脚本资源。
- **7 个完整浏览器隔离场景通过**：历史 ID；费用关闭不访问费用 API；回执保留；网关失败后费用关闭；严格标签生成；费用开启时二次报价；报价变化后取消上传；402 拒绝不重试（第 1–7 项按测试脚本组合计数）。
- **RSA-PSS/ANS-104 独立测试通过**：临时 4096 位测试密钥，直接执行 v1.5 的 `signDataItem()`，以独立 deep hash 和 Node Crypto 验证 RSA-PSS 签名、Tx ID、原始正文位置、数据长度和标签顺序。
- **1 个针对性反例通过**：错误网关正文可导致非真实 `dataTxId` 进入签名上传路径，证明 F01。
- **F02 结构缺失反例**：错误 JSON 缺少 `size` / `lastModifiedDate` / `dataContentType` 也能被 v1.5 预检接受。
- **并发**：源代码存在 `previewRevision` 和 `publishLocked` 防线，之前版本曾做浏览器隔离验证；本轮尝试更复杂的挂起异步脚本未完成，不能把它称为本轮再次全部覆盖成功。
- **真实交易证据**：用户提供的 `metadata-ScHfqO_xeSDihT8jdme_4srb4nerY8YIaAap-h50Clo.json` 报告来源 `ELv8Gw...`、新 ID `ScHfqO_x...`、`File-Id` / `dataTxId` 保持不变、3 个 `key` 以及 `actualWinc = 0`。随后用户截图显示新 ID 通过 GraphQL 的 `key` 标签与区块时间筛选返回。未使用真实钱包重新支付或发布；当前外部网页浏览工具也未独立取得最新链上结果。

**不能把“浏览器模拟通过”“用户的真实操作回执”“独立主网密码学验证”混为同一个证据等级。**

## 六、是否冻结？

**不建议标记为“无逻辑漏洞、安全最终版”。** F01/F02 尚未关闭，且 F01 与“保留真实文件 `dataTxId`”的核心承诺存在直接关系。

可将 v1.5 **原样保存为已实测的功能基线**，在用户自己选择并信任的 Arweave 网关、已知合法的 Public File Metadata 范围内使用。若要宣称“任意网关/任意来源安全”，至少要解决来源交易与 Metadata 正文的真实性绑定，以及 ArFS JSON 必要字段验证。任何修复都应先列出最小变更清单并由用户授权，不能自动加入 Drive 权限追溯、最新版强制检查、数据库、自动重试等无关功能。

## 官方交叉核对

- ArFS Entity Types: https://docs.ar.io/build/advanced/arfs/entity-types
- ArFS Reading Data: https://docs.ar.io/build/advanced/arfs/reading-data
- ArFS Data Model: https://docs.ar.io/build/advanced/arfs/data-model
- ANS-104: https://cookbook.ar.io/references/specs/ans/ANS-104.html
- Turbo Upload & Verify: https://docs.ar.io/build/upload/upload-and-verify/
- Turbo pricing: https://docs.turbo-gateway.com/apis/turbo/payment-service/pricing/
- Turbo free balance: https://docs.ar.io/apis/turbo/payment-service/balance/
