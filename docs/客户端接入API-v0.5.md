# PhoneHub 客户端 API 接入说明 v0.5.2

> **现行版本 v0.5.21：已移除 IMEI 和手机号的采集、补报、后台查看和新建黑名单功能。** 本文下方涉及 v0.5.2/v0.5.16 原号上报的段落属于历史协议记录，不再作为当前接入要求。旧版客户端发送这些额外字段时服务器会忽略，不保存、不参与新身份识别，也不向客户端返回相关保存状态。现行身份只使用手机指纹 phone_id（64 位小写 SHA-256）。历史已保存的摘要/密文和安全禁令不会自动删除或解除。

服务端运行版本：v0.5.21；接口仍使用 `api=1` 协议号。测试期只支持当前 PhoneHub 客户端接口，手机以 `phone_id` 进行绑定及授权校验，IMEI 与手机号采集已经下线。

## 一、地址与认证

**唯一受支持的接口地址**：https://data.tmd.pet/license/api/phonehub.php?action=ACTION

旧版 `/phonehub/api.php` 已停止支持，不能再由后台“接管”或自动重写。所有测试客户端必须改用以上路径；已部署旧文件或旧 Nginx 路由须在生产站点核实并单独下线。

- health：GET，无认证，返回 ok/service/api/mobile_binding；当前协议号 api=1。
- login：POST，JSON body，传 username/password/device_id，不传 Bearer。
- 除 health 和 login 以外：POST，Content-Type: application/json，Authorization: Bearer TOKEN。
- 所有经过认证的请求都必须传 device_id（与登录时相同的 64 位小写十六进制 SHA-256）。
- 登录后 token 为 64 位小写十六进制，8 小时到期；expires_at 为 Unix 秒。
- JSON 请求不超过 64 KiB。错误为 HTTP 4xx/5xx、ok:false、error 中文描述；新增接口还可能返回 error_code。

### 登录请求

~~~json
{"username":"customer_001","password":"客户密码","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
~~~

POST ?action=login，返回：

~~~json
{"ok":true,"token":"<64位十六进制令牌>","expires_at":1794830400,"username":"customer_001","license_until":"2026-12-31 15:59:59","entitlements":["douyin"]}
~~~

**电脑名额满额时自动换机（v0.5.26）：** 新电脑输入正确账号和密码登录时，服务端会在数据库事务中撤销当前客户**最早登录的有效电脑**的全部会话，释放名额后登录新电脑；无需额外传 `replace_device_id`。默认以最早建立的有效会话 ID 排序；不是按最后操作时间。若后台降低了名额并存在多台超额电脑，会按顺序撤销足够多的旧设备，确保新登录后不超额。相同电脑重新登录仅替换自己的会话令牌，不会无故踢掉其他电脑。旧电脑下次调用受保护接口会收到登录态失效错误（HTTP 401），应清空本地令牌并返回登录页。

仍兼容可选的 `replace_device_id`：新登录需要腾出名额时，若指定的有效设备属于同一客户，优先撤销指定设备；否则自动选择最早登录的电脑，不再要求用户手动选择。

登录成功返回值新增 `replaced_devices`（非负整数，表示本次撤销的**不同电脑数量**，0 表示无需替换），不包含被撤销设备的标识或令牌；其余字段及 API 1 协议保持兼容。密码错误、停用账号、授权到期、黑名单电脑或电脑名额为 0 时仍拒绝登录，不撤销其他电脑。

### 共用的已登录请求范例

~~~http
POST /license/api/phonehub.php?action=mobile_list HTTP/1.1
Content-Type: application/json
Authorization: Bearer <登录令牌>
~~~

~~~json
{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
~~~

## 二、全部客户端 action

| action | 额外请求字段 | 成功响应与含义 |
|---|---|---|
| health | 无 | 服务健康、API 版本 |
| login | username, password, device_id, 可选 replace_device_id | token、expires_at、entitlements |
| session | 无 | 现有登录状态，原 API 1 保持不变 |
| logout | 无 | 注销当前登录令牌 |
| password | old_password, new_password | 修改客户登录密码 |
| license_status | 无 | 授权/平台权限/设备额度/能力开关/心跳参数 |
| capabilities | 无 | 同 license_status |
| client_config | 无 | 同 license_status |
| client_heartbeat | 无 | 同 license_status |
| device_list | 无 | 当前账号占用名额的电脑会话及到期时间 |
| device_revoke | target_device_id | 踢掉指定电脑，返回 revoked |
| mobile_bind | phone_id，可选 display_name、phone_model | 绑定安卓手机指纹；返回 bound、mobile_limit、active_count |
| mobile_list | 无 | 当前用户的手机列表、mobile_limit、active_count、每台设备的 imei_bound |
| mobile_check | phone_id | 检查绑定与黑名单，返回 bound（兼容旧客户端上报的额外字段但不使用） |
| mobile_heartbeat | phone_id，可选 phone_model | 绑定检查、刷新 last_seen 和可选型号；不采集 IMEI/手机号 |
| mobile_unbind | phone_id | 解绑安卓手机，释放名额 |
| package_list | 无 | 客户可用操作包列表与 download_allowed |
| package_check | package_id | 包版本与下载资格 |
| package | package_id | 原 API 1 的 envelope + content_key，服务端加手机绑定限制 |
| update_check | platform, channel, current_version | available/latest_version/release |
| update_manifest | platform, channel, current_version | 同 update_check |
| update_list | platform, channel | releases[] 历史可用更新版本 |
| update_download | release_id | ZIP 二进制，支持 HTTP 单段 Range |
| log_upload | level, event, message | received:1 |
| log_batch | logs 数组 | received:本批数量 |
| ai_status | 无 | AI 是否开放、服务器模式/BYOK 状态与额度；不返回密钥 |
| ai_chat | credential_mode, messages 等 | 非流式 DeepSeek 兼容 Chat Completions JSON |

除 login 和 health 外，以上表格省略了每个 JSON 请求都必填的 device_id。未知 action 返回 404。

## 三、手机绑定（APP 接入重点）

v0.5.2 服务端可选接收 `phone_model`（手机型号，最多 120 字）、`imei`（14～16 位数字）和 `phone_number`（国际号码形式，例如 `+8613912345678`）。原始 IMEI 与手机号以可逆密文保存，管理员默认只看掩码；主管理员按需查看全文并写入审计。旧 API 和未上传这些字段的客户端仍可运行，后台显示“未获取”。

详见 [统一设备管理与独立黑名单说明](设备管理与签名-v0.5.2.md)。服务端无法在没有客户端上报时自行读取手机的 SIM 电话号码；号码存在性及真实性未经运营商核验。


phone_id 格式：64 位小写十六进制 SHA-256，作为主要设备指纹，建议由稳定且非个人敏感的 Android 标识推导；不能使用手机号，也不能让用户输入任意数字充当设备证明。它是授权标识，不等于可信硬件远程认证。IMEI 是可选辅助标识，不替代 phone_id。

POST ?action=mobile_bind：

~~~json
{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","phone_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","display_name":"Android 设备 1","imei":"490154203237518"}
~~~

成功：

~~~json
{"ok":true,"phone_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","bound":true,"imei_bound":true,"mobile_limit":3,"active_count":1}
~~~

mobile_limit=0 表示不允许绑定，不表示无限制。手机名额是有效绑定总数，不是当前 USB 在线数量。新增绑定由服务端按客户行锁+事务检查额度；解绑释放名额。APP 应根据自己的 ADB 设备检测结果调用 mobile_bind/mobile_heartbeat。

### 操作包下载强制条件

必须同时满足：登录有效 + 账号正常未到期 + entitlements 含平台 + 手机额度大于 0 + 至少存在一个 enabled=1 的安卓手机绑定 + 操作包可用。只设置额度、没有真实绑定记录，package 仍然被拒绝。解绑最后一台手机后，再次禁止下载。

package 返回结构仍为：

~~~json
{"ok":true,"envelope":{"manifest":"<Base64>","signature":"<Base64>","nonce":"<Base64>","ciphertext":"<Base64>"},"content_key":"<Base64>"}
~~~

该机制检验“已绑定”，不要求下载瞬间手机插着 USB；是否在线应由 APP 自行判断。

### IMEI 辅助绑定、隐私与设备黑名单

- `imei` 是可选字段，格式为 14–16 位数字；只在客户端依法能够读取、用户已明确知情同意时提交，必须使用 HTTPS。
- 服务端收到后使用 `storage/mobile-identity.key` 计算 HMAC-SHA-256，同时用 sodium secretbox 加密保存原始 IMEI，供有审计权限的主管理员按需查看；绝不明文写入数据库或在客户端 API 返回原号。请与数据库一起备份该密钥；若密钥丢失或指纹不匹配，服务端会拒绝自动生成替代密钥，必须恢复原密钥备份，否则旧 IMEI 摘要与黑名单无法继续校验。
- `mobile_list` 返回 imei_bound、imei_stored、phone_number_bound、phone_model_received 布尔状态，不返回 IMEI、手机号原号或摘要。管理员页面仅展示遮盖值或上报状态，完整解密查看受权限和审计保护。
- 管理员将设备拉黑时，会同时拉黑该设备的 `phone_id` 和已绑定的 IMEI 摘要，并停用匹配的所有绑定。解除黑名单只解除对应标识，不会自动恢复绑定；需要重新绑定。
- API 对命中黑名单的绑定、检查、心跳和操作包资格进行拒绝。常见错误码：`DEVICE_BLACKLISTED`、`DEVICE_IDENTITY_MISMATCH`、`INVALID_IMEI`。
- **Android 系统限制：** Android 10/API 29 起，普通第三方应用通常不能读取 IMEI；只有预装特权应用、设备/配置文件所有者、具备运营商权限、默认短信角色或相应特权权限的应用才可能访问。不得尝试绕过系统限制；读不到 IMEI 时继续使用 `phone_id`，`imei` 留空即可。官方说明：https://developer.android.com/about/versions/10/privacy/changes 和 https://developer.android.com/reference/android/telephony/TelephonyManager#getImei(int)

### MCP、Codex、DeepSeek Harness 与 Skill 云端控制（v0.5）

保持旧版 \`mcp\` 和 \`skill\` 权限兼容，新增两种 **独立且默认关闭** 的 MCP 子平台。**客户端接入不是本轮服务端开发的内容**；调用这些字段的客户端需要自行适配：

| 平台 ID（更新目标） | 云端全局开关 | 客户授权字段 |
|---|---|---|
| \`mcp\`（原有 MCP） | \`mcp_enabled\` | \`mcp\` |
| \`mcp-codex\`（Codex MCP） | \`mcp_enabled\` + \`mcp_codex_enabled\` | \`mcp\` + \`mcp-codex\` |
| \`mcp-harness\`（DeepSeek Harness MCP） | \`mcp_enabled\` + \`mcp_harness_enabled\` | \`mcp\` + \`mcp-harness\` |
| \`skill\`（原有 Skill） | \`skill_enabled\` | \`skill\` |

所有新全局开关默认 \`0\`。已存在的 \`mcp\` 客户权限**不会自动获得** Codex/Harness 权限。只有主管理员能够新授予这些子平台，普通管理员不能绕过。

对于 \`license_status\`、\`capabilities\`、\`client_config\`、\`client_heartbeat\`，\`features\` 采取 **true-only 正向能力披露**：只返回服务器实际开放且该客户已获授权的功能，未开放项整个字段省略，不返回 \`false\`。例如客户仅开放原有 MCP：

~~~json
{
  "features": {
    "mobile_bind": true,
    "mobile_unbind": true,
    "package_requires_mobile_binding": true,
    "update_check": true,
    "update_download": true,
    "log_batch": true,
    "device_list": true,
    "device_revoke": true,
    "mcp_available": true
  }
}
~~~

若 Codex MCP、DeepSeek Harness MCP、Skill 未被授权，\`mcp_codex_available\`、\`mcp_harness_available\` 和 \`skill_available\` **不出现**。客户端以 \`features?.mcp_codex_available === true\` 作为允许条件，不能把字段缺失当成允许。这个规则只用于**能力披露**，不改变操作结果中的 \`ok\`、\`available\`、\`bound\` 等协议布尔值，因为客户端需要区分失败、未绑定、没有更新等正常状态。

这只减少对客户端的未授权能力提示，并非权限安全边界。已知端点仍可能被直接请求，服务端每次调用和下载都会重新验证登录状态、客户授权、全局开关和设备限制，不能只依赖客户端是否看到某个字段。

客户端使用 \`update_list\`、\`update_check\`、\`update_manifest\` 或 \`update_download\` 时，服务端根据平台 ID、全局开关与客户授权执行校验；未开放时返回 \`FEATURE_DISABLED\`，客户未授权时返回 \`NOT_ENTITLED\`。

独立发布 ZIP 仍需要主管理员操作，签名清单及 ZIP SHA-256 校验沿用现有客户端更新机制。对于旧版 \`mcp\`，旧权限和发布行为保持兼容。已下载安装到客户电脑的本地文件不会因云端停用而被远程删除，软件客户端必须自行执行重新联网后的撤销策略。


## 四、客户端核心更新（独立于操作包）

管理员后台地址：https://data.tmd.pet/license/?view=releases

上传 ZIP、填写 platform（core/douyin/xiaohongshu/mcp/skill/mcp-codex/mcp-harness）、channel（stable/beta）、version（如 0.8.0）、min_client、notes 后，服务端：

1. 检验 ZIP 路径和大小，保存到不对外开放的 storage/updates。
2. 计算 ZIP SHA-256。
3. 首次发布时生成并保存长期 Ed25519 签名密钥，签名原始 UTF-8 manifest JSON 字节。
4. 返回已签名 manifest 的 Base64、签名 Base64、版本号、字节数、SHA-256、release_id。
5. 有效客户用 update_download + Bearer 下载 ZIP，支持 Range: bytes=start-end（返回 206 与 Content-Range）。

查询新版本：

~~~json
{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"core","channel":"stable","current_version":"0.7.1"}
~~~

POST ?action=update_check。可能响应：

~~~json
{"ok":true,"available":true,"current_version":"0.7.1","latest_version":"0.8.0","download_action":"update_download","release":{"id":1,"platform":"core","channel":"stable","version":"0.8.0","min_client":"0.7.1","manifest":"<Base64原始JSON>","signature":"<Base64 Ed25519>","public_key":"<Base64公钥>","sha256":"<64位十六进制>","size_bytes":123456,"filename":"phonehub-core.zip","notes":"版本说明"}}
~~~

下载请求：

~~~json
{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_id":1}
~~~

POST ?action=update_download，成功响应为 application/zip，不是 JSON。Range 下载仍然必须附带相同 Bearer 头。

**APP 必须实现：**

- 在 APP 安装包中预置可信 Ed25519 公钥（从主管理员后台签名公钥页面取得）。不能只信任 API 返回的 public_key。
- 标准 Base64 解码 release.manifest，使用预置公钥验证 release.signature 对**原始 manifest 字节**的 Ed25519 签名。
- 校验已签名 manifest 中的 platform、channel、version、min_client、size_bytes 和 sha256。
- 下载 ZIP 后核对 SHA-256、限制危险 ZIP 条目、临时目录解压、安装前备份、安装失败回滚。
- 正常更新禁止退回较旧版本；APP 正在运行的核心文件不得直接无保护地覆盖。

私钥由 PHP sodium 生成并保存在 storage/updates/signing.key，必须定期安全备份。若丢失私钥重新生成，已固定公钥的客户端将不能验证新的更新。

## 五、运行日志

POST ?action=log_upload：

~~~json
{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","level":"error","event":"adb_disconnect","message":"设备连接断开"}
~~~

POST ?action=log_batch：

~~~json
{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","logs":[{"level":"info","event":"app_start","message":"应用启动"},{"level":"error","event":"adb_disconnect","message":"设备断开"}]}
~~~

限制：level=debug/info/warn/error，event 限 1–64 个英文字母、数字、下划线、点或横线；message 长度 1–2000 UTF-8 字节；每批 1–50 条，每账号最多 1000 条/小时，整次 JSON 不超过 64 KiB。服务器对常见令牌/密码文本进行二次脱敏，但 APP 仍须先移除原始敏感信息；不得上传账号密码、令牌、联系人、私信正文等。

## 六、异常处理与建议的调用顺序

常见 HTTP：400=参数问题；401=登录失效；403=授权或额度问题；404=资源不存在；413=请求太大；416=Range 无效；429=限流；503=服务繁忙。

建议 APP：

~~~text
login -> license_status -> mobile_list
   -> 检测实际安卓手机 -> mobile_check -> mobile_bind（若未绑定）
   -> package_check -> package（下载原加密操作包）
   -> update_check -> Ed25519验签 -> update_download -> SHA256核对 -> 安装与回滚
   -> 运行期间 client_heartbeat/mobile_heartbeat/log_batch
   -> logout
~~~

电脑换机：新电脑直接 `login`，满额自动撤销最早登录的旧电脑；手动设备管理仍可使用 `device_list` / `device_revoke` 或 `replace_device_id`。
手机换机：mobile_unbind/mobile_bind。

## 七、AI 接口（v0.4.0，兼容 v0.3）

AI 默认由服务器中转，APP 不需要也不应该拿到服务器 DeepSeek Key。主管理员在后台「AI 接口管理」配置服务器 Key、默认模型和额度。默认模型为 \`deepseek-flash\`，请求固定发往 \`https://api.deepseek.com/chat/completions\`，不允许客户端自定义 URL、Host 或代理地址，防止 SSRF。

### 7.1 查询 AI 可用状态

\`POST ?action=ai_status\`，仅需通用的 \`device_id\` 和 Bearer Token。响应不包含任何密钥：

~~~json
{
  "ok": true,
  "enabled": true,
  "provider": "deepseek",
  "default_model": "deepseek-flash",
  "server_mode_available": true,
  "allowed_models": ["deepseek-flash", "deepseek-v4-pro"],
  "max_tokens": 4096,
  "requests_per_minute": 10,
  "daily_limit": 100,
  "daily_used": 2,
  "daily_remaining": 98
}
~~~

当 AI 已开放时，只返回值为 \`true\` 的权限布尔项：例如服务器模式不可用则省略 \`server_mode_available\`，客户端自带 Key 未开放则省略 \`client_key_allowed\`；不再向客户端透露服务器是否存有 API Key（移除 \`server_key_configured\`）。当 AI 全部关闭时只返回 \`{"ok":true}\`，不会输出模型列表或隐藏的可用功能。客户端应按字段存在且严格等于 \`true\` 判断能力。AI 请求仍由服务器逐次检查权限。

### 7.2 默认服务器中转

\`POST ?action=ai_chat\`。客户端不传 API Key，默认 \`credential_mode=server\`：

~~~json
{
  "device_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "credential_mode": "server",
  "messages": [
    {"role": "system", "content": "你是一个专业的软件助手。"},
    {"role": "user", "content": "帮我解释这个错误。"}
  ],
  "max_tokens": 2048,
  "temperature": 0.7,
  "top_p": 1,
  "thinking": "disabled"
}
~~~

成功响应采用 DeepSeek OpenAI 兼容 Chat Completions JSON 格式（包含 \`choices\`、\`usage\` 等字段）。APP 读取 \`choices[0].message.content\`。当前版本只支持非流式，\`stream=true\` 会返回 \`STREAM_UNSUPPORTED\`。

### 7.3 客户端自带 Key（BYOK，可选）

只有同时满足以下条件才允许：
1. 主管理员在「AI 接口管理」打开全局「允许客户端自带 Key」。
2. 主管理员在客户账号编辑页对该客户单独勾选「允许该客户自带 Key」。
3. 客户 AI 功能已开启、账号有效且额度未用尽。

APP 先调用 \`ai_status\` 检查 \`client_key_allowed=true\`，然后才可发送：

~~~json
{
  "device_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "credential_mode": "client",
  "api_key": "客户自己在本地配置的 DeepSeek Key",
  "messages": [
    {"role": "user", "content": "你好"}
  ]
}
~~~

BYOK Key 仅随当前 HTTPS 请求转发给 DeepSeek，不写入 PhoneHub 数据库、日志或审计记录，也不会返回给客户端。建议 APP 安全保存在系统凭据库中。客户端不能指定 Provider、模型、URL 或代理；仍使用后台选定的模型。全局开关关闭或客户未获单独授权时，服务端返回 \`CLIENT_KEY_FORBIDDEN\`，即使客户端绕过界面自行提交 Key 也无效。

### 7.4 服务端安全与限额

- 服务端 Key 使用 PHP sodium secretbox 加密后存入设置表；加密主密钥位于 \`storage/ai-master.key\`，权限限制为仅服务器用户可读。数据库和该主密钥文件必须一起备份。主密钥丢失时不会自动生成替代密钥，以免原 Key 永久无法解密。
- DeepSeek Provider 和 HTTPS API URL 固定，客户端不能构造任意 URL；TLS 证书校验开启、禁止重定向。
- 每客户默认每分钟最多 10 次、每天最多 100 次；客户额度可在授权编辑页调整，0 表示关闭。主管理员可调整服务器最大输出 Token（256–8192）。
- 每次调用先校验客户启用状态、授权有效期、AI 总开关、客户 AI 权限、Key 模式权限和额度；数据库锁避免并发请求绕过限额。DeepSeek 上游请求固定开启 `safety_check.level=high`，客户端不能关闭。
- 消息最多 40 条；单条最多 32 KiB、总内容最多 128 KiB；整个 AI JSON 请求最多 256 KiB；上游响应最多 4 MiB；连接超时 10 秒、总超时 90 秒。
- 不保存 Prompt、Completion、客户端 Key 或服务器 Key。只记录客户、设备、模式、模型、状态、HTTP 状态、Token 用量与耗时；服务商错误响应不原样透传。
- AI 接口不提供流式传输；如后续 APP 需要 SSE，再单独增加带限额的流式代理。

常见 AI 错误码：\`AI_DISABLED\`（未开放）、\`AI_NOT_CONFIGURED\`（服务器 Key 未配置）、\`CLIENT_KEY_FORBIDDEN\`（BYOK 未获双重授权）、\`AI_RATE_LIMIT\`（每分钟限额）、\`AI_DAILY_LIMIT\`（每日额度）、\`AI_UPSTREAM_AUTH\`（上游 Key 无效）、\`AI_UPSTREAM_RATE_LIMIT\`（服务商限流）、\`AI_UPSTREAM_UNAVAILABLE\`（上游不可用）。

## 八、管理后台接口与上线开关

管理后台 POST /license/index.php 使用 Cookie Session + CSRF，**不提供给客户 APP 使用**：

- 管理员：login/logout；admin_create/admin_reset/admin_toggle/admin_delete（仅主管理员），owner_password（仅主管理员）。
- 客户：account_save/account_password/reset_sessions/revoke_session。
- 分组：group_create/group_delete/group_bulk。
- 手机：mobile_add/mobile_revoke；mobile_blacklist/mobile_unblacklist（仅主管理员）。手工绑定支持可选 IMEI，服务端只存 HMAC 摘要。
- 核心更新：release_publish/release_toggle（仅主管理员）。
- 系统自身更新：update_check/update_apply（仅主管理员；与客户端更新同名但路径和认证不同）。
- AI 配置：ai_settings_save（仅主管理员）。
- MCP/Codex/Harness/Skill 云端总开关：cloud_features_save（仅主管理员）；新客户默认不授予 mcp/skill。
- 日志清理：logs_purge（仅主管理员）。

**测试版部署顺序（v0.5.18）：**

1. 更新 /license/ 后台，验证 Ed25519 签名、MySQL 5.7、环境自检、手机指纹授权、签名 ZIP 和 AI/MCP/Skill 策略。
2. 让所有测试客户端将 API 基础 URL 改为 `https://data.tmd.pet/license/api/phonehub.php`，不要继续请求旧的 `/phonehub/api.php`。
3. 若旧目录的 `/phonehub/api.php` 曾在生产服务器上存在或被接管，先备份并检查其是否仍承载请求，再由服务器管理员手工删除该旧文件、清理对应的 Nginx/ESA 转发规则；此次 GitHub 自更新只安装 /license/ 下签名白名单文件，**不会自动删除仓库之外的文件**。
4. 新后台不再提供旧接口覆盖、接管或备份命令；操作包下载仍通过当前手机指纹绑定和客户授权验证。

Web 服务器必须禁止 HTTP 访问 /license/storage/，否则更新私钥、数据库配置、日志、备份可能泄露。首次部署和管理后台自身升级不自动修改 Nginx。网址 /license/ 请加末尾斜杠。

## 九、已测试与未完成的部分

已加入 PHP/JS 语法、MySQL 5.7 自动建表/迁移、手机绑定前后 package 访问控制、会话认证、日志上报、更新查询的 GitHub Actions 集成测试。

仍需在你的实际宝塔环境验证：Nginx/ESA 路由、代理 ZIP 下载、PHP 上传限制、真实 APP 客户端、IMEI 在目标设备上的可读取性、真实签名 ZIP 安装/失败回滚。服务端能提供签名与下载不等于桌面 APP 已有完整安全升级器。

### 可选的批量心跳（向后兼容，v0.5.9）

既有 `client_heartbeat` 不带 `batch` 参数时，响应结构保持不变；`license_status`、`capabilities`、`client_config` 也不受影响。仅显式传入 `batch` 时，服务端在原响应基础上追加 `batch` 字段。登录态和电脑授权仍由原有 Bearer Token + `device_id` 校验。

请求示例（演示字段，`phone_id` 为客户端已获取的 64 位十六进制指纹）：

```json
{
  "device_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "batch": {
    "phones": [
      {"phone_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
    ],
    "package_versions": {"douyin": 4}
  }
}
```

成功响应继续包含原 `username`、`server_time`、`session_expires_at`、`license_until`、`entitlements`、`mobile`、`computer`、`features`、`settings`，另外：

```json
{
  "batch": {
    "phones": [{"phone_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","bound":true,"status":"bound","imei_bound":false}],
    "packages": [{"package_id":"douyin","version":5,"download_allowed":true,"update_available":true}],
    "ai": {"enabled":true,"server_mode_available":true,"client_key_allowed":false},
    "limits": {"phones":8,"package_versions":16}
  }
}
```

- `phones` 最多 8 项，必须为 `{"phone_id":"…"}` 对象的数组；可选 `imei` 仅用于当次身份核验，必须遵守知情同意与 HTTPS 要求，不在响应中返回。重复手机、非法身份/版本数据、超限批次均返回有 `error_code` 的结构化 400。
- 服务端逐个按**当前数据库**核验该用户的绑定、设备黑名单、可选 IMEI 一致性及**最旧有效绑定优先**的手机额度。手机状态为 `bound`、`not_bound`、`blacklisted`、`identity_mismatch`、`quota_exceeded`、`quota_disabled`。只有 `bound=true` 刷新 `last_seen`。客户端遇到任何其他状态必须立即将该手机视为不可用；不可沿用先前授权。
- `packages` 只包含当前客户已授权、服务器启用、对应全局开关开启的操作包，不返回 `envelope` 或 `content_key`。下载资格仍需至少有**本批通过核验**的手机；`update_available` 仅按服务端版本与客户端上报版本比较，客户端版本**不参与权限判断**，未提交版本返回 `null`。资源变化后仍需调用原 `package` 端点，由服务端重新检查授权和有效手机绑定。
- `ai` 只返回有效 AI 策略、可用服务器模式与 BYOK 许可三个布尔字段；同时遵守当前用户每日额度，不返回任何上游密钥、密文、Token 或密钥是否存在的原始内容。
- 请求体继续采用现有 64 KiB 限制，手机 8 项/包版本 16 项；这不是延长客户端离线有效期或绕过手机心跳的许可。旧客户端继续使用原调用即可；新客户端只有拿到明确的当次 `bound=true` 和 `download_allowed=true` 才能采用批量结果。
- **安全边界：** `batch` 是当前状态快照，不能代替实际下载时再次验权。手机指纹/可选 IMEI 不是可信硬件证明；不保证客户端本机不会被逆向、Hook 或读取内存。


### 批量心跳客户端接入、降级与验收（2026-11-18）

本节保留批量心跳的历史功能说明；现行部署以 v0.5.19 后台和 `/license/api/phonehub.php` 为准。CI 代码检查不代表生产 Nginx、ESA、客户端安装和真实流量已经联调完成。

**实际调用路径**

- 直接联调：`POST https://data.tmd.pet/license/api/phonehub.php?action=client_heartbeat`，使用登录后的 `Authorization: Bearer ...` 和登录时相同的 `device_id`。
- 不再提供 `/phonehub/api.php` 兼容路由或自动接管；所有客户端一律使用新路径。
- `phones` 应来自客户端当前实际检测到的手机；本接口只验证服务器绑定资格，**不证明 USB 实时在线**。客户端必须自行进行在线检测和按手机 ID 关联结果。
- `package_versions` 应填写真实已缓存包的整数版本（0 到 2147483647，最多 16 个），例如 `{"douyin":1}`。这里没有提供版本的包，服务端返回的 `update_available` 为 `null`；不能将 `null` 当成无更新。

**客户端必须采用拒绝优先的状态机**

1. 原有 Bearer 会话失效、账号过期或电脑受限：停止本次授权访问；不能拿本地缓存的旧 `batch` 替代实时鉴权。
2. 旧服务端**完全没有**返回 `batch` 字段：可临时退回旧的 `mobile_check/mobile_heartbeat`、`package_list/package_check`、`ai_status` 分项检查，不能因此省略手机检查。
3. 已明确返回 `batch`，但其数据缺失、类型错误、手机数量或手机 ID 对不上、含重复或冲突结果：**视为协议错误，不回退到放宽检查的模式**；应停止受影响的操作包和手机授权使用，并提示联系管理员。
4. 逐个手机核对 `phone_id`、`bound === true` 且 `status === "bound"`；`not_bound`、`blacklisted`、`identity_mismatch`、`quota_exceeded`、`quota_disabled` 都必须当次拒绝，不复用其他手机的结果。
5. 对每个包同时检查它仍在本次 `packages` 中、`download_allowed === true`，以及本地版本未过期、包内容通过原有验签和防回退校验。服务端不在 `batch` 返回密文或密钥；需要更新时仍使用已有 `package` 下载接口并再次验权。
6. `ai` 中的 `enabled`、`server_mode_available`、`client_key_allowed` 均要求布尔值严格等于 `true`；服务端对实际 `ai_chat` 仍重新检查开关、客户额度和密钥模式。任何响应不延长离线授权期限。

**已审查接口文件与校验值（仅对应当前这份 ZIP）**

| 接口文件 | SHA-256 |
|---|---|
| `api/phonehub.php` | `2f235b1cb0fd279c1f26231000b00f0c4296949ca3e44de92a86ba75c7e5c191` |
| `api/extensions.php` | `1de8af6f6d07826ad1b2e47602c9e13880fbafd7f2c4dc7bcfcb8f68e50566fc` |

这组哈希用于识别已审查的文件，**不代表对未来版本固定哈希**。客户端交付包自述单次手动检查约 2.120 秒、其中一次心跳约 1.972 秒，并自述客户端测试通过；这些是**交付方的报告值，尚未由服务端实测独立复核**。若要确认 2 秒耗时来源，应启用可选 PHP 分段采样并结合 Nginx 请求耗时和客户端 DNS/TCP/TLS/TFFB 数据，不应凭这一次读数认定数据库慢。

**资源保密边界：** 原 `package` 返回的加密 `envelope` 与 `content_key` 可被合法客户端同时获取，因此有效客户端仍可能提取解密后的操作包；已签名 ZIP 验证的是完整性和发布者身份，**不是 ZIP 内容加密**。批量心跳不会改变这个事实。请先按照 [运维备份与升级](运维备份与升级.md) 的 Nginx 防护要求阻止对 `/license/storage/` 的匿名直接访问，并验证所有 CDN/源站入口。

## v0.5.16 既有安卓绑定的身份补报

旧手机第一次 mobile_bind 如果没有传 imei、phone_number，服务器不能凭空恢复原号。v0.5.16 修复 mobile_heartbeat 只核验 IMEI 而不保存补报字段的问题。
客户端通过 HTTPS、认证 Bearer、正确的登录电脑 device_id 调用 POST /license/api/phonehub.php?action=mobile_heartbeat。请求可选字段为 imei（14～16 位数字）、phone_number（国际号码或国内 11 位手机号）、phone_model（最多 120 字节）；必须包含已有的 phone_id（64 位小写 SHA-256）。

例如：

~~~json
{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","phone_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","imei":"490154203237518","phone_number":"13912345678","phone_model":"Test Galaxy"}
~~~

只在设备已经绑定且仍有效、未黑名单和额度允许的情况下补充加密字段，不自动新增设备或静默覆盖冲突身份。重复调用原 mobile_bind 也可以补齐已有记录。

成功响应在原字段外追加 imei_stored、phone_number_bound、phone_model_received，mobile_list/mobile_check 也能读取相同的布尔状态；imei_bound 仍仅代表 HMAC 摘要存在。所有返回均不含敏感原文。

client_heartbeat.batch.phones[].imei 依旧只是身份核验，不执行原号持久化。老版 Windows/Android 客户端必须更新其请求构造逻辑才能真正补报。Android 10+ 普通第三方 APP 不一定有权限读取 IMEI，SIM 号码也可能为空；无法合法获得时不要传伪造值，继续用 phone_id。


## v0.5.17 当前接口与页面精简

- 移除独立 IMEI、手机号的接收验证、HMAC 生成、可逆加密、读取原号及后台编辑；`mobile_bind`、`mobile_heartbeat`、`mobile_check`、`client_heartbeat.batch` 只依据 `phone_id` 执行新设备的授权逻辑。
- 兼容处理：老客户端 JSON 中如果还携带 `imei`、`phone_number`，服务端忽略这些字段，不会触发新保存和黑名单匹配，也不会在返回结果包含 `imei_bound`、`imei_stored`、`phone_number_bound` 等状态。客户端应删除上传逻辑。
- 为避免隐式撤销以前已经生效的黑名单，服务端内部可以继续使用历史绑定记录中 **已经存储的摘要** 校验历史禁令。不会创建新摘要或开放新建这两类黑名单的入口；后台列表只保留电脑 ID / 手机指纹两种可维护类型。
- 历史迁移列和加密数据 **不在此次升级时自动删除**；无用户明确数据清除指令时，升级不能不可逆地删除授权历史。需要清除历史 PII 时，应另行进行受控备份、保留策略审查和数据库清理。
- 后台菜单将「操作包」放入「版本发布与操作包」管理页，历史加密操作包与 Ed25519 客户端更新包的数据和下载接口完全独立。「AI 接口管理」合入「客户端能力与 AI」，保留原模型/密钥/用量配置及 MCP/Skill 开关。

## v0.5.18 后台导航合并及测试期接口收敛

- 「客户分组与批量配置」同页完成分组创建、删除、批量授权预检及提交；保留成员快照校验，原内部书签 `?view=group_bulk` 仅重定向到分组页锚点。
- 「系统维护」统一展示在线更新、运行环境自检、Ed25519 自更新签名与 Curve25519 备份公钥配置；原内部书签 `?view=backup_keys` 仅重定向到维护页锚点。签名私钥与备份解密私钥仍是两套独立安全域。
- 后台 `gateway_install` 操作、`?view=gateway` 页面以及旧接口文件覆盖实现已删除；不提供旧客户端 API 兼容支持。**只支持 `/license/api/phonehub.php`**。
- `app/gateway.php` 在服务端自更新文件包中仅留无功能的最小占位内容，因为历史已安装的自更新器以固定 Ed25519 文件名清单验签；它不会注册、重定向、备份或代理任何旧接口请求。


### v0.5.19 服务器自更新说明

服务端自更新与客户端 ZIP 发布是**独立**机制：更新服务器 PHP 管理程序时，已安装的 v0.5.18 使用 V2 Ed25519 清单完成本次迁移准备升级。v0.5.19 后的新更新器只信任由固定公钥验证的 V3 清单（`format=2`，明确列出签名 SHA-256 文件及受限 `remove` 列表）。本次仅停用 V1，未清理网关占位文件，下一阶段在所有测试服务器升级到 V3 后再执行删除。客户端仍只访问 `/license/api/phonehub.php`，不受上述升级清单切换影响。


### v0.5.20 自更新清单收敛

服务器软件自更新现仅发布 `deploy/self-update-manifest-v3.json` / `.sig`，格式 2，使用原固定 Ed25519 公钥；删除 V1、V2 自更新清单和 `app/gateway.php` 空占位。V3 `remove=["app/gateway.php"]` 可在已安装 v0.5.19 更新器的站点安全清理旧占位并在失败时回滚。历史 v0.5.18 更新器不再支持直接升级，需先迁移至 v0.5.19 或采用可信的手动升级。


### v0.5.21 后台操作包管理

主管理员在「版本发布与操作包 → 操作包管理中心」通过 `package_publish` 上传客户端加密工具生成的 JSON，并用 `package_toggle` 单独启用或停用操作包历史版本；只读管理员无权提交这些动作。新增版本不可覆盖，最高的有效启用版本仍通过 `package_list`、`package_check`、`client_heartbeat.batch`、`package` 原接口提供给合格客户。当前服务端不会给原 `phonehub_package_downloads` 补造历史版本号，下载统计只按 `package_id` 汇总。

加密 JSON 顶层含 `envelope` 对象与 Base64 的 32 字节 `content_key`，其中 envelope 的 `manifest`、`signature`、`nonce`、`ciphertext` 为非空 Base64；该格式与签名 ZIP 不可互换。上传校验不证明密文真实可解密或客户端签名可信，应在真实客户端联调验收。服务端从不在后台 GET 页、保存响应或审计日志输出解密密钥。


## Windows 启动时查询 scrcpy 下载地址（v0.5.24）

无需登录的公开只读 GET 接口，与客户授权登录接口互不影响：

```http
GET /license/api/phonehub.php?action=scrcpy_download HTTP/1.1
Accept: application/json
```

将 `/license` 替换为 PhoneHub 实际部署目录（如部署在网站根目录则使用 `/api/phonehub.php?action=scrcpy_download`）。

成功返回 HTTP 200：

```json
{
  "ok": true,
  "download_url": "https://down.tmd.pet/scrcpy/scrcpy-win64-v5.0.1.zip",
  "cache_ttl_seconds": 300
}
```

- 首次启动时 GET 一次；客户端可保留成功结果 **300 秒**，后续启动优先使用未过期本地缓存。查询失败时可使用已验证的上次成功值并安排重试；不要使用不可信输入作为下载链接。
- HTTP 响应包含 `Cache-Control: public, max-age=300, must-revalidate` 与基于当前 URL 计算的 `ETag`。缓存到期后可带 `If-None-Match`：未改变时返回 HTTP 304（无响应体），修改 URL 后返回新的 HTTP 200 与 ETag。
- API 只返回配置中的 HTTPS ZIP 地址，不代理文件、下载文件或重定向。客户端自行下载，并按需求校验压缩包安全性；**仅凭 HTTPS 不表示 ZIP 来自可信发布者**。
- 后台操作路径：**版本发布与操作包 → scrcpy 下载地址**。全局管理员或受保护主账号可修改；普通管理员不能访问或修改。
- 服务端限制为 HTTPS、标准端口、公开 DNS 域名和 `.zip` 后缀；禁止在 URL 中嵌入账号、密码或片段（fragment）。修改保存后新 GET 立即可获取新值，已缓存的客户端最长可能延迟 5 分钟。
- 数据库存储使用独立的 `phonehub_download_settings`，由增量迁移 v12 建立；不修改原有 `phonehub_feature_settings` 的短字符串开关，也不会覆盖既有用户授权。


## 官网主程序下载地址查询（v0.5.25）

新增**独立于 scrcpy** 的公开只读 GET 接口：

```http
GET /license/api/phonehub.php?action=main_program_download HTTP/1.1
Accept: application/json
```

该路径以部署在 `/license` 为例；部署于根目录时用 `/api/phonehub.php?action=main_program_download`。

HTTP 200 返回示例：

```json
{
  "ok": true,
  "download_url": "https://down.tmd.pet/scrcpy/scrcpy-win64-v5.0.1.zip",
  "cache_ttl_seconds": 300
}
```

- **当前 URL 仅为用户指定的临时占位地址（scrcpy ZIP），不是已验证的官网主程序安装包。** 正式安装包发布后，请在后台替换为真正的主程序下载地址。
- 后台入口：**版本发布与操作包 → 官网主程序下载地址**。仅全局管理员与受保护的主账号可修改，和「scrcpy 下载地址」互不影响。
- 同样支持 `ETag`、`If-None-Match` / HTTP 304 和 `Cache-Control: public, max-age=300, must-revalidate`。客户端可缓存 300 秒。每个资源有独立的 ETag，后台保存的新地址会在新的 GET 请求中立即返回。
- 官网主程序地址接受 HTTPS 公开域名的 `.zip` / `.exe` / `.msi` 文件 URL，禁止用户名、密码、fragment、IP、本地域名和非标准端口；接口只返回字符串，不重定向或代理下载，下载与文件验签由客户端自行完成。
- 数据库迁移 13 在 `phonehub_download_settings` 表中添加 `main_program` 项，使用 `INSERT IGNORE`，不会修改既有 scrcpy 配置。


## v0.5.27 · 授权安全、自动换机审计、设备筛选与采样

### 客户密码变更的唯一入口
管理端 `account_save` 创建客户时随机生成密码；任何通过该动作提交非空 `password` 字段的请求都会在服务器拒绝（即使管理员拥有全局权限）。编辑客户授权不会更改客户密码。需更换密码时通过后台 `account_password` 专用动作随机重置，并撤销该账号全部电脑会话。禁止让客户端或第三方管理脚本通过 `account_save` 自定义客户密码。

### 电脑会话完全撤销
后台「设备管理 → 电脑设备」每个电脑行可使用“撤销该电脑全部会话”。服务端以 `user_id + device_id` 一次撤销该电脑所有会话 Token，其他电脑和其他客户的会话保持不变；操作依然采用管理员 Cookie + CSRF 和服务器角色校验。老接口动作 `revoke_session` 沿用原来的会话 `id` 参数，响应新增 `revoked_sessions`（已撤销 Token 数量）。

### 自动换机事件与异常提示
`login` 保留 `replaced_devices`，新增 `frequent_replacement` 布尔字段：当前客户在过去 15 分钟内累计自动换机事件达到 5 次时为 true，仅提示，不会自动禁止登录。只有成功撤销其他电脑并建立新会话时才写入 `phonehub_computer_replacement_events`；只记录客户内部 ID、被撤销的电脑数量和 UTC 时间，不保存设备标识/Token/IP。后台「设备管理 → 电脑设备」显示命中阈值的客户概览。

### 设备列表
`GET /license/index.php?view=devices&device_tab=computers&device_q=查询内容&device_page=1`
支持 computers（电脑）、mobiles（安卓手机）、blacklist（禁止访问）三类；每类独立查询、30 条每页。根据所在类别匹配账号、设备指纹、手机号之外的型号/备注或拉黑原因。所有筛选条件使用参数化查询，分页数字有上限。管理界面仍需已登录、有 devices 页面权限的后台管理员。

### 授权请求性能采样与 P50/P95
PHP-FPM 中可临时设置 `PHONEHUB_PERF_SAMPLE_PERCENT=10`（取值 0–100；默认 0），对 `client_heartbeat`、`license_status`、`capabilities`、`client_config` 以统一比例抽样记录。示例行包含：

```text
PhoneHub heartbeat_perf status=200 action=license_status total_ms=... connect_ms=... auth_ms=... db_ms=... package_ms=... response_ms=... queries=...
```

日志不记录客户账号、手机标识、IP、URL、令牌或请求正文。可在有权限读取 PHP-FPM 日志的服务器本地执行如下汇总（将 `/path/to/php-fpm.log` 换成真实路径）：

```bash
PH_LOG=/path/to/php-fpm.log python3 - <<'PY'
import os,re,math,collections
data=collections.defaultdict(list)
pattern=re.compile(r'PhoneHub heartbeat_perf status=200 action=(\w+) total_ms=([\d.]+)')
with open(os.environ['PH_LOG'],encoding='utf-8',errors='replace') as source:
    for line in source:
        match=pattern.search(line)
        if match:
            data[match[1]].append(float(match[2]))
for action,values in sorted(data.items()):
    values.sort()
    n=len(values)
    p=lambda frac: values[min(n-1,max(0,math.ceil(n*frac)-1))]
    print(f'{action}: samples={n} PHP_P50={p(.5):.1f}ms PHP_P95={p(.95):.1f}ms')
PY
```

请同时检查 `connect_ms`、`db_ms` 和 `queries`。以上测得的 **PHP 服务端时间不包含客户端 DNS/TLS、代理网络以及 ZIP 下载**；不要直接把单次客户端 2198ms 与服务端总耗时对比。样本量少时 P95 不稳定，尽量收集足够多的请求后对比上线前后数据。请不要将完整生产日志上传公共问题讨论区。


## v0.5.28 · 历史记录维护、设备搜索和发布历史

**用户已确认官网主程序下载地址和独立官网首页均已完成。** 不以 `app/releases.php` 初始默认 URL 判断生产配置是否更新，正式地址以生产数据库中的 `phonehub_download_settings` 为准。

后台「系统维护」新增可交互的历史记录保留/分批清理。安全边界：

- 明确选择类别和保留最近天数，点击预览。预览不会删除记录，展示符合条件的历史数量。
- 用户确认后服务器验证当前管理员权限、5 分钟以内的防篡改预览、当前符合条件的数量是否改变；每次最多按最老 ID 删除 500 条。剩余记录需要重新预览确认。
- `client_logs` 至少保留 7 天、`ai_usage` 至少 30 天、`replacement_events` 至少 30 天、`package_downloads` 至少 90 天；全局管理员和受保护主账号可执行。管理员操作审计 `admin_audit` 仅主账号能删且至少保留 365 天。最大保留设置 3650 天。
- 服务器永远不将客户授权、管理员账号、设备绑定、会话 Token、实际 ZIP 操作包、软件签名或密钥纳入清理白名单。
- 后端动作 `history_cleanup_preview` 和 `history_cleanup_apply` 只接受后台已认证管理员 Cookie、CSRF、服务器权限检查。不得作为公网接口调用。默认**不自动定时执行清理**；需要定时任务应另行设计有明确权限的执行路径。
- 客户端日志既有 `logs_purge` 动作保留兼容，旧功能行为不变。

「设备管理 → 安卓手机」的管理员手动绑定增加 GET 参数 `mobile_customer_q`，至少输入两个字符，后台通过 SQL 参数化查询支持全量客户搜索（每次最多展示 25 个匹配项）。`mobile_add` 继续由服务器根据客户 ID、额度和设备黑名单进行校验，绝不信任下拉框状态。

「版本发布与操作包」现支持 `pkg_q`、`pkg_page` 筛选加密操作包历史，以及 `release_q`、`release_page` 筛选签名更新版本历史；均为只读 GET、每页 50 条。原有 `package_publish`、`package_toggle`、`release_publish`、`release_toggle` 权限与路径保持不变。
