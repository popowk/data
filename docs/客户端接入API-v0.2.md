# PhoneHub 客户端 API v3 接入说明

服务端版本：0.3.0。适配对象：PhoneHub 桌面 APP（此前为 0.7.1）。先完成服务端接口，客户端暂不需要改动。

## 一、地址与认证

生产统一地址：https://data.tmd.pet/phonehub/api.php?action=ACTION

开发测试（尚未接管旧接口时）：https://data.tmd.pet/license/api/phonehub.php?action=ACTION

- health：GET，无认证，返回 ok/service/api/mobile_binding。
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

电脑满额可在登录请求中额外传 replace_device_id（准备踢下线的旧电脑设备标识）；前提是密码验证通过，该旧电脑属于同一客户，并且替换后名额足够。由用户确认后调用。

### 共用的已登录请求范例

~~~http
POST /phonehub/api.php?action=mobile_list HTTP/1.1
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
| mobile_bind | phone_id, 可选 display_name | 绑定安卓手机，返回 bound 与手机额度 |
| mobile_list | 无 | 当前用户的手机列表、mobile_limit、active_count |
| mobile_check | phone_id | 检查该安卓手机是否绑定，返回 bound |
| mobile_heartbeat | phone_id | 绑定检查并刷新 last_seen |
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

除 login 和 health 外，以上表格省略了每个 JSON 请求都必填的 device_id。未知 action 返回 404。

## 三、手机绑定（APP 接入重点）

phone_id 格式：64 位十六进制 SHA-256，建议由稳定的、非个人敏感的安卓设备标识推导。不能直接使用手机号/IMEI，也不能让用户输入任意数字当作设备证明。设备绑定是授权标识，不等于可信硬件远程认证。

POST ?action=mobile_bind：

~~~json
{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","phone_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","display_name":"Android 设备 1"}
~~~

成功：

~~~json
{"ok":true,"phone_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","bound":true,"mobile_limit":3,"active_count":1}
~~~

mobile_limit=0 表示不允许绑定，不表示无限制。手机名额是有效绑定总数，不是当前 USB 在线数量。新增绑定由服务端按客户行锁+事务检查额度；解绑释放名额。APP 应根据自己的 ADB 设备检测结果调用 mobile_bind/mobile_heartbeat。

### 操作包下载强制条件

必须同时满足：登录有效 + 账号正常未到期 + entitlements 含平台 + 手机额度大于 0 + 至少存在一个 enabled=1 的安卓手机绑定 + 操作包可用。只设置额度、没有真实绑定记录，package 仍然被拒绝。解绑最后一台手机后，再次禁止下载。

package 返回结构仍为：

~~~json
{"ok":true,"envelope":{"manifest":"<Base64>","signature":"<Base64>","nonce":"<Base64>","ciphertext":"<Base64>"},"content_key":"<Base64>"}
~~~

该机制检验“已绑定”，不要求下载瞬间手机插着 USB；是否在线应由 APP 自行判断。

## 四、客户端核心更新（独立于操作包）

管理员后台地址：https://data.tmd.pet/license/?view=releases

上传 ZIP、填写 platform（core/douyin/xiaohongshu）、channel（stable/beta）、version（如 0.8.0）、min_client、notes 后，服务端：

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

电脑换机：device_list/device_revoke 或登录的 replace_device_id。
手机换机：mobile_unbind/mobile_bind。

## 七、AI 接口（v0.3.0）

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
  "server_key_configured": true,
  "client_key_allowed": false,
  "allowed_models": ["deepseek-flash", "deepseek-v4-pro"],
  "max_tokens": 4096,
  "requests_per_minute": 10,
  "daily_limit": 100,
  "daily_used": 2,
  "daily_remaining": 98
}
~~~

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
2. 客户账号编辑页对该客户单独勾选「允许该客户自带 Key」。
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
- 每次调用先校验客户启用状态、授权有效期、AI 总开关、客户 AI 权限、Key 模式权限和额度；数据库锁避免并发请求绕过限额。
- 消息最多 40 条；单条最多 32 KiB、总内容最多 128 KiB；整个 AI JSON 请求最多 256 KiB；上游响应最多 4 MiB；连接超时 10 秒、总超时 90 秒。
- 不保存 Prompt、Completion、客户端 Key 或服务器 Key。只记录客户、设备、模式、模型、状态、HTTP 状态、Token 用量与耗时；服务商错误响应不原样透传。
- AI 接口不提供流式传输；如后续 APP 需要 SSE，再单独增加带限额的流式代理。

常见 AI 错误码：\`AI_DISABLED\`（未开放）、\`AI_NOT_CONFIGURED\`（服务器 Key 未配置）、\`CLIENT_KEY_FORBIDDEN\`（BYOK 未获双重授权）、\`AI_RATE_LIMIT\`（每分钟限额）、\`AI_DAILY_LIMIT\`（每日额度）、\`AI_UPSTREAM_AUTH\`（上游 Key 无效）、\`AI_UPSTREAM_RATE_LIMIT\`（服务商限流）、\`AI_UPSTREAM_UNAVAILABLE\`（上游不可用）。

## 八、管理后台接口与上线开关

管理后台 POST /license/index.php 使用 Cookie Session + CSRF，**不提供给客户 APP 使用**：

- 管理员：admin_create/admin_reset/admin_toggle/admin_delete（仅主管理员），owner_password（仅主管理员）。
- 客户：account_save/account_password/reset_sessions/revoke_session。
- 分组：group_create/group_delete/group_bulk。
- 手机：mobile_add/mobile_revoke。
- 核心更新：release_publish/release_toggle（仅主管理员）。
- 系统自身更新：update_check/update_apply（仅主管理员；与客户端更新同名但路径和认证不同）。
- 日志清理：logs_purge（仅主管理员）。
- 旧 API 接管：gateway_install（仅主管理员）。

**上线顺序（重要）：**

1. 先让已部署的 /license/ 管理后台从 GitHub 国内镜像升级到 0.2.0，自动执行 MySQL 5.7 数据表迁移。
2. 暂时保留现有 /phonehub/api.php，不影响旧 APP 和已经在使用的客户。
3. APP 开发可先调用 /license/api/phonehub.php 测试新 API，绑定手机、日志、核心 ZIP 更新等。
4. 完成 APP 适配后，以主管理员打开 /license/?view=gateway 进行旧 API 接管。此操作只会在旧接口文件 SHA-256 与上传的 0.7.1 参考版相同、目录可写时执行，原文件备份保存到 storage/backups/gateways。
5. 接管后，原地址 /phonehub/api.php 对操作包严格实行“至少绑定一台已授权安卓手机”限制。旧 APP 如果没有绑定功能，会遇到下载拒绝；需要先升级 APP 或手工绑定客户手机。

Web 服务器必须禁止 HTTP 访问 /license/storage/，否则更新私钥、数据库配置、日志、备份可能泄露。首次部署和管理后台自身升级不自动修改 Nginx。网址 /license/ 请加末尾斜杠。

## 九、已测试与未完成的部分

已加入 PHP/JS 语法、MySQL 5.7 自动建表/迁移、手机绑定前后 package 访问控制、会话认证、日志上报、更新查询的 GitHub Actions 集成测试。

仍需在你的实际宝塔环境验证：Nginx/ESA 路由、代理 ZIP 下载、PHP 上传限制、真实 APP 客户端、真实签名 ZIP 安装/失败回滚。服务端能提供签名与下载不等于桌面 APP 已有完整安全升级器。
