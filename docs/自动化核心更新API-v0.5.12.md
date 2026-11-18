# PhoneHub v0.5.12 客户端核心更新：AI / CI 自动发布接口

注意：本文件描述实际实现的 PHP 后台接口。Windows 客户端安装、失败回滚、真实安装验证和生产 Nginx 配置是单独的验收项目；服务端发布成功不代表客户端已成功升级。

## 1. 入口和现有接口

生产目标路径（需要部署 deploy/nginx-automation.conf 里的 Nginx rewrite）：

| HTTP | 路径 | 机器令牌权限 |
|---|---|---|
| POST | /license/automation/v1/releases/prepare | release:prepare |
| GET | /license/automation/v1/releases | release:read |
| GET | /license/automation/v1/releases/{id} | release:read |
| POST | /license/automation/v1/releases/{id}/publish | release:publish |
| POST | /license/automation/v1/releases/{id}/disable | release:disable |

**无需 Nginx rewrite 的等价地址：** /license/automation/v1/index.php?route=releases/prepare；通过 route=releases、releases/123、releases/123/publish、releases/123/disable 访问其他接口。Apache 已有 .htaccess rewrite；宝塔 Nginx 不读取 .htaccess。若站点部署目录不是 /license，需相应调整配置和 URL。自动化接口在生产必须以 HTTPS 到达 PHP；不能信任客户端任意伪造的 X-Forwarded-Proto。

## 2. 专用机器令牌

主管理员登录 PhoneHub → 客户端核心更新 → AI / CI 专用发布令牌。可设置令牌名称、平台（core/douyin/xiaohongshu/mcp/skill/mcp-codex/mcp-harness）、渠道（beta/stable）、独立权限（prepare/read/publish/disable）、有效期 1–365 天、可选完整来源 IP。

生成后明文令牌只显示一次，格式为 phat_ 加 64 位小写十六进制，服务端仅保存 SHA-256 摘要。把令牌保存到受信任的 CI Secret Manager，禁止写入代码、Git、Prompt 或日志。

所有请求必须携带请求头：Authorization: Bearer phat_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

令牌不能充当主管理员 Cookie Session，不能阅读或替换签名私钥。可由主管理员轮换（新令牌保留原权限及原到期时间，旧令牌立即撤销）或撤销。令牌每分钟限速 60 次，服务端通过 MySQL 原子计数；过期、撤销和非法来源拒绝访问。

## 3. 准备阶段：暂存，不发布

POST /license/automation/v1/releases/prepare 使用 multipart/form-data：

| 字段 | 规则 |
|---|---|
| platform / channel | 必填，必须在令牌授权的平台和渠道范围内 |
| version | 必填，语义版本如 0.9.0 |
| min_client | 最低兼容版本，默认 0.7.1 |
| notes | 最多 1000 字节 |
| file | ZIP，最大 50 MiB |
| sha256 | 必填，小写 SHA-256 十六进制摘要 |
| idempotency_key | 必填，8–64 位字母、数字、短横线或下划线 |
| commit_sha | 可选，40 位小写 Git Commit SHA |
| build_run_id | 可选，最多 100 位受限字符 |

示例（令牌由 CI 环境注入，不应直接输出其原文）：

    BASE=https://data.tmd.pet/license/automation/v1
    SHA=$(sha256sum phonehub-core-0.9.0.zip | cut -d' ' -f1)
    curl --fail-with-body -X POST "$BASE/releases/prepare" \
      -H "Authorization: Bearer $PHONEHUB_RELEASE_TOKEN" \
      -F "platform=core" -F "channel=beta" \
      -F "version=0.9.0" -F "sha256=$SHA" \
      -F "idempotency_key=ci-core-beta-0-9-0" \
      -F "file=@phonehub-core-0.9.0.zip;type=application/zip"

新任务返回 HTTP 201、ok=true、replayed=false、release.id、release.status=prepared 和文件摘要。同一令牌用同一幂等键重试，且版本/摘要一致时返回原任务（replayed=true），冲突返回 HTTP 409。已正式发布的相同平台、渠道、版本也会被拒绝。

ZIP 存在 storage/updates/ 的随机文件名下。服务端在暂存前检查 ZIP 路径、危险符号链接、条目数（最多 2000）、解压后尺寸（最多 250 MiB）、实际 SHA-256。prepared 不出现在客户端已发布列表中，也不能被客户端 update_download 下载。提交的 Git SHA / build ID 只是声明，后台不会自行推断构建已经通过 CI 校验。

## 4. 查询版本与任务

GET /license/automation/v1/releases 和 GET /license/automation/v1/releases/{id} 需要 release:read。按令牌的平台/渠道权限过滤，分别返回最多最近 50 条自动化发布任务和正式版历史。公开内容包括 ID、版本、SHA-256、构建来源、审批时间、正式 release_id、启用状态。不会返回 ZIP 字节、私钥或机器令牌。

任务状态：prepared、published、disabled、cancelled、rejected。client_install_verified=false 表示**尚未接入可信独立的 Windows 安装成功证明**，不能被当作测试通过的信号。

## 5. 发布和 stable 审批

POST /license/automation/v1/releases/{id}/publish 要求 release:publish 权限及平台、渠道范围合法：

- beta：CI 获得正确权限后可直接发布。
- stable：主管理员必须先在后台「客户端核心更新 → 待发布任务与稳定版审批」批准。未经批准返回 HTTP 403 / APPROVAL_REQUIRED。
- 真实发布时，重新校验暂存文件大小、ZIP SHA-256、ZIP 内容以及重复版本，使用原客户端签名密钥 storage/updates/signing.key 生成 Ed25519 清单签名，向原 phonehub_releases 写入已启用的发布版本。
- 已发布任务重试是幂等的，返回 replayed=true，不新增签名记录。
- 原有客户端 update_check、update_manifest、update_list、update_download API 保持不变。客户端还要自行验证固定 Ed25519 公钥、原始 manifest 字节签名及 ZIP SHA-256，并实现安装及失败回滚。

主管理员批准不是自动发布；仍需要有发布权限的机器令牌执行 publish。机器令牌不可读取私钥。

## 6. 停用（可安全重试）

POST /license/automation/v1/releases/{id}/disable 要求 release:disable。已发布任务会将正式版本设为 enabled=0；重复调用保持停用。尚未发布的 prepared 任务将取消并尝试删除暂存 ZIP。服务端停用并不能删除用户已安装的程序，也不会自动触发客户端回滚。

## 7. 状态码、审计与安全

错误均为 JSON，包括 ok=false、error_code、error。主要错误：401 UNAUTHORIZED；403 HTTPS_REQUIRED / PERMISSION_DENIED / SCOPE_DENIED / APPROVAL_REQUIRED；409 VERSION_CONFLICT / VERSION_ROLLBACK / IDEMPOTENCY_CONFLICT / INVALID_STATE；413 UPLOAD_LIMIT；422 SHA256_MISMATCH；429 RATE_LIMIT；503 SERVER_UNAVAILABLE。

数据库记录任务发起令牌、版本和渠道、Commit SHA、CI 构建 ID、文件摘要、创建/批准/发布/停用时间，以及事件审计与来源 IP。不会返回管理员密码、原始机器令牌或签名私钥。生产必须在宝塔 Nginx 中拒绝匿名访问整个 /license/storage/ 及其子目录；验证 CDN/ESA、源站 IPv4/IPv6 均被保护。

## 8. 安装、测试及正式上线顺序

1. 确保 PHP 8.2+、pdo_mysql、zip、sodium 模块可用，备份数据库和 storage/updates/signing.key。
2. 后台升级后执行 MySQL 5.7 兼容的结构版本 11 迁移，仅增加四张自动化表，不修改现有客户授权及签名信任链。
3. 按 deploy/nginx-automation.conf 添加 rewrite（若要使用友好路径），执行 nginx -t 后安全重载；确认 HTTPS、Authorization Header 转发及 storage 403。
4. 创建仅授权 beta 和 core 的短期机器令牌，先走无需 rewrite 的直连地址验证 prepare、幂等、publish、版本查询、真实客户端签名 ZIP 下载及 disable。
5. 单独测试 stable 未审批发布必须被拒、主管理员审批之后才允许发布。模拟错误 SHA、超限 ZIP、权限越界、令牌过期和撤销、重复版本和重放。
6. Windows 客户端更新器必须由客户端开发人员完成：下载、可信固定公钥验签、安全解压、独立进程安装、故障回滚和真实测试客户端健康检查。
7. CI 需独立验证 Git Commit、构建和客户端安装结果；服务器不能仅凭 build_run_id 或 commit_sha 字符串宣称测试通过。正式 stable 须获得主管理员明确审批。
8. PHP 管理后台自身更新走 GitHub Actions sign-server-update.yml 和后台 update_apply，**不得**使用上述客户端发布 API 更新服务器 PHP 文件。


## 9. 版本防回退与幂等细则

机器准备和发布会分别比较相同平台、渠道中的全部历史正式版本（包括已经停用的记录）。不能用更小的版本号新建并发布 ZIP；旧的 prepared 任务在等待审批期间如果变为过期版本，也会在 publish 阶段被拒绝（409 / VERSION_ROLLBACK）。旧版人工发布入口的行为保持原状，不应通过修改历史记录来绕过机器自动发布版本规则。

重放同一幂等键时会复核平台、渠道、版本、SHA-256、最低客户端版本；如果再次明确提交 notes、commit_sha 或 build_run_id，它们也不得和原任务冲突。轮换令牌不延长有效期，不追加后缀名称，避免多次轮换后触及数据库长度上限。
