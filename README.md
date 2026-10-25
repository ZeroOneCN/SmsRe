# SMSFor

个人自用的短信验证码中转服务：一台常驻安卓手机负责收短信并转发，服务端解析出验证码，前台用超大字号展示，后台记录谁看过、可拉黑 IP。

> 仅用于本人名下的手机号。不要把这个服务开放给他人使用。

## 功能

- 接收 SmsForwarder 等 App 的 Webhook，服务端二次解析验证码（4–8 位，自动排除金额、尾号、订单号、日期）
- 前台大屏：无需登录，只显示验证码数字与"收到年月日时分秒"，不显示发件人与原文；到期自动清屏
- 前台跟随系统昼夜模式（`prefers-color-scheme`），新验证码到达时弹出 5 秒 toast 并同步更新数字
- SSE 实时推送，手机收到短信后页面秒级刷新，倒计时按秒递减
- 后台管理 PIN，5 次失败锁定 IP 15 分钟
- 后台：访问审计（IP/UA/结果/停留时长）、登录日志（成功/密码错误/锁定/限流，含归属地与 UA）、7 天统计、设备管理、短信原文与发件人记录
- IP 黑名单：支持单 IP 与 CIDR 网段、有效期、命中计数、日志页一键拉黑
- 心跳看门狗：设备超时无心跳时推送离线告警（需配置心跳）

## 技术栈

Node.js 22（内置 `node:sqlite`，无原生依赖）+ Fastify + 原生 HTML/CSS/JS。单进程，SQLite 单文件，1C1G 机器足够。

```
手机(SmsForwarder) --HTTPS POST--> Nginx/Cloudflare --> Fastify --> SQLite
                                                          └--SSE--> 前台大屏
后台管理页 <--------------------- /admin/api/* ------------┘
```

## 快速开始（本地）

```bash
npm install
cp .env.example .env      # 设置 ADMIN_PIN 即可
npm start                 # http://127.0.0.1:8080
npm test                  # 单元测试
```

首次启动会在日志中打印设备 Token（只打印一次），后台「设备」页可随时查看或轮换。

- 前台：`http://127.0.0.1:8080/`
- 常亮屏：`http://127.0.0.1:8080/screen`
- 后台：`http://127.0.0.1:8080/admin`
- 健康检查：`/healthz`

## 线上部署（香港/海外 VPS）

```bash
# 1. 上传代码后
cp .env.example .env && vi .env     # 必改 ADMIN_PIN，线上 COOKIE_SECURE=true

# 2. 启动
docker compose up -d --build
docker compose logs -f              # 记下首次启动打印的设备 Token

# 3. Nginx + HTTPS
sudo cp deploy/nginx.conf.example /etc/nginx/conf.d/smsfor.conf
# 修改域名后
sudo certbot --nginx -d sms.example.com
sudo nginx -s reload
```

要点：

- 容器只监听 `127.0.0.1:8080`，必须由 Nginx 提供 HTTPS，`COOKIE_SECURE=true` 才能生效。
- Nginx 配置里用 `proxy_set_header X-Forwarded-For $remote_addr;` **覆盖**而不是追加，否则客户端可伪造 IP 绕过黑名单。
- 若前面套 Cloudflare，需显式设置 `TRUST_CF_HEADER=true` 才会采信 `CF-Connecting-IP`；默认关闭，避免客户端伪造该头绕过黑名单与登录锁定。
- 若使用 Cloudflare Tunnel，可去掉 `ports` 映射，把 Tunnel 指向 `http://smsfor:8080`。

## 手机端配置（SmsForwarder）

1. 安装 [SmsForwarder](https://github.com/pppscn/SmsForwarder)，授予短信权限，关闭电池优化并允许自启动。
2. 新增转发规则 → 转发方式选 **Webhook**：
   - 地址：`https://sms.example.com/h/<设备Token>`（短地址；旧版 `/hook/<Token>` 仍兼容）
   - 方法：`POST`，`Content-Type: application/json`
   - 请求体：把 App 提供的「短信内容」变量填入 `text`，「发件人」变量填入 `from`（变量写法以 App 内提示为准，常见为 `[msg]` / `[from]`）：

```json
{"from":"[from]","text":"[msg]"}
```

> App 的地址输入框较窄，长地址会显示省略号，但粘贴进去的值是完整的；后台「设备」页点「复制地址」可一次复制全文。Token 为 16 位十六进制，配短路径 `/h/` 后整条地址约 40 个字符，基本能完整显示。

3. 建议在 App 内再配一条 Bark / 飞书通道做备份，服务端挂了也能收到码。
4. 心跳（可选但强烈建议）：每 10 分钟 `POST https://sms.example.com/api/heartbeat/<设备Token>`。SmsForwarder 若没有定时任务，可用 MacroDroid / Tasker 定时发送。**未配置心跳的设备不会触发离线告警。**

保活清单见 [PLAN_SMSFor.md §3.3](docs/SMSFor/PLAN_SMSFor.md)。

## 配置项

| 变量 | 说明 | 默认 |
|---|---|---|
| `ADMIN_PIN` | 后台管理 PIN，首次启动写入数据库并哈希保存，之后可在后台「修改 PIN」调整 | 必填 |
| `PIN` | 历史兼容项，前台已无需 PIN，可留空 | 空 |
| `PORT` / `HOST` | 监听地址 | 8080 / 0.0.0.0 |
| `COOKIE_SECURE` | HTTPS 环境必须为 true | true |
| `TRUST_PROXY` | 反向代理后为 true，用于取真实 IP | true |
| `CODE_TTL_SECONDS` | 验证码前台可见时长 | 600 |
| `OFFLINE_ALERT_MINUTES` | 心跳超时告警阈值 | 15 |
| `ALERT_WEBHOOK_URL` | 飞书机器人 / Bark / 自建告警地址 | 空 |
| `ADMIN_ALLOW_IPS` | 后台 IP 白名单，逗号分隔，支持网段 | 空 |
| `DATA_DIR` | SQLite 目录 | `data` |

## 安全设计

- 前台为公开只读页面，接口仅返回验证码数字、收到时间与到期时间，**不返回发件人、原文、设备等字段**
- 短信原文与发件人只存库、仅在后台鉴权后可见
- 前台接口按 IP 限流，SSE 连接数上限 200
- 验证码过期后 `code` 字段被置空，只保留 SHA-256 哈希供审计
- 全站 `noindex` + CSP + `X-Frame-Options: DENY`
- 后台登录失败 5 次锁定 IP 15 分钟，并推送告警；登录接口单独限流，所有尝试写入 `login_logs`（保留 90 天）
- 登录页与 `/api/auth*` 始终可达，误拉黑自己后仍能登录解封
- 后台 Cookie 为 `HttpOnly` + `SameSite=Strict`，会话 ID 192 位随机
- IP 判定：直接暴露端口时必须 `TRUST_PROXY=false`；反向代理必须覆盖 `X-Forwarded-For`；`CF-Connecting-IP` 默认不采信（需 `TRUST_CF_HEADER=true`）
- IP 规则 allow 优先于 block；已登录后台的会话不受黑名单影响（防止误封自己后进不去）
- 后台操作写入 `audit_log`

**上线前必做**：改掉默认 ADMIN_PIN、确认 `COOKIE_SECURE=true`、`.env` 不提交到仓库。

## 运维

- 备份：`sqlite3 data/smsfor.db ".backup 'backup/smsfor-$(date +%F).db'"`，建议每日 cron
- 恢复：停止容器 → 用备份文件替换 `data/smsfor.db` → 启动
- 日志：`docker compose logs -f --tail=100`
- 数据保留：过期短信 30 天后自动清理，登录失败记录保留 7 天

## 进度

| 里程碑 | 状态 |
|---|---|
| M1 打通链路（Hook + SQLite + 解析） | 已完成 |
| M2 前台大屏（公开展示 + SSE + 秒级倒计时 + 昼夜模式 + toast） | 已完成 |
| M3 安全加固（锁定、IP 规则、noindex） | 已完成 |
| M4 后台（审计、统计、设备、清理） | 已完成 |
| M5 稳定性（心跳配置、备份 cron、线上 TLS） | 待部署时完成 |
| M6 收尾（恢复演练） | 待完成 |

## 已知限制

- 访问日志与登录日志展示完整 IP，归属地由随包分发的 ip2region 离线库查询，不把访客 IP 发往第三方
- 单进程单实例，不支持多节点共享会话
- 短信原文与发件人仅存于本地库、只在后台可见，前台接口不会下发
