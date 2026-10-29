# iamhc 自动签到脚本

自动登录 [api.hcnsec.cn](https://api.hcnsec.cn)并执行每日签到，签到后通过 Telegram 推送通知(可选)。

test
### 配置 Secrets

在仓库 **Settings → Secrets and variables → Actions** 中添加以下 Secrets：

| Secret 名称 | 说明 |
|-------------|------|
| `EMAIL` | 登录邮箱(必填) |
| `PASSWORD` | 登录密码(必填) |
| `TG_BOT_TOKEN` | Telegram Bot Token(可选) |
| `TG_CHAT_ID` | Telegram Chat ID(可选)  |

### 手动触发

在仓库 **Actions** 页面选择 `iamhc Daily Checkin` 工作流，点击 **Run workflow** 即可手动触发。

## 获取 Telegram Bot Token 和 Chat ID

1. 在 Telegram 中搜索 `@BotFather`，发送 `/newbot` 创建机器人，获取 **Bot Token**
2. 搜索 `@userinfobot`，发送任意消息，获取你的 **Chat ID**
3. 先给你的 Bot 发一条消息（激活会话），否则 Bot 无法主动推送
