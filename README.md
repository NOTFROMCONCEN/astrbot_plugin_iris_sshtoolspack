# astrbot_plugin_iris_sshtoolspack

Iris SSH 工具包，讓使用者可在 IM 入口與 Bot 交流，並由 Bot 透過插件內設定的 SSH 連線方式連到指定伺服器執行命令。

目前版本僅提供 SSH 透傳命令，後續可在同一套格式下擴充更多連線方式或工具。

## 指令

- `/SSH執行 <命令>`
- `/SSH執行 <設定名> <命令>`
- `/SSH狀態`
- `/SSH帮助`

簡中相容：

- `/SSH执行 <命令>`
- `/SSH执行 <配置名> <命令>`
- `/SSH状态`
- `/SSH帮助`

英文相容：

- `/ssh_exec <command>`
- `/ssh_exec <profile> <command>`
- `/ssh_status`
- `/ssh_help`

## 1.0.1-beta 功能

- 透過 SSH 連線到插件設定的伺服器並執行 IM 入口傳入的命令
- 支援密碼或私鑰登入
- 支援命令逾時、連線逾時與輸出長度截斷
- 僅允許 AstrBot 管理員或 `admin_user_ids` 內的使用者執行
- 指令入口提供英文、簡中、繁中三套別名

## 推薦設定

- `ssh_profile_name=default`: 連線設定名稱
- `ssh_host`: SSH 伺服器地址
- `ssh_port=22`
- `ssh_username`: SSH 使用者名稱
- `ssh_password`: 密碼登入時填寫
- `ssh_private_key_path`: 私鑰登入時填寫私鑰路徑
- `ssh_private_key_passphrase`: 私鑰密碼，沒有可留空
- `command_timeout_sec=30`
- `connect_timeout_sec=10`
- `max_output_chars=3500`
- `admin_user_ids`: 可執行 SSH 命令的使用者 ID
- `allow_astrbot_admin=true`

## 安全提醒

本插件是命令透傳工具，等同於讓被授權的 IM 使用者在目標伺服器上執行 shell 命令。請務必限制管理員、使用低權限 SSH 帳號，並避免在高權限帳號上直接使用。
