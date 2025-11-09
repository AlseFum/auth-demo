项目开发运行说明（使用 uv）

一、环境准备
- 安装 Python 3.12+
- 安装 uv（Windows PowerShell）：

```powershell
irm https://astral.sh/uv/install.ps1 | iex
```

二、安装依赖
（无需生成 venv，uv 会自动管理）
```powershell
uv sync
```

三、运行开发服务器
代码位于 `src` 目录，使用 `--app-dir src` 让 uvicorn 识别模块：
```powershell
uv run uvicorn main:app --app-dir src --reload
```

八、测试（标准库 unittest）
- 运行全部测试：
```powershell
uv run python -m unittest
```

四、目录结构
- `src/`：应用代码（已扁平化）
- `data/`：数据目录（含密钥与数据文件）
- `scripts/`：脚本（可选）

五、密钥与登录
- 密钥文件：存放于 `data/` 下，命名为 `<key_id>.key.pem`
- 若 `data/` 内未发现任何 `*.key.pem`，服务启动会自动生成 `default.key.pem`
- 生成新密钥：`POST /api/login/keys/generate`（可提供 `key_id`，否则使用时间戳命名；文件存放于 `data/<key_id>.key.pem`）
- 获取公钥列表：`GET /api/login/publickeys`
- 注册：`POST /api/login/register`，请求体包含 `name`, `key_id`, `key`（base64 的密文）
- 登录：`POST /api/login/login`，请求体同上；账户支持多密码与多角色

六、数据存储（无外部数据库）
- 不依赖外部数据库，使用本地 JSON 持久化：`data/data.json`；密钥：`data/*.key.pem`
- 首次运行会自动创建该文件
- 结构包含：`users / credentials / roles / user_roles`

七、注意
- 将私钥放入 `data/` 目录，文件名去掉 `.key.pem` 的部分作为 `key_id`
- 生产环境请自行管理数据库连接、密钥权限与日志
