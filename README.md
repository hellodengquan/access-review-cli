# 权限复核辅助命令行工具 (access-review)

一个帮助安全团队每季度进行用户权限审计、复核状态记录和异常权限检测的命令行工具。基于 Python 和 Typer 构建。

## 功能特性

- 📋 **权限清单管理** - 导入、导出、查询用户权限数据
- 🔍 **季度复核流程** - 创建复核周期、批量标记待复核、记录复核结果
- ⚠️ **异常权限检测** - 自动识别过期、长期未使用、越权等异常权限
- 📊 **复核报告生成** - 生成摘要报告、部门统计、收回清单
- ✅ **权限收回辅助** - 标记收回、批量导出待收回列表

## 安装

### 方式一：使用 pip 安装

```bash
# 在项目目录下执行
pip install -e .
```

### 方式二：直接安装依赖运行

```bash
pip install -r requirements.txt

# 作为模块运行
python -m access_review.cli --help
```

## 快速开始

### 1. 初始化

```bash
# 初始化数据目录（默认在 ~/.access_review）
access-review init

# 或指定自定义目录
export ACCESS_REVIEW_HOME=/path/to/data
access-review init
```

### 2. 导入示例数据

```bash
access-review permission import sample_data.json
```

### 3. 查看系统状态

```bash
access-review stats
```

### 4. 执行一键季度复核

```bash
access-review quarterly 2026-Q2 Q2 2026 --reviewer security-team --output ./reports
```

## 命令详解

### 权限清单管理 (`permission`)

```bash
# 列出所有权限
access-review permission list

# 按部门筛选
access-review permission list --dept 研发部

# 按状态筛选 (active/expired/revoked/pending_review)
access-review permission list --status active

# 查看权限详情
access-review permission show perm-002

# 添加单条权限
access-review permission add \
  --username testuser \
  --email testuser@example.com \
  --department 测试部 \
  --role tester \
  --resource test-system \
  --permission-level read \
  --granted-date 2026-01-01

# 导出权限清单
access-review permission export permissions.csv --format csv
```

### 复核流程管理 (`review`)

```bash
# 开始新的复核周期
access-review review cycle-start 2026-Q2 Q2 2026

# 查看所有复核周期
access-review review cycle-list

# 查看待复核权限
access-review review pending

# 按部门查看待复核
access-review review pending --dept 研发部

# 记录复核结果
# 结果类型: approved / revoke_recommended / escalated / pending
access-review review record perm-001 \
  --reviewer security-admin \
  --result approved \
  --comments "业务需要，权限合理"

# 记录建议收回
access-review review record perm-002 \
  --reviewer security-admin \
  --result revoke_recommended \
  --comments "权限已过期，且长期未使用" \
  --anomaly expired_access,unused_long_term

# 关闭复核周期
access-review review cycle-close
```

### 异常检测与管理 (`anomaly`)

```bash
# 运行异常检测
access-review anomaly detect --unused-days 90

# 查看所有未解决异常
access-review anomaly list

# 查看所有（包括已解决）
access-review anomaly list --all

# 按类型筛选
access-review anomaly list --type over_privileged

# 按严重度筛选
access-review anomaly list --severity high

# 查看异常摘要
access-review anomaly summary

# 标记异常为已解决
access-review anomaly resolve <anomaly-id> --notes "已与部门确认，权限合理"

# 查看建议收回的权限清单
access-review anomaly revoke-list
```

### 报告生成 (`report`)

```bash
# 生成复核摘要报告
access-review report summary --output summary.json

# 指定周期生成报告
access-review report summary --cycle <cycle-id> --output summary.json

# 导出待收回权限清单（CSV格式）
access-review report revoke revoke_list.csv

# 导出权限清单报告
access-review report permissions permissions.csv

# 仅导出现役权限
access-review report permissions active_permissions.csv --status active

# 生成用户权限报告
access-review report user zhangsan --output zhangsan_report.json
```

## 异常检测规则

### 1. 长期未使用权限 (unused_long_term)
- 检测条件：权限最后使用时间或授予时间早于 N 天（默认 90 天）
- 严重度：medium
- 处理建议：确认用户是否仍需该权限，不需要则收回

### 2. 过期访问 (expired_access)
- 检测条件：权限过期日期早于当前日期
- 严重度：high
- 处理建议：立即收回

### 3. 越权风险 (over_privileged)
- 检测条件：满足以下任一条件：
  - 角色为高危角色（admin/superuser/root/owner 等）
  - 资源为高危资源（production/prod/database/pii 等）
  - 权限级别为高权限（write/admin/owner/full 等）
  - 单用户权限数量超过 10 个
- 严重度：满足 2 个及以上条件为 high，否则为 medium
- 处理建议：复核权限是否合理，考虑降权或拆分

### 4. 可疑模式 (suspicious_pattern)
- 检测条件：同一部门近期（30 天内）授予 5 个及以上权限
- 严重度：medium
- 处理建议：确认是否为正常业务调整

## 数据存储

默认数据存储在 `~/.access_review/data/` 目录下：

```
~/.access_review/data/
├── permissions/    # 用户权限数据 (JSON)
├── reviews/        # 复核记录 (JSON)
├── anomalies/      # 异常报告 (JSON)
└── cycles/         # 复核周期 (JSON)
```

可通过环境变量 `ACCESS_REVIEW_HOME` 自定义存储位置。

## 权限数据格式

导入的 JSON 文件格式示例：

```json
{
  "permissions": [
    {
      "id": "perm-001",
      "username": "zhangsan",
      "email": "zhangsan@example.com",
      "department": "研发部",
      "role": "developer",
      "resource": "code-repo",
      "permission_level": "write",
      "granted_date": "2024-01-15T10:00:00",
      "last_used_date": "2026-06-10T14:30:00",
      "expiry_date": null,
      "status": "active",
      "granted_by": "admin",
      "description": "代码仓库读写权限",
      "tags": ["dev", "code"]
    }
  ]
}
```

### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| id | string | 权限唯一标识 |
| username | string | 用户名 |
| email | string | 邮箱 |
| department | string | 所属部门 |
| role | string | 角色 |
| resource | string | 访问资源 |
| permission_level | string | 权限级别: read/write/admin/full |
| granted_date | datetime | 授予日期 |
| last_used_date | datetime | 最后使用日期 |
| expiry_date | datetime | 过期日期，可为 null |
| status | string | 状态: active/expired/revoked/pending_review |
| granted_by | string | 授权人 |
| description | string | 权限描述 |
| tags | string[] | 标签数组 |

## 季度复核工作流

### 标准流程

```
1. 准备阶段
   ├─ 从 IAM 系统导出权限清单
   └─ 导入到工具: access-review permission import <iam-export.json>

2. 启动复核
   └─ access-review quarterly <cycle-name> Q2 2026 \
          --reviewer <your-name> --output ./reports

3. 复核执行
   ├─ 查看待复核: access-review review pending
   ├─ 查看异常: access-review anomaly list
   ├─ 逐笔复核: access-review review record <perm-id> --result approved
   └─ 批量记录复核结果

4. 报告生成
   ├─ 摘要报告: access-review report summary --output summary.json
   ├─ 权限清单: access-review report permissions permissions.csv
   └─ 收回清单: access-review report revoke revoke_list.csv

5. 权限收回
   ├─ 根据收回清单在 IAM 系统执行收回
   ├─ 在工具中标记: access-review permission revoke <perm-id> --reason "季度复核收回"
   └─ 关闭复核周期: access-review review cycle-close
```

## 项目结构

```
access_review/
├── __init__.py          # 版本信息
├── cli.py               # 命令行入口
├── models.py            # 数据模型定义
├── storage.py           # 数据存储管理
├── anomaly_detector.py  # 异常检测引擎
└── report_generator.py  # 报告生成器
```

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试（如果有）
pytest
```

## License

MIT
