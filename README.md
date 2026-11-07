# quality-dashboard (qdash)

把数据质量规则、血缘记录、PII 扫描结果汇总成**一个 HTML 文件**的离线看板。
CSS/SVG/JS 全部内联，断网双击就能打开，不引 CDN、不建服务、不依赖任何第三方包。

- **一份报告，三种输入**：质量规则跑分（CSV/JSONL）、血缘 JSON、PII 命中 JSON，都能汇总进同一个看板。
- **单文件**：默认把体积压在 480 KB 以内，超出时自动收紧表格/图表数据量，而不是截断页面。
- **零依赖**：`dependencies = []`，只用标准库。
- **只读展示**：渲染阶段只读数据，不执行报告内容里的任何东西。

## 快速开始

```bash
# 1. 对 CSV 跑质量规则，直接出 JSON + HTML
python -m qdash check examples/demo.csv --rules examples/rules.json \
    -o artifacts/report.json --html artifacts/report.html

# 2. 把目录里的血缘 / PII 产物汇总进报告
python -m qdash collect examples/artifacts -o artifacts/report.json --html artifacts/report.html

# 3. 已有报告 JSON，只重新渲染 HTML
python -m qdash build artifacts/report.json -o artifacts/report.html

# 4. 校验报告 JSON 是否符合契约
python -m qdash validate artifacts/report.json
```

不需要安装：仓库根目录下 `python -m qdash ...` 即可。
想用短命令 `qdash`，执行 `pip install -e .`（只注册入口点，仍然零运行期依赖）。

## 命令参考

```text
qdash build   <report.json> [-o report.html] [--title TEXT] [--max-bytes N] [--strict]
qdash collect <dir|file.json> [-b BASE.json] [-o report.json] [--html report.html] [--title TEXT]
qdash check   <data.csv|data.jsonl> --rules rules.json [-o report.json] [--html report.html]
              [--title TEXT] [--name NAME] [--version VER] [--owner OWNER] [--now ISO8601]
qdash validate <report.json> [--json]
```

| 退出码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 1 | 报告/规则不合法（`validate` 失败、`build --strict` 遇到 schema 错误） |
| 2 | 用法或 IO 错误（文件读不到、参数不对） |

`check` 的 `--now` 用来固定"当前时间"，让 `freshness` 规则可复现：
CI 里传固定的 UTC 时间，同一天的两次运行结果一定一致。

## 报告契约（schema `data-quality-report/1.0`）

```json
{
  "schema": "data-quality-report/1.0",
  "generated_at": "2026-11-08T02:00:00Z",
  "subject":  { "name": "demo", "version": "v0", "owner": "data-platform" },
  "summary":  { "score": 86.8, "grade": "B", "checks_total": 144,
                "checks_passed": 126, "issues_total": 9, "issues_open": 9 },
  "dimensions": [ { "key": "completeness", "name": "完整性", "score": 75.0, "weight": 0.25 } ],
  "issues": [ { "id": "Q-001", "title": "user_id 不能为空", "severity": "high",
                "dimension": "completeness", "status": "open", "count": 1, "samples": ["..."] } ],
  "distributions": [ { "name": "问题严重度分布", "buckets": [ { "label": "高", "value": 4 } ] } ],
  "lineage": null,
  "pii": null,
  "model_fitness": { "models": [] },
  "trend": []
}
```

- 五个固定维度：`completeness / uniqueness / validity / consistency / timeliness`，
  权重 0.25 / 0.20 / 0.25 / 0.15 / 0.15。
- `lineage` / `pii` 原样内嵌对应工具的 JSON（`dataset-lineage/1.0`、`pii-hits/1.0`），
  渲染层只读容错访问，不要求字段齐全。
- 任何字段缺失/类型不对都会被**容错归一化**（补默认值、降级成 `—`），
  不会因为一个坏字段导致整页渲染失败。

## 评分

- 单条规则检查次数 = 数据行数；违例数 = 不满足该规则的行数。
- 维度分 = `100 × (检查次数 - 违例数) / 检查次数`，该维度没有规则时显示 `—`。
- 总分 = 各维度分按权重加权；等级 `A ≥ 90 > B ≥ 80 > C ≥ 70 > D ≥ 60 > E`。

示例 `examples/demo.csv`（16 行）× 9 条规则 = 144 次检查、18 条违例，
最终 86.8 分 / B 级。

## 质量规则

规则文件是 JSON（`quality-rules/1.0`），示例见 `examples/rules.json`：

```json
{
  "schema": "quality-rules/1.0",
  "rules": [
    { "id": "R-001", "type": "required", "column": "user_id", "severity": "high",
      "owner": "data-platform", "title": "user_id 不能为空" }
  ]
}
```

| 类型 | 维度 | 关键字段 | 说明 |
| --- | --- | --- | --- |
| `required` | 完整性 | `column` | 空值/缺失计违例 |
| `unique` | 唯一性 | `column` | 重复值计违例（空值不参与） |
| `range` | 有效性 | `column`, `min`, `max` | 数值区间 |
| `regex` | 有效性 | `column`, `pattern`, `mode` | `fullmatch/match/search` |
| `enum` | 有效性 | `column`, `values` | 不在枚举内计违例 |
| `length` | 有效性 | `column`, `min`, `max` | 字符串长度 |
| `freshness` | 及时性 | `column`, `max_days` | 日期超过 max_days 天计违例 |
| `consistency` | 一致性 | `columns`, `mode` | 目前支持 `equal` |

公共字段：`id`、`type`、`severity`（high/medium/low）、`owner`、`title`。
单条规则配置错误只产生 warning 并跳过，不影响其他规则。

## 汇总产物（collect）

`collect` **只按顶层 `schema` 字段识别**，文件名叫什么都不影响：

- `dataset-lineage/1.0` → 按 `name` 归并，取 `finished_at` 最新的那一次；
- `pii-hits/1.0` → 按 `source` 归并，取 `generated_at` 最新的那份；
- 多个不同来源的 PII 合并成一个对象：findings 拼接、summary 重算、`source` 用 `"; "` 连接；
- 无法识别的 JSON 计入 `ignored`，坏文件计入 `skipped` 并在最后打印 warning。

```bash
python -m qdash collect artifacts/ -o report.json --html report.html
```

## HTML 看板

单文件，页面打开时**不发起任何网络请求**：

- 页面结构：总览（分数/等级/检查数/问题数）→ 质量维度（柱状图 + 表）→ 问题清单
  （按严重度/状态/维度过滤、点表头排序）→ 问题构成与趋势（环形图 + 折线）→
  数据血缘（分层 DAG，失败节点红色）→ PII 命中概览 → 模型适配评测 → 分布统计；
- 所有图表是构建时手写的内联 SVG，没有图表库；
- 报告里出现的 URL 会被插入零宽字符，避免被扫描器当成外链；
- 体积软上限 480 KB（`--max-bytes` 可调）；超出时按三档递减 问题/命中/节点/趋势桶 的条数，
  而不是截断 HTML；
- 中文标签内嵌在 Python 侧，页面不依赖任何字体 CDN；
- PII 类型名同时兼容 `pii-scan` 的规则名（`cn_id_card`、`mobile_cn`）和上游短名（`id_card`、`phone`），统一显示为中文。

## 目录结构

```text
quality-dashboard/
├─ qdash/
│  ├─ cli.py        # build / collect / check / validate
│  ├─ rules.py      # CSV/JSONL 读取、8 类规则、评分
│  ├─ schema.py     # 报告契约、容错归一化、校验
│  ├─ collect.py    # 按 schema 识别并合并 lineage / pii 产物
│  ├─ render.py     # 单文件 HTML 渲染（内联 CSS/SVG/JS）
│  ├─ templates/report.html
│  ├─ jsonio.py     # 原子化 JSON 读写
│  └─ console.py    # 控制台表格、UTF-8 输出
├─ examples/        # demo.csv / rules.json / artifacts/ / sample_report.json
├─ artifacts/       # 生成物（可重新生成）
└─ tests/           # unittest，标准库跑
```

## 测试

```bash
python -m unittest discover -s tests -v
```

覆盖：schema 归一化与校验、等级/加权分、8 类规则、空数据集、产物识别与归并、
HTML 无外链与体积上限、CLI 四个子命令与退出码。

## 边界（这个工具不做什么）

- 不连数据库、不扫目录外的文件、不起服务、不写前端构建产物；
- 不做数据清洗，只报告问题；修数据是上游的事；
- HTML 是**静态快照**，不含实时数据，不适合当监控大屏；
- 报告里不放原始 PII 值，只放上游给的 `preview`。

## License

MIT，见 [LICENSE](LICENSE)。
