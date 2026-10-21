# GT 标注助手操作规范（Agent 协同指引）

你在本目录中协助人类专家对 TraceSage 攻击场景标注 Ground Truth（GT，标准答案）。
**人类专家做最终决策；你负责检索图数据库、提出候选证据、管理步骤状态机并在质检门禁下闭环交付。**

---

## 1. 核心定位与行为红线

1. **只读安全性**：所有图数据库查询均为只读，严禁向 Neo4j 写入任何节点或关系。
2. **真实性第一**：严禁伪造图上不存在的边，严禁虚构 `edge_key`，严禁通过外部文件“抄答案”顶替图检索。
3. **全流程人机对齐**：
   - Entry 与 POI 必须由你提供 3~5 个候选，**停下来由人拍板确定**；
   - 攻击路径各阶段边逐步展示给人类专家，审核确认后方可固化；
   - 严禁一次性私自生成整份 GT 并宣布完成。
4. **断链桥接人工裁决底线**：
   - 当图连通性检查未通过出现孤岛断裂时，工具与 AI 严禁自动挑选桥梁边私自修补 GT。
   - 必须逐一针对每一个断裂口，在交互终端穷举展示所有候选桥接边的标准四元组 `(src, action, dst, effect)`、系统调用、时间戳、Edge Key 及现实物理动作解释，将最终选用权 100% 交由人类专家决策。未经显式确认具体边编号，严禁写入或改动 GT。

---

## 2. 溯源图物理 Schema（标准 -v2 库）

- **Process** 主键 `(host_id, container_id, pid, start_ns)`
  - 属性：`exe_path`（缺失记为 `<NA>`）、`cmdline`、`ppid`、`uid`、`euid`
  - 顶点键格式：`p:<host>/<container>:<exe_path>`（例如 `p:1_Web/host:/usr/bin/bash`）
- **File** 主键 `(host_id, container_id, path)`
  - 属性：`file_type` (`file`, `directory`, `pipe`, `unix`, `unknown`)
  - 顶点键格式：`f:<host>/<container>:<path>`（例如 `f:1_Web/host:/etc/passwd`）
- **Network** 主键 `(host_id, endpoints)`
  - 顶点键格式：`n:<host>:<endpoints>`（例如 `n:1_Web:100.74.213.15:59360->100.86.108.4:22`）
- **边证据键**：
  - `edge_key = 关系类型:event_id:action`（例如 `ProcessToFile:123456:write`）
  - **特别注意**：在标准 `-v2` 库中，进程执行动作名为 `exec`（底层系统调用 `syscall` 为 `execve`）。

---

## 3. GT 攻击路径定界与两大集合准则

GT 是从 **Entry 到 POI 之间** 的因果连通攻击子图。评测口径：**“召回按步骤算（必须阶段数 + 规则数），查准按边算（正确边 / 报告总边）”**。

### 3.1 标注详细程度权威参考基准
- **基准标杆文件**：[groundtruth/1_Web_Exploit_Ransomware.groundtruth.json](file:///E:/Work/TraceSage/groundtruth/1_Web_Exploit_Ransomware.groundtruth.json)
- **详细程度口径**：面对任何未知场景，攻击标注的颗粒度**以此文件为参考**：
  1. **全生命周期无死角覆盖**：参考该文件包含的阶段、 must 边与 possible 规则。
  2. **绝对拒绝“最小割剪枝”**：凡是攻击者在会话中真实执行过的命令，只要事实在图上存在且属于攻击过程，**必须全部逐条列入 Must 集合**，绝不能为了追求“最简连通”而随意剔除。

### 3.2 必须集合 (must) vs 可能集合 (possible)
- **必须集合（`collection: "must"`）**：
  - 确定性的单步因果行为（命令执行、写脚本、改配置、建连接等），条数固定，在 `edges` 数组中逐条枚举。
- **可能集合（`collection: "possible"`）**：
  - 数量随环境动态膨胀的批量行为（如遍历加密 3000 个文件、批量覆写全量系统日志）。
  - **三大定律（违背任一条 GT 作废）**：
    1. **纯度（Purity）**：规则覆盖范围内 100% 为攻击行为，不得误伤背景噪声；
    2. **互斥（Mutual Exclusion）**：任意一条边最多命中一条规则；
    3. **两不相交（Disjointness）**：**禁止覆盖任何 must 边**。若必须边落在规则范围内，必须在规则的 `target` 或 `source` 中通过 `none_of` 显式排除。

---

## 4. 边界锚定：Entry 与 POI

- **Entry（起点）**：日志中最早可归属的攻击动作（通常为攻击源 IP 发起的第一条入网 `accept` 或反弹连接）。
- **POI（终点 / 核心锚点）**：最显著的最终破坏产物（勒索信生成、备份库被删、挖矿进程启动、关键数据渗漏等）。
- **时序约束**：`entry.start_ns <= 所有 must 边 <= poi.start_ns`。
- **呈现形式**：检索 3~5 个候选，以标准四元组卡片展示给人类专家拍板，**严禁擅自越过确认环节**。
- **Entry 与 POI 必须作为 attack_path 阶段边底线**：
  - Entry（入口事件）与 POI（破坏/终局锚点事件）是攻击图不可分割的因果首尾两端，**必须显式收录为 `attack_path` 相应阶段的具体边**（Entry 为初始阶段第一条边，POI 为终局破坏阶段的具体边），同时在顶层 `entry`/`poi` 字段作为锚点元数据保留。
  - **严禁以“去重”为由将 Entry 或 POI 从 `attack_path` 的阶段边中剔除**。评测工具与校验器必须支持顶层锚点与阶段边的同构映射。

---

## 5. 工具箱核心指令速查

统一在项目虚拟环境运行：`.venv/Scripts/python.exe gt-annotator/gt.py <命令>`。
数据库名统一采用标准库（如 `--db attack-1-web-exploit-ransomware-v2`）。

| 指令 | 典型用法 | 说明 |
|---|---|---|
| `edges` | `gt.py edges --db <库> [--src-exe /bin/bash] [--path /etc/passwd] [--action exec] [--limit 200] [--count]` | 检索满足条件的具体边。先加 `--count` 探知量级；若 $N \le 20$ 逐条看，若 $N > 50$ 考虑规则。 |
| `activity` | `gt.py activity --db <库> --pid N --start-ns N [--direction down] [--limit 1000]` | **核心提效工具**：锁定攻击者会话 Shell PID 后，一键拉取整棵子树全部命令与读写操作。 |
| `tree` | `gt.py tree --db <库> --pid N --start-ns N [--direction up\|down]` | 查看进程克隆与执行父子衍生关系。 |
| `summary` | `gt.py summary --db <库> --from-ns N --to-ns N --group-by action,dst [--limit 100]` | 对高频批量边按目标或动作聚合，提炼 Possible 规则。 |
| `path` | `gt.py path --db <库> --from-key <顶点A> --to-key <顶点B> --causal` | 沿时间递增方向寻找因果连通路径，用于跨组件寻桥。 |
| `steps` | `gt.py steps init --scenario <场景> [--from-attack <doc>]`<br>`gt.py steps update --scenario <场景> --id S01 --status found\|context\|absent`<br>`gt.py steps status --scenario <场景>` | 跟踪攻击步骤销账状态机，自动同步 `tmp/<场景>/steps.md`。 |
| `validate` | `gt.py validate --db <库> --gt groundtruth/<场景>.groundtruth.json [--check-steps]` | 质量门禁校验：100% 边存在性、连通性（分量数=1）、时间单调性、规则附着与两不相交、counts 统计一致性。 |

---

## 6. 实战避坑核心要点

1. **会话命令展开**：
   定位到攻击者的交互式进程（如 `bash`, `sh`, `python` 等反弹 Shell 或提权会话）后，直接执行 `gt.py activity --pid <PID> --direction down`，一次性获取会话内的所有执行命令与文件操作，不要一条一条凭空盲猜。
2. **防查询死锁**：
   严禁执行未指定方向和关系类型的多跳图查询，多跳一律走 `gt.py path --causal`。

---

## 7. GT 标准交付格式（评测兼容）

文件路径：`groundtruth/<场景>.groundtruth.json`（UTF-8 编码）。
格式统一以 [groundtruth/1_Web_Exploit_Ransomware.groundtruth.json](file:///E:/Work/TraceSage/groundtruth/1_Web_Exploit_Ransomware.groundtruth.json) 顶层结构为准，包含 `scenario`、`entry`、`poi`、`counts` 与 `attack_path`：

```json
{
  "scenario": "1_Web_Exploit_Ransomware",
  "entry": {
    "src": "n:1_Web_Exploit_Ransomware:100.74.213.15:59360->100.86.108.4:22",
    "action": "accept",
    "dst": "p:1_Web_Exploit_Ransomware/host:/usr/sbin/sshd",
    "effect": "success",
    "edge_key": "NetworkToProcess:114782:accept",
    "syscall": "accept",
    "time": "18:33:14.079",
    "why": "攻击在日志里最早的可归属动作：外部对 22 端口服务探测的第一条连接"
  },
  "poi": {
    "src": "p:1_Web_Exploit_Ransomware/host:/usr/bin/cat",
    "action": "write",
    "dst": "f:1_Web_Exploit_Ransomware/host:/srv/data/README_RESTORE.txt",
    "effect": "success",
    "edge_key": "ProcessToFile:7080705:write",
    "syscall": "write",
    "time": "18:39:30.700",
    "why": "攻击最终破坏产物：勒索信落盘"
  },
  "counts": {
    "actions": 11,
    "must_entries": 50,
    "rules": 2,
    "steps_total": 52,
    "edges_total_with_dupes": 50,
    "edges_unique": 50
  },
  "attack_path": [
    {
      "id": "A1",
      "phase": "侦察与利用",
      "time": "18:33:14~18:33:32",
      "what": "从外部探测站点及插件版本",
      "collection": "must",
      "edges": [
        {
          "src": "p:1_Web_Exploit_Ransomware/host:/usr/sbin/sshd",
          "action": "send",
          "dst": "n:1_Web_Exploit_Ransomware:100.74.213.15:59360->100.86.108.4:22",
          "effect": "success",
          "edge_key": "ProcessToNetwork:116168:send",
          "syscall": "write"
        }
      ]
    },
    {
      "id": "A14",
      "phase": "批量加密业务数据",
      "collection": "possible",
      "rules": [
        {
          "rule_id": "R2",
          "direction": "src_to_dst",
          "action": ["exec", "read", "write", "rename", "unlink"],
          "source": {
            "any_of": [
              {"vertex": "process", "match": "in", "values": ["/usr/bin/bash", "/usr/bin/openssl", "/usr/bin/shred"]},
              {"vertex": "file", "match": "path_prefix", "value": "/srv/data/"}
            ]
          },
          "target": {
            "any_of": [
              {"vertex": "process", "match": "in", "values": ["/usr/bin/openssl", "/usr/bin/shred"]},
              {"vertex": "file", "match": "path_prefix", "value": "/srv/data/"}
            ]
          }
        }
      ]
    }
  ]
}
```

### 7.1 counts 统计块字段口径
- `actions`: 阶段总数，等于 `attack_path` 数组的长度（阶段个数）；
- `must_entries`: 必须边总数，等于所有 `collection: "must"` 阶段的 `edges` 元素总数；
- `rules`: 可能规则总数，等于所有 `collection: "possible"` 阶段的 `rules` 元素总数；
- `steps_total`: 评估总步骤数，严格等于 `must_entries + rules`（即下游召回率评分的分母）；
- `edges_total_with_dupes`: 必须边原始条数（含重放边）；
- `edges_unique`: 必须边去重后的独立三元组条数。
> `gt.py validate` 会对 `counts` 声明的各项数值与 `attack_path` 实际条目做严格一致性自动校验。
