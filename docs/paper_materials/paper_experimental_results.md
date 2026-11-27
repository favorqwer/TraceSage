# 论文核心实验实测数据表

- 本系统数据：`output/attack-graph-baseline/summary_v2.json`（现行零 Neo4j 主线 `.tsg` + 本地 `output/rule-kg/v1`；全部 10 场景均于 2026-11-27 基于替换后的场景 9 `9_Site_Defacement` 与更新后规则库完成实时大模型重跑，场景 1–8、10 并发 `12`）。
- 引擎数据：引用 `output/engine-baseline/OVERVIEW.md`（场景 1–8、10 沿用既有 Neo4j `-v2` 库产物按现行 `triplet-v1` 重评分，场景 9 为 `attack-9-site-defacement-v2` 实测重跑）。
- 两侧统一使用 `triplet-v1` 口径（`tools/score_report_product.py` / `tools/score_graph_product.py`）：召回按标注步骤，查准按去重 `(源, 系统调用, 目标)` **三元组**（合计总步骤 `825`）。

## 一、十场景效果（Table 1）

| 场景 | 引擎召回 | 引擎查准 | 引擎评分三元组 | 本系统召回 | 本系统查准 | 本系统命中步骤/总步骤 | 本系统命中/报告三元组 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1_Web_Exploit_Ransomware | 53.47% | 79.56% | 7753 | 97.03% | 74.47% | 98/101 | 12472/16748 |
| 2_SSH_Spray_Lateral_Exfiltration | 59.26% | 7.09% | 536 | 100.00% | 32.82% | 54/54 | 637/1941 |
| 3_Phishing_Beacon_Cryptomining | 66.67% | 43.13% | 262 | 100.00% | 7.65% | 72/72 | 141/1843 |
| 4_Repo_Poisoning_Backdoor | 82.14% | 1.85% | 3721 | 100.00% | 4.89% | 84/84 | 84/1719 |
| 5_Exposed_Service_Pivot | 57.06% | 0.91% | 10195 | 99.39% | 9.37% | 162/163 | 162/1729 |
| 6_Web_SQLi_Data_Exfiltration | 8.70% | 0.33% | 1216 | 97.83% | 1.13% | 45/46 | 45/3993 |
| 7_DB_Bruteforce_Datawipe | 15.07% | 24.44% | 45 | 91.78% | 95.26% | 67/73 | 3855/4047 |
| 8_FTP_WeakCreds_WebShell_Exfiltration | 44.44% | 67.38% | 141 | 96.83% | 82.74% | 61/63 | 561/678 |
| 9_Site_Defacement | 51.35% | 1.30% | 2926 | 100.00% | 14.31% | 74/74 | 74/517 |
| 10_Tomcat_Weakcreds_DNS_Exfiltration | 26.32% | 0.13% | 26702 | 97.89% | 3.12% | 93/95 | 217/6955 |
| 合并平均 | 48.73% | 12.46% | 53497 | 98.18% | 45.43% | 810/825 | 18248/40170 |

```latex
\begin{table*}[t]
\centering
\caption{Investigation results across ten scenarios (triplet-v1).}
\begin{tabular}{lrrrrrr}
\hline
Scenario & Engine R & Engine P & Engine triples & Ours R & Ours P & Ours triples \\
\hline
1 & 53.47\% & 79.56\% & 7753 & 97.03\% & 74.47\% & 16748 \\
2 & 59.26\% & 7.09\% & 536 & 100.00\% & 32.82\% & 1941 \\
3 & 66.67\% & 43.13\% & 262 & 100.00\% & 7.65\% & 1843 \\
4 & 82.14\% & 1.85\% & 3721 & 100.00\% & 4.89\% & 1719 \\
5 & 57.06\% & 0.91\% & 10195 & 99.39\% & 9.37\% & 1729 \\
6 & 8.70\% & 0.33\% & 1216 & 97.83\% & 1.13\% & 3993 \\
7 & 15.07\% & 24.44\% & 45 & 91.78\% & 95.26\% & 4047 \\
8 & 44.44\% & 67.38\% & 141 & 96.83\% & 82.74\% & 678 \\
9 & 51.35\% & 1.30\% & 2926 & 100.00\% & 14.31\% & 517 \\
10 & 26.32\% & 0.13\% & 26702 & 97.89\% & 3.12\% & 6955 \\
Overall & 48.73\% & 12.46\% & 53497 & 98.18\% & 45.43\% & 40170 \\
\hline
\end{tabular}
\end{table*}
```

## 二、耗时与调用（Table 2）

本系统耗时取 `output/attack-graph-baseline/summary_v2.json` 各场景 `elapsed_seconds`（含图检索、大模型分批与后置剪枝；全 10 场景合计实时调用 `663` 次 / `677` 次请求含重试）；引擎耗时引用各场景 Java 进程墙钟。

| 场景 | 引擎秒 | 本系统秒 | 模型调用/请求 | 保留边 (确认/未排除) |
|---|---:|---:|---:|---:|
| 1_Web_Exploit_Ransomware | 47.9 | 175.38 | 68/68 | 16748 (16406/349) |
| 2_SSH_Spray_Lateral_Exfiltration | 24.0 | 170.28 | 54/61 | 1941 (1800/145) |
| 3_Phishing_Beacon_Cryptomining | 5.9 | 213.09 | 114/120 | 1843 (1768/294) |
| 4_Repo_Poisoning_Backdoor | 19.1 | 187.35 | 92/92 | 1719 (1398/330) |
| 5_Exposed_Service_Pivot | 10.0 | 100.56 | 38/38 | 1729 (1482/247) |
| 6_Web_SQLi_Data_Exfiltration | 16.8 | 31.16 | 2/2 | 3993 (3983/10) |
| 7_DB_Bruteforce_Datawipe | 2.6 | 52.72 | 7/7 | 4047 (4037/10) |
| 8_FTP_WeakCreds_WebShell_Exfiltration | 7.8 | 93.37 | 33/33 | 678 (655/23) |
| 9_Site_Defacement | 26.9 | 353.76 | 73/73 | 517 (328/189) |
| 10_Tomcat_Weakcreds_DNS_Exfiltration | 86.5 | 407.34 | 182/183 | 6955 (5756/1361) |
| 合计 | 247.5 | 1785.01 | 663/677 | 40170 (37613/2958) |

```latex
\begin{table}[h]
\centering
\caption{Recorded runtime and model invocations.}
\begin{tabular}{lrrr}
\hline
Scenario & Engine seconds & Ours seconds & Calls \\
\hline
1 & 47.9 & 175.38 & 68 \\
2 & 24.0 & 170.28 & 54 \\
3 & 5.9 & 213.09 & 114 \\
4 & 19.1 & 187.35 & 92 \\
5 & 10.0 & 100.56 & 38 \\
6 & 16.8 & 31.16 & 2 \\
7 & 2.6 & 52.72 & 7 \\
8 & 7.8 & 93.37 & 33 \\
9 & 26.9 & 353.76 & 73 \\
10 & 86.5 & 407.34 & 182 \\
Total & 247.5 & 1785.01 & 663 \\
\hline
\end{tabular}
\end{table}
```

## 三、场景 8

当前正式基线实测：召回 61/63（96.83%），查准 561/678（82.74%），模型调用 33 次（请求 33 次），主流程耗时 93.37 秒。

现有 `case_study_scenario_8.svg` 与 `.dot` 是手工示意材料，未由本批报告重建，不能作为本次实际输出连通性或物理边验证结果。

## 四、分布与合并分母占比

逐场景最小值、中位数、最大值及各场景的召回/查准分母占比见 `output/attack-graph-baseline/OVERVIEW.md`、`output/attack-graph-baseline/summary_v2.json` 与 `output/engine-baseline/OVERVIEW.md`。
