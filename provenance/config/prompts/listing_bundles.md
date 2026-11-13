@@head
## 本批要判的束（{COUNT} 个，来自层级「{LEVEL}」）

@@bundle
{ID}｜程序 {PROGRAMS}｜动作 {RELS} {SYSCALL}｜对象目录 {DIRS}｜成员 {SIZE} 条

@@clue
    线索：{BITS}——这些痕迹与已判相关的活动有重合；重合只表示出现过，不表示本束一定相关。若本束样本与它们同类，倾向相关；若明显是例行对象，仍可判无关。

@@clue_dir
对象类别 {DIR}（已判相关的束里出现 {COUNT} 次）

@@clue_program
本束程序 {PROGRAM}（已判相关的束里出现 {COUNT} 次）

@@cmdline
    命令行：{CMDLINE}

@@unlisted
    （还有 {COUNT} 条成员未列出；样本只是成员的一部分，不代表全部）

@@tail
请按系统说明对每个束给出四值判定；每个 id 原样回抄；只输出 JSON。

@@scale
    规模：成员 {SIZE} 条／{BYTES}／不同对象 {OBJECTS} 个{CLASS_TAIL}

@@parent
    上一级：{PARENT_ID}

@@class_header
### 同类规模（本批涉及的每个对象类别下有多少个束、中位成员数；束行「规模」行里的 C 编号引用这里）

@@class_row
{CID} {CLASS}｜共 {COUNT} 个束（中位 {MEDIAN} 条）

@@parent_header
### 上一级束（本批子束拆自这些束；束行「上一级：P*」引用这里）

@@parent_row
{PID} {PROGRAMS} {SYSCALL}｜{SIZE} 条／{BYTES}／{OBJECTS} 个对象｜判定 {VERDICT}｜{REASON}

@@no_owner
(无属主)

@@no_dir
(无)

@@no_reason
(未给理由)

@@scale_class_tail
；同类 {CLASS} 第 {RANK}（前 {PCT}%）
