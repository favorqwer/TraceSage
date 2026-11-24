@@header
    【规则证据】(本束成员 {SIZE} 条，命中 {TOTAL} 条规则；每条规则的跳链见下)

@@row
      {RID}｜形态 {MOTIF}｜{ALIGNS}｜训练折精确率 {PRECISION}（0-1）｜训练折命中 攻击/背景/忽略 {ATTACK}/{BACKGROUND}/{IGNORE}｜出现在 {SCENARIOS} 个训练场景

@@hop
        hop{INDEX}: {SRC_ROLE} --{SYSCALL}--> {DST_ROLE}{MARK}

@@empty
    【规则证据】本束没有规则证据

@@align_exact
精确对齐 {COUNT} 条

@@align_partial
部分对齐 {COUNT} 条

@@align_structure
结构走通 {DONE}/{TOTAL} 跳

@@hop_mark
  [与本束系统调用一致]
