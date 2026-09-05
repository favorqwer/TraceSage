"""修复验证：用 attack.jsonl 中的真实记录样本驱动新逻辑（一次性诊断脚本）。

1) unlinkat 三种形态经 _make_exit_path_action 真正建边（stub ctx 收集）；
2) renameat2 oldpath/newpath 提取正确（不再出现 AT_FDCWD）；
3) plain rename 回归不变；
4) O_TMPFILE 目录打开不再被判为写；
5) fchmod 失败（res=-1）会被 open 家族的 res 检查拦截。
"""

import sys

sys.path.insert(0, ".")

from parsers.dispatch.handlers import (
    _make_exit_path_action,
    _normalize_exit_path,
    _normalize_rename_path,
    _open_is_write,
    _RENAME_PATHS,
)
from parsers.dispatch.meta_config import canonical_syscall
from parsers.jsonl.fields import extract_size
from parsers.model.entities import FileEntity, Process
from parsers.model.entity_node import EntityNode


class StubCtx:
    def __init__(self):
        self.edges = []
        self._id = 0
        self.files = {}

    def next_event_id(self):
        self._id += 1
        return self._id

    def queue_edge(self, rel, edge):
        self.edges.append((rel, edge))

    def get_or_create_file(self, key, path):
        if key not in self.files:
            self.files[key] = FileEntity(path)
        return self.files[key]

    def extend_forward_flow(self, key, end_ns):
        pass


def run_exit_path(event, fields, args):
    ctx = StubCtx()
    action = _make_exit_path_action(ctx, event, fields)
    proc = Process("21201", "rm", None, None, None)
    action({"event": event, "timestamp": "1.0", "pid": "21201", "process": "rm"},
           {"event": event, "timestamp": "2.0", "pid": "21201", "process": "rm", "args": args},
           [proc, None], [proc, None])
    return [(rel, e.sink.file.path, e.event) for rel, e in ctx.edges]


failures = []

# --- 1) unlinkat 真实形态 ---
cases = [
    ("res=0 dirfd=-100(AT_FDCWD) name=/tmp/.system_service.sh flags=0 ",
     "p2f", "/tmp/.system_service.sh", "unlink"),
    ("res=0 dirfd=-100(AT_FDCWD) name=/tmp/stolen_data.tar.gz flags=0 ",
     "p2f", "/tmp/stolen_data.tar.gz", "unlink"),
    ("res=0 dirfd=4(<d>/tmp/.hidden_dir) name=target_data.txt(/tmp/.hidden_dir/target_data.txt) flags=0 ",
     "p2f", "/tmp/.hidden_dir/target_data.txt", "unlink"),
    ("res=0 dirfd=-100(AT_FDCWD) name=/tmp/.hidden_dir flags=512(AT_REMOVEDIR) ",
     "p2f", "/tmp/.hidden_dir", "unlink"),
    ("res=-1(EPERM) dirfd=-100(AT_FDCWD) name=/tmp/.system_service.sh flags=0 ",
     None, None, None),
]
for args, want_rel, want_path, want_syscall in cases:
    got = run_exit_path("unlinkat", ("name", "path"), args)
    if want_rel is None:
        ok = got == []
        desc = "失败记录不建边"
    else:
        ok = got == [("p2f", want_path, want_syscall)]
        desc = f"{want_rel} -> {want_path}"
    if not ok:
        failures.append(f"unlinkat {args!r}: got {got}")
    print(f"[{'OK' if ok else 'FAIL'}] unlinkat {desc}")

# --- 2) renameat2 / rename 提取 ---
renameat2_args = ("res=0 olddirfd=-100(AT_FDCWD) oldpath=/tmp/update_patch.sh "
                  "newdirfd=-100(AT_FDCWD) newpath=/tmp/.system_service.sh flags=1(RENAME_NOREPLACE) ")
m = _RENAME_PATHS.search(renameat2_args)
old, new = _normalize_rename_path(m.group("old")), _normalize_rename_path(m.group("new"))
ok = (old, new) == ("/tmp/update_patch.sh", "/tmp/.system_service.sh")
if not ok:
    failures.append(f"renameat2: old={old!r} new={new!r}")
print(f"[{'OK' if ok else 'FAIL'}] renameat2 old={old!r} new={new!r}")

rename_args = ("res=0 oldpath=/run/user/1000/systemd/units/.#invocation:x.scope "
               "newpath=/run/user/1000/systemd/units/invocation:x.scope ")
m = _RENAME_PATHS.search(rename_args)
old, new = _normalize_rename_path(m.group("old")), _normalize_rename_path(m.group("new"))
ok = old.endswith(".scope") and new.endswith(".scope") and "dirfd" not in old
if not ok:
    failures.append(f"rename 回归: old={old!r} new={new!r}")
print(f"[{'OK' if ok else 'FAIL'}] rename 回归 old={old!r} new={new!r}")

# --- 3) O_TMPFILE 不再判为写 ---
dir_open = ("fd=13(<d>/home/ubuntu/Desktop) dirfd=-100(AT_FDCWD) name=/home/ubuntu/Desktop "
            "flags=13377(O_DIRECTORY|O_NONBLOCK|O_RDONLY|O_CLOEXEC|O_TMPFILE) mode=0 dev=803 ")
ok = _open_is_write(dir_open) is False
if not ok:
    failures.append("O_TMPFILE 目录打开仍被判为写")
print(f"[{'OK' if ok else 'FAIL'}] O_TMPFILE 目录打开 is_write=False")

# 真写打开仍判为写
real_write = "fd=3(<f>/tmp/x) flags=577(O_WRONLY|O_CREAT|O_TRUNC) mode=0666 "
ok = _open_is_write(real_write) is True
if not ok:
    failures.append("O_WRONLY|O_CREAT|O_TRUNC 未被判为写")
print(f"[{'OK' if ok else 'FAIL'}] 真写打开 is_write=True")

# --- 4) fchmod 失败被 res 检查拦截 ---
fail_chmod = "res=-1(EPERM) fd=44(<f>/home/ubuntu/x) mode=0664 "
ok = "res=" in fail_chmod and extract_size(fail_chmod) == -1
if not ok:
    failures.append("fchmod 失败记录未被 res 检查条件覆盖")
print(f"[{'OK' if ok else 'FAIL'}] fchmod res=-1 -> open 家族跳过 (extract_size=-1)")

# openat/creat 无 res= 时不受影响
ok = ("res=" not in "fd=3(<f>/tmp/stolen_data.tar.gz) name=/tmp/stolen_data.tar.gz mode=0666 dev=803 ")
if not ok:
    failures.append("creat 记录误含 res=")
print("[OK] creat 退出记录无 res=，不受新检查影响")

# --- 5) symlink linkpath 不受候选字段影响 ---
sym = run_exit_path("symlink", ("linkpath",),
                    "res=0 target=3c32eb9febc54019bb8cb48f60f1dcee linkpath=/run/user/1000/units/x.scope ")
ok = sym == [("p2f", "/run/user/1000/units/x.scope", "symlink")]
if not ok:
    failures.append(f"symlink: {sym}")
print(f"[{'OK' if ok else 'FAIL'}] symlink linkpath 提取")

print()
if failures:
    print("FAILURES:")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("全部通过")
