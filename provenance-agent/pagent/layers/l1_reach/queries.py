"""图上要用的通用查询：进程静态属性。

取边的查询在 `sources.py`（数据库直查）与 `snapshot.py`（索引快照）里各自实现；
这里只放与来源无关的通用查询。**全部不设条数上限。**
"""

# --- 进程静态属性（步骤摘要要用）---
_PROCESS_INFO_CYPHER = """
MATCH (p:Process {process_id:$pid})
RETURN p.process_id AS process_id, p.pid AS pid, p.name AS name,
       p.exepath AS exepath, p.args AS args, p.cwd AS cwd
"""
