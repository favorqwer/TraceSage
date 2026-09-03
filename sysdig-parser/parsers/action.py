from typing import Callable, Dict, List, Optional
from .entity import Entity

Action = Callable[
    [Dict[str, str], Dict[str, str], List[Optional[Entity]], List[Optional[Entity]]],
    None,
]
