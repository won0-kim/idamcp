from typing import Callable

MFF_FAST: int
MFF_READ: int
MFF_WRITE: int

def execute_sync(callable: Callable[[], int], reqf: int) -> int: ...
def msg(message: str) -> None: ...
