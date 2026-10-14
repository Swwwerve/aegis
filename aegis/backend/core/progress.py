"""Optional progress hooks shared by streaming and synchronous scans."""

from collections.abc import Awaitable, Callable

Progress = Callable[[dict], Awaitable[None]]


async def emit(
    progress: Progress | None, stage: str, status: str, message: str, **data
):
    if progress:
        await progress({"stage": stage, "status": status, "message": message, **data})
