"""Bounded, reviewable output from commands run inside Docker."""

from typing import Literal

from pydantic import BaseModel, Field


class ExecutionLog(BaseModel):
    command_id: str
    argv: list[str]
    cwd: str = "."
    phase: Literal["resolution", "validation"]
    status: str
    exit_code: int | None = None
    stdout: str = Field(default="", max_length=16384)
    stderr: str = Field(default="", max_length=16384)
    truncated: bool = False
    reason: str = ""
