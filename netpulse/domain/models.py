"""Domain data models shared across capture and aggregation."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True, slots=True)
class Packet:
    ts: datetime
    direction: str
    protocol: str
    src: str
    dst: str
    sport: Optional[int]
    dport: Optional[int]
    size: int
    remote: str
    pid: Optional[int] = None
    proc_name: str = ""
