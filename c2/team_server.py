"""
Multi-Operator Team Server
SocketIO-based collaboration layer for MONOLITH C2/operator workflows.

Features:
- Operator rooms and event broadcasting
- Shared target sessions
- Real-time finding streaming
- Operator presence and role management
"""
from __future__ import annotations

import time
import uuid
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class Operator:
    operator_id: str
    username: str
    role: str = "operator"
    room: Optional[str] = None
    connected_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


@dataclass
class Session:
    session_id: str
    target: str
    operators: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    findings: List[Dict[str, Any]] = field(default_factory=list)


class TeamServer:
    """
    In-memory team server state manager.

    Intended to be used alongside Flask-SocketIO for real-time events.
    """

    def __init__(self):
        self._operators: Dict[str, Operator] = {}
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

    def register_operator(self, username: str, role: str = "operator") -> Operator:
        operator_id = str(uuid.uuid4())
        operator = Operator(operator_id=operator_id, username=username, role=role)
        with self._lock:
            self._operators[operator_id] = operator
        return operator

    def join_session(self, operator_id: str, session_id: str) -> bool:
        with self._lock:
            operator = self._operators.get(operator_id)
            session = self._sessions.get(session_id)
            if not operator or not session:
                return False
            operator.room = session_id
            if operator_id not in session.operators:
                session.operators.append(operator_id)
            return True

    def create_session(self, target: str) -> Session:
        session_id = str(uuid.uuid4())
        session = Session(session_id=session_id, target=target)
        with self._lock:
            self._sessions[session_id] = session
        return session

    def add_finding(self, session_id: str, finding: Dict[str, Any]) -> Optional[Session]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            session.findings.append(finding)
            return session

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "session_id": s.session_id,
                    "target": s.target,
                    "operators": s.operators,
                    "created_at": s.created_at,
                    "finding_count": len(s.findings)
                }
                for s in self._sessions.values()
            ]

    def session_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            return {
                "session_id": session.session_id,
                "target": session.target,
                "operators": session.operators,
                "created_at": session.created_at,
                "findings": session.findings
            }

    def remove_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def operator_state(self, operator_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            op = self._operators.get(operator_id)
            if not op:
                return None
            return {
                "operator_id": op.operator_id,
                "username": op.username,
                "role": op.role,
                "room": op.room,
                "connected_at": op.connected_at,
                "last_seen": op.last_seen
            }
