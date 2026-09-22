"""
Base Agent Abstract Class for Multi-Agent Compliance & Security Ecosystem
"""

import logging
from datetime import datetime
from typing import Optional, Dict, Any
try:
    from core.llm_client import LLMClient
    from database.db import get_db
except (ImportError, ValueError):
    from ..core.llm_client import LLMClient
    from ..database.db import get_db

logger = logging.getLogger(__name__)

class BaseAgent:
    """Foundational class for all specialized AI agents."""

    def __init__(self, name: str, role: str, description: str, llm_client: Optional[LLMClient] = None):
        self.name = name
        self.role = role
        self.description = description
        self.llm = llm_client or LLMClient()
        self.db = get_db()

    def log(self, audit_id: str, action: str, output_summary: str):
        """Record agent action to persistent memory trace."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.db.log_agent_trace(audit_id, self.name, action, output_summary, timestamp)
        except Exception as e:
            logger.warning(f"Failed to log trace for agent {self.name}: {e}")
        logger.info(f"[{self.name}] {action} -> {output_summary[:100]}...")

    def execute(self, *args, **kwargs) -> Any:
        raise NotImplementedError("Subclasses must implement the execute method.")
