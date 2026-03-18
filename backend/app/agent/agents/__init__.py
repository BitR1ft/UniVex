"""
Multi-Agent Framework — Base Agent and Shared State

Defines MultiAgentState (extends AgentState) and the BaseAgent abstract class
that all specialised sub-agents inherit from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.agent.state.agent_state import AgentState, Phase
from app.agent.tools.base_tool import BaseTool
from app.agent.tools.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------


class MultiAgentState(AgentState, total=False):
    """
    Extended agent state shared across all sub-agents in the orchestration
    framework.  Inherits all fields from AgentState and adds orchestration
    metadata.
    """

    # Names of sub-agents currently active in this run
    active_agents: List[str]

    # Accumulated results keyed by agent name
    agent_results: Dict[str, Any]

    # Ordered list of task dicts decomposed by the orchestrator
    orchestrator_plan: Optional[List[Dict[str, Any]]]

    # Metadata about the target (IP, domain, open ports, …)
    target_info: Optional[Dict[str, Any]]

    # Parallel execution workstreams (each is a WorkItem-like dict)
    workstreams: Optional[List[Dict[str, Any]]]


# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------


class BaseAgent(ABC):
    """
    Abstract parent class for all specialised sub-agents.

    Concrete sub-classes must implement:
      - ``AGENT_NAME`` class attribute
      - ``PREFERRED_TOOLS`` class attribute
      - ``get_phase()``
      - ``_build_system_prompt()``
      - ``run(state, task)``
    """

    AGENT_NAME: str = "base"
    PREFERRED_TOOLS: List[str] = []

    def __init__(
        self,
        registry: ToolRegistry,
        llm: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.registry = registry
        self.llm = llm
        self.config = config or {}
        self._tools: List[BaseTool] = self._select_tools(registry)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_tool_names(self) -> List[str]:
        """Return the names of tools currently assigned to this agent."""
        return [t.name for t in self._tools]

    @abstractmethod
    def get_phase(self) -> Phase:
        """Return the primary phase for this agent."""

    @abstractmethod
    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Execute the agent's main workstream.

        Args:
            state: Shared multi-agent state.
            task:  Natural language task description.

        Returns:
            Result dict that the orchestrator merges into ``agent_results``.
        """

    # ------------------------------------------------------------------
    # Overridable helpers
    # ------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        """Return a specialised system prompt for this agent."""
        phase = self.get_phase()
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            f"You are the {self.AGENT_NAME} agent operating in the "
            f"{phase.value} phase.\n"
            f"Available tools: {tool_names}.\n"
            "Perform your specialised security assessment tasks and return "
            "structured findings."
        )

    def _select_tools(self, registry: ToolRegistry) -> List[BaseTool]:
        """
        Filter tools from *registry* that match ``PREFERRED_TOOLS``.

        Falls back to all tools available for this agent's phase when
        ``PREFERRED_TOOLS`` is empty or none of the preferred tools are
        registered.
        """
        selected: List[BaseTool] = []

        for name in self.PREFERRED_TOOLS:
            tool = registry.get_tool(name)
            if tool is not None:
                selected.append(tool)

        if not selected:
            phase_tools = registry.get_tools_for_phase(self.get_phase())
            selected = list(phase_tools.values())

        return selected


__all__ = ["MultiAgentState", "BaseAgent"]
