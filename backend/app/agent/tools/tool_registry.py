"""
Tool Registry System

Manages dynamic tool loading and phase-based access control.
"""

from typing import Dict, List, Optional, Type
from app.agent.tools.base_tool import BaseTool
from app.agent.state.agent_state import Phase
import logging

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    Registry for managing agent tools with phase-based access control.
    """
    
    def __init__(self):
        """Initialize tool registry"""
        self._tools: Dict[str, BaseTool] = {}
        self._tool_phases: Dict[str, List[Phase]] = {}
        self._tool_classes: Dict[str, Type[BaseTool]] = {}
    
    def register_tool(
        self, 
        tool: BaseTool, 
        allowed_phases: Optional[List[Phase]] = None
    ):
        """
        Register a tool with optional phase restrictions.
        
        Args:
            tool: Tool instance to register
            allowed_phases: List of phases where tool is available (None = all phases)
        """
        tool_name = tool.name
        self._tools[tool_name] = tool
        self._tool_phases[tool_name] = allowed_phases or list(Phase)
        self._tool_classes[tool_name] = type(tool)
        
        logger.info(f"Registered tool '{tool_name}' for phases: {[p.value for p in self._tool_phases[tool_name]]}")
    
    def unregister_tool(self, tool_name: str):
        """
        Remove a tool from registry.
        
        Args:
            tool_name: Name of tool to remove
        """
        if tool_name in self._tools:
            del self._tools[tool_name]
            del self._tool_phases[tool_name]
            del self._tool_classes[tool_name]
            logger.info(f"Unregistered tool '{tool_name}'")
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """
        Get a tool by name.
        
        Args:
            tool_name: Name of tool
            
        Returns:
            Tool instance or None
        """
        return self._tools.get(tool_name)
    
    def get_tools_for_phase(self, phase: Phase) -> Dict[str, BaseTool]:
        """
        Get all tools available for a specific phase.
        
        Args:
            phase: Current agent phase
            
        Returns:
            Dictionary of tool name -> tool instance
        """
        available_tools = {}
        
        for tool_name, tool in self._tools.items():
            allowed_phases = self._tool_phases.get(tool_name, [])
            if phase in allowed_phases:
                available_tools[tool_name] = tool
        
        return available_tools
    
    def is_tool_allowed(self, tool_name: str, phase: Phase) -> bool:
        """
        Check if a tool is allowed in a specific phase.
        
        Args:
            tool_name: Name of tool
            phase: Current phase
            
        Returns:
            True if tool is allowed
        """
        if tool_name not in self._tool_phases:
            return False
        
        allowed_phases = self._tool_phases[tool_name]
        return phase in allowed_phases
    
    def list_all_tools(self) -> List[str]:
        """
        List all registered tool names.
        
        Returns:
            List of tool names
        """
        return list(self._tools.keys())
    
    def get_tool_metadata(self, tool_name: str) -> Optional[Dict]:
        """
        Get tool metadata.
        
        Args:
            tool_name: Name of tool
            
        Returns:
            Tool metadata dictionary or None
        """
        tool = self.get_tool(tool_name)
        if tool:
            return {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.metadata.parameters,
                "allowed_phases": [p.value for p in self._tool_phases.get(tool_name, [])]
            }
        return None
    
    def get_all_tool_metadata(self, phase: Optional[Phase] = None) -> List[Dict]:
        """
        Get metadata for all tools, optionally filtered by phase.
        
        Args:
            phase: Optional phase filter
            
        Returns:
            List of tool metadata dictionaries
        """
        if phase:
            tools = self.get_tools_for_phase(phase)
        else:
            tools = self._tools
        
        return [
            self.get_tool_metadata(tool_name)
            for tool_name in tools.keys()
        ]


def create_default_registry() -> ToolRegistry:
    """
    Create default tool registry with standard tools.
    
    Returns:
        Configured ToolRegistry instance
    """
    from app.agent.tools import (
        EchoTool, 
        CalculatorTool, 
        QueryGraphTool, 
        WebSearchTool,
        NaabuTool,
        CurlTool,
        NucleiTool,
        MetasploitTool,
        ExploitExecuteTool,
        BruteForceTool,
        SessionManagerTool,
        FileOperationsTool,
        SystemEnumerationTool,
        PrivilegeEscalationTool,
        FfufFuzzDirsTool,
        FfufFuzzFilesTool,
        FfufFuzzParamsTool,
        # Week 3 betterment plan — SQLMap
        SQLMapDetectTool,
        SQLMapDatabasesTool,
        SQLMapTablesTool,
        SQLMapColumnsTool,
        SQLMapDumpTool,
        # Week 4 betterment plan — post-exploitation extended
        LinPEASTool,
        WinPEASTool,
        HashCrackTool,
        CredentialReuseTool,
        FlagCaptureTool,
        # Week 6 betterment plan — SearchSploit + CMS
        SearchSploitTool,
        WPScanTool,
        NiktoAgentTool,
        # Week 7 betterment plan — Network service tools
        SSHLoginTool,
        SSHKeyExtractTool,
        ReverseShellTool,
        SNMPTool,
        AnonymousFTPTool,
        # Week 8 betterment plan — Active Directory
        KerbrouteTool,
        Enum4LinuxTool,
        ASREPRoastTool,
        KerberoastTool,
        PassTheHashTool,
        LDAPEnumTool,
        CrackMapExecTool,
        # PLAN.md Day 1 — XSS tools
        ReflectedXSSTool,
        StoredXSSTool,
        DOMXSSTool,
        # PLAN.md Day 2 — CSRF / SSRF / Open Redirect tools
        CSRFDetectTool,
        CSRFExploitTool,
        SSRFProbeTool,
        SSRFBlindTool,
        OpenRedirectTool,
        # PLAN.md Day 3 — IDOR & Access Control tools
        IDORDetectTool,
        IDORExploitTool,
        PrivilegeEscalationWebTool,
        AuthBypassTool,
        SessionPuzzlingTool,
        RateLimitBypassTool,
        # PLAN.md Day 4 — JWT, OAuth & Token Attack tools
        JWTAnalyzeTool,
        JWTBruteForceTool,
        JWTForgeTool,
        OAuthFlowTool,
        OAuthTokenLeakTool,
        APIKeyLeakTool,
    )
    
    registry = ToolRegistry()
    
    # Development/testing tools (all phases)
    registry.register_tool(
        EchoTool(),
        allowed_phases=list(Phase)
    )
    
    registry.register_tool(
        CalculatorTool(),
        allowed_phases=list(Phase)
    )
    
    # Information gathering tools (INFORMATIONAL phase)
    registry.register_tool(
        QueryGraphTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    
    registry.register_tool(
        WebSearchTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        NaabuTool(),
        allowed_phases=[Phase.INFORMATIONAL]
    )
    
    registry.register_tool(
        CurlTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        NucleiTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    
    # Exploitation tools (EXPLOITATION phase only)
    registry.register_tool(
        MetasploitTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        ExploitExecuteTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        BruteForceTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    
    registry.register_tool(
        SessionManagerTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    
    # Post-exploitation tools
    registry.register_tool(
        FileOperationsTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )
    
    registry.register_tool(
        SystemEnumerationTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    
    registry.register_tool(
        PrivilegeEscalationTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )

    # Week 2 betterment plan — ffuf web fuzzing (INFORMATIONAL + EXPLOITATION)
    registry.register_tool(
        FfufFuzzDirsTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    registry.register_tool(
        FfufFuzzFilesTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    registry.register_tool(
        FfufFuzzParamsTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # Week 3 betterment plan — SQLMap
    registry.register_tool(
        SQLMapDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        SQLMapDatabasesTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SQLMapTablesTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SQLMapColumnsTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SQLMapDumpTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )

    # Week 4 betterment plan — post-exploitation extended + hash cracking
    registry.register_tool(
        LinPEASTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        WinPEASTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        HashCrackTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        CredentialReuseTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        FlagCaptureTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )

    # Week 6 betterment plan — SearchSploit + CMS tools
    registry.register_tool(
        SearchSploitTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        WPScanTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        NiktoAgentTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # Week 7 betterment plan — Network service tools
    registry.register_tool(
        SSHLoginTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        SSHKeyExtractTool(),
        allowed_phases=[Phase.POST_EXPLOITATION]
    )
    registry.register_tool(
        ReverseShellTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SNMPTool(),
        allowed_phases=[Phase.INFORMATIONAL]
    )
    registry.register_tool(
        AnonymousFTPTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # Week 8 betterment plan — Active Directory tools
    registry.register_tool(
        KerbrouteTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        Enum4LinuxTool(),
        allowed_phases=[Phase.INFORMATIONAL]
    )
    registry.register_tool(
        ASREPRoastTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        KerberoastTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        PassTheHashTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        LDAPEnumTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        CrackMapExecTool(),
        allowed_phases=[Phase.EXPLOITATION, Phase.POST_EXPLOITATION]
    )

    # PLAN.md Day 1 — XSS Detection & Exploitation Engine
    registry.register_tool(
        ReflectedXSSTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        StoredXSSTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        DOMXSSTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # PLAN.md Day 2 — CSRF, SSRF & Request Forgery Toolkit
    registry.register_tool(
        CSRFDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        CSRFExploitTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        SSRFProbeTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        SSRFBlindTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        OpenRedirectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # PLAN.md Day 3 — IDOR & Access Control Testing Suite
    registry.register_tool(
        IDORDetectTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        IDORExploitTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        PrivilegeEscalationWebTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        AuthBypassTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        SessionPuzzlingTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        RateLimitBypassTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    # PLAN.md Day 4 — JWT, OAuth & Token Attack Suite
    registry.register_tool(
        JWTAnalyzeTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        JWTBruteForceTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        JWTForgeTool(),
        allowed_phases=[Phase.EXPLOITATION]
    )
    registry.register_tool(
        OAuthFlowTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        OAuthTokenLeakTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )
    registry.register_tool(
        APIKeyLeakTool(),
        allowed_phases=[Phase.INFORMATIONAL, Phase.EXPLOITATION]
    )

    logger.info(f"Created default tool registry with {len(registry.list_all_tools())} tools")
    
    return registry


# Global registry instance
_global_registry: Optional[ToolRegistry] = None


def get_global_registry() -> ToolRegistry:
    """
    Get or create the global tool registry.
    
    Returns:
        Global ToolRegistry instance
    """
    global _global_registry
    
    if _global_registry is None:
        _global_registry = create_default_registry()
    
    return _global_registry
