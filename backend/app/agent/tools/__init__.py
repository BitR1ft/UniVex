"""Agent tools"""

from .base_tool import BaseTool, ToolMetadata
from .error_handling import (
    ToolExecutionError,
    ToolTimeoutError,
    ToolValidationError,
    ToolRateLimitError,
    ErrorCategory,
    ToolErrorReporter,
    default_reporter,
    categorise_error,
    get_recovery_hint,
    truncate_output,
    with_timeout,
    with_error_context,
    with_retry,
)
from .echo_tool import EchoTool
from .calculator_tool import CalculatorTool
from .query_graph_tool import QueryGraphTool
from .web_search_tool import WebSearchTool
from .mcp_tools import NaabuTool, CurlTool, NucleiTool, MetasploitTool
from .exploitation_tools import ExploitExecuteTool, BruteForceTool, SessionManagerTool
from .post_exploitation_tools import FileOperationsTool, SystemEnumerationTool, PrivilegeEscalationTool

# Week 15 tool adapters (Days 93-97)
from .tool_adapters import (
    # Day 93: Recon
    DomainDiscoveryTool,
    PortScanTool,
    # Day 94: HTTP Probe
    HttpProbeTool,
    TechDetectionTool,
    EndpointEnumerationTool,
    # Day 95: Nuclei
    NucleiTemplateSelectTool,
    NucleiScanTool,
    # Day 96: Graph Query
    AttackSurfaceQueryTool,
    VulnerabilityLookupTool,
    # Day 97: Web Search
    ExploitSearchTool,
    CVELookupTool,
)

# Week 2 betterment plan — ffuf web fuzzing tools (Days 8-11)
from .ffuf_tool import FfufFuzzDirsTool, FfufFuzzFilesTool, FfufFuzzParamsTool

# Week 3 betterment plan — SQLMap agent adapter (Days 19-21)
from .sqlmap_tool import (
    SQLMapDetectTool,
    SQLMapDatabasesTool,
    SQLMapTablesTool,
    SQLMapColumnsTool,
    SQLMapDumpTool,
)

# Week 4 betterment plan — Post-exploitation extended + hash cracking (Days 22-28)
from .post_exploitation_extended import (
    LinPEASTool,
    WinPEASTool,
    HashCrackTool,
    CredentialReuseTool,
    FlagCaptureTool,
)

# Week 6 betterment plan — SearchSploit + CMS tools (Days 31-37)
from .searchsploit_tool import SearchSploitTool
from .cms_tools import WPScanTool, NiktoAgentTool

# Week 7 betterment plan — Network service tools (Days 38-44)
from .network_service_tools import (
    SSHLoginTool,
    SSHKeyExtractTool,
    ReverseShellTool,
    SNMPTool,
    AnonymousFTPTool,
)

# Week 8 betterment plan — Active Directory tools (Days 45-51)
from .active_directory_tools import (
    KerbrouteTool,
    Enum4LinuxTool,
    ASREPRoastTool,
    KerberoastTool,
    PassTheHashTool,
    LDAPEnumTool,
    CrackMapExecTool,
)

# PLAN.md Day 1 — XSS Detection & Exploitation Engine
from .xss_tools import ReflectedXSSTool, StoredXSSTool, DOMXSSTool

# PLAN.md Day 2 — CSRF, SSRF & Request Forgery Toolkit
from .csrf_tools import CSRFDetectTool, CSRFExploitTool
from .ssrf_tools import SSRFProbeTool, SSRFBlindTool, OpenRedirectTool

# PLAN.md Day 3 — IDOR & Access Control Testing Suite
from .idor_tools import IDORDetectTool, IDORExploitTool, PrivilegeEscalationWebTool
from .auth_bypass_tools import AuthBypassTool, SessionPuzzlingTool, RateLimitBypassTool

# PLAN.md Day 4 — JWT, OAuth & Token Attack Suite
from .jwt_tools import JWTAnalyzeTool, JWTBruteForceTool, JWTForgeTool
from .oauth_tools import OAuthFlowTool, OAuthTokenLeakTool, APIKeyLeakTool

__all__ = [
    # Base
    "BaseTool",
    "ToolMetadata",
    # Error handling (Day 98)
    "ToolExecutionError",
    "ToolTimeoutError",
    "ToolValidationError",
    "ToolRateLimitError",
    "ErrorCategory",
    "ToolErrorReporter",
    "default_reporter",
    "categorise_error",
    "get_recovery_hint",
    "truncate_output",
    "with_timeout",
    "with_error_context",
    "with_retry",
    # Core tools
    "EchoTool",
    "CalculatorTool",
    "QueryGraphTool",
    "WebSearchTool",
    "NaabuTool",
    "CurlTool",
    "NucleiTool",
    "MetasploitTool",
    "ExploitExecuteTool",
    "BruteForceTool",
    "SessionManagerTool",
    "FileOperationsTool",
    "SystemEnumerationTool",
    "PrivilegeEscalationTool",
    # Week 15 adapters (Days 93-97)
    "DomainDiscoveryTool",
    "PortScanTool",
    "HttpProbeTool",
    "TechDetectionTool",
    "EndpointEnumerationTool",
    "NucleiTemplateSelectTool",
    "NucleiScanTool",
    "AttackSurfaceQueryTool",
    "VulnerabilityLookupTool",
    "ExploitSearchTool",
    "CVELookupTool",
    # Week 2 betterment plan — ffuf (Days 8-11)
    "FfufFuzzDirsTool",
    "FfufFuzzFilesTool",
    "FfufFuzzParamsTool",
    # Week 3 betterment plan — SQLMap (Days 19-21)
    "SQLMapDetectTool",
    "SQLMapDatabasesTool",
    "SQLMapTablesTool",
    "SQLMapColumnsTool",
    "SQLMapDumpTool",
    # Week 4 betterment plan — Post-exploitation extended (Days 22-28)
    "LinPEASTool",
    "WinPEASTool",
    "HashCrackTool",
    "CredentialReuseTool",
    "FlagCaptureTool",
    # Week 6 betterment plan — SearchSploit + CMS (Days 31-37)
    "SearchSploitTool",
    "WPScanTool",
    "NiktoAgentTool",
    # Week 7 betterment plan — Network service tools (Days 38-44)
    "SSHLoginTool",
    "SSHKeyExtractTool",
    "ReverseShellTool",
    "SNMPTool",
    "AnonymousFTPTool",
    # Week 8 betterment plan — Active Directory tools (Days 45-51)
    "KerbrouteTool",
    "Enum4LinuxTool",
    "ASREPRoastTool",
    "KerberoastTool",
    "PassTheHashTool",
    "LDAPEnumTool",
    "CrackMapExecTool",
    # PLAN.md Day 1 — XSS tools
    "ReflectedXSSTool",
    "StoredXSSTool",
    "DOMXSSTool",
    # PLAN.md Day 2 — CSRF / SSRF / Open Redirect tools
    "CSRFDetectTool",
    "CSRFExploitTool",
    "SSRFProbeTool",
    "SSRFBlindTool",
    "OpenRedirectTool",
    # PLAN.md Day 3 — IDOR & Access Control tools
    "IDORDetectTool",
    "IDORExploitTool",
    "PrivilegeEscalationWebTool",
    "AuthBypassTool",
    "SessionPuzzlingTool",
    "RateLimitBypassTool",
    # PLAN.md Day 4 — JWT, OAuth & Token Attack tools
    "JWTAnalyzeTool",
    "JWTBruteForceTool",
    "JWTForgeTool",
    "OAuthFlowTool",
    "OAuthTokenLeakTool",
    "APIKeyLeakTool",
]
