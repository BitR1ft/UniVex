"""
AutoChain REST API — Day 7

Exposes the AutoChain pipeline via three endpoints:

  POST   /api/autochain/start           — create and launch a chain run
  GET    /api/autochain/{chain_id}       — poll or stream current status
  GET    /api/autochain/{chain_id}/flags — retrieve captured flags
  GET    /api/autochain/{chain_id}/steps — list all completed steps

Each run is stored in an in-memory dict keyed by chain_id.
For multi-replica deployments this should be replaced with Redis or a DB.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from app.autochain import AutoChain, ChainResult, ChainStatus, ScanPlan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/autochain", tags=["autochain"])

# ---------------------------------------------------------------------------
# In-memory run store  (chain_id → ChainResult)
# ---------------------------------------------------------------------------
_chains: Dict[str, ChainResult] = {}
_orchestrators: Dict[str, AutoChain] = {}


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class AutoChainStartRequest(BaseModel):
    """Parameters for launching an automated pentest chain."""

    target: str = Field(
        ...,
        description="Target IP address, hostname, or URL",
        examples=["10.10.10.3"],
    )
    project_id: Optional[str] = Field(
        None, description="Optional project ID to associate the run with"
    )
    auto_approve_risk_level: str = Field(
        "none",
        description=(
            "Maximum risk level auto-approved without human confirmation. "
            "Values: none | low | medium | high | critical. "
            "Use 'high' for HTB lab mode."
        ),
    )
    naabu_url: str = Field("http://kali-tools:8000", description="Naabu MCP server URL")
    nuclei_url: str = Field("http://kali-tools:8002", description="Nuclei MCP server URL")
    msf_url: str = Field("http://kali-tools:8003", description="Metasploit MCP server URL")


class AutoChainStartResponse(BaseModel):
    """Response returned when a chain run is successfully created."""

    chain_id: str
    plan_id: str
    target: str
    status: str
    started_at: str
    message: str


class AutoChainStatusResponse(BaseModel):
    """Current status of an AutoChain run."""

    chain_id: str
    target: str
    status: str
    current_phase: Optional[str]
    total_steps: int
    completed_steps: int
    total_vulns_found: int
    total_exploits_attempted: int
    exploitation_success: bool
    flags_found: int
    session_id: Optional[int]
    started_at: str
    finished_at: Optional[str]
    error: Optional[str]


class AutoChainFlagsResponse(BaseModel):
    """Flags captured during post-exploitation."""

    chain_id: str
    target: str
    flags: List[Dict[str, str]]
    count: int


class AutoChainStepsResponse(BaseModel):
    """Full step log for an AutoChain run."""

    chain_id: str
    target: str
    status: str
    steps: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------


class AutoChainTemplateStartRequest(BaseModel):
    """Parameters for launching an AutoChain run from a named template."""

    template: str = Field(
        ...,
        description="Template name (e.g. 'htb_easy', 'htb_medium')",
        examples=["htb_easy"],
    )
    target: str = Field(
        ...,
        description="Target IP address, hostname, or URL",
        examples=["10.10.10.3"],
    )
    project_id: Optional[str] = Field(None)
    auto_approve_risk_level: Optional[str] = Field(
        None,
        description=(
            "Override template's auto-approve level. "
            "Values: none | low | medium | high | critical"
        ),
    )
    naabu_url: str = Field("http://kali-tools:8000")
    nuclei_url: str = Field("http://kali-tools:8002")
    msf_url: str = Field("http://kali-tools:8003")


# ---------------------------------------------------------------------------


async def _run_chain(chain_id: str, orchestrator: AutoChain) -> None:
    """Background task that drives the AutoChain pipeline."""
    try:
        result = await orchestrator.run()
        _chains[chain_id] = result
        logger.info(
            "AutoChain %s finished with status=%s flags=%d",
            chain_id,
            result.status,
            len(result.flags),
        )
    except Exception as exc:
        logger.error("AutoChain %s crashed: %s", chain_id, exc, exc_info=True)
        if chain_id in _chains:
            _chains[chain_id].finish(ChainStatus.FAILED, error=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/start", response_model=AutoChainStartResponse, status_code=201)
async def start_chain(
    request: AutoChainStartRequest,
    background_tasks: BackgroundTasks,
) -> AutoChainStartResponse:
    """
    Create and launch an automated pentest chain.

    The chain runs in the background; poll ``GET /api/autochain/{chain_id}``
    or subscribe to ``GET /api/autochain/{chain_id}/stream`` for live updates.
    """
    chain_id = str(uuid.uuid4())

    plan = ScanPlan(
        target=request.target,
        project_id=request.project_id,
        auto_approve_risk_level=request.auto_approve_risk_level,
    )

    orchestrator = AutoChain(
        plan=plan,
        naabu_url=request.naabu_url,
        nuclei_url=request.nuclei_url,
        msf_url=request.msf_url,
    )

    # Initialise result in the store so status polls work immediately
    _chains[chain_id] = orchestrator.result
    _orchestrators[chain_id] = orchestrator

    background_tasks.add_task(_run_chain, chain_id, orchestrator)

    logger.info("Started AutoChain %s for target=%s", chain_id, request.target)

    return AutoChainStartResponse(
        chain_id=chain_id,
        plan_id=plan.plan_id,
        target=request.target,
        status=ChainStatus.RUNNING.value,
        started_at=orchestrator.result.started_at,
        message=(
            f"AutoChain started. Poll GET /api/autochain/{chain_id} for status "
            f"or subscribe to GET /api/autochain/{chain_id}/stream for live updates."
        ),
    )


@router.get("/templates", response_model=List[Dict[str, Any]])
async def list_templates() -> List[Dict[str, Any]]:
    """
    Return metadata for all available attack templates.

    Templates are JSON files in ``backend/app/autochain/templates/``.
    Built-in templates:

    * ``htb_easy``   — standard HackTheBox Easy attack sequence
    * ``htb_medium`` — extended HackTheBox Medium attack sequence
    """
    return AutoChain.list_templates()


@router.post("/start/template", response_model=AutoChainStartResponse, status_code=201)
async def start_chain_from_template(
    request: AutoChainTemplateStartRequest,
    background_tasks: BackgroundTasks,
) -> AutoChainStartResponse:
    """
    Create and launch an AutoChain run using a pre-defined attack template.

    Templates define the full attack sequence (tools, parameters, retry logic,
    auto-approve level) so callers only need to supply the target.

    Example::

        POST /api/autochain/start/template
        {"template": "htb_easy", "target": "10.10.10.3"}
    """
    try:
        orchestrator = AutoChain.from_template(
            request.template,
            target=request.target,
            project_id=request.project_id,
            auto_approve_risk_level=request.auto_approve_risk_level,
            naabu_url=request.naabu_url,
            nuclei_url=request.nuclei_url,
            msf_url=request.msf_url,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    chain_id = str(uuid.uuid4())
    _chains[chain_id] = orchestrator.result
    _orchestrators[chain_id] = orchestrator

    background_tasks.add_task(_run_chain, chain_id, orchestrator)

    logger.info(
        "Started template-based AutoChain %s (template=%s, target=%s)",
        chain_id,
        request.template,
        request.target,
    )

    return AutoChainStartResponse(
        chain_id=chain_id,
        plan_id=orchestrator.plan.plan_id,
        target=request.target,
        status=ChainStatus.RUNNING.value,
        started_at=orchestrator.result.started_at,
        message=(
            f"AutoChain started from template '{request.template}'. "
            f"Poll GET /api/autochain/{chain_id} for status or subscribe to "
            f"GET /api/autochain/{chain_id}/stream for live updates."
        ),
    )


@router.get("/{chain_id}", response_model=AutoChainStatusResponse)
async def get_chain_status(chain_id: str) -> AutoChainStatusResponse:
    """Return the current status of an AutoChain run."""
    result = _chains.get(chain_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Chain '{chain_id}' not found.")

    completed = sum(
        1 for s in result.steps if s.status in ("success", "failed", "skipped")
    )

    return AutoChainStatusResponse(
        chain_id=chain_id,
        target=result.target,
        status=result.status.value,
        current_phase=result.current_phase.value if result.current_phase else None,
        total_steps=len(result.steps),
        completed_steps=completed,
        total_vulns_found=result.total_vulns_found,
        total_exploits_attempted=result.total_exploits_attempted,
        exploitation_success=result.exploitation_success,
        flags_found=len(result.flags),
        session_id=result.session_id,
        started_at=result.started_at,
        finished_at=result.finished_at,
        error=result.error,
    )


@router.get("/{chain_id}/flags", response_model=AutoChainFlagsResponse)
async def get_chain_flags(chain_id: str) -> AutoChainFlagsResponse:
    """Return flags captured during post-exploitation."""
    result = _chains.get(chain_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Chain '{chain_id}' not found.")

    return AutoChainFlagsResponse(
        chain_id=chain_id,
        target=result.target,
        flags=result.flags,
        count=len(result.flags),
    )


@router.get("/{chain_id}/steps", response_model=AutoChainStepsResponse)
async def get_chain_steps(chain_id: str) -> AutoChainStepsResponse:
    """Return the complete step log for an AutoChain run."""
    result = _chains.get(chain_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Chain '{chain_id}' not found.")

    return AutoChainStepsResponse(
        chain_id=chain_id,
        target=result.target,
        status=result.status.value,
        steps=[s.model_dump() for s in result.steps],
    )


@router.get("/{chain_id}/stream")
async def stream_chain_progress(chain_id: str, request: Request):
    """
    SSE stream of live step updates for an AutoChain run.

    Each event is a JSON-encoded ``ChainStep``. The stream closes when the
    chain reaches a terminal state (complete / failed / stopped).
    """
    result = _chains.get(chain_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Chain '{chain_id}' not found.")

    orchestrator = _orchestrators.get(chain_id)

    async def _event_generator():
        # Yield already-completed steps first so a late subscriber catches up
        seen_step_ids: set = set()
        for step in list(result.steps):
            seen_step_ids.add(step.step_id)
            yield {
                "event": "step",
                "data": json.dumps(step.model_dump()),
            }

        # If there is an orchestrator still running, stream new steps as they arrive
        if orchestrator is not None:
            while result.status == ChainStatus.RUNNING:
                if await request.is_disconnected():
                    break
                for step in list(result.steps):
                    if step.step_id not in seen_step_ids:
                        seen_step_ids.add(step.step_id)
                        yield {
                            "event": "step",
                            "data": json.dumps(step.model_dump()),
                        }
                await asyncio.sleep(0.5)

        # Send final status event
        yield {
            "event": "status",
            "data": json.dumps(
                {
                    "status": result.status.value,
                    "exploitation_success": result.exploitation_success,
                    "flags_found": len(result.flags),
                    "finished_at": result.finished_at,
                    "error": result.error,
                }
            ),
        }

    return EventSourceResponse(
        _event_generator(),
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.delete("/{chain_id}", status_code=204, response_model=None)
async def stop_chain(chain_id: str) -> None:
    """
    Request cancellation of a running AutoChain.

    Sets the chain status to STOPPED and removes it from the active orchestrator
    registry. Already-completed steps are preserved for review.
    """
    result = _chains.get(chain_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Chain '{chain_id}' not found.")

    if result.status == ChainStatus.RUNNING:
        result.finish(ChainStatus.STOPPED)

    _orchestrators.pop(chain_id, None)
    logger.info("AutoChain %s stopped by user request.", chain_id)
