"""GET /api/v1/agents: the agent registry, as metadata only.

Prompt bodies are never returned; each agent carries the SHA-256 of its prompt
file so a client can tell which version produced a report.
"""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status

from api.middleware.auth import Subscriber
from api.schemas import AgentInfo, AgentPage, DivisionInfo

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


@router.get("", response_model=AgentPage)
async def list_agents(
    request: Request,
    principal: Subscriber,
    division: Annotated[str | None, Query(pattern="^[a-z0-9-]{1,60}$")] = None,
    source: Annotated[str | None, Query(pattern="^(custom|upstream)$")] = None,
) -> AgentPage:
    snapshot = request.app.state.registry.snapshot()
    agents = [
        AgentInfo(**agent.public())
        for agent in sorted(snapshot.agents.values(), key=lambda a: a.agent_id)
        if (division is None or agent.division == division) and (source is None or agent.source == source)
    ]
    divisions = [DivisionInfo(division=name, **info) for name, info in sorted(snapshot.divisions.items())]
    return AgentPage(agents=agents, divisions=divisions, warnings=snapshot.warnings)


@router.get("/{agent_id}", response_model=AgentInfo)
async def get_agent(agent_id: str, request: Request, principal: Subscriber) -> AgentInfo:
    agent = request.app.state.registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent not found")
    return AgentInfo(**agent.public())
