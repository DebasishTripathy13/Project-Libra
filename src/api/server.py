"""
FastAPI REST API Server for ProjectLibra.

Provides endpoints for:
- System status and health
- Threat assessments
- Database integrity
- Agent management
- Learning feedback
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
import uvicorn

from ..config import ProjectLibraConfig, get_default_config
from ..database.dual_db_manager import DualDatabaseManager
from ..agents.orchestrator import AgentOrchestrator


# Create a simple default app for import testing
# (Full app is created via create_api_app factory)
app = FastAPI(
    title="ProjectLibra API",
    description="Agentic AI Security Platform API",
    version="1.0.0",
)


# Pydantic models for API
class HealthResponse(BaseModel):
    """Health check response."""
    healthy: bool
    status: str
    total_agents: int
    healthy_agents: int
    error_agents: List[str]


class StatusResponse(BaseModel):
    """System status response."""
    running: bool
    uptime_seconds: float
    environment: str
    database_healthy: bool
    agent_count: int
    messages_routed: int


class IntegrityResponse(BaseModel):
    """Database integrity response."""
    healthy: bool
    verified_records: int
    missing_records: int
    tampered_records: int
    tampered_ids: List[int]


class ThreatAssessmentResponse(BaseModel):
    """Threat assessment response."""
    assessment_id: str
    timestamp: str
    threat_level: str
    confidence: float
    summary: str
    indicators: List[str]
    recommended_actions: List[str]


class FeedbackRequest(BaseModel):
    """Learning feedback request."""
    event_id: str
    was_anomaly: bool = True
    is_malicious: bool
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    notes: str = ''


class CommandRequest(BaseModel):
    """Command request."""
    command: str
    params: Dict[str, Any] = Field(default_factory=dict)


class LogEntry(BaseModel):
    """Log entry for manual submission."""
    message: str
    source: str = 'manual'
    level: str = 'info'
    hostname: str = ''


class ActionApprovalRequest(BaseModel):
    """Action approval request."""
    action_id: str
    approved_by: str = 'api_user'


# API application factory
def create_api_app(
    config: ProjectLibraConfig,
    db_manager: DualDatabaseManager,
    orchestrator: AgentOrchestrator,
) -> FastAPI:
    """
    Create FastAPI application.
    
    Args:
        config: Application configuration
        db_manager: Database manager
        orchestrator: Agent orchestrator
        
    Returns:
        Configured FastAPI app
    """
    app = FastAPI(
        title="ProjectLibra API",
        description="Agentic AI Security Platform API",
        version="1.0.0",
        docs_url="/docs" if config.api.debug else None,
        redoc_url="/redoc" if config.api.debug else None,
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # API key authentication
    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
    
    async def verify_api_key(api_key: str = Security(api_key_header)) -> bool:
        if not config.api.api_key:
            return True  # No API key configured
        if api_key != config.api.api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return True
    
    # Store references
    app.state.config = config
    app.state.db_manager = db_manager
    app.state.orchestrator = orchestrator
    
    # Health endpoints
    @app.get("/health", response_model=HealthResponse, tags=["Health"])
    async def health_check():
        """Check system health."""
        health = orchestrator.get_health()
        return HealthResponse(**health)
    
    @app.get("/status", response_model=StatusResponse, tags=["Health"])
    async def get_status(authenticated: bool = Depends(verify_api_key)):
        """Get detailed system status."""
        status = orchestrator.get_status()
        integrity = db_manager.verify_integrity()
        
        return StatusResponse(
            running=status.get('running', False),
            uptime_seconds=status.get('uptime_seconds', 0),
            environment=config.environment,
            database_healthy=integrity.get('tampered', 0) == 0,
            agent_count=status.get('agent_count', 0),
            messages_routed=status.get('messages_routed', 0),
        )
    
    # Database integrity endpoints
    @app.get("/integrity", response_model=IntegrityResponse, tags=["Database"])
    async def check_integrity(authenticated: bool = Depends(verify_api_key)):
        """Check database integrity."""
        result = db_manager.verify_integrity()
        
        return IntegrityResponse(
            healthy=result.get('tampered', 0) == 0 and result.get('missing', 0) == 0,
            verified_records=result.get('verified', 0),
            missing_records=result.get('missing', 0),
            tampered_records=result.get('tampered', 0),
            tampered_ids=result.get('tampered_ids', []),
        )
    
    @app.get("/integrity/details", tags=["Database"])
    async def get_integrity_details(authenticated: bool = Depends(verify_api_key)):
        """Get detailed integrity information including tampered records."""
        result = db_manager.verify_integrity()
        
        details = {
            'summary': {
                'verified': result.get('verified', 0),
                'missing': result.get('missing', 0),
                'tampered': result.get('tampered', 0),
            },
            'tampered_records': [],
        }
        
        # Get details of tampered records
        for record_id in result.get('tampered_ids', [])[:10]:  # Limit to 10
            forensic = db_manager.get_forensic_comparison(record_id)
            if forensic:
                details['tampered_records'].append(forensic)
        
        return details
    
    # Threat assessment endpoints
    @app.get("/threats", tags=["Threats"])
    async def get_recent_threats(
        limit: int = 10,
        authenticated: bool = Depends(verify_api_key)
    ):
        """Get recent threat assessments."""
        threat_agent = orchestrator.get_agent('threat')
        if not threat_agent:
            return []
        
        return threat_agent.get_recent_assessments(limit=limit)
    
    @app.get("/threats/{assessment_id}", tags=["Threats"])
    async def get_threat_details(
        assessment_id: str,
        authenticated: bool = Depends(verify_api_key)
    ):
        """Get details of a specific threat assessment."""
        threat_agent = orchestrator.get_agent('threat')
        if not threat_agent:
            raise HTTPException(status_code=404, detail="Threat agent not available")
        
        assessments = threat_agent.get_recent_assessments(limit=100)
        for a in assessments:
            if a.get('assessment_id') == assessment_id:
                return a
        
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    # Learning endpoints
    @app.post("/feedback", tags=["Learning"])
    async def submit_feedback(
        feedback: FeedbackRequest,
        background_tasks: BackgroundTasks,
        authenticated: bool = Depends(verify_api_key)
    ):
        """Submit learning feedback for a detection."""
        result = await orchestrator.send_command('feedback', feedback.dict())
        return result
    
    @app.get("/learning/metrics", tags=["Learning"])
    async def get_learning_metrics(authenticated: bool = Depends(verify_api_key)):
        """Get learning metrics."""
        learning_agent = orchestrator.get_agent('learning')
        if not learning_agent:
            return {}
        
        return learning_agent.get_learning_metrics()
    
    @app.get("/learning/threshold", tags=["Learning"])
    async def get_current_threshold(authenticated: bool = Depends(verify_api_key)):
        """Get current anomaly threshold."""
        learning_agent = orchestrator.get_agent('learning')
        if not learning_agent:
            return {'threshold': 0.6}
        
        return {'threshold': learning_agent.get_current_threshold()}
    
    # Agent management endpoints
    @app.get("/agents", tags=["Agents"])
    async def list_agents(authenticated: bool = Depends(verify_api_key)):
        """List all agents and their status."""
        status = orchestrator.get_status()
        return status.get('agents', {})
    
    @app.get("/agents/{agent_name}", tags=["Agents"])
    async def get_agent_status(
        agent_name: str,
        authenticated: bool = Depends(verify_api_key)
    ):
        """Get status of a specific agent."""
        agent = orchestrator.get_agent(agent_name)
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
        
        return agent.get_status()
    
    @app.post("/command", tags=["Control"])
    async def send_command(
        request: CommandRequest,
        authenticated: bool = Depends(verify_api_key)
    ):
        """Send a command to the system."""
        result = await orchestrator.send_command(request.command, request.params)
        return result
    
    # Maintenance action endpoints
    @app.get("/actions/pending", tags=["Maintenance"])
    async def get_pending_actions(authenticated: bool = Depends(verify_api_key)):
        """Get pending maintenance actions requiring approval."""
        maintenance_agent = orchestrator.get_agent('maintenance')
        if not maintenance_agent:
            return []
        
        return maintenance_agent.get_pending_actions()
    
    @app.post("/actions/approve", tags=["Maintenance"])
    async def approve_action(
        request: ActionApprovalRequest,
        authenticated: bool = Depends(verify_api_key)
    ):
        """Approve a pending maintenance action."""
        result = await orchestrator.send_command('approve_action', {
            'action_id': request.action_id,
            'approved_by': request.approved_by,
        })
        return result
    
    @app.get("/actions/history", tags=["Maintenance"])
    async def get_action_history(
        limit: int = 20,
        authenticated: bool = Depends(verify_api_key)
    ):
        """Get maintenance action history."""
        maintenance_agent = orchestrator.get_agent('maintenance')
        if not maintenance_agent:
            return []
        
        return maintenance_agent.get_recent_actions(limit=limit)
    
    # Log submission endpoint
    @app.post("/logs", tags=["Logs"])
    async def submit_log(
        entry: LogEntry,
        authenticated: bool = Depends(verify_api_key)
    ):
        """Submit a log entry for analysis."""
        db_manager.add_log({
            'timestamp': datetime.now().isoformat(),
            'source': entry.source,
            'level': entry.level,
            'message': entry.message,
            'hostname': entry.hostname,
        })
        
        return {'status': 'logged', 'message': 'Log entry submitted for analysis'}
    
    # Metrics endpoints
    @app.get("/metrics", tags=["Metrics"])
    async def get_metrics(authenticated: bool = Depends(verify_api_key)):
        """Get aggregated system metrics."""
        return orchestrator.get_metrics()
    
    @app.get("/metrics/collection", tags=["Metrics"])
    async def get_collection_stats(authenticated: bool = Depends(verify_api_key)):
        """Get data collection statistics."""
        observation_agent = orchestrator.get_agent('observation')
        if not observation_agent:
            return {}
        
        return observation_agent.get_collection_stats()
    
    # Correlation endpoints
    @app.get("/correlations", tags=["Correlations"])
    async def get_active_correlations(authenticated: bool = Depends(verify_api_key)):
        """Get active event correlations."""
        correlation_agent = orchestrator.get_agent('correlation')
        if not correlation_agent:
            return []
        
        return correlation_agent.get_active_correlations()
    
    return app


async def run_api_server(
    config: ProjectLibraConfig,
    db_manager: DualDatabaseManager,
    orchestrator: AgentOrchestrator,
) -> None:
    """
    Run the API server.
    
    Args:
        config: Application configuration
        db_manager: Database manager
        orchestrator: Agent orchestrator
    """
    app = create_api_app(config, db_manager, orchestrator)
    
    config_uvicorn = uvicorn.Config(
        app,
        host=config.api.host,
        port=config.api.port,
        log_level="info" if config.api.debug else "warning",
    )
    server = uvicorn.Server(config_uvicorn)
    await server.serve()
