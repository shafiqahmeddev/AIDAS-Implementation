"""
Session Management for AIDAS Protocol
Handles session lifecycle, security, and monitoring
"""

import time
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from ..utils.logger import get_logger
from ..utils.config import config

logger = get_logger(__name__)


class SessionStatus(Enum):
    """Session status enumeration"""
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    SUSPENDED = "suspended"


@dataclass
class SessionInfo:
    """Session information data class"""
    session_id: str
    operator_id: str
    vehicle_id: str
    station_id: str
    status: SessionStatus
    created_at: float
    last_activity: float
    expires_at: float
    session_key: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    activity_log: List[Dict[str, Any]] = field(default_factory=list)


class SessionManager:
    """
    Manages session lifecycle for AIDAS protocol
    
    Provides:
    - Session creation and termination
    - Automatic expiration handling
    - Session security monitoring
    - Activity tracking and auditing
    """
    
    def __init__(self, cleanup_interval: int = 60):
        """
        Initialize session manager
        
        Args:
            cleanup_interval: Interval in seconds for cleanup tasks
        """
        self.sessions: Dict[str, SessionInfo] = {}
        self.cleanup_interval = cleanup_interval
        self.session_timeout = config.security.session_timeout_seconds
        
        # Statistics
        self.stats = {
            "total_sessions_created": 0,
            "active_sessions": 0,
            "expired_sessions": 0,
            "terminated_sessions": 0,
            "security_violations": 0
        }
        
        # Session callbacks
        self.callbacks = {
            "on_session_created": [],
            "on_session_expired": [],
            "on_session_terminated": [],
            "on_security_violation": []
        }
        
        # Background cleanup thread
        self.cleanup_thread = None
        self.cleanup_running = False
        
        # Thread locks
        self.session_lock = threading.RLock()
        
        logger.info("Session manager initialized", {
            "cleanup_interval": cleanup_interval,
            "session_timeout": self.session_timeout
        })
    
    def start_cleanup_service(self):
        """Start background cleanup service"""
        if self.cleanup_running:
            logger.warning("Cleanup service already running")
            return
        
        self.cleanup_running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        logger.info("Session cleanup service started")
    
    def stop_cleanup_service(self):
        """Stop background cleanup service"""
        if not self.cleanup_running:
            return
        
        self.cleanup_running = False
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        
        logger.info("Session cleanup service stopped")
    
    def _cleanup_loop(self):
        """Background cleanup loop"""
        while self.cleanup_running:
            try:
                self.cleanup_expired_sessions()
                time.sleep(self.cleanup_interval)
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                time.sleep(self.cleanup_interval)
    
    def create_session(self, operator_id: str, vehicle_id: str, station_id: str,
                      session_key: Optional[bytes] = None, 
                      timeout: Optional[int] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a new session
        
        Args:
            operator_id: Operator identifier
            vehicle_id: Vehicle identifier  
            station_id: Station identifier
            session_key: Session encryption key
            timeout: Custom timeout in seconds
            metadata: Additional session metadata
            
        Returns:
            Session ID
        """
        current_time = time.time()
        session_id = f"SESSION_{operator_id}_{vehicle_id}_{station_id}_{int(current_time)}"
        
        # Calculate expiration time
        timeout = timeout or self.session_timeout
        expires_at = current_time + timeout
        
        session_info = SessionInfo(
            session_id=session_id,
            operator_id=operator_id,
            vehicle_id=vehicle_id,
            station_id=station_id,
            status=SessionStatus.ACTIVE,
            created_at=current_time,
            last_activity=current_time,
            expires_at=expires_at,
            session_key=session_key,
            metadata=metadata or {}
        )
        
        # Add creation activity
        session_info.activity_log.append({
            "timestamp": current_time,
            "action": "session_created",
            "details": {
                "operator_id": operator_id,
                "vehicle_id": vehicle_id,
                "station_id": station_id,
                "timeout": timeout
            }
        })
        
        with self.session_lock:
            self.sessions[session_id] = session_info
            self.stats["total_sessions_created"] += 1
            self.stats["active_sessions"] += 1
        
        # Trigger callbacks
        self._trigger_callbacks("on_session_created", session_info)
        
        logger.info(f"Session created", {
            "session_id": session_id,
            "operator_id": operator_id,
            "vehicle_id": vehicle_id,
            "station_id": station_id,
            "expires_at": expires_at
        })
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """
        Get session information
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session information or None if not found
        """
        with self.session_lock:
            return self.sessions.get(session_id)
    
    def update_session_activity(self, session_id: str, action: str, 
                              details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update session activity
        
        Args:
            session_id: Session identifier
            action: Action description
            details: Action details
            
        Returns:
            True if update successful
        """
        with self.session_lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.warning(f"Session not found for activity update: {session_id}")
                return False
            
            if session.status != SessionStatus.ACTIVE:
                logger.warning(f"Attempted to update inactive session: {session_id}")
                return False
            
            current_time = time.time()
            session.last_activity = current_time
            
            # Add activity log entry
            session.activity_log.append({
                "timestamp": current_time,
                "action": action,
                "details": details or {}
            })
            
            # Limit activity log size
            if len(session.activity_log) > 100:
                session.activity_log = session.activity_log[-50:]  # Keep last 50 entries
            
            logger.debug(f"Session activity updated", {
                "session_id": session_id,
                "action": action,
                "last_activity": current_time
            })
            
            return True
    
    def extend_session(self, session_id: str, additional_time: int) -> bool:
        """
        Extend session expiration time
        
        Args:
            session_id: Session identifier
            additional_time: Additional time in seconds
            
        Returns:
            True if extension successful
        """
        with self.session_lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.warning(f"Session not found for extension: {session_id}")
                return False
            
            if session.status != SessionStatus.ACTIVE:
                logger.warning(f"Cannot extend inactive session: {session_id}")
                return False
            
            session.expires_at += additional_time
            
            # Log extension
            self.update_session_activity(session_id, "session_extended", {
                "additional_time": additional_time,
                "new_expires_at": session.expires_at
            })
            
            logger.info(f"Session extended", {
                "session_id": session_id,
                "additional_time": additional_time,
                "new_expires_at": session.expires_at
            })
            
            return True
    
    def terminate_session(self, session_id: str, reason: str = "manual_termination") -> bool:
        """
        Terminate a session
        
        Args:
            session_id: Session identifier
            reason: Termination reason
            
        Returns:
            True if termination successful
        """
        with self.session_lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.warning(f"Session not found for termination: {session_id}")
                return False
            
            if session.status != SessionStatus.ACTIVE:
                logger.info(f"Session already inactive: {session_id}")
                return True
            
            # Update session status
            session.status = SessionStatus.TERMINATED
            self.stats["active_sessions"] = max(0, self.stats["active_sessions"] - 1)
            self.stats["terminated_sessions"] += 1
            
            # Log termination
            session.activity_log.append({
                "timestamp": time.time(),
                "action": "session_terminated",
                "details": {"reason": reason}
            })
        
        # Trigger callbacks
        self._trigger_callbacks("on_session_terminated", session)
        
        logger.info(f"Session terminated", {
            "session_id": session_id,
            "reason": reason,
            "duration": time.time() - session.created_at
        })
        
        return True
    
    def suspend_session(self, session_id: str, reason: str = "security_violation") -> bool:
        """
        Suspend a session (can be resumed later)
        
        Args:
            session_id: Session identifier
            reason: Suspension reason
            
        Returns:
            True if suspension successful
        """
        with self.session_lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.warning(f"Session not found for suspension: {session_id}")
                return False
            
            if session.status != SessionStatus.ACTIVE:
                logger.warning(f"Cannot suspend inactive session: {session_id}")
                return False
            
            # Update session status
            session.status = SessionStatus.SUSPENDED
            self.stats["active_sessions"] = max(0, self.stats["active_sessions"] - 1)
            
            # Log suspension
            session.activity_log.append({
                "timestamp": time.time(),
                "action": "session_suspended",
                "details": {"reason": reason}
            })
        
        # Check if this is a security violation
        if "security" in reason.lower() or "violation" in reason.lower():
            self.stats["security_violations"] += 1
            self._trigger_callbacks("on_security_violation", session)
        
        logger.warning(f"Session suspended", {
            "session_id": session_id,
            "reason": reason
        })
        
        return True
    
    def resume_session(self, session_id: str) -> bool:
        """
        Resume a suspended session
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if resumption successful
        """
        with self.session_lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.warning(f"Session not found for resumption: {session_id}")
                return False
            
            if session.status != SessionStatus.SUSPENDED:
                logger.warning(f"Cannot resume non-suspended session: {session_id}")
                return False
            
            # Check if session would be expired
            if time.time() > session.expires_at:
                session.status = SessionStatus.EXPIRED
                self.stats["expired_sessions"] += 1
                logger.warning(f"Cannot resume expired session: {session_id}")
                return False
            
            # Resume session
            session.status = SessionStatus.ACTIVE
            session.last_activity = time.time()
            self.stats["active_sessions"] += 1
            
            # Log resumption
            session.activity_log.append({
                "timestamp": time.time(),
                "action": "session_resumed",
                "details": {}
            })
        
        logger.info(f"Session resumed", {
            "session_id": session_id
        })
        
        return True
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions
        
        Returns:
            Number of sessions cleaned up
        """
        current_time = time.time()
        expired_sessions = []
        
        with self.session_lock:
            for session_id, session in self.sessions.items():
                if session.status == SessionStatus.ACTIVE and current_time > session.expires_at:
                    session.status = SessionStatus.EXPIRED
                    expired_sessions.append(session)
                    
                    # Update statistics
                    self.stats["active_sessions"] = max(0, self.stats["active_sessions"] - 1)
                    self.stats["expired_sessions"] += 1
                    
                    # Log expiration
                    session.activity_log.append({
                        "timestamp": current_time,
                        "action": "session_expired",
                        "details": {"auto_cleanup": True}
                    })
        
        # Trigger callbacks for expired sessions
        for session in expired_sessions:
            self._trigger_callbacks("on_session_expired", session)
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    def get_sessions_by_entity(self, entity_id: str, entity_type: str) -> List[SessionInfo]:
        """
        Get sessions for a specific entity
        
        Args:
            entity_id: Entity identifier
            entity_type: Entity type (operator, vehicle, station)
            
        Returns:
            List of matching sessions
        """
        matching_sessions = []
        
        with self.session_lock:
            for session in self.sessions.values():
                if entity_type.lower() == "operator" and session.operator_id == entity_id:
                    matching_sessions.append(session)
                elif entity_type.lower() == "vehicle" and session.vehicle_id == entity_id:
                    matching_sessions.append(session)
                elif entity_type.lower() == "station" and session.station_id == entity_id:
                    matching_sessions.append(session)
        
        return matching_sessions
    
    def get_active_sessions(self) -> List[SessionInfo]:
        """Get all active sessions"""
        with self.session_lock:
            return [s for s in self.sessions.values() if s.status == SessionStatus.ACTIVE]
    
    def add_callback(self, event_type: str, callback: Callable):
        """
        Add event callback
        
        Args:
            event_type: Event type (on_session_created, on_session_expired, etc.)
            callback: Callback function
        """
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
            logger.debug(f"Callback added for event: {event_type}")
        else:
            logger.warning(f"Unknown event type: {event_type}")
    
    def _trigger_callbacks(self, event_type: str, session_info: SessionInfo):
        """Trigger callbacks for an event"""
        for callback in self.callbacks.get(event_type, []):
            try:
                callback(session_info)
            except Exception as e:
                logger.error(f"Error in callback for {event_type}: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get session manager statistics"""
        with self.session_lock:
            current_stats = self.stats.copy()
            current_stats.update({
                "total_sessions": len(self.sessions),
                "session_status_breakdown": {
                    status.value: len([s for s in self.sessions.values() if s.status == status])
                    for status in SessionStatus
                }
            })
        
        return current_stats
    
    def export_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Export session data for analysis
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data dictionary
        """
        session = self.get_session(session_id)
        if not session:
            return None
        
        return {
            "session_id": session.session_id,
            "operator_id": session.operator_id,
            "vehicle_id": session.vehicle_id,
            "station_id": session.station_id,
            "status": session.status.value,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "expires_at": session.expires_at,
            "duration": time.time() - session.created_at,
            "activity_count": len(session.activity_log),
            "metadata": session.metadata,
            "activity_log": session.activity_log
        }
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        self.stop_cleanup_service()
    
    def __repr__(self) -> str:
        return (f"SessionManager(total_sessions={len(self.sessions)}, "
                f"active_sessions={self.stats['active_sessions']}, "
                f"cleanup_running={self.cleanup_running})")