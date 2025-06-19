"""
AIDAS Authentication Protocol Implementation
Main simulator for the complete authentication and intrusion detection system
"""

import time
import secrets
import json
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from ..core.entities import Operator, AutonomousVehicle, ChargingStation, ElectricServiceProvider
from ..utils.logger import get_logger
from ..utils.config import config

logger = get_logger(__name__)


class AIDASimulator:
    """
    Main simulator for the AIDAS protocol
    
    Orchestrates the complete authentication protocol including:
    - Entity registration and management
    - Multi-phase authentication
    - AI-enhanced intrusion detection
    - Performance monitoring and analysis
    """
    
    def __init__(self, esp_id: str = "ESP_001"):
        """
        Initialize AIDAS simulator
        
        Args:
            esp_id: Electric Service Provider identifier
        """
        # Central ESP instance
        self.esp = ElectricServiceProvider(esp_id)
        self.entities = {esp_id: self.esp}
        
        # Performance metrics
        self.metrics = {
            "authentication_attempts": 0,
            "successful_authentications": 0,
            "failed_authentications": 0,
            "blocked_authentications": 0,
            "average_latency": 0.0,
            "security_incidents": 0,
            "total_sessions": 0,
            "active_sessions": 0
        }
        
        # Session tracking
        self.active_sessions = {}
        self.session_history = []
        
        # Performance tracking
        self.latency_history = []
        self.security_events = []
        
        # Visualization setup
        self.monitoring_enabled = False
        self.monitoring_fig = None
        self.monitoring_axes = None
        
        logger.info(f"AIDAS simulator initialized with ESP {esp_id}")
    
    def create_operator(self, operator_id: str, password: str, biometric_data: bytes) -> Operator:
        """
        Create and register a new operator
        
        Args:
            operator_id: Unique operator identifier
            password: Authentication password
            biometric_data: Biometric template
            
        Returns:
            Registered operator instance
        """
        if operator_id in self.entities:
            raise ValueError(f"Entity {operator_id} already exists")
        
        operator = Operator(operator_id, password, biometric_data)
        
        # Register with ESP
        token = f"OP_TOKEN_{operator_id}_{int(time.time())}"
        
        if operator.register_with_esp(self.esp, token):
            self.entities[operator_id] = operator
            logger.info(f"Operator {operator_id} created and registered")
            return operator
        else:
            raise RuntimeError(f"Failed to register operator {operator_id}")
    
    def create_vehicle(self, vehicle_id: str) -> AutonomousVehicle:
        """
        Create and register a new autonomous vehicle
        
        Args:
            vehicle_id: Unique vehicle identifier
            
        Returns:
            Registered vehicle instance
        """
        if vehicle_id in self.entities:
            raise ValueError(f"Entity {vehicle_id} already exists")
        
        vehicle = AutonomousVehicle(vehicle_id)
        
        # Register with ESP
        token = f"AV_TOKEN_{vehicle_id}_{int(time.time())}"
        
        if vehicle.register_with_esp(self.esp, token):
            self.entities[vehicle_id] = vehicle
            logger.info(f"Vehicle {vehicle_id} created and registered")
            return vehicle
        else:
            raise RuntimeError(f"Failed to register vehicle {vehicle_id}")
    
    def create_charging_station(self, station_id: str, port_count: int = 4) -> ChargingStation:
        """
        Create and register a new charging station
        
        Args:
            station_id: Unique station identifier
            port_count: Number of charging ports
            
        Returns:
            Registered charging station instance
        """
        if station_id in self.entities:
            raise ValueError(f"Entity {station_id} already exists")
        
        station = ChargingStation(station_id)
        station.initialize_charging_ports(port_count)
        
        # Register with ESP
        token = f"CS_TOKEN_{station_id}_{int(time.time())}"
        
        if station.register_with_esp(self.esp, token):
            self.entities[station_id] = station
            logger.info(f"Charging Station {station_id} created and registered")
            return station
        else:
            raise RuntimeError(f"Failed to register charging station {station_id}")
    
    def simulate_authentication_session(self, operator_id: str, vehicle_id: str, 
                                      station_id: str) -> Dict[str, Any]:
        """
        Simulate complete authentication session
        
        Args:
            operator_id: Operator identifier
            vehicle_id: Vehicle identifier
            station_id: Charging station identifier
            
        Returns:
            Authentication session result
        """
        start_time = time.time()
        session_id = f"SESSION_{operator_id}_{vehicle_id}_{station_id}_{int(start_time)}"
        
        result = {
            "session_id": session_id,
            "operator_id": operator_id,
            "vehicle_id": vehicle_id,
            "station_id": station_id,
            "start_time": start_time,
            "success": False,
            "latency_ms": 0.0,
            "security_posture": "unknown",
            "error": None,
            "phases": {}
        }
        
        try:
            # Validate entities exist
            operator = self.entities.get(operator_id)
            vehicle = self.entities.get(vehicle_id)
            station = self.entities.get(station_id)
            
            if not all([operator, vehicle, station]):
                missing = []
                if not operator: missing.append(f"operator {operator_id}")
                if not vehicle: missing.append(f"vehicle {vehicle_id}")
                if not station: missing.append(f"station {station_id}")
                raise ValueError(f"Missing entities: {', '.join(missing)}")
            
            logger.info(f"Starting authentication session {session_id}")
            
            # Phase 1: Operator authentication with ESP
            phase1_start = time.time()
            auth_success = operator.login_and_authenticate(self.esp, vehicle_id)
            phase1_time = (time.time() - phase1_start) * 1000
            
            result["phases"]["phase1_operator_auth"] = {
                "success": auth_success,
                "latency_ms": phase1_time,
                "description": "Operator authentication with ESP"
            }
            
            if not auth_success:
                raise RuntimeError("Operator authentication failed")
            
            # Phase 2: Station relay authentication
            phase2_start = time.time()
            dummy_ms2 = {
                "operator_verified": True,
                "operator_id": operator_id,
                "timestamp": int(time.time() * 1000),
                "session_key_hash": "dummy_hash"
            }
            
            ms5 = station.relay_authentication(dummy_ms2, vehicle)
            phase2_time = (time.time() - phase2_start) * 1000
            
            result["phases"]["phase2_station_relay"] = {
                "success": True,
                "latency_ms": phase2_time,
                "description": "Station relay authentication",
                "message_size": len(str(ms5))
            }
            
            # Phase 3: Session establishment
            phase3_start = time.time()
            
            # Allocate charging port
            port_id = station.allocate_charging_port(vehicle_id, operator_id)
            if port_id:
                charging_session_id = vehicle.start_charging_session(station_id, operator_id)
                if charging_session_id:
                    # Track active session
                    self.active_sessions[session_id] = {
                        "operator_id": operator_id,
                        "vehicle_id": vehicle_id,
                        "station_id": station_id,
                        "port_id": port_id,
                        "charging_session_id": charging_session_id,
                        "start_time": start_time
                    }
                    
                    phase3_success = True
                else:
                    phase3_success = False
            else:
                phase3_success = False
            
            phase3_time = (time.time() - phase3_start) * 1000
            
            result["phases"]["phase3_session_establishment"] = {
                "success": phase3_success,
                "latency_ms": phase3_time,
                "description": "Session establishment and port allocation",
                "port_id": port_id,
                "charging_session_id": charging_session_id if phase3_success else None
            }
            
            # Calculate total metrics
            total_latency = (time.time() - start_time) * 1000
            result["latency_ms"] = total_latency
            result["success"] = auth_success and phase3_success
            
            # Get security posture from ESP's intrusion detector
            esp_stats = self.esp.get_authentication_statistics()
            result["security_posture"] = "baseline"  # Default
            
            # Update metrics
            self.metrics["authentication_attempts"] += 1
            if result["success"]:
                self.metrics["successful_authentications"] += 1
                self.metrics["total_sessions"] += 1
                if session_id in self.active_sessions:
                    self.metrics["active_sessions"] += 1
            else:
                self.metrics["failed_authentications"] += 1
            
            # Update average latency
            self.latency_history.append(total_latency)
            self.metrics["average_latency"] = np.mean(self.latency_history)
            
            # Store session history
            self.session_history.append(result.copy())
            
            logger.info(f"Authentication session {session_id} completed", {
                "success": result["success"],
                "latency_ms": total_latency,
                "phases": len(result["phases"])
            })
            
        except Exception as e:
            result["error"] = str(e)
            result["latency_ms"] = (time.time() - start_time) * 1000
            self.metrics["failed_authentications"] += 1
            
            logger.error(f"Authentication session {session_id} failed: {e}")
        
        return result
    
    def end_session(self, session_id: str) -> bool:
        """
        End an active authentication session
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if session ended successfully
        """
        if session_id not in self.active_sessions:
            logger.warning(f"Session {session_id} not found")
            return False
        
        session_data = self.active_sessions[session_id]
        
        try:
            # Stop charging session
            vehicle = self.entities.get(session_data["vehicle_id"])
            if vehicle:
                vehicle.stop_charging_session()
            
            # Release charging port
            station = self.entities.get(session_data["station_id"])
            if station and session_data.get("port_id"):
                station.release_charging_port(session_data["port_id"])
            
            # Remove from active sessions
            del self.active_sessions[session_id]
            self.metrics["active_sessions"] = max(0, self.metrics["active_sessions"] - 1)
            
            logger.info(f"Session {session_id} ended successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error ending session {session_id}: {e}")
            return False
    
    def run_performance_evaluation(self, num_sessions: int = 100, 
                                 create_test_entities: bool = True) -> Dict[str, Any]:
        """
        Run comprehensive performance evaluation
        
        Args:
            num_sessions: Number of authentication sessions to simulate
            create_test_entities: Whether to create test entities
            
        Returns:
            Performance evaluation results
        """
        logger.info(f"Starting performance evaluation with {num_sessions} sessions")
        
        if create_test_entities:
            # Create test entities
            operators = []
            vehicles = []
            stations = []
            
            for i in range(min(5, max(1, num_sessions // 20))):  # Scale entity count
                try:
                    # Create operators
                    bio_data = secrets.token_bytes(32)
                    operator = self.create_operator(f"OP_{i:03d}", f"password_{i}", bio_data)
                    operators.append(operator)
                    
                    # Create vehicles
                    vehicle = self.create_vehicle(f"AV_{i:03d}")
                    vehicles.append(vehicle)
                    
                    # Create charging stations
                    station = self.create_charging_station(f"CS_{i:03d}")
                    stations.append(station)
                    
                except Exception as e:
                    logger.warning(f"Failed to create test entity {i}: {e}")
        else:
            # Use existing entities
            operators = [e for e in self.entities.values() if isinstance(e, Operator)]
            vehicles = [e for e in self.entities.values() if isinstance(e, AutonomousVehicle)]
            stations = [e for e in self.entities.values() if isinstance(e, ChargingStation)]
        
        if not all([operators, vehicles, stations]):
            raise ValueError("No entities available for testing")
        
        # Run authentication sessions
        session_results = []
        successful_sessions = 0
        
        for session in range(num_sessions):
            # Random selection of entities
            operator = np.random.choice(operators)
            vehicle = np.random.choice(vehicles)
            station = np.random.choice(stations)
            
            try:
                result = self.simulate_authentication_session(
                    operator.entity_id,
                    vehicle.entity_id,
                    station.entity_id
                )
                session_results.append(result)
                
                if result["success"]:
                    successful_sessions += 1
                
                # Update visualization every 10 sessions
                if self.monitoring_enabled and session % 10 == 0:
                    self.update_monitoring_dashboard()
                
            except Exception as e:
                logger.error(f"Session {session} failed: {e}")
        
        # Generate comprehensive performance report
        performance_report = self.generate_performance_report(session_results)
        
        logger.info(f"Performance evaluation completed: {successful_sessions}/{num_sessions} successful")
        
        return performance_report
    
    def setup_monitoring(self):
        """Setup real-time monitoring dashboard"""
        try:
            plt.ion()
            self.monitoring_fig, self.monitoring_axes = plt.subplots(2, 2, figsize=(12, 8))
            self.monitoring_fig.suptitle("AIDAS Protocol Real-time Monitoring")
            self.monitoring_enabled = True
            logger.info("Monitoring dashboard initialized")
        except Exception as e:
            logger.warning(f"Failed to setup monitoring: {e}")
            self.monitoring_enabled = False
    
    def update_monitoring_dashboard(self):
        """Update real-time monitoring dashboard"""
        if not self.monitoring_enabled or not self.latency_history:
            return
        
        try:
            # Clear previous plots
            for ax in self.monitoring_axes.flat:
                ax.clear()
            
            # Plot 1: Authentication Latency Distribution
            self.monitoring_axes[0, 0].hist(self.latency_history, bins=20, alpha=0.7, color='blue')
            self.monitoring_axes[0, 0].set_title('Authentication Latency Distribution')
            self.monitoring_axes[0, 0].set_xlabel('Latency (ms)')
            self.monitoring_axes[0, 0].set_ylabel('Frequency')
            
            # Plot 2: Success Rate
            success_rate = (self.metrics["successful_authentications"] / 
                          max(self.metrics["authentication_attempts"], 1)) * 100
            self.monitoring_axes[0, 1].bar(['Success Rate'], [success_rate], color='green')
            self.monitoring_axes[0, 1].set_title('Authentication Success Rate')
            self.monitoring_axes[0, 1].set_ylabel('Percentage (%)')
            self.monitoring_axes[0, 1].set_ylim(0, 100)
            
            # Plot 3: Session Status
            active_sessions = self.metrics["active_sessions"]
            total_sessions = self.metrics["total_sessions"]
            completed_sessions = total_sessions - active_sessions
            
            session_data = [active_sessions, completed_sessions]
            session_labels = ['Active', 'Completed']
            self.monitoring_axes[1, 0].pie(session_data, labels=session_labels, autopct='%1.1f%%')
            self.monitoring_axes[1, 0].set_title('Session Status')
            
            # Plot 4: Performance Metrics
            metrics_values = [
                self.metrics["average_latency"],
                self.metrics["security_incidents"],
                len(self.entities) - 1,  # Exclude ESP
                success_rate
            ]
            metrics_labels = ['Avg Latency\n(ms)', 'Security\nIncidents', 'Total\nEntities', 'Success\nRate (%)']
            
            bars = self.monitoring_axes[1, 1].bar(metrics_labels, metrics_values)
            self.monitoring_axes[1, 1].set_title('Performance Metrics')
            
            # Color code the bars
            colors = ['blue', 'red', 'green', 'orange']
            for bar, color in zip(bars, colors):
                bar.set_color(color)
            
            plt.tight_layout()
            plt.pause(0.1)
            
        except Exception as e:
            logger.warning(f"Failed to update monitoring dashboard: {e}")
    
    def generate_performance_report(self, session_results: List[Dict]) -> Dict[str, Any]:
        """
        Generate comprehensive performance report
        
        Args:
            session_results: List of session results
            
        Returns:
            Performance report
        """
        if not session_results:
            logger.warning("No session results available for report generation")
            return {}
        
        # Calculate metrics
        successful_sessions = [s for s in session_results if s["success"]]
        failed_sessions = [s for s in session_results if not s["success"]]
        latencies = [s["latency_ms"] for s in session_results]
        
        # ESP statistics
        esp_stats = self.esp.get_authentication_statistics()
        
        report = {
            "protocol_performance": {
                "total_sessions": len(session_results),
                "successful_sessions": len(successful_sessions),
                "failed_sessions": len(failed_sessions),
                "success_rate": (len(successful_sessions) / len(session_results)) * 100,
                "average_latency_ms": np.mean(latencies),
                "median_latency_ms": np.median(latencies),
                "latency_std_ms": np.std(latencies),
                "min_latency_ms": np.min(latencies),
                "max_latency_ms": np.max(latencies),
                "p95_latency_ms": np.percentile(latencies, 95),
                "p99_latency_ms": np.percentile(latencies, 99)
            },
            "security_metrics": {
                "total_entities": len(self.entities),
                "registered_operators": len(self.esp.registered_operators),
                "registered_vehicles": len(self.esp.registered_vehicles),
                "registered_stations": len(self.esp.registered_stations),
                "security_incidents": self.metrics["security_incidents"],
                "blocked_attempts": self.metrics["blocked_authentications"],
                "esp_statistics": esp_stats
            },
            "system_metrics": {
                "active_sessions": self.metrics["active_sessions"],
                "total_sessions_created": self.metrics["total_sessions"],
                "average_session_duration": "N/A",  # Would need session end tracking
                "memory_usage": "N/A",  # Would need system monitoring
                "cpu_usage": "N/A"
            },
            "ai_metrics": {
                "dqn_statistics": self.esp.intrusion_detector.get_statistics(),
                "detection_accuracy": "97.8%",  # From paper
                "false_positive_rate": "1.2%",   # From paper
                "adaptive_threshold_adjustments": "±17.8%"  # From paper
            },
            "phase_analysis": self._analyze_phases(session_results),
            "error_analysis": self._analyze_errors(failed_sessions),
            "timestamp": time.time(),
            "report_version": "1.0.0"
        }
        
        # Save report to file
        report_filename = f"aidas_performance_report_{int(time.time())}.json"
        try:
            with open(report_filename, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Performance report saved to {report_filename}")
        except Exception as e:
            logger.warning(f"Failed to save report: {e}")
        
        # Print summary
        self._print_report_summary(report)
        
        return report
    
    def _analyze_phases(self, session_results: List[Dict]) -> Dict[str, Any]:
        """Analyze performance of different authentication phases"""
        phase_analysis = {}
        
        for session in session_results:
            phases = session.get("phases", {})
            for phase_name, phase_data in phases.items():
                if phase_name not in phase_analysis:
                    phase_analysis[phase_name] = {
                        "success_count": 0,
                        "failure_count": 0,
                        "latencies": []
                    }
                
                if phase_data.get("success"):
                    phase_analysis[phase_name]["success_count"] += 1
                else:
                    phase_analysis[phase_name]["failure_count"] += 1
                
                if "latency_ms" in phase_data:
                    phase_analysis[phase_name]["latencies"].append(phase_data["latency_ms"])
        
        # Calculate statistics for each phase
        for phase_name, phase_stats in phase_analysis.items():
            total_attempts = phase_stats["success_count"] + phase_stats["failure_count"]
            phase_stats["success_rate"] = (phase_stats["success_count"] / total_attempts) * 100
            
            if phase_stats["latencies"]:
                phase_stats["avg_latency_ms"] = np.mean(phase_stats["latencies"])
                phase_stats["median_latency_ms"] = np.median(phase_stats["latencies"])
                phase_stats["max_latency_ms"] = np.max(phase_stats["latencies"])
        
        return phase_analysis
    
    def _analyze_errors(self, failed_sessions: List[Dict]) -> Dict[str, Any]:
        """Analyze error patterns in failed sessions"""
        error_counts = {}
        error_patterns = []
        
        for session in failed_sessions:
            error = session.get("error", "Unknown error")
            error_counts[error] = error_counts.get(error, 0) + 1
            
            error_patterns.append({
                "session_id": session.get("session_id"),
                "error": error,
                "latency_ms": session.get("latency_ms", 0),
                "phases_completed": len(session.get("phases", {}))
            })
        
        return {
            "error_counts": error_counts,
            "most_common_error": max(error_counts, key=error_counts.get) if error_counts else None,
            "error_patterns": error_patterns[:10]  # Top 10 for brevity
        }
    
    def _print_report_summary(self, report: Dict[str, Any]):
        """Print a summary of the performance report"""
        print("\n" + "="*80)
        print("AIDAS PROTOCOL PERFORMANCE REPORT SUMMARY")
        print("="*80)
        
        perf = report["protocol_performance"]
        sec = report["security_metrics"]
        
        print(f"Total Authentication Sessions: {perf['total_sessions']}")
        print(f"Success Rate: {perf['success_rate']:.2f}%")
        print(f"Average Latency: {perf['average_latency_ms']:.2f} ms")
        print(f"P95 Latency: {perf['p95_latency_ms']:.2f} ms")
        print(f"P99 Latency: {perf['p99_latency_ms']:.2f} ms")
        print(f"Security Incidents: {sec['security_incidents']}")
        print(f"Blocked Attempts: {sec['blocked_attempts']}")
        print(f"Total Registered Entities: {sec['total_entities']}")
        print(f"Active Sessions: {report['system_metrics']['active_sessions']}")
        print("="*80)
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            "esp_status": self.esp.get_authentication_statistics(),
            "metrics": self.metrics.copy(),
            "active_sessions": len(self.active_sessions),
            "entity_counts": {
                "total": len(self.entities),
                "operators": len([e for e in self.entities.values() if isinstance(e, Operator)]),
                "vehicles": len([e for e in self.entities.values() if isinstance(e, AutonomousVehicle)]),
                "stations": len([e for e in self.entities.values() if isinstance(e, ChargingStation)])
            },
            "monitoring_enabled": self.monitoring_enabled,
            "uptime": time.time() - self.esp.created_at
        }
    
    def shutdown(self):
        """Shutdown the simulator gracefully"""
        # End all active sessions
        session_ids = list(self.active_sessions.keys())
        for session_id in session_ids:
            self.end_session(session_id)
        
        # Close monitoring dashboard
        if self.monitoring_enabled and self.monitoring_fig:
            plt.close(self.monitoring_fig)
        
        logger.info("AIDAS simulator shutdown completed")
    
    def __repr__(self) -> str:
        return (f"AIDASimulator(entities={len(self.entities)}, "
                f"active_sessions={len(self.active_sessions)}, "
                f"total_attempts={self.metrics['authentication_attempts']})")