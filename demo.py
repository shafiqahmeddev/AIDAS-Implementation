#!/usr/bin/env python3
"""
AIDAS Protocol New Interactive Demo
Comprehensive demonstration using the modular architecture
"""

import time
import secrets
import asyncio
from typing import Dict, List, Any
import numpy as np

# Import the new modular AIDAS components
from aidas import (
    AIDASimulator, 
    Config, 
    get_logger,
    PUFSimulator,
    ChaoticMap,
    DQNIntrusionDetector,
    CryptographicEngine
)

logger = get_logger(__name__)


class AIDASDemoRunner:
    """
    Enhanced interactive demonstration runner for AIDAS protocol
    
    Showcases all major features of the new modular implementation
    """
    
    def __init__(self):
        """Initialize demo runner"""
        self.config = Config()
        self.simulator = None
        self.demo_entities = {}
        
        print("\n" + "="*80)
        print("🔐 AIDAS Protocol - Enhanced Interactive Demonstration")
        print("AI-Enhanced Intrusion Detection and Authentication for Autonomous Vehicles")
        print("="*80)
        
    def print_header(self, title: str):
        """Print formatted header"""
        print("\n" + "="*60)
        print(f" {title}")
        print("="*60)
    
    def print_step(self, step_num: int, description: str):
        """Print formatted step"""
        print(f"\n[Step {step_num}] {description}")
        print("-" * 40)
    
    def demo_configuration_system(self):
        """Demonstrate the configuration management system"""
        self.print_header("Configuration Management System Demo")
        
        print("📋 Current Configuration Settings:")
        print(f"  Security Key Length: {self.config.security.encryption_key_length} bytes")
        print(f"  PUF Noise Level: {self.config.security.puf_noise_level}")
        print(f"  DQN Learning Rate: {self.config.ai.learning_rate}")
        print(f"  Session Timeout: {self.config.security.session_timeout_seconds}s")
        print(f"  Logging Level: {self.config.logging.log_level}")
        
        # Demonstrate configuration validation
        try:
            self.config.validate()
            print("✅ Configuration validation: PASSED")
        except ValueError as e:
            print(f"❌ Configuration validation: FAILED - {e}")
        
        print(f"\n📁 Configuration file: {self.config.config_path or 'Using defaults'}")
        
        input("\nPress Enter to continue...")
    
    def demo_enhanced_logging(self):
        """Demonstrate the enhanced logging system"""
        self.print_header("Enhanced Logging System Demo")
        
        # Test different log levels
        logger.debug("This is a debug message", {"component": "demo", "level": "debug"})
        logger.info("This is an info message", {"component": "demo", "level": "info"})
        logger.warning("This is a warning message", {"component": "demo", "level": "warning"})
        
        # Test structured logging
        logger.log_authentication_attempt("DEMO_OP", "DEMO_AV", "DEMO_CS", True, 15.3)
        
        logger.log_security_event("demo_security_test", "LOW", {
            "source": "demo",
            "description": "Testing security event logging",
            "timestamp": time.time()
        })
        
        logger.log_performance_metrics("demo_component", {
            "latency_ms": 12.5,
            "throughput": 100.0,
            "error_rate": 0.01
        })
        
        print("📝 Logging system demonstration completed")
        print("   - Console logging (with colors)")
        print("   - File logging (general and errors)")
        print("   - Structured JSON logging")
        print("   - Specialized logging methods")
        
        input("\nPress Enter to continue...")
    
    def demo_advanced_puf(self):
        """Demonstrate advanced PUF functionality"""
        self.print_header("Advanced Physical Unclonable Function Demo")
        
        # Create multiple PUF instances
        puf1 = PUFSimulator("DEMO_DEVICE_001")
        puf2 = PUFSimulator("DEMO_DEVICE_002")
        
        print("🔧 Testing PUF uniqueness and reliability...")
        
        # Test uniqueness
        uniqueness_metrics = puf1.get_uniqueness_metrics(puf2, num_challenges=100)
        print(f"  Uniqueness: {uniqueness_metrics['uniqueness_percentage']:.2f}%")
        print(f"  Ideal target: {uniqueness_metrics['ideal_uniqueness']}%")
        
        # Test reliability
        reliability_metrics = puf1.get_reliability_metrics(num_tests=50)
        print(f"  Reliability: {reliability_metrics['reliability_percentage']:.2f}%")
        print(f"  Min reliability: {reliability_metrics['min_reliability']:.3f}")
        
        # Export CRP pairs for demonstration
        crp_pairs = puf1.export_challenge_response_pairs(num_pairs=5)
        print(f"\n📊 Sample Challenge-Response Pairs:")
        for i, (challenge, response) in enumerate(crp_pairs[:3]):
            print(f"  {i+1}. Challenge: {challenge[:16]}...")
            print(f"     Response:  {response[:16]}...")
        
        input("\nPress Enter to continue...")
    
    def demo_enhanced_chaotic_crypto(self):
        """Demonstrate enhanced chaotic cryptography"""
        self.print_header("Enhanced Chaotic Map Cryptography Demo")
        
        chaotic_map = ChaoticMap()
        
        print(f"🌀 Chaotic Map Parameters:")
        print(f"  Control parameter (r): {chaotic_map.r}")
        print(f"  Initial condition: {chaotic_map.initial_x:.6f}")
        
        # Analyze chaotic behavior
        print("\n📈 Analyzing chaotic behavior...")
        lyapunov = chaotic_map.get_lyapunov_exponent(iterations=1000)
        print(f"  Lyapunov exponent: {lyapunov:.6f}")
        print(f"  Chaotic behavior: {'✅ YES' if lyapunov > 0 else '❌ NO'}")
        
        # Test randomness quality
        randomness_metrics = chaotic_map.analyze_randomness(sequence_length=1000)
        print(f"\n🎲 Randomness Analysis:")
        print(f"  Balance ratio: {randomness_metrics['balance_ratio']:.3f}")
        print(f"  Average run length: {randomness_metrics['average_run_length']:.2f}")
        print(f"  Max autocorrelation: {randomness_metrics['max_autocorrelation']:.3f}")
        
        # Demonstrate encryption
        plaintext = b"AIDAS Protocol Demonstration Message"
        ciphertext = chaotic_map.encrypt_xor(plaintext)
        
        # Reset and decrypt
        chaotic_map.reset()
        decrypted = chaotic_map.decrypt_xor(ciphertext)
        
        print(f"\n🔐 XOR Encryption Test:")
        print(f"  Original:  {plaintext}")
        print(f"  Encrypted: {ciphertext.hex()[:32]}...")
        print(f"  Decrypted: {decrypted}")
        print(f"  Match: {'✅ YES' if plaintext == decrypted else '❌ NO'}")
        
        input("\nPress Enter to continue...")
    
    def demo_ai_intrusion_detection(self):
        """Demonstrate enhanced AI intrusion detection"""
        self.print_header("Enhanced AI Intrusion Detection Demo")
        
        detector = DQNIntrusionDetector()
        
        print("🤖 DQN Intrusion Detector Configuration:")
        print(f"  State dimension: {detector.state_dim}")
        print(f"  Action dimension: {detector.action_dim}")
        print(f"  Learning rate: {detector.learning_rate}")
        print(f"  Memory size: {len(detector.memory)}")
        
        # Test various network scenarios
        test_scenarios = {
            "Normal Operation": np.array([0.3, 0.1, 1.0, 0.2, 0.05, 0.3, 0.1, 0.0, 0.4, 0.3]),
            "High Traffic Load": np.array([0.8, 0.2, 1.0, 0.6, 0.15, 0.7, 0.2, 0.1, 0.8, 0.7]),
            "DDoS Attack": np.array([0.95, 0.1, 1.0, 0.9, 0.8, 0.9, 0.7, 0.9, 0.95, 0.9]),
            "Replay Attack": np.array([0.4, 0.9, 1.0, 0.6, 0.1, 0.7, 0.9, 0.8, 0.6, 0.5]),
            "Insider Threat": np.array([0.2, 0.3, 1.0, 0.8, 0.4, 0.6, 0.7, 0.7, 0.3, 0.4])
        }
        
        print(f"\n🛡️ Testing Threat Detection:")
        print(f"{'Scenario':<20} {'Action':<12} {'Posture':<15} {'Confidence':<12} {'Threat Level'}")
        print("-" * 75)
        
        for scenario_name, features in test_scenarios.items():
            result = detector.detect_intrusion(features)
            action_names = ["Baseline", "Monitor", "Multi-Factor", "Block"]
            
            print(f"{scenario_name:<20} {action_names[result['action']]:<12} "
                  f"{result['posture']['level']:<15} {result['confidence']:<12.3f} "
                  f"{result['posture']['threat_level']}")
        
        # Show detection statistics
        stats = detector.get_statistics()
        print(f"\n📊 Detection Statistics:")
        print(f"  Training steps: {stats['training_steps']}")
        print(f"  Detection accuracy: {stats['detection_accuracy']}")
        print(f"  False positive rate: {stats['false_positive_rate']}")
        
        input("\nPress Enter to continue...")
    
    def demo_protocol_simulation(self):
        """Demonstrate complete protocol simulation"""
        self.print_header("Complete Protocol Simulation Demo")
        
        # Initialize simulator
        self.simulator = AIDASimulator("DEMO_ESP")
        
        print("🏗️ Creating AIDAS ecosystem entities...")
        
        # Create entities
        bio_data = secrets.token_bytes(32)
        operator = self.simulator.create_operator("DEMO_OPERATOR", "SecurePass123!", bio_data)
        print(f"  ✅ Operator created: {operator.entity_id}")
        
        vehicle = self.simulator.create_vehicle("DEMO_VEHICLE_001")
        print(f"  ✅ Vehicle created: {vehicle.entity_id}")
        
        station = self.simulator.create_charging_station("DEMO_STATION_001", port_count=2)
        print(f"  ✅ Charging station created: {station.entity_id}")
        
        # Demonstrate authentication session
        print(f"\n🔐 Simulating authentication session...")
        
        session_result = self.simulator.simulate_authentication_session(
            operator.entity_id,
            vehicle.entity_id,
            station.entity_id
        )
        
        print(f"  Session ID: {session_result['session_id']}")
        print(f"  Success: {'✅ YES' if session_result['success'] else '❌ NO'}")
        print(f"  Total latency: {session_result['latency_ms']:.2f} ms")
        print(f"  Security posture: {session_result['security_posture']}")
        
        # Show phase breakdown
        if session_result['phases']:
            print(f"\n📋 Authentication Phases:")
            for phase_name, phase_data in session_result['phases'].items():
                status = "✅ SUCCESS" if phase_data['success'] else "❌ FAILED"
                print(f"  {phase_name}: {status} ({phase_data['latency_ms']:.1f}ms)")
        
        # Get system status
        system_status = self.simulator.get_system_status()
        print(f"\n📊 System Status:")
        print(f"  Total entities: {system_status['entity_counts']['total']}")
        print(f"  Active sessions: {system_status['active_sessions']}")
        print(f"  Success rate: {system_status['metrics']['successful_authentications']}/{system_status['metrics']['authentication_attempts']}")
        
        self.demo_entities = {
            'operator': operator,
            'vehicle': vehicle,
            'station': station
        }
        
        input("\nPress Enter to continue...")
    
    def demo_performance_evaluation(self):
        """Demonstrate performance evaluation"""
        if not self.simulator:
            print("⚠️ Simulator not initialized. Running protocol simulation first...")
            self.demo_protocol_simulation()
        
        self.print_header("Performance Evaluation Demo")
        
        print("🚀 Running performance evaluation with 25 authentication sessions...")
        
        # Setup monitoring
        self.simulator.setup_monitoring()
        
        # Run performance evaluation
        performance_report = self.simulator.run_performance_evaluation(
            num_sessions=25,
            create_test_entities=False  # Use existing entities
        )
        
        # Display key metrics
        perf = performance_report['protocol_performance']
        print(f"\n📈 Performance Results:")
        print(f"  Total sessions: {perf['total_sessions']}")
        print(f"  Success rate: {perf['success_rate']:.1f}%")
        print(f"  Average latency: {perf['average_latency_ms']:.2f} ms")
        print(f"  P95 latency: {perf['p95_latency_ms']:.2f} ms")
        print(f"  P99 latency: {perf['p99_latency_ms']:.2f} ms")
        
        # Security metrics
        sec = performance_report['security_metrics']
        print(f"\n🛡️ Security Metrics:")
        print(f"  Security incidents: {sec['security_incidents']}")
        print(f"  Blocked attempts: {sec['blocked_attempts']}")
        print(f"  Total entities: {sec['total_entities']}")
        
        print(f"\n💾 Performance report saved to file")
        
        input("\nPress Enter to continue...")
    
    def demo_advanced_features(self):
        """Demonstrate advanced features"""
        self.print_header("Advanced Features Demo")
        
        crypto = CryptographicEngine()
        
        print("🔐 Testing Advanced Cryptographic Operations:")
        
        # ECC keypair generation
        private_key, public_key = crypto.generate_ecc_keypair()
        print("  ✅ ECC keypair generated")
        
        # Hybrid encryption
        test_data = b"Confidential AIDAS protocol message for testing encryption"
        ephemeral_public, ciphertext, iv = crypto.encrypt_hybrid(public_key, test_data)
        decrypted = crypto.decrypt_hybrid(private_key, ephemeral_public, ciphertext, iv)
        
        print(f"  ✅ Hybrid encryption test: {'PASSED' if test_data == decrypted else 'FAILED'}")
        
        # Digital signatures
        signature = crypto.sign_data(private_key, test_data)
        signature_valid = crypto.verify_signature(public_key, signature, test_data)
        print(f"  ✅ Digital signature test: {'PASSED' if signature_valid else 'FAILED'}")
        
        # Key derivation
        shared_secret = crypto.generate_random_bytes(32)
        derived_key = crypto.derive_key(shared_secret, length=32)
        print(f"  ✅ Key derivation: {len(derived_key)} bytes generated")
        
        # Performance timing
        start_time = time.perf_counter()
        for _ in range(100):
            crypto.sha256_hash(test_data)
        hash_time = (time.perf_counter() - start_time) * 1000
        
        start_time = time.perf_counter()
        for _ in range(10):
            crypto.aes_encrypt(derived_key, test_data)
        encryption_time = (time.perf_counter() - start_time) * 10  # Per operation
        
        print(f"\n⚡ Performance Benchmarks:")
        print(f"  SHA-256 hashing: {hash_time:.2f} ms/100 ops")
        print(f"  AES encryption: {encryption_time:.2f} ms/10 ops")
        
        input("\nPress Enter to continue...")
    
    def demo_error_handling(self):
        """Demonstrate error handling and security features"""
        self.print_header("Error Handling & Security Demo")
        
        if not self.simulator:
            print("⚠️ Simulator not initialized")
            return
        
        print("🔒 Testing Security Features:")
        
        # Test account locking
        operator = self.demo_entities.get('operator')
        if operator:
            print(f"  Testing account locking for {operator.entity_id}")
            
            # Simulate failed attempts
            for i in range(4):  # Exceed max attempts
                valid = operator.verify_credentials("wrong_password", b"wrong_bio_data")
                print(f"    Attempt {i+1}: {'✅ Valid' if valid else '❌ Invalid'}")
            
            print(f"    Account locked: {'✅ YES' if operator.is_locked() else '❌ NO'}")
            
            # Unlock account
            operator.unlock_account()
            print(f"    Account unlocked: {'✅ YES' if not operator.is_locked() else '❌ NO'}")
        
        # Test session management
        print(f"\n📱 Testing Session Management:")
        active_sessions = self.simulator.active_sessions
        print(f"  Active sessions: {len(active_sessions)}")
        
        if active_sessions:
            session_id = list(active_sessions.keys())[0]
            success = self.simulator.end_session(session_id)
            print(f"  Session termination: {'✅ SUCCESS' if success else '❌ FAILED'}")
        
        # Test ESP statistics
        esp_stats = self.simulator.esp.get_authentication_statistics()
        print(f"\n📊 ESP Authentication Statistics:")
        print(f"  Success rate: {esp_stats['success_rate_percent']:.1f}%")
        print(f"  Total attempts: {esp_stats['authentication']['total_attempts']}")
        print(f"  Security incidents: {esp_stats['authentication']['security_incidents']}")
        
        input("\nPress Enter to continue...")
    
    def run_full_demo(self):
        """Run the complete demonstration"""
        print("🎯 Welcome to the complete AIDAS protocol demonstration!")
        print("This demo showcases the enhanced modular implementation.")
        
        input("\nPress Enter to start...")
        
        # Run all demo sections
        demo_sections = [
            ("Configuration Management", self.demo_configuration_system),
            ("Enhanced Logging", self.demo_enhanced_logging),
            ("Advanced PUF", self.demo_advanced_puf),
            ("Enhanced Chaotic Crypto", self.demo_enhanced_chaotic_crypto),
            ("AI Intrusion Detection", self.demo_ai_intrusion_detection),
            ("Protocol Simulation", self.demo_protocol_simulation),
            ("Performance Evaluation", self.demo_performance_evaluation),
            ("Advanced Features", self.demo_advanced_features),
            ("Error Handling & Security", self.demo_error_handling)
        ]
        
        for section_name, demo_function in demo_sections:
            try:
                demo_function()
            except KeyboardInterrupt:
                print(f"\n⏹️ Demo interrupted. Exiting...")
                break
            except Exception as e:
                logger.error(f"Error in {section_name}: {e}")
                print(f"❌ Error in {section_name}: {e}")
                input("Press Enter to continue with next section...")
        
        # Cleanup
        if self.simulator:
            self.simulator.shutdown()
        
        self.print_header("Demo Completed")
        print("🎉 Thank you for exploring the enhanced AIDAS protocol!")
        print("✨ All major features have been demonstrated successfully.")
        print("\n📚 For more information:")
        print("  • Check the logs/ directory for detailed logging output")
        print("  • Review generated performance reports")
        print("  • Explore the modular codebase in the aidas/ package")
        print("  • Read the comprehensive documentation")
    
    def run_interactive_menu(self):
        """Run interactive demo menu"""
        while True:
            self.print_header("AIDAS Protocol Interactive Demo Menu")
            print("1. 🎯 Run Full Demonstration")
            print("2. ⚙️  Configuration System Demo")
            print("3. 📝 Enhanced Logging Demo")
            print("4. 🔧 Advanced PUF Demo")
            print("5. 🌀 Enhanced Chaotic Crypto Demo")
            print("6. 🤖 AI Intrusion Detection Demo")
            print("7. 🔐 Protocol Simulation Demo")
            print("8. 🚀 Performance Evaluation Demo")
            print("9. ⚡ Advanced Features Demo")
            print("10. 🔒 Error Handling & Security Demo")
            print("11. ❌ Exit")
            
            try:
                choice = input("\nSelect an option (1-11): ").strip()
                
                if choice == "1":
                    self.run_full_demo()
                elif choice == "2":
                    self.demo_configuration_system()
                elif choice == "3":
                    self.demo_enhanced_logging()
                elif choice == "4":
                    self.demo_advanced_puf()
                elif choice == "5":
                    self.demo_enhanced_chaotic_crypto()
                elif choice == "6":
                    self.demo_ai_intrusion_detection()
                elif choice == "7":
                    self.demo_protocol_simulation()
                elif choice == "8":
                    self.demo_performance_evaluation()
                elif choice == "9":
                    self.demo_advanced_features()
                elif choice == "10":
                    self.demo_error_handling()
                elif choice == "11":
                    print("👋 Goodbye! Thank you for using the AIDAS demonstration.")
                    break
                else:
                    print("❌ Invalid choice. Please select 1-11.")
            
            except KeyboardInterrupt:
                print("\n👋 Exiting demo. Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                input("Press Enter to continue...")


def main():
    """Main function to run the demo"""
    try:
        demo = AIDASDemoRunner()
        demo.run_interactive_menu()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        logger.error(f"Fatal demo error: {e}")


if __name__ == "__main__":
    main()