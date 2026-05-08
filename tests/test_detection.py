"""
Unit Tests for Detection Pipeline
==================================
Tests for feature extraction, ensemble prediction, RL agent, threat explainer, and API endpoints.
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_agent import extract_features, EnsemblePredictor, DQNAgent
from threat_explainer import ThreatExplainer


# ---------------------------------------------------------------------------
# Tests for extract_features
# ---------------------------------------------------------------------------

def test_extract_features_returns_none_for_non_ip_packet():
    """Test that extract_features returns None for non-IP packets."""
    # Create a mock packet without IP layer
    mock_packet = Mock()
    mock_packet.haslayer.return_value = False
    
    result = extract_features(mock_packet)
    assert result is None


def test_extract_features_returns_correct_fields_for_tcp_packet():
    """Test that extract_features returns correct protocol/port/flag fields for a mock TCP packet."""
    # Create a mock TCP packet
    mock_packet = Mock()
    mock_ip = Mock()
    mock_ip.src = "192.168.1.10"
    mock_ip.dst = "8.8.8.8"
    mock_ip.proto = 6  # TCP
    mock_packet.haslayer.return_value = True
    mock_packet.__getitem__ = Mock(side_effect=lambda x: mock_ip if x == 0 else Mock())
    
    mock_tcp = Mock()
    mock_tcp.sport = 12345
    mock_tcp.dport = 443
    mock_tcp.flags = "SA"
    mock_packet.haslayer.side_effect = lambda layer: layer == 0 or layer.__name__ == 'TCP'
    
    # Manually set the TCP layer
    mock_packet.__getitem__ = Mock(return_value=mock_ip)
    
    # For this test, we'll create a simpler mock that returns the expected structure
    from scapy.all import IP, TCP
    try:
        # Try to create a real packet if scapy is available
        packet = IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=443, flags="SA")
        feature_dict, numeric = extract_features(packet)
        
        assert feature_dict is not None
        assert feature_dict['protocol'] == 'TCP'
        assert feature_dict['sport'] == 12345
        assert feature_dict['dport'] == 443
        assert feature_dict['src_ip'] == '192.168.1.10'
        assert feature_dict['dst_ip'] == '8.8.8.8'
        assert numeric is not None
        assert numeric.shape == (1, 11)
    except ImportError:
        # If scapy is not available, skip this test
        pytest.skip("Scapy not available")


# ---------------------------------------------------------------------------
# Tests for EnsemblePredictor
# ---------------------------------------------------------------------------

def test_ensemble_predictor_predict_returns_tuple_with_prediction_in_range():
    """Test that EnsemblePredictor.predict returns (int, float) with prediction in {0,1}."""
    predictor = EnsemblePredictor()
    
    # Create a mock feature vector (11 features)
    numeric_features = np.array([
        6,      # proto_num (TCP)
        12345,  # sport
        443,    # dport
        512,    # pkt_size
        1,      # is_src_private
        0,      # is_dst_private
        0,      # has_syn
        0,      # has_fin
        0,      # has_rst
        0,      # port_is_suspicious
        1,      # port_is_well_known
    ], dtype=np.float64).reshape(1, -1)
    
    prediction, confidence = predictor.predict(numeric_features)
    
    assert isinstance(prediction, int)
    assert prediction in {0, 1}
    assert isinstance(confidence, float)
    assert 0.0 <= confidence <= 1.0


# ---------------------------------------------------------------------------
# Tests for DQNAgent
# ---------------------------------------------------------------------------

def test_dqn_agent_choose_action_returns_valid_action():
    """Test that DQNAgent.choose_action returns a value in ['allow', 'block']."""
    agent = DQNAgent()
    
    # Create a mock state tuple
    state_tuple = ("syn_scan", "external_to_internal", "TCP", "suspicious", "high", "normal", "S")
    
    action, was_exploration = agent.choose_action(state_tuple)
    
    assert action in ["allow", "block"]
    assert isinstance(was_exploration, bool)


def test_dqn_agent_update_does_not_raise_and_increments_total_decisions():
    """Test that DQNAgent.update does not raise and increments total_decisions."""
    agent = DQNAgent()
    initial_decisions = agent.total_decisions
    
    state_tuple = ("syn_scan", "external_to_internal", "TCP", "suspicious", "high", "normal", "S")
    
    # Should not raise
    agent.update(state_tuple, "block", 1.0)
    
    assert agent.total_decisions == initial_decisions + 1


# ---------------------------------------------------------------------------
# Tests for ThreatExplainer
# ---------------------------------------------------------------------------

def test_threat_explainer_cache_hit_skips_api_call():
    """Test that ThreatExplainer cache hit skips the API call (mock the Anthropic client)."""
    explainer = ThreatExplainer()
    
    detection = {
        'src_ip': '192.168.1.10',
        'dst_ip': '8.8.8.8',
        'protocol': 'TCP',
        'sport': 12345,
        'dport': 443,
        'size': 512,
        'flags': 'SA',
        'reason': 'syn_scan',
        'rf_confidence': 0.85,
        'rl_action': 'block',
        'severity': 'High',
    }
    
    # First call should hit the API (or return placeholder if no key)
    explanation1 = explainer.explain(detection)
    
    # Second call with same detection should hit cache
    explanation2 = explainer.explain(detection)
    
    # Both should return the same explanation (from cache)
    assert explanation1 == explanation2
    
    # Cache stats should show 1 entry
    stats = explainer.get_cache_stats()
    assert stats['cache_size'] == 1


# ---------------------------------------------------------------------------
# Tests for Flask API endpoints
# ---------------------------------------------------------------------------

def test_api_auth_login_returns_200_with_valid_credentials():
    """Test that /api/auth/login returns 200 with valid credentials using Flask test client."""
    # Import app here to avoid import issues
    from app import app
    
    with app.test_client() as client:
        # Register a test user first
        client.post('/api/auth/register', json={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        
        # Login with valid credentials
        response = client.post('/api/auth/login', json={
            'username': 'testuser',
            'password': 'testpass123'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert 'user' in data


def test_api_explain_returns_400_if_payload_missing_required_fields():
    """Test that /api/explain returns 400 if payload is missing required fields."""
    from app import app
    
    with app.test_client() as client:
        # First login to get token
        register_response = client.post('/api/auth/register', json={
            'username': 'testuser2',
            'email': 'test2@example.com',
            'password': 'testpass123'
        })
        
        login_response = client.post('/api/auth/login', json={
            'username': 'testuser2',
            'password': 'testpass123'
        })
        token = login_response.get_json()['access_token']
        
        # Test with missing required fields
        response = client.post('/api/explain',
            json={'src_ip': '192.168.1.10'},  # Missing required fields
            headers={'Authorization': f'Bearer {token}'}
        )
        
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
