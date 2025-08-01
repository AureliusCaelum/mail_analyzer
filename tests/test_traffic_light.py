"""
Test-Suite für das Traffic Light System
"""
import pytest
from analyzer.traffic_light import TrafficLight
from config.settings import THREAT_LEVELS

@pytest.fixture
def traffic_light():
    return TrafficLight()

def test_display_threat_level(traffic_light):
    """Test der Bedrohungslevel-Anzeige"""
    test_analysis = {
        "level": THREAT_LEVELS["LOW"],
        "score": 2,
        "indicators": ["Test Indikator"]
    }

    result = traffic_light.display_threat_level(test_analysis)
    assert isinstance(result, str), "Ausgabe sollte ein String sein"
    assert "Bedrohungslevel" in result, "Ausgabe sollte Bedrohungslevel enthalten"
    assert "Score" in result, "Ausgabe sollte Score enthalten"

def test_get_recommendation(traffic_light):
    """Test der Handlungsempfehlungen"""
    # Test für hohes Risiko
    high_risk = {"level": THREAT_LEVELS["HIGH"]}
    high_recommendation = traffic_light.get_recommendation(high_risk)
    assert "WARNUNG" in high_recommendation

    # Test für mittleres Risiko
    medium_risk = {"level": THREAT_LEVELS["MEDIUM"]}
    medium_recommendation = traffic_light.get_recommendation(medium_risk)
    assert "VORSICHT" in medium_recommendation

    # Test für niedriges Risiko
    low_risk = {"level": THREAT_LEVELS["LOW"]}
    low_recommendation = traffic_light.get_recommendation(low_risk)
    assert "INFO" in low_recommendation
