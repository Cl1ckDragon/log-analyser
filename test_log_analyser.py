import pytest
from main import extract_ips, count_ips, detect_suspicious

# Sample log lines
sample_logs = [
    "Jan 01 12:00:01 server sshd[123]: Failed login for user root from 192.168.1.10",
    "Jan 01 12:01:05 server sshd[124]: Failed login for user admin from 192.168.1.20",
    "Jan 01 12:02:10 server sshd[125]: Failed login for user root from 192.168.1.10",
    "Jan 01 12:03:15 server sshd[126]: Failed login for user admin from 192.168.1.30",
    "Jan 01 12:04:20 server sshd[127]: Failed login for user root from 192.168.1.10"
]

def test_extract_ips():
    ips = extract_ips(sample_logs)
    assert ips == ["192.168.1.10", "192.168.1.20", "192.168.1.10", "192.168.1.30", "192.168.1.10"]

def test_count_ips():
    ips = ["192.168.1.10", "192.168.1.20", "192.168.1.10", "192.168.1.30", "192.168.1.10"]
    ip_count = count_ips(ips)
    assert ip_count == {
        "192.168.1.10": 3,
        "192.168.1.20": 1,
        "192.168.1.30": 1
    }

def test_detect_suspicious(capfd):
    ip_count = {
        "192.168.1.10": 3,
        "192.168.1.20": 1,
        "192.168.1.30": 2
    }
    detect_suspicious(ip_count, threshold=3)
    out, err = capfd.readouterr()
    assert "192.168.1.10 (3 attempts)" in out
    assert "No suspicious activity detected!" not in out

def test_detect_suspicious_no_matches(capfd):
    ip_count = {
        "192.168.1.10": 2,
        "192.168.1.20": 1
    }
    detect_suspicious(ip_count, threshold=3)
    out, err = capfd.readouterr()
    assert "No suspicious activity detected!" in out