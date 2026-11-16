import pytest

from robusta_krr.core.models.result import Result


def _scan(memory_request_severity: str) -> dict:
    return {
        "object": {
            "cluster": "mock-cluster",
            "name": "mock-object",
            "container": "mock-container",
            "pods": [],
            "hpa": None,
            "namespace": "default",
            "kind": "Deployment",
            "allocations": {"requests": {}, "limits": {}, "info": {}},
            "warnings": [],
        },
        "recommended": {
            "requests": {
                "cpu": {"value": "?", "severity": "UNKNOWN"},
                "memory": {"value": "?", "severity": memory_request_severity},
            },
            "limits": {
                "cpu": {"value": "?", "severity": "UNKNOWN"},
                "memory": {"value": "?", "severity": "CRITICAL"},
            },
            "info": {},
        },
        "severity": memory_request_severity,
    }


def _score(*severities: str) -> int:
    return Result(
        scans=[_scan(s) for s in severities],
        strategy={"name": "simple", "settings": {}},
        config=None,
    ).score


@pytest.mark.parametrize(
    "severities, expected",
    [
        ((), 100),
        (("GOOD",), 100),
        (("CRITICAL",), 0),
        (("GOOD", "CRITICAL"), 50),
        (("OK", "WARNING"), 50),
        # UNKNOWN containers are excluded rather than counted as perfect
        (("CRITICAL", "UNKNOWN", "UNKNOWN"), 0),
        (("UNKNOWN", "UNKNOWN"), 100),
    ],
)
def test_score_uses_memory_request_severity(severities: tuple, expected: int) -> None:
    assert _score(*severities) == expected
