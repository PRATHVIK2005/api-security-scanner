import json

from scanner.models import ScanResult


def generate_json_report(
    result: ScanResult,
) -> str:
    """Convert a scan result into formatted JSON."""

    report = result.model_dump(
        mode="json",
    )

    return json.dumps(
        report,
        indent=2,
    )