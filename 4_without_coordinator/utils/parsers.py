def extract_service_name(context_text: str) -> str:
    """Safely extracts the service name under 'Project / Service Name' header."""
    lines = [line.strip() for line in context_text.splitlines()]
    for i, line in enumerate(lines):
        if "Project / Service Name" in line:
            for j in range(i + 1, len(lines)):
                if lines[j] and not lines[j].startswith("#"):
                    return lines[j]
    return "Unknown Service"
