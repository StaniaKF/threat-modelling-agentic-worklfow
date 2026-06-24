def extract_service_name(context_text: str) -> str:
    """Safely extracts the service name under 'Project / Service Name' header."""
    lines = [line.strip() for line in context_text.splitlines()]
    for i, line in enumerate(lines):
        if "Project / Service Name" in line:
            for candidate_name in lines[i + 1 :]:
                if candidate_name and not candidate_name.startswith("#"):
                    return candidate_name
    return "Unknown Service"
