"""Input sanitization helpers."""

import bleach


def sanitize_string(value: str) -> str:
    """Strip HTML/script tags from user input."""
    if not value:
        return value
    return bleach.clean(value, tags=[], attributes={}, strip=True).strip()
