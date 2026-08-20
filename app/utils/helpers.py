"""
General helper utilities.
"""

from typing import Any


def safe_int(
    value: Any,
    default: int = 0,
) -> int:
    """
    Convert a value to int safely.

    Args:
        value:
            Value to convert.

        default:
            Value returned when conversion fails.

    Returns:
        Integer value or default.
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_str(
    value: Any,
    default: str = "",
) -> str:
    """
    Convert a value to string safely.
    """

    if value is None:
        return default

    return str(value)


def clamp(
    value: int | float,
    minimum: int | float,
    maximum: int | float,
) -> int | float:
    """
    Restrict a numeric value to a range.
    """

    return max(
        minimum,
        min(value, maximum),
    )