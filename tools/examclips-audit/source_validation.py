import math

def validate_duration(actual, expected, minimum=0, maximum=10800):
    if not math.isfinite(actual) or actual <= 0 or actual > maximum:
        raise ValueError('Actual source duration is invalid or exceeds the supported maximum')
    if actual < minimum:
        raise ValueError('Actual source duration is below the selected corpus minimum')
    if expected and abs(actual - expected) > max(2, expected * .005):
        raise ValueError('Downloaded duration does not match the complete public source')
