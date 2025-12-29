import warnings

# Silence ResourceWarning noise from sqlite connections during test runs.
warnings.simplefilter("ignore", ResourceWarning)
