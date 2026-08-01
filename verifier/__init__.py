"""Independent verifier for flightrec bundles.

Written from SPEC.md alone. This package must never import `flightrec`: two
implementations that share code prove nothing about the format. Standard
library plus `dilithium_py`, and nothing else.
"""
