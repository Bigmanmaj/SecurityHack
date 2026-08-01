"""Demo and adversary tooling.

Deliberately a package rather than loose scripts: the attack registry in
``attacks.py`` is imported by the tamper-matrix tests *and* by the web UI, so the
buttons a judge presses are the same mutations the test suite asserts on.
"""
