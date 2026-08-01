"""Flight recorder: canonicalization, hashing, forward-secure ratchet, append, seal.

Knows nothing about agents.
"""

from .recorder import Recorder, RecorderError, genesis_payload, new_episode_id

__all__ = ["Recorder", "RecorderError", "genesis_payload", "new_episode_id"]
