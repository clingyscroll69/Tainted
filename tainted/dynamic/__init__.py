"""The Proof register — live execution.

A suspicion is not a finding. Candidates are confirmed by running the attack against the
owner's already-running app and observing the result. For the Supabase stack the request-plane
attack is a direct PostgREST query carrying account B's token.
"""

from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target

__all__ = ["Account", "ProveSetup", "RouteProber", "SeedRecord", "Target"]
