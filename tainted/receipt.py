"""A signed receipt for one run: what was fired, what worked, and what was never tried.

A security report is read by someone deciding whether to trust software they did not write — a
customer, an acquirer, a reviewer. What they are handed today is a PDF asserting that a test
happened. They cannot check it, and it does not say what was skipped, so the most important
sentence in any security report is the one nobody writes: *here is what we did not look at.*

Tainted already computes that sentence. The coverage ledger records every plane cleared, every
check proof did not reach, and why. This module turns it into an artifact someone else can verify:
a canonical, machine-readable statement covering both halves of the run, with an HMAC over the
whole thing.

The point is **what the signature covers**. Signing only the findings would leave the silence
editable — a report could drop the "account B never authenticated, so nothing was fired at the
request plane" line and still verify. Here the negative space is inside the signed payload, so
removing it breaks the signature. You cannot quietly publish the good half.

What this is not: proof that the run was honest, or that Tainted is correct. It proves that the
holder of the key attested to *this exact set of claims, including the admissions*, and that
nobody edited them afterwards. That is a narrow guarantee, stated narrowly on the receipt itself,
because the alternative is a trust badge that means less than it appears to.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from tainted.report.enrich import silence_ledger
from tainted.report.model import Report
from tainted.standards import CATALOGUES

RECEIPT_VERSION = "tainted-receipt/1"

_SCOPE_STATEMENT = (
    "This receipt attests that the holder of the signing key published these claims, including "
    "the untested surface recorded under `not_tested`, and that they have not been altered since. "
    "It does not attest that the application is secure, that Tainted is correct, or that anything "
    "outside `fired` was examined."
)


@dataclass
class Receipt:
    """One run's claims, in the form they get signed in."""

    repo_path: str
    fired: list[dict] = field(default_factory=list)
    not_tested: dict = field(default_factory=dict)
    catalogues: dict = field(default_factory=lambda: dict(CATALOGUES))
    version: str = RECEIPT_VERSION

    def payload(self) -> dict:
        """The exact object the signature covers.

        `not_tested` sits inside it deliberately. A receipt whose signature covered only the
        findings could have its admissions deleted and still verify, which would make the
        signature worse than none — it would authenticate a half-truth.
        """
        return {
            "version": self.version,
            "repo": self.repo_path,
            "fired": self.fired,
            "not_tested": self.not_tested,
            "catalogues": self.catalogues,
            "scope": _SCOPE_STATEMENT,
        }

    def canonical(self) -> str:
        """A stable serialization — sorted keys, no incidental whitespace."""
        return json.dumps(self.payload(), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """A content hash, so a receipt can be referenced without being reproduced in full."""
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def as_dict(self, signature: Optional[str] = None) -> dict:
        out: dict[str, Any] = dict(self.payload())
        out["digest"] = self.digest()
        if signature is not None:
            out["signature"] = signature
        return out


def build_receipt(report: Report) -> Receipt:
    """Gather one run's claims — the attacks that fired and the surface that was not touched.

    Only findings where an attack actually ran appear under `fired`, each with the outcome. A
    static suspicion is not an attack and would inflate the positive half of the receipt, which is
    the half a reader is inclined to trust least and check most.
    """
    fired: list[dict] = []
    for f in report.findings:
        proof = f.proof
        executed = bool(proof and proof.exploit and proof.exploit.executed)
        if not executed:
            continue
        fired.append(
            {
                "id": f.candidate.id,
                "check": f.check.value,
                "title": f.candidate.title,
                "location": str(f.candidate.location),
                "status": f.status.value,
                "succeeded": bool(proof and proof.succeeded),
                "response_status": proof.response_status if proof else None,
            }
        )
    fired.sort(key=lambda r: r["id"])
    return Receipt(
        repo_path=report.repo_path,
        fired=fired,
        not_tested=silence_ledger(report),
    )


def sign(receipt: Receipt, secret: bytes) -> str:
    """HMAC-SHA256 over the canonical payload. Returns a hex signature."""
    return hmac.new(secret, receipt.canonical().encode("utf-8"), hashlib.sha256).hexdigest()


def verify(receipt: Receipt, signature: str, secret: bytes) -> bool:
    """Whether `signature` is this receipt's, under `secret`. Constant-time."""
    return hmac.compare_digest(sign(receipt, secret), signature)


def verify_payload(payload: dict, signature: str, secret: bytes) -> bool:
    """Verify a receipt received as plain JSON, without trusting its own digest field.

    A third party holds a document, not a `Receipt`. Rebuilding the object from the payload's own
    fields is what makes the check meaningful: the signature is recomputed over the content as
    received, so an edited `fired` list or a deleted `not_tested` section fails here rather than
    being waved through by a `digest` the editor also rewrote.
    """
    rebuilt = Receipt(
        repo_path=str(payload.get("repo", "")),
        fired=list(payload.get("fired") or []),
        not_tested=dict(payload.get("not_tested") or {}),
        catalogues=dict(payload.get("catalogues") or {}),
        version=str(payload.get("version", RECEIPT_VERSION)),
    )
    return verify(rebuilt, signature, secret)
