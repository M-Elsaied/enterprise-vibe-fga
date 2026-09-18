"""OpenFgaAuthorizer that lets neuro-san temporary (reservation) networks through.

THE PROBLEM: neuro-san checks authorization BEFORE it looks a temporary network
up in the reservations storage (base_request_handler.get_service: allow_agent
first, 403 on deny, reservation lookup only after). A reservation has no tuples
by design - it is evicted on a timer and its scope is decided at promotion - so
the stock authorizer denies it (even for a super admin) and the reservation
branch is never reached. Symptom: the network is listed and downloadable in the
UI but opening it fails with 403 on connectivity/function.

THE FIX: answer "allow" locally for reservation names and send everything else
to OpenFGA unchanged. Reservation names are "<prefix>-<uuid4>" and
AgentReservation.is_reservation_name is the library's own detector, so this can
never drift from how names are minted, and a permanent network can never match.
No tuple is written or read for a reservation; OpenFGA is not contacted at all.

Trust boundary: on the server nothing ties a reservation to its creator - what
protects it is the unguessable UUIDv4, the short lifetime, and the SSO proxy in
front. This matches neuro-san's own design for temporary networks.

Wire-in (only the value of the existing variable changes):
    AGENT_AUTHORIZER=authz.enforcement.reservation_aware_authorizer.ReservationAwareOpenFgaAuthorizer
The module must be importable by the server (PYTHONPATH / installed package).
The promotion strategy must never mint a permanent name ending in a UUIDv4.
"""

from typing import Any, Dict

from neuro_san.internals.authorization.openfga.open_fga_authorizer import OpenFgaAuthorizer
from neuro_san.internals.reservations.agent_reservation import AgentReservation


class ReservationAwareOpenFgaAuthorizer(OpenFgaAuthorizer):
    """Stock OpenFGA authorizer plus a local allow for reservation names."""

    async def authorize(self, actor: Dict[str, Any], action: str,
                        resource: Dict[str, Any]) -> bool:
        if AgentReservation.is_reservation_name(resource.get("id")):
            return True
        return await super().authorize(actor, action, resource)
