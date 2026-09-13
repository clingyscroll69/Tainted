"""A FastAPI surface with one unscoped read."""

from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/tickets/{ticket_id}")
async def read_ticket(ticket_id: str, session=Depends(get_session)):
    # VULNERABLE: no caller identity anywhere, no owner predicate.
    ticket = session.query(Ticket).filter(Ticket.id == ticket_id).first()
    return ticket
