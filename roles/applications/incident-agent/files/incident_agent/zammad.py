"""Zammad REST client.

Same auth and request shape as monitoring/files/zammad_relay.py, which has
been in production against this instance -- deliberately not a different
approach for the same API. urllib rather than requests keeps this dependency-
light, matching the relay.

Every endpoint used here was verified against the live instance before being
relied on, including the link paths (Zammad's links API is /links/add and
/links/remove, NOT the /links/list that a reasonable person would guess -- that
404s).
"""
import json
import urllib.error
import urllib.parse
import urllib.request

from . import config


class ZammadError(RuntimeError):
    pass


def request(method, path, data=None, timeout=20):
    url = f"{config.ZAMMAD_URL}{path}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Token token={config.ZAMMAD_API_TOKEN}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raise ZammadError(f"{method} {path} -> HTTP {e.code}: {e.read()[:300].decode(errors='replace')}") from e
    except urllib.error.URLError as e:
        raise ZammadError(f"{method} {path} -> {e.reason}") from e


def get_ticket(ticket_id):
    return request("GET", f"/api/v1/tickets/{ticket_id}")


def add_article(ticket_id, subject, body, internal=True):
    """Post a note. Internal by default -- diagnostic dumps are for whoever
    works the ticket, not for a customer-facing thread."""
    return request(
        "PUT",
        f"/api/v1/tickets/{ticket_id}",
        {"article": {"subject": subject[:200], "body": body, "type": "note", "internal": internal}},
    )


def close_ticket(ticket_id, subject, body, internal=False):
    return request(
        "PUT",
        f"/api/v1/tickets/{ticket_id}",
        {
            "state": "closed",
            "article": {"subject": subject[:200], "body": body, "type": "note", "internal": internal},
        },
    )


def create_ticket(title, body, internal=False):
    return request(
        "POST",
        "/api/v1/tickets",
        {
            "title": title[:200],
            "group": config.ZAMMAD_GROUP,
            "customer": config.ZAMMAD_CUSTOMER_EMAIL,
            "article": {"subject": title[:200], "body": body, "type": "note", "internal": internal},
        },
    )


def get_tags(ticket_id):
    result = request("GET", f"/api/v1/tags?object=Ticket&o_id={ticket_id}")
    return (result or {}).get("tags", [])


def add_tag(ticket_id, tag):
    q = urllib.parse.urlencode({"object": "Ticket", "o_id": ticket_id, "item": tag})
    return request("POST", f"/api/v1/tags/add?{q}")


def remove_tag(ticket_id, tag):
    q = urllib.parse.urlencode({"object": "Ticket", "o_id": ticket_id, "item": tag})
    return request("DELETE", f"/api/v1/tags/remove?{q}")


def get_links(ticket_id):
    result = request("GET", f"/api/v1/links?link_object=Ticket&link_object_value={ticket_id}")
    return (result or {}).get("links", [])


def link_tickets(source_number, target_id, link_type="normal"):
    """Link two tickets.

    Note the asymmetry, which is Zammad's own and not a mistake here: the
    target is identified by ticket *id*, the source by ticket *number*. Passing
    an id as the source silently fails to link anything.
    """
    return request(
        "POST",
        "/api/v1/links/add",
        {
            "link_type": link_type,
            "link_object_target": "Ticket",
            "link_object_target_value": target_id,
            "link_object_source": "Ticket",
            "link_object_source_number": str(source_number),
        },
    )


def search(query, limit=25):
    result = request("GET", f"/api/v1/tickets/search?query={urllib.parse.quote(query)}&limit={limit}")
    # This endpoint returns a bare list of ticket objects rather than
    # {"tickets": [...]}, and matches loosely -- callers must filter.
    return result or []


def is_open(ticket):
    """Zammad state_id 4 = closed, 5 = merged."""
    return ticket.get("state_id") not in (4, 5)
