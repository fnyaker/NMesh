"""
How a list is filtered and paged. Once, for every list on the plane.

Three small decisions that were spread across one handler and are the same
wherever a table is asked for:

* **what a query matches** — any string this row carries, folded; a search box
  over a table means "show me the rows with this in them", not a field name the
  operator has to know;
* **how a page of *nodes* is cut** when the rows are *links* — a node may hold
  several, and taking rows in flat slices lets one node's links straddle a page
  boundary and show it twice, once with each half, under a heading that says
  nodes (`CLAUDE.md`: name the thing, then count the thing);
* **the bounds** — how long a query may be, how many rows a page may carry.

The bounds live here because two callers already share them: the operation that
answers the table and the HTTP door that still parses a query string for the
routes which have not moved yet.
"""
from __future__ import annotations

MAX_QUERY = 128
DEFAULT_LIMIT = 20
MAX_LIMIT = 100


def matches(item: dict, query: str) -> bool:
    """Does this row carry ``query`` anywhere a person would look?"""
    if not query:
        return True
    for value in item.values():
        if isinstance(value, str) and query in value.casefold():
            return True
        if isinstance(value, (list, tuple)):
            if any(isinstance(part, str) and query in part.casefold()
                   for part in value):
                return True
    return False


def page_by_node(links: list, offset: int, limit: int) -> tuple:
    """One page of *nodes*, carrying every link each of them holds.

    Returns ``(links_on_this_page, node_total)``. The node order is the order
    the links arrived in, so the caller's sort still decides it."""
    order, by_node = [], {}
    for link in links:
        bucket = by_node.get(link["id"])
        if bucket is None:
            bucket = by_node[link["id"]] = []
            order.append(link["id"])
        bucket.append(link)
    page = order[offset:offset + limit]
    return [link for node_id in page for link in by_node[node_id]], len(order)
