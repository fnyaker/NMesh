"""The core, split into the parts it is made of.

`MeshNode` was one 12,000-line class in `node.py`. It is still the same class —
same methods, same behaviour, same public surface — but its state is now
distributed over mixins that each own one subject, and `MeshNode` composes
them. Nothing here needs to know about the others beyond the attributes it
touches on `self`, which is what a mixin is.

The grouping is by *what a method is about*, not by when it was written: a
link's keepalive sits with the keepalive, hole punching with hole punching,
and the console's hundred entry points with the console. Where a subject is
large enough to have its own invariants (the wire, the bounds, a link) it is a
plain module rather than a mixin, because it needs no node to be tested.
"""
