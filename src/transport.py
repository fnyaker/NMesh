from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine
from typing import Any, TYPE_CHECKING

from .packet import Packet

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Transport settings — one shape, so every medium is configurable for free
# ---------------------------------------------------------------------------
# A transport declares what it takes; the coercion, the bounds, the refusal
# messages and the rendering are written once, here and in the console. Adding a
# setting to a transport is one line in its ``OPTIONS``; adding a *transport*
# costs the console nothing at all.

KINDS = ("bool", "int", "float", "text", "choice", "multi")

MAX_TEXT = 255
MAX_MULTI = 16
MAX_OPTIONS = 24          # per transport, so a declaration cannot be a payload


class OptionError(Exception):
    """A value a transport will not take, phrased for whoever typed it."""


def option(name: str, kind: str, default, help: str, *, label: str = "",
           choices=None, minimum=None, maximum=None, unit: str = "",
           placeholder: str = "", restart: bool = False) -> dict:
    """Declare one setting.

    ``restart`` marks a value the running process cannot pick up — it is stored
    and applied at the next start. Saying so is the difference between a setting
    that looks broken and one that is simply not live yet."""
    if kind not in KINDS:
        raise OptionError(f"unknown kind {kind!r}")
    return {
        "name": name, "kind": kind, "default": default, "help": help,
        "label": label or name.replace("_", " "),
        "choices": [dict(entry) for entry in (choices or [])],
        "min": minimum, "max": maximum, "unit": unit,
        "placeholder": placeholder, "restart": bool(restart),
    }


def coerce(field: dict, raw):
    """Turn one submitted value into the type the field declares.

    Raises :class:`OptionError` with a sentence a human can act on. Every
    transport gets this for free — a medium that had to validate its own fields
    would be a medium that validates them slightly differently."""
    kind = field["kind"]
    if kind == "bool":
        if isinstance(raw, bool):
            return raw
        text = str(raw).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off", ""):
            return False
        raise OptionError("expected yes or no")
    if kind in ("int", "float"):
        try:
            value = int(raw) if kind == "int" else float(raw)
        except (TypeError, ValueError):
            raise OptionError("expected a number") from None
        if value != value or value in (float("inf"), float("-inf")):
            raise OptionError("expected a number")
        low, high = field.get("min"), field.get("max")
        if low is not None and value < low:
            raise OptionError(f"must be at least {low}")
        if high is not None and value > high:
            raise OptionError(f"must be at most {high}")
        return value
    if kind == "text":
        text = "" if raw is None else str(raw).strip()
        if len(text) > MAX_TEXT:
            raise OptionError(f"longer than {MAX_TEXT} characters")
        if "\n" in text or "\r" in text:
            raise OptionError("must be a single line")
        return text
    if kind == "choice":
        allowed = [entry["value"] for entry in field.get("choices") or []]
        if raw not in allowed:
            raise OptionError("not one of the offered values")
        return raw
    if kind == "multi":
        if isinstance(raw, str):
            raw = [part.strip() for part in raw.split(",") if part.strip()]
        if not isinstance(raw, (list, tuple)):
            raise OptionError("expected a list")
        if len(raw) > MAX_MULTI:
            raise OptionError(f"more than {MAX_MULTI} entries")
        allowed = [entry["value"] for entry in field.get("choices") or []]
        chosen = []
        for entry in raw:
            if entry not in allowed:
                raise OptionError("not one of the offered values")
            if entry not in chosen:
                chosen.append(entry)
        return chosen
    raise OptionError("unsupported setting")


def as_text(field: dict, value) -> str:
    """One value, written the way the configuration file spells it."""
    if field["kind"] == "bool":
        return "true" if value else "false"
    if field["kind"] == "multi":
        return ",".join(str(entry) for entry in (value or []))
    return "" if value is None else str(value)


class BaseTransport(ABC):
    """
    Represents a single bidirectional connection between two nodes.

    One instance = one link. The transport is responsible for:
    - Framing (delimiting packet boundaries on stream protocols like TCP)
    - Serialisation of Packet objects to bytes and back

    It knows nothing about routing, encryption, or the mesh protocol.
    """

    def __init__(self) -> None:
        self.on_connect: Callable[[], Coroutine[Any, Any, None]] | None = None

    @abstractmethod
    async def connect(self, address: str) -> None:
        """Open an outgoing connection to the given address."""
        ...

    @abstractmethod
    async def listen(self, address: str) -> None:
        """Listen on the given address and accept exactly one incoming connection.
        Blocks until a client connects."""
        ...

    @abstractmethod
    async def send(self, packet: Packet) -> None:
        """Send a packet over this connection."""
        ...

    @abstractmethod
    async def receive(self) -> Packet:
        """Block until a packet is received and return it."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close this connection and release resources."""
        ...

    def remote_ip(self) -> str | None:
        """The peer's source IP as observed locally, if the medium exposes one.

        Lets a node learn its own public address from a peer that accepted its
        connection (mesh-native public-IP discovery). Media without a network
        address (e.g. spool files) return None."""
        return None

    # -- observability ----------------------------------------------------
    # Two optional hooks, both with the same shape as ``reachability``: the
    # medium describes itself, the core never interprets. A new transport
    # becomes observable in the console without a line of console code.

    def endpoints(self) -> dict:
        """Where this link actually runs: ``{"local": str|None,
        "remote": str|None}``.

        Not the URI that was dialled — the endpoint as the medium sees it now.
        For an *accepted* link that is the only address there is, and it is what
        tells an operator which of a peer's addresses is carrying traffic."""
        return {"local": None, "remote": None}

    # -- settings ---------------------------------------------------------

    #: Declared with :func:`option`. Empty means "nothing to configure", which
    #: is a perfectly good answer.
    OPTIONS: tuple = ()
    #: Current values, by name. Class-level: a setting belongs to the medium,
    #: not to one link.
    SETTINGS: dict = {}

    @classmethod
    def options(cls) -> list[dict]:
        """The declaration, with the values in force right now."""
        out = []
        for field in cls.OPTIONS[:MAX_OPTIONS]:
            entry = dict(field)
            entry["value"] = cls.SETTINGS.get(field["name"], field["default"])
            out.append(entry)
        return out

    @classmethod
    def configure(cls, values: dict) -> dict:
        """Apply what is valid, refuse the rest, and say which was which.

        Partial application on purpose: one bad field should not throw away the
        four good ones typed with it."""
        fields = {field["name"]: field for field in cls.OPTIONS}
        applied, rejected = {}, {}
        for name, raw in (values or {}).items():
            field = fields.get(name)
            if field is None:
                rejected[str(name)[:64]] = "unknown setting"
                continue
            try:
                applied[name] = coerce(field, raw)
            except OptionError as exc:
                rejected[name] = str(exc)
        if applied:
            # Replaced, never mutated in place: a class attribute shared by
            # instances is not a place to edit under a live link.
            cls.SETTINGS = dict(cls.SETTINGS, **applied)
        return {"applied": applied, "rejected": rejected}

    @classmethod
    def setting(cls, name: str):
        """The value in force, falling back to the declared default."""
        if name in cls.SETTINGS:
            return cls.SETTINGS[name]
        for field in cls.OPTIONS:
            if field["name"] == name:
                return field["default"]
        return None

    def stats(self) -> dict:
        """Live counters this medium can report about *this* link.

        Free-form on purpose: a UDP link has retransmits and a reorder buffer, a
        serial link has a baud rate, a LoRa link has an SNR. Keys are rendered
        as-is, so pick names a human can read.

        Two rules, because this is polled by the console: values must be
        JSON-safe scalars, and reading them must never block or allocate
        anything of significance."""
        return {}


class BaseServer(ABC):
    """
    Server-side transport: listens and accepts multiple incoming connections.

    One instance = one listening endpoint that spawns a new BaseTransport
    per accepted client. The server calls on_new_connection(transport) for
    each incoming connection.

    Implement this alongside BaseTransport to make your protocol fully
    pluggable with MeshNode.
    """

    def __init__(self) -> None:
        self.on_new_connection: (
            Callable[['BaseTransport'], Coroutine[Any, Any, None]] | None
        ) = None

    @abstractmethod
    async def listen(self, address: str) -> None:
        """Bind to the given address and start accepting connections.
        Returns immediately after binding (non-blocking)."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Stop accepting connections and release resources."""
        ...

    def reachability(self, uri: str, ctx: dict) -> list[dict]:
        """Describe how this server can be reached, and by which audience.

        Transport-agnostic: the core never classifies addresses itself — each
        transport reports its own reachability descriptors. A descriptor is::

            {"transport": scheme, "scope": "world"|"lan"|"broadcast"|"none",
             "anchor": str, "address": uri|None, "confirmed": bool}

        ``scope`` is the audience breadth; ``anchor`` distinguishes two audiences
        of the same breadth (e.g. a LAN ``192.168.0.0/24`` is anchored by the
        public IP it sits behind, so it is not the neighbour's identical range).
        ``uri`` is this listener's URI; ``ctx`` carries node-level discovered
        facts (see ``MeshNode._reachability_ctx``). Default: nothing known."""
        return []

    async def broadcast(self, data: bytes) -> bool:
        """Send *data* to every reachable peer on this medium at once, if the
        transport supports it (LAN UDP, BLE advertising, LoRa…). Used for
        opportunistic discovery when no relay is configured. Returns True if
        the transport actually broadcast. Default: not broadcast-capable."""
        return False
