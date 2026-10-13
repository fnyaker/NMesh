/**
 * What a peer puts in front of a node, declared to CodeQL as remote input.
 *
 * The standard Python models know HTTP servers, and the console's three are
 * covered by them. The mesh is not: its bytes arrive through asyncio
 * protocols and streams, a spool directory and handlers reached through a
 * dispatch table, none of which the library models. Without these, CodeQL
 * would see none of what the threat model calls hostile.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources

private predicate inTree(AstNode n) {
  n.getLocation().getFile().getRelativePath().matches("src/%")
}

private DataFlow::ParameterNode nthParameter(Function f, int i) {
  result.getParameter() = f.getArg(i)
}

/** Raw bytes off a socket: what an asyncio protocol is handed. */
class WireDatagram extends RemoteFlowSource::Range, DataFlow::ParameterNode {
  WireDatagram() {
    exists(Function f |
      f.getName() in ["datagram_received", "data_received"] and
      inTree(f) and
      this = nthParameter(f, 1)
    )
  }

  override string getSourceType() { result = "bytes from a socket" }
}

/** Raw bytes off a stream: what a reader hands back. */
class WireStream extends RemoteFlowSource::Range, DataFlow::MethodCallNode {
  WireStream() {
    inTree(this.asExpr()) and
    (
      this.getMethodName() in ["readexactly", "readuntil"]
      or
      this.getMethodName() = "read" and
      this.getObject().asExpr().(Attribute).getName().matches("%reader%")
    )
  }

  override string getSourceType() { result = "bytes from a stream" }
}

/** A frame left in a spool directory by whoever carried the medium. */
class SpoolFrame extends RemoteFlowSource::Range, DataFlow::MethodCallNode {
  SpoolFrame() {
    this.getMethodName() = "read" and
    this.asExpr().getLocation().getFile().getRelativePath() = "src/transports/spool.py"
  }

  override string getSourceType() { result = "a spooled frame" }
}

/**
 * What a peer sent an app or the core, at the handler it is dispatched to.
 *
 * Handlers are found through tables (`_HANDLERS[kind]`) the call graph does
 * not follow, so the dispatcher's input does not reach them as flow; they are
 * declared by the convention the tree keeps: `_on_*(self, src, …)` in an app,
 * `_handle_*(self, peer, packet)` in the core, `_dispatch(self, src, payload)`.
 */
class PeerMessage extends RemoteFlowSource::Range, DataFlow::ParameterNode {
  PeerMessage() {
    exists(Function f, int i |
      inTree(f) and
      this = nthParameter(f, i) and
      i >= 2 and
      (
        f.getName().matches("\\_on\\_%") and
        f.getArgName(1) = "src" and
        f.getArgName(i) in ["document", "body", "payload", "raw", "data"]
        or
        f.getName().matches("\\_handle\\_%") and
        f.getArgName(1) = "peer" and
        f.getArgName(i) = "packet"
        or
        f.getName() = "_dispatch" and
        f.getArgName(1) = "src" and
        f.getArgName(i) = "payload"
      )
    )
  }

  override string getSourceType() { result = "a message from a peer" }
}

/** A packet's payload, read off the parameter a core handler receives. */
class PacketPayload extends RemoteFlowSource::Range {
  PacketPayload() {
    exists(DataFlow::AttrRead read | read = this |
      read.getAttributeName() in ["payload", "src_id", "dst_id"] and
      read.getObject().getALocalSource() instanceof PeerMessage
    )
  }

  override string getSourceType() { result = "a packet field" }
}

/** Any of the above. */
class MeshInput extends DataFlow::Node {
  MeshInput() {
    this instanceof WireDatagram or
    this instanceof WireStream or
    this instanceof SpoolFrame or
    this instanceof PeerMessage or
    this instanceof PacketPayload
  }
}
