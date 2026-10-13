/**
 * @name Partial server-side request forgery (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id nmesh/partial-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import NMeshSources
import semmle.python.security.dataflow.ServerSideRequestForgeryQuery
import PartialServerSideRequestForgeryFlow::PathGraph

from PartialServerSideRequestForgeryFlow::PathNode source, PartialServerSideRequestForgeryFlow::PathNode sink
where PartialServerSideRequestForgeryFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "Part of the URL of this request depends on $@.", source.getNode(), "data from a peer"
