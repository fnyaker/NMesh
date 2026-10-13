/**
 * @name Full server-side request forgery (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id nmesh/full-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import NMeshSources
import semmle.python.security.dataflow.ServerSideRequestForgeryQuery
import FullServerSideRequestForgeryFlow::PathGraph

from FullServerSideRequestForgeryFlow::PathNode source, FullServerSideRequestForgeryFlow::PathNode sink
where FullServerSideRequestForgeryFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "The full URL of this request depends on $@.", source.getNode(), "data from a peer"
