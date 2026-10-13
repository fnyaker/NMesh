/**
 * @name XML external entity expansion (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id nmesh/xxe
 * @tags security
 *       external/cwe/cwe-611
 */

import python
import NMeshSources
import semmle.python.security.dataflow.XxeQuery
import XxeFlow::PathGraph

from XxeFlow::PathNode source, XxeFlow::PathNode sink
where XxeFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "XML parsing depends on $@.", source.getNode(), "data from a peer"
