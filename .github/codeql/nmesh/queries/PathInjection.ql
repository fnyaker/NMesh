/**
 * @name Uncontrolled data used in path expression (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id nmesh/path-injection
 * @tags security
 *       external/cwe/cwe-022
 */

import python
import NMeshSources
import semmle.python.security.dataflow.PathInjectionQuery
import PathInjectionFlow::PathGraph

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "This path depends on $@.", source.getNode(), "data from a peer"
