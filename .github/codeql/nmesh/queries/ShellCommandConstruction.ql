/**
 * @name Unsafe shell command constructed from mesh input (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.3
 * @precision high
 * @id nmesh/shell-command-constructed-from-input
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import NMeshSources
import semmle.python.security.dataflow.UnsafeShellCommandConstructionQuery
import UnsafeShellCommandConstructionFlow::PathGraph

from UnsafeShellCommandConstructionFlow::PathNode source, UnsafeShellCommandConstructionFlow::PathNode sink
where UnsafeShellCommandConstructionFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "This shell command depends on $@.", source.getNode(), "data from a peer"
