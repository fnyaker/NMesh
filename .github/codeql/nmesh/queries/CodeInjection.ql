/**
 * @name Code injection (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id nmesh/code-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import python
import NMeshSources
import semmle.python.security.dataflow.CodeInjectionQuery
import CodeInjectionFlow::PathGraph

from CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink
where CodeInjectionFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "This code execution depends on $@.", source.getNode(), "data from a peer"
