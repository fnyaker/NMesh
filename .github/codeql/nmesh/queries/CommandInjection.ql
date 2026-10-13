/**
 * @name Uncontrolled command line (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id nmesh/command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import NMeshSources
import semmle.python.security.dataflow.CommandInjectionQuery
import CommandInjectionFlow::PathGraph

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "This command line depends on $@.", source.getNode(), "data from a peer"
