/**
 * @name Regular expression injection (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id nmesh/regex-injection
 * @tags security
 *       external/cwe/cwe-730
 */

import python
import NMeshSources
import semmle.python.security.dataflow.RegexInjectionQuery
import RegexInjectionFlow::PathGraph

from RegexInjectionFlow::PathNode source, RegexInjectionFlow::PathNode sink
where RegexInjectionFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "This regular expression depends on $@.", source.getNode(), "data from a peer"
