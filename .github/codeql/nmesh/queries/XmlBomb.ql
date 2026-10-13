/**
 * @name XML internal entity expansion (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id nmesh/xml-bomb
 * @tags security
 *       external/cwe/cwe-776
 */

import python
import NMeshSources
import semmle.python.security.dataflow.XmlBombQuery
import XmlBombFlow::PathGraph

from XmlBombFlow::PathNode source, XmlBombFlow::PathNode sink
where XmlBombFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "XML parsing depends on $@.", source.getNode(), "data from a peer"
