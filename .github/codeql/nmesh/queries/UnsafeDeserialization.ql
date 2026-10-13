/**
 * @name Deserialization of untrusted data (from the mesh)
 * @description The standard query, with what a peer sends as its source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id nmesh/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import python
import NMeshSources
import semmle.python.security.dataflow.UnsafeDeserializationQuery
import UnsafeDeserializationFlow::PathGraph

from UnsafeDeserializationFlow::PathNode source, UnsafeDeserializationFlow::PathNode sink
where UnsafeDeserializationFlow::flowPath(source, sink) and source.getNode() instanceof MeshInput
select sink.getNode(), source, sink, "Unsafe deserialization depends on $@.", source.getNode(), "data from a peer"
