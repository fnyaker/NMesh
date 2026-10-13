/**
 * @name Mesh inputs declared to CodeQL
 * @description Every node `NMeshSources.qll` declares as remote input.
 * @kind table
 * @id nmesh/list-sources
 */

import python
import NMeshSources

from MeshInput s
select s.getLocation().getFile().getRelativePath(), s.getLocation().getStartLine(),
  s.(RemoteFlowSource).getSourceType()
