/**
 * @name Path Traversal en Spring Cloud Config Server (CVE-2026-40982)
 * @description Detecta cómo un dato controlado por el usuario llega hasta una operación de
 *              acceso a ficheros sin sanear, lo que puede provocar el acceso a recursos
 *              fuera del directorio permitido.
 * @kind path-problem
 * @problem.severity warning
 * @id java/path-traversal-spring
 * @tags security
 *       external/cwe/cwe-022
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module PathTraversalConfig implements DataFlow::ConfigSig {

  // SOURCE: cualquier entrada remota (RemoteFlowSource), porque la ruta llega desde la
  // petición HTTP del usuario, que es el dato que no controlamos.
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  // SINK: el argumento de findOne que recibe la ruta, porque es donde el path del usuario
  // se usa para resolver el fichero que se va a leer.
  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasName("findOne") and sink.asExpr() = mc.getArgument(3)
    )
  }

  // BARRIER: las llamadas a normalize, porque normalizan la ruta y eliminan los "../",
  // cortando el path traversal antes de que llegue al sink.
  predicate isBarrier(DataFlow::Node node) {
    exists(MethodCall mc | mc.getMethod().hasName("normalize") and node.asExpr() = mc)
  }
}

module PathTraversalFlow = TaintTracking::Global<PathTraversalConfig>;
import PathTraversalFlow::PathGraph

from PathTraversalFlow::PathNode source, PathTraversalFlow::PathNode sink
where PathTraversalFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Path Traversal: una ruta del usuario llega a findOne sin haber sido sanitizada."
