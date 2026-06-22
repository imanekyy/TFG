/**
 * @name Server-Side Request Forgery en Spring Cloud Config Server (CVE-2026-22742)
 * @description Detecta cómo un dato controlado por el usuario llega hasta una petición de red
 *              sin validar el host de destino, lo que puede provocar SSRF.
 * @kind path-problem
 * @problem.severity warning
 * @id java/ssrf-spring
 * @tags security
 *       external/cwe/cwe-918
 */

import java
import semmle.code.java.dataflow.TaintTracking

module SSRFConfig implements DataFlow::ConfigSig {

  // SOURCE: el parámetro uri de setUri, porque la URL del repositorio SCM no llega por HTTP sino
  // por configuración, y puede contener un placeholder ({profile}) que rellena el atacante.
  predicate isSource(DataFlow::Node source) {
    exists(Method m |
      m.hasName("setUri") and
      m.getDeclaringType().hasName("AbstractScmAccessor") and
      source.asParameter() = m.getParameter(0)
    )
  }

  // SINK: la asignación al campo uri, porque ahí queda guardada la URL que el servidor usará
  // luego para conectarse al repositorio remoto.
  predicate isSink(DataFlow::Node sink) {
    exists(AssignExpr a, FieldAccess fa |
      a.getDest() = fa and
      fa.getField().hasName("uri") and
      fa.getField().getDeclaringType().hasName("AbstractScmAccessor") and
      sink.asExpr() = a.getRhs()
    )
  }

  // BARRIER: el argumento de validateNoTemplateInAuthority, porque ese método valida el host y
  // lanza si contiene un comodín; se marca el argumento al ser un método void (no devuelve valor).
  predicate isBarrier(DataFlow::Node node) {
    exists(Call c |
      c.getCallee().hasName("validateNoTemplateInAuthority") and node.asExpr() = c.getAnArgument()
    )
  }
}

module SSRFFlow = TaintTracking::Global<SSRFConfig>;
import SSRFFlow::PathGraph

from SSRFFlow::PathNode source, SSRFFlow::PathNode sink
where SSRFFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "URI de repositorio SCM que se guarda sin validar el host (posible SSRF)."
