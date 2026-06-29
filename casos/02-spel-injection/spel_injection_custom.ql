/**
 * @name Inyección SpEL en SimpleVectorStore (CVE-2026-22738)
 * @description Detecta cómo un dato controlado por el usuario llega hasta la evaluación de una
 *              expresión SpEL sin restringir, lo que puede provocar ejecución remota de código.
 * @kind path-problem
 * @problem.severity warning
 * @id java/spel-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.dataflow.TaintTracking

module SpelInjectionConfig implements DataFlow::ConfigSig {

  // SOURCE: el valor que devuelve getFilterExpression, porque es el filtro que escribe el
  // usuario y que acaba interpretándose como expresión.
  predicate isSource(DataFlow::Node source) {
    exists(MethodCall mc | mc.getMethod().hasName("getFilterExpression") and source.asExpr() = mc)
  }

  // SINK: el argumento de parseExpression, porque es donde el texto se compila y se evalúa
  // como expresión SpEL (el punto peligroso).
  predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      c.getCallee().hasName("parseExpression") and
      sink.asExpr() = c.getAnArgument()
    )
  }

  // PASO ADICIONAL: convertExpression transforma el filtro en la cadena SpEL final; sin este
  // paso el flujo se perdería entre el source y el sink.
  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodCall mc |
      mc.getMethod().hasName("convertExpression") and
      node1.asExpr() = mc.getAnArgument() and
      node2.asExpr() = mc
    )
  }

  // BARRIER: no se modela ninguno, porque en el código vulnerable no existe ningún saneamiento ni
  // antes de evaluar la expresión.
}

module SpelFlow = TaintTracking::Global<SpelInjectionConfig>;
import SpelFlow::PathGraph

from SpelFlow::PathNode source, SpelFlow::PathNode sink
where SpelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Filtro controlado por el usuario evaluado como expresión SpEL sin restricciones (inyección SpEL, posible RCE)."
