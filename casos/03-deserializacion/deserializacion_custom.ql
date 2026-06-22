/**
 * @name Deserialización insegura en Spring Kafka (CVE-2023-34040)
 * @description Detecta cómo un dato controlado por el usuario llega hasta una deserialización
 *              con ObjectInputStream sin validar, lo que puede provocar ejecución remota de código.
 * @kind path-problem
 * @problem.severity warning
 * @id java/unsafe-deser-kafka-header
 * @tags security
 *       external/cwe/cwe-502
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.controlflow.Guards

module KafkaDeserConfig implements DataFlow::ConfigSig {

  // SOURCE: el valor de una cabecera Kafka (Header.value), porque esos bytes vienen del
  // registro recibido y un atacante puede controlarlos.
  predicate isSource(DataFlow::Node source) {
    exists(MethodCall mc |
      mc.getMethod().hasName("value") and
      mc.getMethod().getDeclaringType().hasName("Header") and   // org.apache.kafka.common.header.Header
      source.asExpr() = mc
    )
  }

  // SINK: el objeto sobre el que se llama readObject, porque es donde esos bytes se
  // deserializan y pueden acabar ejecutando código.
  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasName("readObject") and
      sink.asExpr() = mc.getQualifier()
    )
  }

  // BARRIER: el instanceof DeserializationExceptionHeader, porque cuando controla el flujo
  // garantiza que solo se deserializan las cabeceras del tipo esperado.
  predicate isBarrier(DataFlow::Node node) {
    exists(InstanceOfExpr ioe |
      ioe.getCheckedType().hasName("DeserializationExceptionHeader") and
      ioe.(Guard).controls(node.asExpr().getBasicBlock(), true)
    )
  }
}

module KafkaDeserFlow = TaintTracking::Global<KafkaDeserConfig>;
import KafkaDeserFlow::PathGraph

from KafkaDeserFlow::PathNode source, KafkaDeserFlow::PathNode sink
where KafkaDeserFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Bytes de una cabecera del registro se deserializan sin validar su procedencia (CWE-502, posible RCE)."
