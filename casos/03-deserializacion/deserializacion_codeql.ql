// Consulta oficial de CodeQL (proyecto github/codeql).
// Incluida en este repositorio únicamente como referencia para la comparación.
// Fuente: java/ql/src/Security/CWE/CWE-502/UnsafeDeserialization.ql
// Licencia original: MIT (https://github.com/github/codeql/blob/main/LICENSE.md)

/**
 * @name Deserialization of user-controlled data
 * @description Deserializing user-controlled data may allow attackers to
 *              execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import java
import semmle.code.java.security.UnsafeDeserializationQuery
import UnsafeDeserializationFlow::PathGraph

from UnsafeDeserializationFlow::PathNode source, UnsafeDeserializationFlow::PathNode sink
where UnsafeDeserializationFlow::flowPath(source, sink)
select sink.getNode().(UnsafeDeserializationSink).getMethodCall(), source, sink,
  "Unsafe deserialization depends on a $@.", source.getNode(), "user-provided value"
