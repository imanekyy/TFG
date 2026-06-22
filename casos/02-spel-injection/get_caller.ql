import java

from MethodCall call, Callable caller
where
  call.getMethod().hasName("doFilterPredicate") and
  caller = call.getEnclosingCallable()
select call, "Llamado desde " + caller.getDeclaringType().getName() + "." + caller.getName()