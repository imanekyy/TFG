# TFG — Detección temprana de n-days utilizando CodeQL

Trabajo de Fin de Grado centrado en el uso de CodeQL para detectar
vulnerabilidades de seguridad en proyectos Java del ecosistema Spring mediante
análisis estático y seguimiento de flujo de datos (*taint tracking*).

El proyecto desarrolla un conjunto de consultas personalizadas a partir del
análisis de vulnerabilidades reales documentadas mediante CVE. Para cada caso se
estudia el parche de seguridad y se modelan los elementos necesarios para
reproducir el comportamiento de la vulnerabilidad, definiendo las *sources*,
*sinks* y *barriers* correspondientes. Posteriormente, las consultas se ejecutan
sobre las versiones vulnerable y corregida del proyecto para comprobar que
detectan el flujo únicamente en la primera. Finalmente, los resultados se
comparan con las consultas oficiales de CodeQL para analizar las diferencias
entre ambos enfoques.

## Casos de estudio

Cada caso analiza un tipo de vulnerabilidad sobre un CVE real del ecosistema Spring:

| Caso | Vulnerabilidad | CWE | CVE | Vulnerable → Parcheada |
|------|----------------|-----|-----|------------------------|
| `01-path-traversal` | Path Traversal | CWE-22 | CVE-2026-40982 | 4.3.2 → 4.3.3 |
| `02-spel-injection` | Inyección de expresiones SpEL | CWE-094 / CWE-917 | CVE-2026-22738 | 1.0.4 → 1.0.5 |
| `03-deserializacion` | Deserialización insegura | CWE-502 | CVE-2023-34040 | 3.0.9 → 3.0.10 |
| `04-ssrf` | Server-Side Request Forgery | CWE-918 | CVE-2026-22739 | 4.3.1 → 4.3.2 |

## Estructura del repositorio

```
codeql-tfg/
├── casos/                  # Un directorio por vulnerabilidad
│   ├── 01-path-traversal/
│   │   ├── *_codeql.ql     # Query oficial de CodeQL empleada en el caso
│   │   └── *_custom.ql     # Query personalizada del TFG
│   ├── 02-spel-injection/
│   ├── 03-deserializacion/
│   └── 04-ssrf/
├── qlpack.yml              # Paquete CodeQL y dependencias
└── codeql-pack.lock.yml
```

> **Nota:** las bases de datos de CodeQL y el código fuente de los proyectos
> analizados (`databases/`, `repos/`) no se incluyen en el repositorio por su
> tamaño. Se generan localmente siguiendo los pasos de abajo.

## Requisitos

- [CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli)
- La extensión [CodeQL para VS Code](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql) (opcional)
- JDK 17 (necesario para construir los proyectos Spring analizados)

## Uso

### 1. Instalar las dependencias del paquete

Descarga las librerías de CodeQL para Java declaradas en `qlpack.yml`:

```bash
codeql pack install
```

### 2. Clonar el proyecto y estudiar el parche

Cada caso parte de un proyecto del ecosistema Spring y de un CVE concreto. El
primer paso es clonar el repositorio y situarse en las versiones que delimitan la
vulnerabilidad (la última vulnerable y la primera corregida):

```bash
git clone <url-del-repositorio> repos/<caso>/<proyecto>
cd repos/<caso>/<proyecto>
git tag | grep <version>          # localizar los tags exactos
```

El análisis del parche es la base del modelado: comparando la versión vulnerable
con la corregida se identifica qué fichero cambia y se deducen los elementos de
la consulta (la *source*, el *sink* y, cuando procede, la *barrier*).

```bash
# Resumen de ficheros modificados entre ambas versiones
git diff <tag-vulnerable> <tag-parcheada> --stat

# Cambios concretos del fichero o ficheros de interés
git diff <tag-vulnerable> <tag-parcheada> -- '*<FicheroDeInteres>.java'
```

### 3. Crear la base de datos

La base de datos se construye una vez situado en el tag correspondiente. La forma
de construirla depende del proyecto.

**Proyectos Maven** (por ejemplo, Spring AI o Spring Cloud Config), con build
dirigido al módulo afectado:

```bash
git checkout -f <tag-de-la-version>

codeql database create <ruta-db> \
  --language=java \
  --source-root=. \
  --overwrite \
  --command="./mvnw -pl <modulo> -am clean compile -DskipTests"
```

**Proyectos cuya compilación no es reproducible** (por ejemplo, Spring Kafka,
cuyas dependencias de build ya no se resuelven desde `repo.spring.io`). En ese
caso se extrae el código fuente sin compilar:

```bash
git checkout -f <tag-de-la-version>

codeql database create <ruta-db> \
  --language=java \
  --build-mode=none \
  --source-root=. \
  --overwrite
```

### 4. Ejecutar las queries sobre la base de datos

Cada caso incluye dos consultas: la personalizada (`*_custom.ql`) y la oficial de
CodeQL empleada como referencia (`*_codeql.ql`). Para ejecutar cualquiera de
ellas y ver los resultados:

```bash
codeql query run casos/03-deserializacion/<query>_custom.ql \
  --database=<ruta-db>
```

```bash
codeql query run casos/03-deserializacion/<query>_codeql.ql \
  --database=<ruta-db>
```

El análisis de cada caso consiste en ejecutar ambas consultas sobre la versión
vulnerable y sobre la versión parcheada, y comparar qué detecta cada una en cada
versión.

## Autora

Imane Kadiri Yamani — Grado en Ingeniería de la Ciberseguridad

## Licencia

Este proyecto se distribuye bajo la licencia [MIT](LICENSE).
