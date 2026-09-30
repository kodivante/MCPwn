# MCPwn

**Auditor de Seguridad y Linter de Fuzzing para el Model Context Protocol (MCP)**

MCPwn es un escáner de seguridad y toolkit de fuzzing para servidores MCP: audita los schemas de las tools con trece reglas estáticas, fuzzea el protocolo JSON-RPC y confirma inyección de comandos, path traversal, SSRF, mass assignment, prompt injection, race conditions y riesgos de denegación de servicio con payloads benignos — y califica cada servidor de A a F.

Diseñado y desarrollado por **kodivante**

**Lee esto en inglés:** [README.md](../README.md)

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE) [![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://golang.org) [![Security Standard](https://img.shields.io/badge/Security-Audit_Ready-brightgreen)](#) [![CI](https://github.com/kodivante/MCPwn/actions/workflows/ci.yml/badge.svg)](https://github.com/kodivante/MCPwn/actions/workflows/ci.yml)

---

## Historia

MCPwn nació durante un engagement autorizado de red team, en los primeros meses del Model Context Protocol. Kodivante auditaba infraestructura de IA, y el mismo hallazgo aparecía en todas partes: servidores MCP escuchando en la red con tools que confiaban en cualquier input — ejecución de comandos en crudo ofrecida a cualquier modelo lo bastante educado para pedirla, lectores de archivos sin restricción de rutas, credenciales escritas directo en los schemas.

El momento decisivo: un cliente insistía en que su agente "solo tenía tools de lectura". Un único request `tools/list` después, el servidor respondió con una tool descrita como "Execute an OS command" — un parámetro string, sin enum, sin validación. Y lo peor: ningún scanner del mercado podía ver la falla. Cada servidor MCP en esa red era una API sin guardia que nadie estaba testeando.

Esa noche se escribió la primera versión de MCPwn. Creció hasta ser una suite completa: trece reglas estáticas, un fuzzer que confirma hallazgos con sondas inofensivas, un simulador de prompt injection, generación de PoCs, puntaje de seguridad y modo watch. Una regla nunca ha cambiado: ataca como red teamer y se comporta como blue teamer. Cada payload es benigno por diseño, y una deny-list hardcodeada garantiza que MCPwn solo puede ser un detector, nunca un arma. Apúntalo a un servidor que no es tuyo, y la vulnerabilidad eres tú.

---

## Características Principales

- **Descubrimiento nativo del protocolo**: handshake MCP completo (`initialize`/`initialized`) vía stdio, SSE o Streamable HTTP, incluyendo `tools/call`, `resources/list`, `resources/read`, `prompts/list` y `prompts/get`.
- **17 reglas de seguridad estáticas**: inyección de comandos, path traversal, SSRF, fuga de credenciales, inyección SQL, denegación de servicio, mutación de estado, tool poisoning, IDOR, mass assignment, tipado débil, campos requeridos faltantes, over-sharing de contexto, template injection, deserialización insegura, prototype pollution e inyección NoSQL.
- **Análisis de código fuente** (`-source`): motor de taint interprocedural puro-Go sobre árboles Python/JS/TS que identifica handlers de tools MCP como fuentes, resuelve imports (`import subprocess as sp`), from-imports, `require` de JS, clases, métodos, cadenas de constructores, alias de funciones y atributos de estado de objetos, propaga el taint a través de límites de función y respeta sanitizers (`shlex.quote`, `re.escape`, `int`) y guards de allowlist antes de reportar la ruta completa al sink. Cada hallazgo lleva su tier de verificación: `static`, `dynamic` o `correlated`. Corre standalone en CI.
- **Correlación source→runtime**: cuando una ruta de taint estática coincide con un probe confirmado dinámicamente sobre la misma tool, `CorrelatedVuln01` (CRITICAL) fusiona ambas pruebas en un solo hallazgo verificado — una hipótesis trazada en código y reproducida en runtime ya no es una hipótesis.
- **Auditoría de supply chain** (`-supply-chain`): parsea `requirements.txt`, `package.json` y `go.mod`, consulta la base de vulnerabilidades OSV.dev en vivo, marca typosquats (distancia Damerau-Levenshtein 1 de paquetes populares) y dependencias sin pinchar.
- **Auditoría de autorización OAuth** (`-auth-audit`): sigue los challenges 401 hasta los metadatos OAuth, verifica el anuncio de PKCE S256, detecta metadatos RFC 9728 faltantes y aceptación de tokens bearer fabricados.
- **Discovery de MCPs shadow** (`-discover`): inventaría cada servidor MCP configurado en la máquina (Claude Desktop, Claude Code, Cursor, VS Code, `.mcp.json`) con clasificación local-stdio/local-http/remoto.
- **Campañas autopilot** (`-autopilot`): un plan determinista de hipótesis — qué esperamos probar y con cuál probe — construido antes de testear y evaluado después, imprimiendo un resumen de confirmadas versus no probadas.
- **Probing adaptativo** (`-mutate`, `-sequence`): payloads benignos de sustitución prueban si el input de las tools llega a un intérprete de comandos (consciente de ejecución, inmune a falsos positivos de reflejo), mientras que las sondas de secuencia exponen violaciones de idempotencia y sangrado de estado entre tools.
- **Policy gates** (`-policy`): archivos JSON que aplican gates personalizadas (`failOn` severidades, `maxFindings`, `ignoreRules`) sobre la lógica de severidad por defecto, para pipelines de CI con requisitos más estrictos.
- **LLM advisor opcional** (`-advisor-endpoint`): envía contexto estrictamente anonimizado (hashes, capacidades, IDs de reglas) a un endpoint externo y convierte las hipótesis recibidas en leads `AdvisorHint01` claramente marcados — severidad LOW, confidence 40, jamás confirmados. Asistido por IA, nunca autoridad de IA.
- **Suite de testing dinámico profundo** (`-deep`): dieciocho motores — prober de traversal, canary SSRF, sonda de schema pollution, desync de lifecycle, fuzzer de protocolo, prober de race conditions, sonda de agotamiento, detector de rug-pull, escáner de token leaks, sonda de sampling, detector de side-channels, prober de resource traversal, auditor de prompt templates, motor de amenazas HTTP, sonda de elicitation y sonda de roots del cliente.
- **Mapping OWASP MCP Top 10**: cada hallazgo lleva su tag `MCPxx:2025` en JSON, SARIF y HTML, más una matriz de cobertura de los diez riesgos en cada reporte HTML.
- **Auditoría de flotas** (`-targets`): audita todos los servidores MCP de la organización desde un solo archivo JSON, con reportes por objetivo e inventario consolidado.
- **Análisis de cadenas de ataque**: post-análisis siempre activo que enlaza hallazgos en rutas de explotación (RCE + fuga de credenciales, SSRF + token leak, prompt injection + SSRF) y reporta la cadena completa con evidencia.
- **Grafo de ataque de entidades**: cada tool recibe un perfil de capacidades (exec, filesystem, network, database, state, credentials) que alimenta un grafo de conocimiento — serializable con `-output=graph` — que impulsa la detección de cadenas multi-hop (`AttackChain02`) y queries de alcance por tool.
- **Risk Index 0-100**: severidad, confirmación y confidence ponderados por hallazgo, con amplificación por cadenas y bonos de densidad — un veredicto numérico más allá de los conteos simples, visible en terminal, HTML e inventarios batch.
- **Snapshots de aprobación**: `-snapshot-save` congela los fingerprints de tools aprobadas y el shape de sus respuestas; `-snapshot-compare` reporta `ToolDrift01` (cambios de descripción, schema, altas/bajas de tools) y `BehaviorDrift01` (cambios de estructura de respuesta) — rug pulls detectados entre ejecuciones y días, no solo entre sesiones.
- **Confianza por hallazgo**: cada hallazgo lleva un score `Confidence` de 0-100 — confirmado con evidencia puntúa 95, estático 70 — habilitando gates de CI con casi cero falsos positivos.
- **Transcripciones completas** (`-record`): cada request y response JSON-RPC queda logueado como JSONL con timestamps para reproducibilidad total.
- **Motor de fuzzing dinámico**: confirma hallazgos de inyección de comandos con payloads benignos (echo con marca única, sleep controlado, archivo temporal auto-borrable) con una deny-list estricta hardcodeada.
- **Simulador de prompt injection**: envía tres payloads benignos fijos y clasifica el reflejo total o parcial del input del usuario.
- **Puntaje de seguridad**: cada auditoría colapsa en un grado de A (limpio) a F (crítico).
- **Salidas**: terminal, JSON, SARIF (listo para CI), reporte HTML autocontenido en tema claro (inspirado en OWASP ZAP), e insignia SVG.
- **Modos watch y diff**: re-auditoría continua por intervalo, y comparación de regresión contra un reporte baseline.
- **Generador de PoC**: scripts didácticos y reproducibles en Python/Bash para hallazgos confirmados — con filtro de seguridad que rechaza primitivas prohibidas.
- **Plugins de payloads**: extiende el fuzzer con tus propios payloads en el DSL `.mcpwn`.
- **Go stdlib pura**: cero dependencias externas.

---

## Instalación

```bash
go install github.com/kodivante/MCPwn/v3/cmd/mcpwn@latest
```

O desde el código fuente:

```bash
git clone https://github.com/kodivante/MCPwn
cd MCPwn
go build -o mcpwn ./cmd/mcpwn
```

---

## Inicio Rápido

Auditar un servidor MCP local vía stdio:

```bash
mcpwn -transport=stdio -command=node -args=server.js
```

Auditar un servidor MCP por SSE:

```bash
mcpwn -transport=sse -url=http://localhost:8080/sse
```

Batería completa: auditoría estática, confirmación dinámica por fuzzing, simulación de prompt injection y generación de PoCs:

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -fuzz -prompt-inject -gen-poc
```

Mira el reporte HTML completo contra nuestro servidor demo intencionalmente vulnerable (33 hallazgos, grado F):

```bash
mcpwn -transport=stdio -command=python3 -args=test/fixtures/mockServerDemo.py -fuzz -prompt-inject -output=html -file=report.html
```

Corre la batería profunda completa: todas las reglas estáticas, todos los motores dinámicos:

```bash
mcpwn -transport=stdio -command=python3 -args=test/fixtures/mockServerDemo.py -deep
```

Audita un servidor remoto vía Streamable HTTP:

```bash
mcpwn -transport=http -url=https://mcp.example.com/mcp -auth-header="Bearer token" -deep
```

Audita una flota completa desde un solo archivo:

```bash
mcpwn -targets=targets.json -deep -outdir=reports -file=inventory.json
```

---

## Referencia de CLI

| Flag | Default | Descripción |
|---|---|---|
| `-transport` | `stdio` | Tipo de transporte: `stdio`, `sse` o `http` |
| `-command` | — | Comando a ejecutar para el transporte stdio |
| `-args` | — | Argumentos del comando, separados por comas |
| `-url` | — | URL para los transportes SSE/HTTP |
| `-auth-header` | — | Valor del header `Authorization` para el transporte HTTP (ej. `Bearer token`) |
| `-output` | `terminal` | Formato: `terminal`, `json`, `sarif`, `html`, `badge`, `graph` |
| `-file` | — | Escribir la salida a un archivo en vez de stdout |
| `-timeout` | `30s` | Timeout por auditoría |
| `-fuzz` | `false` | Ejecutar fuzzing dinámico para confirmar hallazgos |
| `-fuzz-timeout` | `10s` | Timeout por probe de fuzzing |
| `-prompt-inject` | `false` | Simular prompt injection con payloads benignos |
| `-gen-poc` | `false` | Generar scripts PoC de hallazgos confirmados en `./pocs` |
| `-poc-lang` | `python` | Lenguaje del PoC: `python` o `bash` |
| `-payloads` | — | Archivo o directorio de payloads custom (`.mcpwn`) |
| `-watch` | `false` | Re-auditar continuamente por intervalo (Ctrl+C para parar) |
| `-interval` | `30s` | Intervalo del modo watch |
| `-diff` | — | Reporte JSON baseline contra el que comparar |
| `-deep` | `false` | Activa todos los motores dinámicos en un solo flag |
| `-quick` | `false` | Detiene el sondeo profundo tras la primera confirmación |
| `-traverse` | `false` | Confirma path traversal con un archivo marcador |
| `-ssrf` | `false` | Confirma SSRF con un canary local |
| `-pollute` | `false` | Confirma mass assignment con propiedades no declaradas |
| `-desync` | `false` | Sondea el manejo de lifecycle del MCP |
| `-protofuzz` | `false` | Envía JSON-RPC malformado y detecta caídas |
| `-race-probe` | `false` | Envía llamadas concurrentes idénticas |
| `-exhaust` | `false` | Mide degradación de latencia bajo ráfaga acotada |
| `-rugpull` | `false` | Detecta cambios de descripción de tools entre sesiones |
| `-tokenleak` | `false` | Escanea respuestas y errores en busca de credenciales filtradas |
| `-sampling` | `false` | Detecta si el servidor acepta sampling/createMessage |
| `-side-channel` | `false` | Detecta inyección ciega por timing, tamaño y errores |
| `-restraverse` | `false` | Sondea resources/read con payloads de traversal |
| `-prompt-audit` | `false` | Audita templates de prompts por instrucciones ocultas y exfiltración |
| `-http-probe` | `false` | Sondea la seguridad del transporte HTTP: auth bypass, sesión y Origin |
| `-elicitation` | `false` | Detecta si el servidor acepta elicitation/create |
| `-roots` | `false` | Detecta si el servidor acepta roots/list |
| `-record` | — | Guarda una transcripción JSONL de cada mensaje JSON-RPC |
| `-targets` | — | Modo batch: archivo JSON con el arreglo de objetivos a auditar |
| `-outdir` | — | Directorio para reportes por objetivo en modo batch |
| `-snapshot-save` | — | Guarda un snapshot de fingerprints de tools aprobadas |
| `-snapshot-compare` | — | Compara el servidor contra un snapshot y reporta el drift |
| `-source` | — | Ruta del árbol de código fuente del servidor a escanear |
| `-supply-chain` | — | Ruta del proyecto con manifests para auditar dependencias |
| `-auth-audit` | `false` | Sondea metadatos OAuth, PKCE y validación de tokens en HTTP |
| `-discover` | `false` | Inventaría los servidores MCP configurados en esta máquina |
| `-autopilot` | `false` | Corre la campaña completa guiada por hipótesis e imprime su resumen |
| `-policy` | — | Archivo de policy con gates de seguridad (`failOn`, `maxFindings`, `ignoreRules`) |
| `-advisor-endpoint` | — | Endpoint opcional de advisor LLM que recibe contexto anonimizado para hipótesis |
| `-mutate` | `false` | Prueba alcanzabilidad de intérprete de comandos via payloads benignos de sustitución |
| `-sequence` | `false` | Sondea violaciones de idempotencia y drift de estado entre tools |
| `-version` | — | Imprimir la versión y salir |

**Códigos de salida**: `0` sin hallazgos CRITICAL ni HIGH, `1` en cualquier otro caso. Cualquier error operativo también sale con `1` y mensaje en stderr.

---

## Reglas Estáticas

| Regla | Severidad | Detecta |
|---|---|---|
| `CmdInjection01` | CRITICAL | Parámetros string que permiten ejecución de comandos sin restricciones de enum |
| `CredentialsLeak01` | CRITICAL | Parámetros que piden credenciales crudas al LLM (token, apiKey, secret, password) |
| `ToolPoisoning01` | CRITICAL | Instrucciones adversarias embebidas en nombres o descripciones de tools |
| `PathTraversal01` | HIGH | Parámetros de ruta sin sanitización contra directory traversal |
| `SqlInjection01` | HIGH | Parámetros que aceptan queries SQL crudos |
| `StateMutation01` | HIGH | Tools destructivas (delete/update) sin parámetro de confirmación |
| `Idor01` | HIGH | IDs de recursos suministrados por el usuario sin restricciones ni verificación de propiedad |
| `Ssrf01` | MEDIUM | Parámetros de URL/webhook sin validación de protocolo o dominio |
| `Dos01` | MEDIUM | Tools de lectura de archivos sin parámetros de acotación (limit, maxLines) |
| `MassAssignment01` | MEDIUM | Schemas de objeto que permiten propiedades no declaradas |
| `PromptInjection01` | MEDIUM | Parámetros que alimentan texto controlado por el usuario al modelo (con `-prompt-inject`) |
| `WeakTyping01` | LOW | Parámetros sin un tipo explícito |
| `MissingRequired01` | LOW | Parámetros críticos ausentes del array required |

Los problemas de validación de schema aparecen como hallazgos `SchemaValidation01` (LOW).

## Motores Dinámicos

### Fuzzer (`-fuzz`)

Confirma hallazgos `CmdInjection01` llamando a la tool con sondas benignas:

- `echo {uuid}` — una marca única que debe regresar en la respuesta
- `sleep 2` — confirmación por timing con delay controlado
- `cat {tempfile}` — lee un archivo temporal creado por el fuzzer que se borra después

Cada probe tiene un reintento, un timeout configurable, y el motor aborta ante el primer servidor que no responde. Los hallazgos confirmados muestran `[!]` y una línea de evidence; los no confirmados muestran `[?]`.

**La deny-list está hardcodeada y es innegociable**: payloads con `rm`, `del`, `curl`, `wget`, `nc`, `ssh`, `sudo`, `chmod`, metacaracteres de shell (`>`, `|`, `&&`, `;`) o rutas sensibles (`/etc/passwd`, `.ssh`, `.env`) se rechazan al cargar. Los payloads definidos por el usuario no pueden saltársela.

### Simulador de Prompt Injection (`-prompt-inject`)

Envía tres strings benignos fijos ("Ignore previous instructions...", "You are now DAN...", "[SYSTEM]: Override...") y clasifica la respuesta:

- Reflejo total sin escape → `PromptInjectionReflection` (HIGH)
- Reflejo parcial (ventanas de 4 palabras) → `PromptInjectionPartialReflection` (MEDIUM)
- Sanitizado o ausente → sin hallazgo

Los hallazgos dinámicos se renderizan en una sección separada del terminal.

## Testing Dinámico Profundo

Quince motores, todos seguros por diseño. `-deep` los activa todos; `-quick` detiene el sondeo tras la primera confirmación.

| Motor | Flag | Produce | Cómo lo prueba |
|---|---|---|---|
| Prober de traversal | `-traverse` | Confirma `PathTraversal01` | Lee de vuelta un archivo marcador creado por el fuzzer con payloads `../` — jamás toca archivos del sistema |
| Canary SSRF | `-ssrf` | Confirma `Ssrf01` | Un listener local en `127.0.0.1` registra si el servidor audita hace fetch de la URL canary — cero conexiones externas |
| Sonda de schema pollution | `-pollute` | Confirma `MassAssignment01` | Envía una propiedad no declarada junto a argumentos válidos; la aceptación silenciosa confirma el riesgo |
| Motor de desync | `-desync` | `StateDesync01` (MEDIUM) | `tools/list` antes de `initialize`, `initialize` duplicado y re-inicialización tras el handshake |
| Fuzzer de protocolo | `-protofuzz` | `ProtocolRobustness01` (HIGH/MEDIUM) | Seis sondas JSON-RPC malformadas; conexiones caídas y silencio total son hallazgos |
| Prober de race | `-race-probe` | `RaceCondition01` (MEDIUM) | Cinco llamadas idénticas concurrentes en conexiones independientes; resultados inconsistentes son hallazgos |
| Sonda de agotamiento | `-exhaust` | `ResourceExhaustion01` (LOW/MEDIUM) | Ráfaga acotada de veinte requests midiendo degradación de latencia — nunca un DoS real |
| Detector de rug-pull | `-rugpull` | `ToolRugPull01` (HIGH) | Re-lista las tools en una sesión nueva y compara descripciones contra el primer listado |
| Escáner de token leaks | `-tokenleak` | `TokenLeak01` (CRITICAL) | Llama cada tool con argumentos benignos derivados del schema y escanea respuestas y errores: `sk-`, API keys, claves AWS, JWTs, bearer tokens, private keys |
| Sonda de sampling | `-sampling` | `SamplingAbuse01` (MEDIUM) | Envía `sampling/createMessage` en conexión nueva; la aceptación significa que el servidor puede invocar tu LLM directamente |
| Detector de side-channels | `-side-channel` | `SideChannel01/02/03` | Baseline benigno por tool, luego mide desviaciones de timing, error-diferencial y tamaño de respuesta — inyección ciega sin reflejo de payload |
| Prober de resource traversal | `-restraverse` | `ResourceTraversal01` (HIGH) | Cobertura completa de MCP Resources: sondea URIs de `resources/read` con marcadores fuera del resource root |
| Auditor de prompts | `-prompt-audit` | `PromptPoisoning01` (HIGH/CRITICAL) | Cobertura completa de MCP Prompts: templates de `prompts/list` y `prompts/get` escaneados por manipulación de roles (`ignore previous instructions`) y directivas de exfiltración (URLs, webhooks, destinos de subida) |
| Motor de amenazas HTTP | `-http-probe` | `HttpAuthBypass01`, `HttpSession01`, `HttpOrigin01`, `HttpBatch01` | Ataques sobre Streamable HTTP: sesiones sin autenticar, aceptación de `Mcp-Session-Id` inválido, tolerancia a Origin ajeno (superficie CSRF/DNS-rebinding) y permisividad de batches JSON-RPC |
| Sonda de elicitation | `-elicitation` | `ElicitationAbuse01` (MEDIUM) | Un servidor que acepta `elicitation/create` puede suplantar diálogos del cliente y phishear credenciales del usuario |
| Sonda de roots del cliente | `-roots` | `RootsProbe01` (MEDIUM) | Un servidor que acepta `roots/list` puede enumerar el alcance del filesystem del cliente |
| Prober de mutación | `-mutate` | `MutationDiff01` (HIGH, confirmado) | Payloads benignos de sustitución (`$(echo MARK)`, backticks, `${VAR}`) por parámetro string; se dispara solo cuando el marker regresa sin su wrapper — el servidor evaluó la sintaxis. Los reflejos literales jamás se disparan |
| Fuzzer de secuencias | `-sequence` | `Idempotency01`, `SequenceDrift01` (MEDIUM, confirmado) | Las llamadas secuenciales idénticas a tools mutadoras de estado no deben divergir, y una llamada benigna a una tool no debe cambiar el estado observado a través de otra (acotado a seis pares) |
| Analizador de cadenas | siempre activo | `AttackChain01` (HIGH/CRITICAL) | Enlaza hallazgos en rutas de explotación: RCE + fuga de credenciales se convierte en toma total del host; SSRF + token leak en movimiento lateral — cada cadena reporta sus eslabones con evidencia |
| Analizador multi-hop | siempre activo | `AttackChain02` (HIGH/CRITICAL) | Camina el grafo de capacidades en tres saltos: exec + credenciales + red se convierte en pipeline de exfiltración completo; filesystem + credenciales en cosecha de secretos; red + exec en toma remota |
| Fuzzer dinámico | `-fuzz` | Confirma `CmdInjection01` | Payloads benignos de echo/sleep/temp-file con deny-list estricta (`rm`, `curl`, `wget`, `nc`, `ssh`, `sudo` son rechazados por hardcode) |
| Simulador de prompt injection | `-prompt-inject` | `PromptInjection01` | Tres payloads benignos fijos clasificados como reflejo total o parcial |

Cada hallazgo confirmado lleva un score `Confidence` (0-100): confirmado con evidencia puntúa 95, estático 70, side-channel 55. Legible por máquinas en JSON y SARIF para gates de CI.

Los hallazgos de protocolo se renderizan en la sección `--- Advanced Probes ---` del terminal para que nunca se mezclen con los de las tools.

---

## OWASP MCP Top 10

Cada hallazgo se mapea al [OWASP Top 10 para MCP](https://owasp.org/www-project-mcp-top-10/) oficial y lleva su tag `OwaspMcp` en JSON, SARIF y HTML:

| ID OWASP | Riesgo | Cobertura MCPwn |
|---|---|---|
| `MCP01:2025` | Token Mismanagement & Secret Exposure | `TokenLeak01`, `CredentialsLeak01` |
| `MCP02:2025` | Privilege Escalation via Scope Creep | `Idor01`, `MassAssignment01` (+pollution), `StateMutation01` |
| `MCP03:2025` | Tool Poisoning | `ToolPoisoning01`, `PromptPoisoning01`, `ToolRugPull01` |
| `MCP04:2025` | Software Supply Chain Attacks | planificado |
| `MCP05:2025` | Command Injection & Execution | `CmdInjection01` + fuzzer, `SqlInjection01` |
| `MCP06:2025` | Prompt Injection via Contextual Payloads | `PromptInjection01` + simulador de reflejo |
| `MCP07:2025` | Insufficient Authentication & Authorization | `HttpAuthBypass01` (auditor OAuth completo planificado) |
| `MCP08:2025` | Lack of Audit and Telemetry | planificado (análisis de código fuente) |
| `MCP09:2025` | Shadow MCP Servers | planificado (discovery local) |
| `MCP10:2025` | Context Injection & Over-Sharing | `PathTraversal01`, `ResourceTraversal01`, `ContextSharing01` |

Los reportes HTML incluyen la matriz de cobertura completa con conteos por riesgo.

---

## Risk Engine y Grafo de Ataque

Más allá de contar severidades, MCPwn puntúa cada hallazgo 0-100 ponderando severidad, confirmación y confidence, y amplifica cadenas y clusters densos en un **Risk Index** a nivel servidor:

```
Security Score: D  |  1 CRITICAL  1 HIGH  3 MEDIUM  0 LOW
Risk Index: 78/100 (D)  |  chains: 3
```

Cada tool se perfila en capacidades (exec, filesystem, network, database, state, credentials) y se conecta en un grafo de entidades. El grafo impulsa la detección de cadenas multi-hop y responde preguntas de alcance; expórtalo con:

```bash
mcpwn -transport=stdio -command=npx -args=-y,@modelcontextprotocol/server-filesystem,/tmp -deep -output=graph -file=graph.json
```

El reporte del grafo contiene el risk index, todos los nodos y aristas, el alcance por tool y cada cadena detectada.

**Workflow de aprobación**: congela un servidor revisado y detecta drift en cada auditoría futura:

```bash
mcpwn ... -snapshot-save=approved.json
mcpwn ... -snapshot-compare=approved.json
```

`ToolDrift01` se dispara ante cambios de descripción (HIGH - señal de rug pull), cambios de schema (MEDIUM) y altas/bajas de tools; `BehaviorDrift01` se dispara cuando la estructura de respuesta de una tool cambia desde la aprobación.

---

## Auditoría de Flotas

Audita todos los servidores MCP de la organización desde un único archivo JSON:

```json
[
  {"name": "filesystem", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]},
  {"name": "remote", "transport": "http", "url": "https://mcp.example.com/mcp", "authHeader": "Bearer token"}
]
```

```bash
mcpwn -targets=targets.json -deep -outdir=reports -file=inventory.json
```

Cada objetivo recibe su línea de grado en el terminal, un reporte JSON completo en `-outdir`, y `-file` recibe el inventario consolidado. `-timeout` aplica por objetivo. El exit code es 1 cuando cualquier objetivo tiene hallazgos CRITICAL o HIGH.

---

## Análisis de Código y Supply Chain

Audita el código y las dependencias detrás del servidor, no solo su superficie de protocolo:

```bash
mcpwn -source=ruta/al/servidor -supply-chain=ruta/al/servidor -output=json -file=code.json
```

- **`-source`**: dos capas complementarias sobre árboles Python/JS/TS (saltando `node_modules`, `venv`, `dist`). El scanner reporta `SourceExec01`, `SourceDeserialization01` y `SourceSecret01` con evidencia archivo:línea. La capa de taint traza el input de las tools MCP a través de funciones hasta los sinks y reporta la ruta completa como `SourceTaint01`. Combinado con una auditoría en vivo, `CorrelatedVuln01` (CRITICAL) fusiona la ruta estática con el comportamiento confirmado dinámicamente. El modo standalone corre en CI: `mcpwn -source=.`.
- **`-supply-chain`**: parsea `requirements.txt`, `package.json` y `go.mod`, consulta OSV.dev en vivo por vulnerabilidades conocidas (`DependencyVuln01`, HIGH con identificadores GHSA/PYSEC reales), marca typosquats (`Typosquat01` — distancia Damerau-Levenshtein 1 de paquetes populares) y dependencias sin pinchar (`UnpinnedDep01`).

**Discovery de MCPs shadow** — inventaría cada servidor MCP configurado en la máquina:

```bash
mcpwn -discover
```

Escanea las ubicaciones de Claude Desktop, Claude Code, Cursor, VS Code y `.mcp.json`, clasifica cada servidor como local-stdio, local-http o remoto, y exporta JSON con `-output=json -file=inventory.json`.

---

## Autopilot, Policies y el Advisor

**Autopilot** convierte una auditoría en una campaña visible: antes de sondear, MCPwn deriva las hipótesis que vale la pena probar (qué hallazgos podría confirmar un probe, qué capacidades merecen atención); tras la batería reporta qué se probó:

```
Campaign summary: 10 hypotheses, 3 confirmed, 7 unproven
  [!] CmdInjection01          systemExec         via fuzzer
  [?] Ssrf01                  fetchUrl           via ssrf canary
  ...
```

```bash
mcpwn -transport=stdio -command=npx -args=-y,@modelcontextprotocol/server-filesystem,/tmp -autopilot
```

**Policy gates** agregan requisitos custom de CI sobre la lógica de severidad por defecto:

```json
{"failOn": ["CRITICAL", "HIGH"], "maxFindings": 20, "ignoreRules": ["SchemaValidation01"]}
```

```bash
mcpwn ... -policy=policy.json
```

Las violaciones se imprimen tras el reporte y fuerzan exit code 1.

**El advisor** es asistencia de IA opcional con rieles de seguridad duros: el request lleva solo hashes SHA-256 de tools, listas de capacidades, IDs de reglas y severidades — nunca nombres, descripciones ni datos del usuario — y cada hipótesis devuelta se convierte en un hallazgo `AdvisorHint01` limitado a severidad LOW y confidence 40, etiquetado como no verificado. Las hipótesis son leads por reproducir, jamás veredictos.

```bash
mcpwn ... -advisor-endpoint=http://localhost:8098/advise
```

---

## Docker

```bash
docker build -t mcpwn .
docker run --rm -v "$PWD":/audit mcpwn -transport=stdio -command=python3 -args=/audit/server.py -deep
```

La imagen está endurecida: build multi-stage, usuario no-root, filesystem de solo lectura y capabilities eliminadas vía el `docker-compose.yml` incluido.

---

## Packs de Comunidad

Packs de payloads `.mcpwn` listos en [`packs/`](../packs/):

| Pack | Sondas |
|---|---|
| `filesystem.mcpwn` | Ejecución de comandos y lectura de archivos con archivos temporales del scanner |
| `database.mcpwn` | Sondas SQL de solo lectura (versión sqlite, UNION, comment break) |
| `kubernetes.mcpwn` | Versión de kubectl, listado de namespaces, exposición de entorno |

Úsalos con `-payloads=packs/kubernetes.mcpwn` o deja cualquier archivo `.mcpwn` en `./mcpwn.d/` para auto-descubrimiento.

---

## Flujo Asistido por IA

La salida de MCPwn está diseñada para triage con IA:

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -deep -output=json -file=findings.json
```

1. Corre el baseline automatizado: linting estático más todos los motores dinámicos, con confirmaciones y evidence adjuntos a cada hallazgo.
2. Alimenta `findings.json` a tu asistente de IA: severidad, remediación y los campos `Confirmed` y `Evidence` eliminan la especulación del análisis.
3. La IA valida los hallazgos en contexto, los encadena en rutas de ataque y redacta los fixes — sobre hechos, no suposiciones.

Baseline automatizado (MCPwn) más análisis contextual profundo (tu IA) es igual a cobertura de seguridad completa.

---

## Por Qué MCPwn

| Capacidad | Escáneres MCP típicos | MCPwn |
|---|---|---|
| Linting estático de schemas | Raro | 13 reglas con guía de remediación |
| Confirmación dinámica | Destructiva por defecto, necesita safe mode | Segura por defecto — no existe safe mode porque nada destructivo sale del box |
| Archivos sensibles en pruebas de traversal | Lee `/etc/passwd`, llaves privadas | Nunca — solo archivos marcador del fuzzer |
| Detección out-of-band | Servidores DNS/callback externos | Canary local `127.0.0.1`, cero conexiones externas |
| Generación de PoC | — | Python/Bash didácticos con filtro de seguridad |
| Puntaje de seguridad | — | Grado A–F más insignia SVG |
| Modos watch y diff | — | Integrados |
| Extensibilidad de payloads | — | DSL `.mcpwn` con directorio de auto-carga |
| Instalación | Clonar, chmod, runtime de Python | Binario Go único vía `go install` |
| Integración CI | Solo documentación | GitHub Action con subida de SARIF |

---

## Salidas

- **terminal**: reporte con colores, indicadores `[!]`/`[?]`, remediación, evidence y el puntaje de seguridad.
- **json**: array de hallazgos (auditorías vacías emiten `[]`; los confirmados incluyen `Confirmed` y `Evidence`).
- **sarif**: SARIF 2.1.0 con versión del driver, listo para la pestaña Security de GitHub.
- **html**: archivo único autocontenido en tema claro (inspirado en OWASP ZAP) con dashboard, secciones por severidad y badges de confirmación. Sin JS, sin assets externos.
- **badge**: SVG estilo shields con tu grado (verde A hasta rojo F) para tu README.

## Puntaje de Seguridad

Calculado con el conteo de severidades:

| Grado | Condición |
|---|---|
| A | Sin hallazgos CRITICAL ni HIGH |
| B | 1–2 HIGH |
| C | 3+ HIGH |
| D | 1–2 CRITICAL |
| F | 3+ CRITICAL |

## Modo Watch

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -watch -interval=10s
```

Ejecuta la auditoría, limpia la pantalla y re-audita en cada tick. Cada auditoría tiene su propio timeout; el loop corre hasta Ctrl+C y se apaga de forma graceful incluso a mitad de auditoría.

## Modo Diff

Compara una ejecución contra un reporte JSON anterior:

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -output=json -file=baseline.json
mcpwn -transport=stdio -command=python3 -args=server.py -diff=baseline.json
```

El reporte de diff (en stderr) lista hallazgos Nuevos, Arreglados e Iguales, con clave regla + tool + path.

## Generación de PoC

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -fuzz -gen-poc
```

Por cada hallazgo **confirmado**, escribe `./pocs/<finding_id>_<tool>.py` (o `.sh` con `-poc-lang=bash`): un script autocontenido basado en pipes que repite el handshake y la sonda benigna. El PoC generado incluye un header obligatorio (tool, finding, severidad, evidence, disclaimer de uso autorizado), un marcador de éxito y la remediación como comentario final. Un filtro de seguridad se niega a generar cualquier PoC que contenga `curl`, `subprocess`, `os.system`, sockets o similares.

```bash
python3 pocs/CmdInjection01_system_exec.py | python3 server.py
```

---

## El Lenguaje de Payloads `.mcpwn`

Extiende el fuzzer con tus propias sondas. Los payloads se suman a los built-in y pasan por la misma deny-list:

```ini
# mispayloads.mcpwn
payload "custom_echo" {
    rule        = CmdInjection01
    template    = "echo probe_{uuid}"
    expect      = "probe_{uuid}"
    delay       = 2s
    description = "Confirma ejecución con un marcador custom"
}
```

| Campo | Requerido | Significado |
|---|---|---|
| `rule` | sí | ID de la regla objetivo (ej. `CmdInjection01`) |
| `template` | sí | Texto del payload; `{uuid}` se vuelve una marca única, `{tempfile}` un archivo temporal del fuzzer |
| `expect` | no | Marca que debe aparecer en la respuesta para confirmar |
| `delay` | no | Umbral de tiempo para confirmación por delay |
| `description` | no | Intención en texto legible |

Carga: `-payloads=archivo.mcpwn` (o directorio), más carga automática de cada `.mcpwn` dentro de `./mcpwn.d/` si existe. Las violaciones de la deny-list se rechazan con warning y el resto del archivo sigue cargando; los errores de sintaxis abortan ese archivo. Mira [examples/](../examples/) para packs de payloads listos para usar.

---

## GitHub Action

Usa la auditoría en el workflow de cualquier repositorio:

```yaml
- uses: kodivante/MCPwn@main
  with:
    transport: stdio
    command: python3
    args: server.py
    output: sarif
    file: mcpwn-results.sarif
```

Con `output: sarif` los resultados suben automáticamente a la pestaña Security del repositorio.

---

## Arquitectura

```
cmd/mcpwn/            entrypoint del CLI (solo parseo de flags)
internal/app/         orquestación: conectar, auditar, fuzz, prompt-inject, sondas profundas, reportar, exit code
internal/auditor/     motor de reglas + 13 reglas estáticas
internal/client/      JSON-RPC 2.0: stdio, SSE, sesión, handshake
internal/fuzzer/      fuzzing dinámico + parser del DSL .mcpwn
internal/promptinject simulador de prompt injection
internal/traversal/   prober de path traversal
internal/ssrfcanary/  canary SSRF local
internal/pollution/   sonda de schema pollution
internal/desync/      motor de desync de lifecycle
internal/protocolfuzz/ fuzzer de protocolo JSON-RPC
internal/raceprober/  sonda de race conditions
internal/exhaustion/  sonda de degradación de latencia
internal/pocgen/      generador de PoC con filtro de seguridad
internal/reporter/    salidas JSON / SARIF / HTML / badge
internal/scorer/      grado de seguridad A-F
internal/schema/      parser y validador de JSON Schema
internal/ui/          render de terminal
internal/version/     única fuente de verdad de la versión
```

## Desarrollo

```bash
go build ./... && go vet ./... && go test ./... -race -cover
```

Piso de cobertura: 80% en `internal/schema` e `internal/auditor`. Cero dependencias externas, tipado estricto, cero emojis, cero guiones bajos fuera de `_test.go`.

Las contribuciones son bienvenidas — abre un issue o un pull request.

---

## Aviso Legal

MCPwn está diseñado y desarrollado exclusivamente para auditorías de seguridad autorizadas, investigación educativa y endurecimiento defensivo de implementaciones del Model Context Protocol (MCP). Los desarrolladores y contribuidores no asumen ninguna responsabilidad y no responden por cualquier uso indebido, daño o pruebas no autorizadas realizadas con este software. Usar esta herramienta contra objetivos sin autorización previa y por escrito de sus dueños está estrictamente prohibido y puede violar leyes locales e internacionales. Al usar MCPwn, aceptas que eres el único responsable de tus acciones y del cumplimiento de todas las regulaciones aplicables.
