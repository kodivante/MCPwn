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

- **Descubrimiento nativo del protocolo**: handshake MCP completo (`initialize`/`initialized`) vía stdio o SSE, incluyendo `tools/call`, `resources/list`, `resources/read`, `prompts/list` y `prompts/get`.
- **13 reglas de seguridad estáticas**: inyección de comandos, path traversal, SSRF, fuga de credenciales, inyección SQL, denegación de servicio, mutación de estado, tool poisoning, IDOR, mass assignment, tipado débil, campos requeridos faltantes y sinks de prompt injection.
- **Suite de testing dinámico profundo** (`-deep`): quince motores — prober de traversal, canary SSRF, sonda de schema pollution, desync de lifecycle, fuzzer de protocolo, prober de race conditions, sonda de agotamiento, detector de rug-pull, escáner de token leaks, sonda de sampling, detector de side-channels, prober de resource traversal y auditor de prompt templates.
- **Análisis de cadenas de ataque**: post-análisis siempre activo que enlaza hallazgos en rutas de explotación (RCE + fuga de credenciales, SSRF + token leak, prompt injection + SSRF) y reporta la cadena completa con evidencia.
- **Confianza por hallazgo**: cada hallazgo lleva un score `Confidence` de 0-100 — confirmado con evidencia puntúa 95, estático 70 — habilitando gates de CI con casi cero falsos positivos.
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

---

## Referencia de CLI

| Flag | Default | Descripción |
|---|---|---|
| `-transport` | `stdio` | Tipo de transporte: `stdio` o `sse` |
| `-command` | — | Comando a ejecutar para el transporte stdio |
| `-args` | — | Argumentos del comando, separados por comas |
| `-url` | — | URL para el transporte SSE |
| `-output` | `terminal` | Formato: `terminal`, `json`, `sarif`, `html`, `badge` |
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
| Analizador de cadenas | siempre activo | `AttackChain01` (HIGH/CRITICAL) | Enlaza hallazgos en rutas de explotación: RCE + fuga de credenciales se convierte en toma total del host; SSRF + token leak en movimiento lateral — cada cadena reporta sus eslabones con evidencia |
| Fuzzer dinámico | `-fuzz` | Confirma `CmdInjection01` | Payloads benignos de echo/sleep/temp-file con deny-list estricta (`rm`, `curl`, `wget`, `nc`, `ssh`, `sudo` son rechazados por hardcode) |
| Simulador de prompt injection | `-prompt-inject` | `PromptInjection01` | Tres payloads benignos fijos clasificados como reflejo total o parcial |

Cada hallazgo confirmado lleva un score `Confidence` (0-100): confirmado con evidencia puntúa 95, estático 70, side-channel 55. Legible por máquinas en JSON y SARIF para gates de CI.

Los hallazgos de protocolo se renderizan en la sección `--- Advanced Probes ---` del terminal para que nunca se mezclen con los de las tools.

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
