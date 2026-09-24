# Idora — Escáner de IDOR / BOLA para auditorías web autorizadas

**Versión 3.6** · Licencia Apache-2.0

Idora detecta **referencias directas inseguras a objetos** (IDOR) y fallos de
**autorización a nivel de objeto** (BOLA — *Broken Object Level Authorization*,
API1 del OWASP API Security Top 10). Son el mismo fallo: la aplicación te deja
acceder a un objeto que no te pertenece por cambiar su identificador, porque el
servidor no verifica que sea tuyo.

Forma parte de la familia de herramientas de auditoría junto a **Centinela**,
**Sereno** y **WP-UserRecon**.

> ⚠️ **Idora es una herramienta ACTIVA.** Envía peticiones que intentan acceder
> a objetos que no corresponden a la identidad usada. **Úsala únicamente sobre
> dominios propios o con autorización explícita y por escrito dentro del alcance
> de la auditoría.** Idora exige declarar un alcance y una autorización, y se
> niega a ejecutar actividad de red sin ellos.

**Novedades de la v3.x (lista para la comunidad):**
- **Empaquetado** como comando global `idora` (instalable con `pipx`).
- Salida **SARIF** + **códigos de salida** para integrar en CI / GitHub code scanning.
- **Guardas de alcance reforzadas** (autorización obligatoria, bloqueo de objetivos
  internos/metadata, denylist, validación anti-trucos, límites de tráfico).
- **Manejo seguro de secretos**: variables de entorno, `--pedir-credenciales`
  (prompt oculto en memoria), redacción de credenciales en cuerpo y URL, `.gitignore`.
- **`--init` interactivo**: elige el método de autenticación y genera solo lo que
  corresponde.
- **Login verificado**: avisa si las credenciales quedaron sin definir (`${VAR}`)
  o si el login no autenticó, en vez de dar un falso "sesión iniciada".
- **`enum` consistente**: usa una sola cuenta (la principal, **A**) y solo prepara
  y pide las credenciales que el método necesita; el re-login deja de reintentar
  tras varios fallos (adiós al bucle de reautenticación).
- **Transparencia del escaneo**: `-v/--verbose` muestra cada petición (método, URL,
  estado), avance por endpoint y un **resumen final** (endpoints, candidatos,
  peticiones enviadas).
- **Re-login fiable**: la sesión solo se considera caída ante señales inequívocas
  (401 o redirección a login), evitando reautenticaciones falsas; `--sin-relogin`
  la desactiva por completo.
- Licencia **Apache-2.0** (archivos `LICENSE` y `NOTICE`).

---

## 1. Instalación

### Como comando global (recomendado)

```bash
pipx install git+https://github.com/Arkuma69/idora.git
idora --help
```

Con `pipx`, Idora queda en su propio entorno aislado (ideal en Kali/Parrot) y
disponible como el comando `idora` desde cualquier carpeta. Para color en
Windows: `pipx install ".[color]"`.

### Como script (desde el repo)

```bash
pip install requests pyyaml colorama     # en macOS/Linux: pip3
python3 idora.py --help
```

Python 3.8+. En macOS/Linux el comando es `python3` (no `python`). En el resto
del README los ejemplos usan `idora`; desde el repo, sustitúyelo por
`python3 idora.py`.

---

## 2. Puesta en marcha rápida

```bash
idora --init                             # interactivo: elige método y crea idora.yaml
idora --detect-auth har:captura.har      # (opcional) deduce la config de auth
# edita idora.yaml (alcance, autorización)
idora --config idora.yaml --pedir-credenciales \
      --crawl https://app.midominio.do/ --method both --out-sarif idora.sarif
```

**`--init` es interactivo:** pregunta qué método usarán las cuentas A y B
(form / cookie / bearer) y genera el `idora.yaml` **solo con los campos y
variables de ese método**. Sin terminal (script/CI) usa `form` por defecto.

```
Método de autenticación de las cuentas A y B:
  1) form   — usuario y contraseña (Idora inicia sesión)
  2) cookie — cookie de sesión ya obtenida
  3) bearer — token / JWT
```

---

## 3. El archivo de configuración (`idora.yaml`)

```yaml
auditoria:
  id: "AUD-2026-001"                 # se envía como cabecera X-Audit-Id
  contacto: "miguel@ejemplo.do"      # se envía como cabecera X-Audit-Contact

autorizacion:                        # REQUERIDO para escaneo activo (queda en el informe)
  referencia: "OFICIO-2026-001"      # nº de oficio / permiso de la auditoría
  responsable: "Nombre del solicitante"
  fecha: "2026-09-21"

alcance:
  dominios_permitidos:               # OBLIGATORIO. Solo el host (sin http:// ni /)
    - "app.midominio.do"
    - "api.midominio.do"
  excluir: []                        # rutas (/admin) o subdominios a excluir

red:
  rate_limit_seg: 0.5                # pausa entre peticiones (mínimo 0.05)
  timeout_seg: 20
  verificar_tls: true
  permitir_privadas: false           # true solo para labs en IP privada/localhost
  max_peticiones: 5000               # tope de seguridad por ejecución
  user_agent: "Idora/3.6 (auditoria autorizada)"

deteccion:
  umbral_similitud: 0.90             # 0-1; a mayor valor, menos falsos positivos
  patrones_parametro_extra: []

identidades:                         # generado por --init según el método elegido
  A:
    tipo: "form"
    login_url: "https://app.midominio.do/login"
    campos: { "email": "${IDORA_USER_A}", "password": "${IDORA_PASS_A}" }
    marcadores: ["${IDORA_USER_A}", "Ana Perez"]
  B:
    tipo: "form"
    login_url: "https://app.midominio.do/login"
    campos: { "email": "${IDORA_USER_B}", "password": "${IDORA_PASS_B}" }
    marcadores: ["${IDORA_USER_B}", "Beto Gomez"]
```

**Formato del dominio:** en `dominios_permitidos` va **solo el host**
(`app.midominio.do`), sin `http://`/`https://`, sin `/` final, sin ruta ni
puerto. Cubre también sus subdominios.

**Tipos de autenticación** (cada `--init` genera uno):

| `tipo`   | Campos / variables                          |
|----------|---------------------------------------------|
| `form`   | `login_url`, `campos` → `${IDORA_USER_x}`, `${IDORA_PASS_x}` |
| `cookie` | `cookies` → `${IDORA_COOKIE_x}` |
| `bearer` | `token` → `${IDORA_TOKEN_x}` |
| `apikey` | `header`, `valor` |
| `none`   | (anónima; incluida siempre de forma automática) |

Los **marcadores** son datos únicos de cada cuenta: si el de A aparece en la
respuesta a B, la fuga queda confirmada. A y B deben ser **dos usuarios distintos**.

---

## 4. Autenticación automática

- **`--detect-auth har:captura.har`** — deduce el tipo de auth desde una petición
  autenticada e imprime el bloque de `identidades` listo para pegar. Sirve cuando
  ya tienes una sesión (cookie/token); no hace login por ti (para eso, `tipo: form`).
- **CSRF automático** — con `tipo: form`, Idora lee el token de la página de login
  (input hidden, meta, o nombres de Laravel/Django/Rails/.NET) y lo envía.
- **Re-login automático** — si la sesión caduca a mitad del escaneo, reautentica
  sola y reintenta (máx. uno cada 10 s por identidad).
- **Login verificado** — si una identidad tiene credenciales sin resolver
  (`${VAR}`) o el login no autentica de verdad (la respuesta sigue siendo la
  página de login y no llega cookie de sesión), Idora lo avisa y la deja como
  **NO autenticada**, en lugar de dar un "sesión iniciada" engañoso.

---

## 5. Manejo seguro de secretos

**No escribas credenciales ni usuarios en el `idora.yaml`.** Todo lo identificable
(usuario, contraseña, token, cookie) va en **variables de entorno**, y el YAML solo
lleva el marcador `${VARIABLE}`. Tienes dos formas de aportar los valores:

### 5.1 Variables de entorno (ideal para CI)

```bash
# Windows (PowerShell)                 # macOS / Linux
$env:IDORA_USER_A = "a@midominio.do"    export IDORA_USER_A="a@midominio.do"
$env:IDORA_PASS_A = "miClaveReal"       export IDORA_PASS_A="miClaveReal"
```

Idora sustituye cada `${VARIABLE}` por su valor al arrancar. Si falta alguna,
avisa **una sola vez por variable** (aunque la uses en varios campos) y sigue.

### 5.2 Prompt oculto (`--pedir-credenciales`, ideal para uso manual)

En lugar de exportar variables, deja que Idora te pregunte los `${VAR}` que falten:

```bash
idora --config idora.yaml --pedir-credenciales
#   IDORA_USER_A: ********   (oculto; solo en memoria, nada en disco ni exportado)
```

Los valores viven solo durante esa ejecución. Si exportaste algunas variables y
otras no, solo te pregunta las que falten.

### 5.3 Redacción en la evidencia

En los informes, las credenciales se tachan como `***REDACTADO***`: en las
**cabeceras** (`Cookie`, `Authorization`, `X-API-Key`), en los **parámetros de
URL** sensibles (`token`, `session`, `apikey`…) y en el **cuerpo** de las
peticiones (campos `password`, `token`, `secret`… en JSON o formularios).

### 5.4 No subas la config al repositorio

Idora incluye un `.gitignore` que excluye `idora.yaml`, los `*.har` (contienen
sesiones), la carpeta `idora_out/`, los `*.sarif` y los `.env`.

---

## 6. Guardas de seguridad (alcance)

- **Autorización obligatoria** (bloque `autorizacion`) para todo escaneo/rastreo
  activo; se estampa en el informe. Sin ella, aborta.
- **Objetivos internos bloqueados**: localhost, IPs privadas y metadata de nube
  (`169.254.169.254`). Actívalos solo con `red.permitir_privadas: true` (labs).
- **Validación anti-trucos**: normaliza el host (puerto, `user@host`, IDN) y
  rechaza alcances amplios (comodines `*`, TLD suelto).
- **Denylist** (`alcance.excluir`) y **límites de tráfico** (piso de rate 0.05 s,
  tope `max_peticiones`).

---

## 7. De dónde salen los endpoints

Fuentes con **`--source`** (repetible; se combinan y deduplican):
`list:endpoints.txt`, `har:captura.har`, `json:reqs.json`,
`openapi:swagger.json` (o una URL de la spec).

Descubrimiento automático:
- **`--crawl URL`** — navega el sitio y descubre endpoints solo (no necesitas
  `endpoints.txt`). Solo lectura, acotado al alcance, ignora logout, usa la
  identidad A si existe. Límites: `--crawl-depth` (2), `--crawl-max` (120).
  `--save-endpoints ARCH` guarda lo descubierto para revisarlo.
- **`--source openapi:`** — de la spec salen todos los endpoints sin crawlear.

```bash
idora --config idora.yaml --crawl https://app.midominio.do/ --method both
```

---

## 8. Metodologías (`--method`) y modos

- `autorize` (recomendada): cruce de sesiones A/B/anónimo. IDs numéricos y UUID.
- `enum`: valores vecinos (id±1…) con **una sola cuenta** (la principal, A); solo
  enteros. Con `--method enum`, Idora prepara y pide únicamente las credenciales de A.
- `both` (por defecto).

Modo **lectura** por defecto. `--mode write` habilita POST/PUT/PATCH (pide
`SI AUTORIZADO`); `--allow-delete` para DELETE; `--detect-only` no envía peticiones
de prueba.

---

## 9. Referencia de la línea de comandos

```
idora [opciones]

--version              Muestra la versión y sale.
--config RUTA          Archivo de configuración YAML.
--pedir-credenciales   Pregunta (oculto) los ${VAR} que falten, sin escribirlos.
-v, --verbose          Muestra cada petición enviada (método, URL, estado).
--sin-relogin          Desactiva la reautenticación automática (útil con cookie).
--source tipo:ruta     Fuente (repetible): list: | har: | json: | openapi:
--crawl URL            Rastrea desde esta URL semilla (repetible).
--crawl-depth N        Profundidad del rastreo           (por defecto: 2)
--crawl-max N          Máximo de páginas                  (por defecto: 120)
--save-endpoints ARCH  Guarda los endpoints descubiertos en un .txt.
--detect-auth FUENTE   Sugiere la config de auth (har:captura.har o un .txt).
--method M             autorize | enum | both             (por defecto: both)
--mode M               read | write                       (por defecto: read)
--allow-delete         Permite DELETE (requiere --mode write).
--detect-only          Solo detecta candidatos; no envía peticiones de prueba.
--out DIR              Directorio de salida               (por defecto: ./idora_out)
--out-sarif ARCH       Escribe SARIF también en esta ruta fija (para CI).
--init                 Genera idora.yaml (interactivo) y endpoints.txt.
```

**Códigos de salida:** `0` sin hallazgos, `1` con hallazgos (para CI/CD).

---

## 10. Resultados e informes

| Nivel | Significado | SARIF |
|-------|-------------|-------|
| **Alta** | Fuga confirmada (marcadores de A en la respuesta a B, o acceso sin auth). | `error` |
| **Media** | Respuesta a B casi idéntica a la de A (similitud ≥ umbral). | `warning` |
| **Baja** | 200 con contenido distinto; revisar manualmente. | `note` |
| **Segura** | 401/403 o "acceso denegado" (no se reporta). | — |

En `--out` se generan, con marca de tiempo: `idora_*.json`, `idora_*.csv`,
`idora_*.md` (con la autorización y recomendación de remediación) e
`idora_*.sarif`. Todas las credenciales se **redactan** (ver sección 5).

Al terminar, Idora imprime un **resumen** (endpoints evaluados, candidatos
numéricos probados y peticiones enviadas), para que sepas cuánto trabajó aunque
no haya hallazgos. Con `-v/--verbose` verás además cada petición en tiempo real.

**SARIF e integración en CI.** Idora emite SARIF 2.1.0 con reglas
(`IDOR-CROSS-ACCOUNT`, `IDOR-UNAUTH`, `BOLA-ENUM`); combinado con el código de
salida, permite fallar un build cuando aparece un IDOR/BOLA nuevo:

```bash
idora --config idora.yaml --source openapi:openapi.json --out-sarif results.sarif
```

---

## 11. Flujo de trabajo recomendado

1. `idora --init` (elige el método) y edita `idora.yaml` con alcance y `autorizacion`.
2. Aporta los secretos: exporta las variables o usa `--pedir-credenciales`.
3. Configura marcadores; usa `--detect-auth` si no sabes el tipo de auth.
4. Descubre endpoints (`--source openapi:` o `--crawl` con `--save-endpoints`).
5. `--detect-only` para revisar los candidatos.
6. Escaneo en lectura con `--method both` (añade `--out-sarif` para CI).
7. Revisa el `.md`; confirma manualmente los *Alta*/*Media* antes de reportar.
8. Solo con autorización por escrito, prueba escritura con `--mode write`.

---

## 12. Problemas comunes

| Síntoma | Causa probable |
|---------|----------------|
| "Variable de entorno no definida: ${...}" | Falta exportar esa variable, o usa `--pedir-credenciales`. |
| "fuera de alcance" con el dominio correcto | Pusiste la URL completa; en `dominios_permitidos` va solo el host. |
| "Idora no realiza actividad activa sin autorización" | Falta el bloque `autorizacion` en la config. |
| "credenciales sin resolver / NO autenticada" | No definiste las `${VAR}` de esa identidad: exporta las variables o usa `--pedir-credenciales`. |
| Se repetía "reautenticando…" muchas veces | La sesión no autenticó (login o credenciales mal). Ya se rinde tras 2 intentos; revisa `login_url` y credenciales. |
| "reautenticando…" estando bien conectado | Falso positivo evitado en v3.6 (solo 401/redirección lo disparan). Si persiste, usa `--sin-relogin`. |
| "Alcance inválido" | Hay comodines o dominios demasiado amplios. |
| El login por formulario falla | El sitio exige CSRF: revisa/forza `csrf_campo` o `csrf_url`. |
| Objetivo bloqueado (privado/metadata) | Es una IP interna; usa `red.permitir_privadas` solo si es un lab. |
| Todo sale *Segura* tras un rato | La sesión expiró; revisa `relogins` en el informe. |

---

## 13. Licencia

Apache License 2.0 — ver `LICENSE` y `NOTICE`. El uso debe limitarse a sistemas
propios o con autorización explícita; los autores no se responsabilizan del mal uso.
