#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Idora — Escáner de IDOR / BOLA para auditorías autorizadas
============================================================
Parte de la familia de herramientas de auditoría (junto a Centinela, Sereno
y WP-UserRecon). A diferencia de esas herramientas —pasivas—, Idora es una
herramienta ACTIVA: envía peticiones que intentan acceder a objetos que no
corresponden a la identidad usada, para detectar referencias directas inseguras
a objetos (IDOR / Broken Object Level Authorization).

USO EXCLUSIVO SOBRE DOMINIOS PROPIOS O CON AUTORIZACIÓN EXPLÍCITA DE PRUEBA
ACTIVA DENTRO DEL ALCANCE DE LA AUDITORÍA.

Metodología principal (estilo Autorize):
  1. Se pide un recurso con la identidad A (propietaria / "víctima").
  2. Se repite la MISMA petición con la sesión de B (atacante / prueba).
  3. Se repite sin sesión (anónimo).
  4. Se comparan las respuestas: si B (o anónimo) obtiene el recurso de A,
     hay una posible fuga de autorización.

Metodología secundaria (enumeración):
  Detecta campos identificadores en la petición, los muta (id±1, vecinos)
  usando una sola sesión y observa si se accede a objetos ajenos.

Requisitos:  pip install requests pyyaml colorama
Autor: (auditoría autorizada)   Licencia de uso interno.
"""

import argparse
import csv
import datetime as _dt
import difflib
import getpass
import ipaddress
import json
import os
import re
import signal
import sys
import time
from collections import deque
from html.parser import HTMLParser
from dataclasses import dataclass, field
from urllib.parse import (urlparse, urlunparse, parse_qsl, urlencode,
                          urljoin, quote, unquote)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] Falta 'requests'. Instala con: pip install requests pyyaml colorama")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None  # Solo obligatorio si se usa config .yaml

# Habilitar colores ANSI en Windows
try:
    import colorama
    colorama.just_fix_windows_console()
except Exception:
    try:
        os.system("")  # activa VT100 en algunas consolas de Windows
    except Exception:
        pass


# =========================================================================
#  Colores y salida (convención de la familia: clase C)
# =========================================================================
class C:
    R = "\033[91m"     # rojo
    G = "\033[92m"     # verde
    Y = "\033[93m"     # amarillo
    B = "\033[94m"     # azul
    M = "\033[95m"     # magenta
    Cy = "\033[96m"    # cian
    W = "\033[97m"     # blanco
    D = "\033[90m"     # gris
    BOLD = "\033[1m"
    RST = "\033[0m"


__version__ = "3.6"

BANNER = f"""{C.Cy}{C.BOLD}
  ___    _
 |_ _|__| | ___  _ __ __ _
  | |/ _` |/ _ \\| '__/ _` |
  | | (_| | (_) | | | (_| |
 |___\\__,_|\\___/|_|  \\__,_|
{C.RST}{C.D}  Escáner de IDOR / BOLA — auditorías autorizadas  v{__version__}
  Herramienta ACTIVA. Úsala solo dentro del alcance autorizado.{C.RST}
"""


def info(msg):    print(f"{C.B}[i]{C.RST} {msg}")
def ok(msg):      print(f"{C.G}[+]{C.RST} {msg}")
def warn(msg):    print(f"{C.Y}[!]{C.RST} {msg}")
def err(msg):     print(f"{C.R}[x]{C.RST} {msg}")
def paso(msg):    print(f"{C.M}[>]{C.RST} {msg}")


# Verbosidad y contadores globales (para transparencia del escaneo)
VERBOSE = False
_STATS = {"peticiones": 0, "candidatos": 0}


# =========================================================================
#  Manejo de Ctrl+C en dos niveles (convención de la familia)
# =========================================================================
_INT_COUNT = {"n": 0}


def _sigint(_sig, _frm):
    _INT_COUNT["n"] += 1
    if _INT_COUNT["n"] == 1:
        print()
        warn("Interrupción recibida. Presiona Ctrl+C otra vez para salir "
             "(se guardará lo recopilado).")
    else:
        print()
        err("Saliendo por interrupción del usuario.")
        raise SystemExit(130)


signal.signal(signal.SIGINT, _sigint)


# =========================================================================
#  Modelos de datos
# =========================================================================
@dataclass
class Identity:
    """Configuración de autenticación de una identidad (A, B, ...)."""
    nombre: str
    tipo: str = "cookie"            # cookie | bearer | apikey | form | none
    cookies: dict = field(default_factory=dict)
    token: str = ""                 # para bearer
    header: str = "X-API-Key"       # para apikey
    valor: str = ""                 # para apikey
    login_url: str = ""             # para form
    campos: dict = field(default_factory=dict)   # form: {campo: valor}
    exito_si_status: int = 200
    marcadores: list = field(default_factory=list)  # datos únicos p/detectar fuga
    # --- login por formulario con token CSRF (paso 2) ---
    csrf_url: str = ""              # página de donde leer el token (por defecto login_url)
    csrf_campo: str = ""           # nombre del campo del token (vacío = autodetectar)
    csrf_en_cookie: str = ""       # cookie tipo XSRF-TOKEN a reflejar en cabecera
    csrf_header: str = "X-XSRF-TOKEN"   # cabecera donde reflejar esa cookie


@dataclass
class Req:
    """Petición normalizada a evaluar."""
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str = None
    content_type: str = None
    origen: str = ""                # de qué fuente vino

    def clave(self):
        return f"{self.method.upper()} {self.url}"


@dataclass
class Resp:
    status: int = 0
    text: str = ""
    length: int = 0
    content_type: str = ""
    elapsed: float = 0.0
    error: str = ""
    location: str = ""


@dataclass
class Candidato:
    """Campo identificador detectado en una petición."""
    localizacion: str   # path | query | form | json
    nombre: str         # nombre del parámetro o índice del segmento
    valor: str
    tipo_valor: str     # int | uuid | hex | base64 | otro


# =========================================================================
#  Detección heurística de campos identificadores  (Bloque 2)
# =========================================================================
NOMBRES_ID = {
    "id", "uid", "uuid", "guid", "pk", "key", "ref", "reference", "referencia",
    "user", "userid", "user_id", "usuario", "usuario_id",
    "account", "accountid", "account_id", "cuenta", "cuenta_id", "acct",
    "customer", "customer_id", "cliente", "cliente_id", "client",
    "order", "order_id", "orden", "pedido", "pedido_id",
    "factura", "invoice", "invoice_id", "folio",
    "doc", "document", "documento", "documento_id", "expediente",
    "file", "file_id", "archivo", "archivo_id",
    "record", "registro", "num", "numero", "no",
    "profile", "perfil", "member", "miembro",
    "empleado", "employee", "emp_id",
    "transaction", "transaccion", "txn", "payment", "pago",
    "ticket", "cita", "appointment", "reserva", "booking",
    "node", "page", "item", "product", "producto", "msg", "message",
    "mensaje", "poliza", "contrato",
}

_RE_INT = re.compile(r"^\d{1,18}$")
_RE_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_RE_HEX24 = re.compile(r"^[0-9a-fA-F]{24}$")           # ObjectId de Mongo
_RE_HEX32 = re.compile(r"^[0-9a-fA-F]{32,}$")          # hashes
_RE_B64 = re.compile(r"^[A-Za-z0-9+/_\-]{8,}={0,2}$")


def tipo_valor(v):
    """Clasifica la 'forma' de un valor para saber si parece un identificador."""
    if v is None:
        return None
    v = str(v).strip()
    if not v:
        return None
    if _RE_INT.match(v):
        return "int"
    if _RE_UUID.match(v):
        return "uuid"
    if _RE_HEX24.match(v):
        return "hex"       # ObjectId
    if _RE_HEX32.match(v):
        return "hex"
    if _RE_B64.match(v) and len(v) >= 8 and not v.isalpha():
        return "base64"
    return None


def _walk_json(obj, prefijo=""):
    """Genera pares (ruta, valor) escalares dentro de un JSON anidado."""
    if isinstance(obj, dict):
        for k, val in obj.items():
            ruta = f"{prefijo}.{k}" if prefijo else str(k)
            yield from _walk_json(val, ruta)
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            ruta = f"{prefijo}[{i}]"
            yield from _walk_json(val, ruta)
    else:
        yield (prefijo, obj)


def detectar_candidatos(req: Req, extra_nombres=None):
    """Devuelve la lista de campos que podrían ser referencias a objetos."""
    nombres = set(NOMBRES_ID)
    if extra_nombres:
        nombres |= {n.lower() for n in extra_nombres}
    cands = []
    p = urlparse(req.url)

    # 1) Segmentos numéricos / con forma de id en la ruta
    for idx, seg in enumerate(p.path.split("/")):
        if not seg:
            continue
        tv = tipo_valor(unquote(seg))
        if tv:
            cands.append(Candidato("path", str(idx), seg, tv))

    # 2) Parámetros en el query string
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        tv = tipo_valor(v)
        if k.lower() in nombres or tv:
            cands.append(Candidato("query", k, v, tv or "otro"))

    # 3) Cuerpo: JSON o form-urlencoded
    if req.body:
        ct = (req.content_type or "").lower()
        if "json" in ct or req.body.strip().startswith(("{", "[")):
            try:
                data = json.loads(req.body)
                for ruta, val in _walk_json(data):
                    hoja = ruta.split(".")[-1].split("[")[0].lower()
                    tv = tipo_valor(val)
                    if hoja in nombres or tv:
                        cands.append(Candidato("json", ruta, str(val),
                                               tv or "otro"))
            except Exception:
                pass
        else:
            for k, v in parse_qsl(req.body, keep_blank_values=True):
                tv = tipo_valor(v)
                if k.lower() in nombres or tv:
                    cands.append(Candidato("form", k, v, tv or "otro"))
    return cands


def marcar_placeholders(req: Req, cands):
    """Representación legible de la petición con los candidatos marcados."""
    txt = f"{req.method.upper()} {req.url}"
    if req.body:
        txt += f"\n    cuerpo: {req.body[:400]}"
    marcas = []
    for c in cands:
        ph = f"{{{{IDOR:{c.localizacion}:{c.nombre}={c.valor} ({c.tipo_valor})}}}}"
        marcas.append(ph)
    return txt, marcas


# =========================================================================
#  Mutación de valores para enumeración
# =========================================================================
def vecinos(valor, tipo, n=3):
    """Genera valores de prueba a partir de un identificador."""
    out = []
    if tipo == "int":
        try:
            base = int(valor)
            for d in range(1, n + 1):
                out.append(str(base + d))
                if base - d >= 0:
                    out.append(str(base - d))
        except ValueError:
            pass
    # Para uuid/hex/base64 no se pueden "adivinar" vecinos de forma fiable;
    # esos casos se cubren con la metodología Autorize (cruce de sesiones).
    return out


def valor_invalido(valor, tipo):
    """Valor claramente inexistente, para aprender la forma de un 404/vacío."""
    if tipo == "int":
        try:
            return str(int(valor) + 999999997)
        except ValueError:
            return "999999999999"
    return "00000000-0000-0000-0000-000000000000"


def _sustituir(req: Req, cand: Candidato, nuevo_valor):
    """Devuelve una copia de req con el candidato sustituido."""
    p = urlparse(req.url)
    new_url = req.url
    new_body = req.body

    if cand.localizacion == "path":
        segs = p.path.split("/")
        idx = int(cand.nombre)
        if 0 <= idx < len(segs):
            segs[idx] = quote(str(nuevo_valor), safe="")
            p = p._replace(path="/".join(segs))
            new_url = urlunparse(p)
    elif cand.localizacion == "query":
        pares = parse_qsl(p.query, keep_blank_values=True)
        pares = [(k, (str(nuevo_valor) if k == cand.nombre else v))
                 for k, v in pares]
        p = p._replace(query=urlencode(pares))
        new_url = urlunparse(p)
    elif cand.localizacion == "form":
        pares = parse_qsl(req.body or "", keep_blank_values=True)
        pares = [(k, (str(nuevo_valor) if k == cand.nombre else v))
                 for k, v in pares]
        new_body = urlencode(pares)
    elif cand.localizacion == "json":
        try:
            data = json.loads(req.body)
            data = _set_json(data, cand.nombre, nuevo_valor)
            new_body = json.dumps(data)
        except Exception:
            pass

    return Req(req.method, new_url, dict(req.headers), new_body,
               req.content_type, req.origen)


def _set_json(data, ruta, nuevo):
    """Fija un valor en un JSON siguiendo una ruta tipo 'a.b[0].id'."""
    tokens = re.findall(r"[^.\[\]]+|\[\d+\]", ruta)
    ref = data
    for i, tok in enumerate(tokens):
        ultimo = (i == len(tokens) - 1)
        if tok.startswith("[") and tok.endswith("]"):
            idx = int(tok[1:-1])
            if ultimo:
                ref[idx] = nuevo
            else:
                ref = ref[idx]
        else:
            if ultimo:
                ref[tok] = nuevo
            else:
                ref = ref[tok]
    return data


# =========================================================================
#  Cargadores de fuentes  (Bloque 3)
# =========================================================================
def cargar_lista(ruta):
    """Formato:  METHOD url  [|| cuerpo || content-type]  (# comentarios)."""
    reqs = []
    with open(ruta, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            partes = [x.strip() for x in ln.split("||")]
            cab = partes[0].split(None, 1)
            if len(cab) == 1:
                method, url = "GET", cab[0]
            else:
                method, url = cab[0], cab[1]
            body = partes[1] if len(partes) > 1 and partes[1] else None
            ct = partes[2] if len(partes) > 2 and partes[2] else None
            reqs.append(Req(method, url, {}, body, ct, f"lista:{os.path.basename(ruta)}"))
    return reqs


def cargar_har(ruta):
    """Extrae peticiones de un archivo HAR (exportado de Burp o DevTools)."""
    reqs = []
    with open(ruta, "r", encoding="utf-8") as f:
        har = json.load(f)
    for entry in har.get("log", {}).get("entries", []):
        r = entry.get("request", {})
        method = r.get("method", "GET")
        url = r.get("url", "")
        if not url:
            continue
        headers = {h["name"]: h["value"] for h in r.get("headers", [])
                   if not h["name"].lower().startswith(":")}
        body = None
        ct = None
        pd = r.get("postData")
        if pd:
            ct = pd.get("mimeType")
            body = pd.get("text")
            if not body and pd.get("params"):
                body = urlencode({p["name"]: p.get("value", "")
                                  for p in pd["params"]})
        reqs.append(Req(method, url, headers, body, ct,
                        f"har:{os.path.basename(ruta)}"))
    return reqs


def cargar_json(ruta):
    """Lista de objetos: {method,url,headers,body,content_type}."""
    reqs = []
    with open(ruta, "r", encoding="utf-8") as f:
        data = json.load(f)
    for o in data:
        reqs.append(Req(o.get("method", "GET"), o["url"],
                        o.get("headers", {}), o.get("body"),
                        o.get("content_type"), f"json:{os.path.basename(ruta)}"))
    return reqs


def cargar_fuentes(fuentes, cfg=None):
    reqs = []
    for spec in fuentes:
        if ":" not in spec:
            warn(f"Fuente ignorada (formato tipo:ruta): {spec}")
            continue
        tipo, ruta = spec.split(":", 1)
        es_url = ruta.startswith(("http://", "https://"))
        if not es_url and not os.path.exists(ruta):
            err(f"No existe la fuente: {ruta}")
            continue
        try:
            if tipo == "list":
                reqs += cargar_lista(ruta)
            elif tipo == "har":
                reqs += cargar_har(ruta)
            elif tipo == "json":
                reqs += cargar_json(ruta)
            elif tipo == "openapi":
                reqs += cargar_openapi(ruta, cfg)
            else:
                warn(f"Tipo de fuente desconocido: {tipo}")
        except Exception as e:
            err(f"Error leyendo {ruta}: {e}")
    return reqs


# =========================================================================
#  Adaptador OpenAPI / Swagger  (descubrimiento sin crawlear)
# =========================================================================
def _resolver_ref(spec, nodo):
    """Resuelve referencias $ref locales (#/...) de forma superficial."""
    if isinstance(nodo, dict) and "$ref" in nodo:
        ref = nodo["$ref"]
        if isinstance(ref, str) and ref.startswith("#/"):
            cur = spec
            for parte in ref[2:].split("/"):
                parte = parte.replace("~1", "/").replace("~0", "~")
                if isinstance(cur, dict) and parte in cur:
                    cur = cur[parte]
                else:
                    return {}
            return cur
    return nodo


def _valor_muestra(esquema):
    """Devuelve un valor de ejemplo para un parámetro."""
    if not isinstance(esquema, dict):
        return "1"
    if "example" in esquema:
        return str(esquema["example"])
    if "default" in esquema:
        return str(esquema["default"])
    if esquema.get("enum"):
        return str(esquema["enum"][0])
    t = esquema.get("type", "integer")
    return {"integer": "1", "number": "1", "string": "1",
            "boolean": "true"}.get(t, "1")


def cargar_openapi(ruta, cfg):
    """Genera peticiones a partir de una especificación OpenAPI/Swagger.

    'ruta' puede ser un archivo local (.json/.yaml) o una URL (que debe estar
    dentro del alcance; se descarga con una sola petición GET de solo lectura).
    """
    if ruta.startswith(("http://", "https://")):
        if cfg is None or not cfg.en_alcance(ruta):
            err(f"La spec {ruta} está fuera de alcance; no se descarga.")
            return []
        r = enviar(cfg, _nueva_sesion(cfg), Req("GET", ruta, {}, None, None, "openapi"))
        if r.error or r.status != 200:
            err(f"No se pudo descargar la spec ({r.status or r.error}).")
            return []
        texto = r.text
    else:
        with open(ruta, "r", encoding="utf-8") as f:
            texto = f.read()

    try:
        spec = json.loads(texto)
    except Exception:
        if yaml is None:
            err("La spec parece YAML; instala pyyaml (pip install pyyaml).")
            return []
        spec = yaml.safe_load(texto)
    if not isinstance(spec, dict):
        err("Especificación OpenAPI no válida.")
        return []

    # Determinar la(s) URL(s) base
    bases = []
    for s in spec.get("servers", []) or []:
        u = (s.get("url") or "").rstrip("/")
        if u.startswith("http"):
            bases.append(u)
        elif u.startswith("/") and cfg:
            bases += [f"https://{d}{u}" for d in cfg.dominios]
    if not bases and spec.get("host"):
        esquema = (spec.get("schemes") or ["https"])[0]
        bases.append(f"{esquema}://{spec['host']}"
                     f"{(spec.get('basePath') or '').rstrip('/')}")
    if not bases and cfg:
        bases = [f"https://{d}" for d in cfg.dominios]
    if not bases:
        err("No se pudo determinar la URL base de la spec.")
        return []
    base = bases[0]

    reqs = []
    etiqueta = f"openapi:{os.path.basename(ruta)[:40]}"
    for ruta_api, item in (spec.get("paths", {}) or {}).items():
        item = _resolver_ref(spec, item)
        if not isinstance(item, dict):
            continue
        params_path = item.get("parameters", [])
        for metodo, op in item.items():
            if metodo.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            op = _resolver_ref(spec, op)
            if not isinstance(op, dict):
                continue
            params = list(params_path) + list(op.get("parameters", []))
            path_final, query = ruta_api, {}
            for p in params:
                p = _resolver_ref(spec, p)
                if not isinstance(p, dict) or not p.get("name"):
                    continue
                esquema = p.get("schema", p)  # v3 usa 'schema'; v2 es inline
                val = _valor_muestra(esquema)
                if p.get("in") == "path":
                    path_final = path_final.replace(
                        "{" + p["name"] + "}", quote(val, safe=""))
                elif p.get("in") == "query":
                    query[p["name"]] = val
            url = base + path_final
            if query:
                url += "?" + urlencode(query)
            if cfg and not cfg.en_alcance(url):
                continue
            body, ct = (None, None)
            if metodo.lower() in ("post", "put", "patch"):
                body, ct = "{}", "application/json"
            reqs.append(Req(metodo.upper(), url, {}, body, ct, etiqueta))
    ok(f"OpenAPI: {len(reqs)} operación(es) cargada(s) desde la spec.")
    return reqs


# =========================================================================
#  Crawler acotado con semilla  (descubrimiento automático de endpoints)
# =========================================================================
class _Extractor(HTMLParser):
    """Extrae enlaces y formularios de una página HTML."""
    def __init__(self):
        super().__init__()
        self.enlaces = []
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ("a", "link") and d.get("href"):
            self.enlaces.append(d["href"])
        elif tag == "form":
            self._form = {"action": d.get("action", ""),
                          "method": (d.get("method") or "GET").upper(),
                          "inputs": {}}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            if d.get("name"):
                self._form["inputs"][d["name"]] = d.get("value", "1")

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


_RE_LOGOUT = re.compile(r"(logout|log-out|cerrar[-_]?sesion|salir|signout)", re.I)


def rastrear(cfg, sesion, semillas, profundidad=2, maximo=120):
    """Rastreo de solo lectura acotado a los dominios permitidos.

    Devuelve una lista de peticiones (Req) descubiertas. Sigue enlaces internos
    hasta 'profundidad' y visita como máximo 'maximo' páginas, respetando el
    rate limit de la config. Los formularios se registran como endpoints
    candidatos pero NO se envían durante el rastreo.
    """
    vistos = set()
    encontrados = {}
    cola = deque((s, 0) for s in semillas)
    paso(f"Rastreo desde {len(semillas)} semilla(s) — profundidad "
         f"{profundidad}, máx {maximo} páginas (solo lectura).")
    while cola and len(vistos) < maximo:
        url, prof = cola.popleft()
        url = url.split("#")[0]
        if url in vistos or not cfg.en_alcance(url) or _RE_LOGOUT.search(url):
            continue
        vistos.add(url)
        encontrados[f"GET {url}"] = Req("GET", url, {}, None, None, "crawler")
        r = enviar(cfg, sesion, Req("GET", url, {}, None, None, "crawler"))
        if r.error or r.status >= 400:
            continue
        ct = (r.content_type or "").lower()
        if ct and "html" not in ct and "xml" not in ct:
            continue
        ext = _Extractor()
        try:
            ext.feed(r.text)
        except Exception:
            pass
        if prof < profundidad:
            for href in ext.enlaces:
                nueva = urljoin(url, href).split("#")[0]
                if (nueva.startswith(("http://", "https://"))
                        and cfg.en_alcance(nueva)
                        and nueva not in vistos
                        and not _RE_LOGOUT.search(nueva)):
                    cola.append((nueva, prof + 1))
        for form in ext.forms:
            accion = urljoin(url, form["action"] or url)
            if not cfg.en_alcance(accion):
                continue
            metodo = form["method"] if form["method"] in ("GET", "POST") else "GET"
            if metodo == "GET":
                p = urlparse(accion)
                q = urlencode(form["inputs"])
                dest = urlunparse(p._replace(query=q)) if q else accion
                encontrados[f"GET {dest}"] = Req(
                    "GET", dest, {}, None, None, "crawler:form")
            else:
                encontrados[f"POST {accion}"] = Req(
                    "POST", accion, {}, urlencode(form["inputs"]),
                    "application/x-www-form-urlencoded", "crawler:form")
    ok(f"Rastreo terminado: {len(vistos)} página(s) visitada(s), "
       f"{len(encontrados)} endpoint(s) único(s).")
    return list(encontrados.values())


def guardar_endpoints(reqs, ruta):
    """Vuelca los endpoints descubiertos a un archivo de lista revisable."""
    with open(ruta, "w", encoding="utf-8") as f:
        f.write("# Endpoints descubiertos por Idora — revísalos antes de usar.\n")
        f.write("# Formato: METHOD url [|| cuerpo || content-type]\n")
        for r in reqs:
            linea = f"{r.method} {r.url}"
            if r.body:
                linea += f" || {r.body} || {r.content_type or ''}"
            f.write(linea + "\n")
    ok(f"Endpoints guardados en {ruta} ({len(reqs)}).")


# =========================================================================
#  Configuración
# =========================================================================
def _es_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _host_norm(h):
    """Normaliza un host: minúsculas, sin espacios ni punto final, IDN→punycode."""
    h = (h or "").strip().lower().rstrip(".")
    try:
        h = h.encode("idna").decode("ascii")
    except Exception:
        pass
    return h


# Nombres de campos/parámetros que se redactan en la evidencia
_CAMPOS_SENSIBLES = {
    "password", "passwd", "pass", "pwd", "secret", "token", "access_token",
    "refresh_token", "apikey", "api_key", "api-key", "key", "sig", "signature",
    "session", "sessionid", "sid", "auth", "authorization", "jwt", "otp",
}


def _redactar_url(url):
    """Redacta valores de parámetros sensibles en el query string de una URL."""
    try:
        p = urlparse(url)
        if not p.query:
            return url
        pares = [(k, ("***REDACTADO***" if k.lower() in _CAMPOS_SENSIBLES else v))
                 for k, v in parse_qsl(p.query, keep_blank_values=True)]
        return urlunparse(p._replace(query=urlencode(pares, safe="*")))
    except Exception:
        return url


def _clave_redactada(req):
    """Como req.clave() pero con la URL redactada (para omitidas/evidencia)."""
    return f"{req.method} {_redactar_url(req.url)}"


def _redactar_json(obj):
    if isinstance(obj, dict):
        return {k: ("***REDACTADO***" if str(k).lower() in _CAMPOS_SENSIBLES
                    else _redactar_json(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redactar_json(x) for x in obj]
    return obj


def _redactar_cuerpo(body, content_type=""):
    """Redacta credenciales dentro del cuerpo (JSON o form-urlencoded)."""
    if not body:
        return body
    ct = (content_type or "").lower()
    try:
        if "json" in ct or body.strip().startswith(("{", "[")):
            return json.dumps(_redactar_json(json.loads(body)))[:1000]
        pares = [(k, ("***REDACTADO***" if k.lower() in _CAMPOS_SENSIBLES else v))
                 for k, v in parse_qsl(body, keep_blank_values=True)]
        if pares:
            return urlencode(pares, safe="*")[:1000]
    except Exception:
        pass
    return body[:1000]


_RE_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expandir_env(obj):
    """Sustituye ${VAR} por variables de entorno en todo el árbol de la config."""
    if isinstance(obj, dict):
        return {k: _expandir_env(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expandir_env(x) for x in obj]
    if isinstance(obj, str):
        def _repl(m):
            v = os.environ.get(m.group(1))
            return m.group(0) if v is None else v
        return _RE_ENV.sub(_repl, obj)
    return obj


def _vars_pendientes(obj, acc=None):
    """Lista única (en orden) de variables ${VAR} sin resolver en el árbol."""
    if acc is None:
        acc = []
    if isinstance(obj, dict):
        for v in obj.values():
            _vars_pendientes(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _vars_pendientes(v, acc)
    elif isinstance(obj, str):
        for m in _RE_ENV.findall(obj):
            if m not in acc:
                acc.append(m)
    return acc


def _sustituir_vars(obj, valores):
    if isinstance(obj, dict):
        return {k: _sustituir_vars(v, valores) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sustituir_vars(x, valores) for x in obj]
    if isinstance(obj, str):
        return _RE_ENV.sub(lambda m: valores.get(m.group(1), m.group(0)), obj)
    return obj


def _datos_relevantes(datos, metodo):
    """Vista de la config sin las identidades que el método no usará (enum → solo A)."""
    if metodo != "enum" or not isinstance(datos, dict):
        return datos
    import copy
    d = copy.deepcopy(datos)
    idents = d.get("identidades", {})
    if isinstance(idents, dict):
        d["identidades"] = {k: v for k, v in idents.items() if k == "A"}
    return d


def _pedir_credenciales(datos, solo=None):
    """Pregunta (oculto, solo en memoria) los ${VAR} que falten por resolver."""
    pendientes = _vars_pendientes(datos)
    if solo is not None:
        pendientes = [v for v in pendientes if v in solo]
    if not pendientes:
        return datos
    info("Introduce los valores que faltan (ocultos; no se guardan en disco):")
    valores = {}
    for var in pendientes:
        try:
            valores[var] = getpass.getpass(f"  {var}: ")
        except Exception:
            valores[var] = ""
    return _sustituir_vars(datos, valores)


class Config:
    def __init__(self, d):
        self.aud_id = d.get("auditoria", {}).get("id", "AUD-SIN-ID")
        self.aud_contacto = d.get("auditoria", {}).get("contacto", "")
        alc = d.get("alcance", {})
        self.dominios = [_host_norm(x) for x in
                         alc.get("dominios_permitidos", []) if x]
        self.excluir = [str(x).lower() for x in alc.get("excluir", [])]
        self.autorizacion = d.get("autorizacion", {})
        # Rechazar alcances demasiado amplios (comodines / TLD suelto)
        self.errores = []
        for dom in alc.get("dominios_permitidos", []):
            s = str(dom).strip().lower()
            if not s or "*" in s:
                self.errores.append(f"comodín no permitido: '{dom}'")
            elif "." not in s and s != "localhost" and not _es_ip(s):
                self.errores.append(f"dominio demasiado amplio: '{dom}'")
        red = d.get("red", {})
        self.rate = float(red.get("rate_limit_seg", 0.5))
        self.timeout = int(red.get("timeout_seg", 20))
        self.verificar_tls = bool(red.get("verificar_tls", True))
        self.permitir_privadas = bool(red.get("permitir_privadas", False))
        self.permitir_sin_limite = bool(red.get("permitir_sin_limite", False))
        self.max_peticiones = int(red.get("max_peticiones", 5000))
        self.user_agent = red.get(
            "user_agent", f"Idora/{__version__} (+auditoria {self.aud_id})")
        # Piso de rate limit: evita un DoS accidental con 0
        if self.rate < 0.05 and not self.permitir_sin_limite:
            warn("rate_limit_seg demasiado bajo; ajustado a 0.05s "
                 "(usa red.permitir_sin_limite para forzarlo).")
            self.rate = 0.05
        det = d.get("deteccion", {})
        self.umbral = float(det.get("umbral_similitud", 0.90))
        self.extra_nombres = det.get("patrones_parametro_extra", [])
        self.identidades = {}
        for nombre, cfg in d.get("identidades", {}).items():
            cfg = dict(cfg)
            cfg["nombre"] = nombre
            self.identidades[nombre] = Identity(**{
                k: v for k, v in cfg.items()
                if k in Identity.__dataclass_fields__})

    def alcance_valido(self):
        return not self.errores

    def objetivo_peligroso(self, host):
        """Motivo si el host es un objetivo prohibido (interno/metadata); si no, None."""
        if host in ("localhost", "ip6-localhost"):
            return None if self.permitir_privadas else "loopback (localhost)"
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        if ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return "IP enlace-local/reservada (p. ej. metadata de nube 169.254.169.254)"
        if (ip.is_loopback or ip.is_private) and not self.permitir_privadas:
            return "IP privada/loopback (usa red.permitir_privadas si es intencional)"
        return None

    def excluido(self, url):
        p = urlparse(url)
        host = _host_norm(p.hostname or "")
        ruta = p.path or "/"
        for pat in self.excluir:
            if pat.startswith("/"):
                if ruta.startswith(pat):
                    return f"ruta excluida ({pat})"
            elif host == pat or host.endswith("." + pat):
                return f"host excluido ({pat})"
        return None

    def motivo_bloqueo(self, url):
        """None si la URL es válida y está en alcance; si no, el motivo textual."""
        host = _host_norm(urlparse(url).hostname or "")
        if not host:
            return "URL sin host"
        if not self.dominios:
            return "sin alcance definido"
        if not any(host == d or host.endswith("." + d) for d in self.dominios):
            return "fuera de alcance"
        peligro = self.objetivo_peligroso(host)
        if peligro:
            return peligro
        return self.excluido(url)

    def en_alcance(self, url):
        return self.motivo_bloqueo(url) is None


CONFIG_TEMPLATE = """\
# ---------------------------------------------------------------------------
# Idora — archivo de configuración
# ---------------------------------------------------------------------------
auditoria:
  id: "AUD-2026-001"                 # se envía como X-Audit-Id
  contacto: "miguel@ejemplo.do"      # se envía como X-Audit-Contact

autorizacion:                        # requerido para escaneo activo (queda en el informe)
  referencia: "OFICIO-2026-001"      # nº de oficio / permiso de la auditoría
  responsable: "Nombre del solicitante"
  fecha: "2026-09-21"

alcance:
  # SOLO se probarán URLs cuyos dominios estén aquí. Obligatorio.
  dominios_permitidos:
    - "app.midominio.do"
    - "api.midominio.do"
  excluir: []                        # rutas (/admin) o subdominios sensibles a excluir

red:
  rate_limit_seg: 0.5                # pausa entre peticiones (mínimo 0.05)
  timeout_seg: 20
  verificar_tls: true
  permitir_privadas: false           # true solo para labs en IP privada/localhost
  max_peticiones: 5000               # tope de seguridad de peticiones por ejecución
  user_agent: "Idora/3.0 (auditoria autorizada)"

deteccion:
  umbral_similitud: 0.90             # 0-1; a mayor valor, menos falsos positivos
  patrones_parametro_extra: []       # nombres de parámetro extra propios del sitio

"""

_IDENT_HEADER = """\
identidades:
  # Buenas prácticas: NO escribas usuarios ni secretos aquí. Usa ${{VARIABLE}}
  # y expórtalas (o usa --pedir-credenciales) antes de ejecutar.
  # Método de autenticación seleccionado: {metodo}.
"""

_IDENT_FORM = """\
  A:                                 # propietaria / "víctima"
    tipo: "form"
    login_url: "https://app.midominio.do/login"
    campos: { "email": "${IDORA_USER_A}", "password": "${IDORA_PASS_A}" }
    exito_si_status: 200
    # csrf_campo: "_token"          # (opcional) nombre del token; vacío = autodetecta
    marcadores: ["${IDORA_USER_A}", "Ana Perez"]   # dato único de A
  B:                                 # atacante / cuenta de prueba
    tipo: "form"
    login_url: "https://app.midominio.do/login"
    campos: { "email": "${IDORA_USER_B}", "password": "${IDORA_PASS_B}" }
    exito_si_status: 200
    marcadores: ["${IDORA_USER_B}", "Beto Gomez"]   # dato único de B
"""

_IDENT_COOKIE = """\
  A:                                 # propietaria / "víctima"
    tipo: "cookie"
    cookies: { "session": "${IDORA_COOKIE_A}" }
    marcadores: ["a@midominio.do", "Ana Perez"]     # dato único de A (edítalo)
  B:                                 # atacante / cuenta de prueba
    tipo: "cookie"
    cookies: { "session": "${IDORA_COOKIE_B}" }
    marcadores: ["b@midominio.do", "Beto Gomez"]    # dato único de B (edítalo)
"""

_IDENT_BEARER = """\
  A:                                 # propietaria / "víctima"
    tipo: "bearer"
    token: "${IDORA_TOKEN_A}"
    marcadores: ["a@midominio.do", "Ana Perez"]     # dato único de A (edítalo)
  B:                                 # atacante / cuenta de prueba
    tipo: "bearer"
    token: "${IDORA_TOKEN_B}"
    marcadores: ["b@midominio.do", "Beto Gomez"]    # dato único de B (edítalo)
"""

_IDENT_BLOQUES = {"form": _IDENT_FORM, "cookie": _IDENT_COOKIE,
                  "bearer": _IDENT_BEARER}

LISTA_TEMPLATE = """\
# Un endpoint por línea.  Formato:  METHOD url  [|| cuerpo || content-type]
GET https://app.midominio.do/api/facturas/1001
GET https://app.midominio.do/perfil?user_id=1001
POST https://app.midominio.do/api/pedidos/ver || {"pedido_id": 1001} || application/json
"""


# =========================================================================
#  Sesiones autenticadas por identidad
# =========================================================================
def _nueva_sesion(cfg: Config):
    s = requests.Session()
    s.verify = cfg.verificar_tls
    retry = Retry(total=2, backoff_factor=0.4,
                  status_forcelist=[502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({
        "User-Agent": cfg.user_agent,
        "X-Audit-Id": cfg.aud_id,
        "X-Audit-Contact": cfg.aud_contacto,
        "Accept": "*/*",
    })
    return s


# Nombres habituales de campos de token CSRF en formularios de login
_CSRF_NOMBRES = ("_token", "csrfmiddlewaretoken", "authenticity_token",
                 "csrf_token", "_csrf", "csrf", "csrftoken", "xsrf",
                 "__requestverificationtoken")


def _extraer_csrf(html, campo=""):
    """Extrae el token CSRF del HTML (input hidden o meta tag)."""
    candidatos = [campo] if campo else list(_CSRF_NOMBRES)
    for nombre in candidatos:
        if not nombre:
            continue
        m = re.search(
            r"""<input[^>]*name=["']%s["'][^>]*value=["']([^"']*)["']"""
            % re.escape(nombre), html, re.I) or re.search(
            r"""<input[^>]*value=["']([^"']*)["'][^>]*name=["']%s["']"""
            % re.escape(nombre), html, re.I)
        if m:
            return nombre, m.group(1)
    m = re.search(
        r"""<meta[^>]*name=["']csrf-token["'][^>]*content=["']([^"']*)["']""",
        html, re.I)
    if m:
        return (campo or "_token"), m.group(1)
    return None, None


def _parece_pagina_login(html):
    """Heurística: ¿la respuesta sigue siendo un formulario de login?"""
    h = (html or "").lower()
    return ("password" in h or "contraseña" in h) and any(
        t in h for t in ("login", "iniciar sesión", "inicia sesión",
                         "sign in", "autentic"))


def _ident_placeholders(ident):
    """Variables ${VAR} sin resolver en las credenciales de una identidad."""
    valores = [ident.token, ident.valor, ident.login_url]
    valores += [str(v) for v in ident.campos.values()]
    valores += [str(v) for v in ident.cookies.values()]
    pend = []
    for val in valores:
        for m in _RE_ENV.findall(val or ""):
            if m not in pend:
                pend.append(m)
    return pend


def _login_formulario(cfg, s, ident):
    """Login por formulario gestionando token CSRF (input hidden, meta o cookie)."""
    campos = dict(ident.campos)
    try:
        # 1) GET a la página de login para capturar token CSRF y cookies previas
        try:
            g = s.get(ident.csrf_url or ident.login_url, timeout=cfg.timeout)
            nombre_tok, valor_tok = _extraer_csrf(g.text or "", ident.csrf_campo)
            if valor_tok:
                campos[nombre_tok] = valor_tok
                info(f"Identidad {ident.nombre}: token CSRF "
                     f"'{nombre_tok}' capturado del formulario.")
            # CSRF entregado como cookie a reflejar en cabecera (SPA/Laravel/Angular)
            cookie_csrf = ident.csrf_en_cookie or "XSRF-TOKEN"
            if cookie_csrf in s.cookies:
                s.headers[ident.csrf_header] = unquote(s.cookies.get(cookie_csrf))
                info(f"Identidad {ident.nombre}: cookie CSRF reflejada en "
                     f"{ident.csrf_header}.")
        except Exception:
            pass  # sin token: se intenta el login directo
        # 2) POST de credenciales
        cookies_antes = len(s.cookies)
        r = s.post(ident.login_url, data=campos,
                   timeout=cfg.timeout, allow_redirects=True)
        if r.status_code != ident.exito_si_status:
            warn(f"Identidad {ident.nombre}: login devolvió {r.status_code} "
                 f"(esperado {ident.exito_si_status}); NO autenticada.")
            return False
        # Verificar de verdad: la respuesta no debe seguir siendo el login, y
        # normalmente el servidor entrega alguna cookie de sesión nueva.
        if _parece_pagina_login(r.text) and len(s.cookies) <= cookies_antes:
            warn(f"Identidad {ident.nombre}: el login respondió "
                 f"{r.status_code} pero la respuesta sigue pareciendo la "
                 f"página de login y no se recibió cookie de sesión; "
                 f"credenciales probablemente incorrectas. NO autenticada.")
            return False
        ok(f"Identidad {ident.nombre}: sesión iniciada.")
        return True
    except Exception as e:
        err(f"Identidad {ident.nombre}: fallo de login: {e}")
        return False


def construir_sesion(cfg: Config, ident: Identity):
    """Crea y autentica la sesión de una identidad."""
    s = _nueva_sesion(cfg)
    if ident.tipo == "none":
        return s
    pend = _ident_placeholders(ident)
    if pend:
        faltan = ", ".join("${" + v + "}" for v in pend)
        warn(f"Identidad {ident.nombre}: credenciales sin resolver ({faltan}); "
             f"quedará como NO autenticada. Define las variables o usa "
             f"--pedir-credenciales.")
        return s
    if ident.tipo == "cookie":
        for k, v in ident.cookies.items():
            s.cookies.set(k, v)
    elif ident.tipo == "bearer":
        s.headers["Authorization"] = f"Bearer {ident.token}"
    elif ident.tipo == "apikey":
        s.headers[ident.header] = ident.valor
    elif ident.tipo == "form":
        _login_formulario(cfg, s, ident)
    return s


# Cabeceras que NO se reenvían de la petición original: dejamos que la
# sesión inyecte sus propias credenciales.
_HEADERS_A_QUITAR = {"cookie", "authorization", "x-api-key", "host",
                     "content-length", "connection"}


def enviar(cfg: Config, sesion, req: Req):
    headers = {k: v for k, v in req.headers.items()
               if k.lower() not in _HEADERS_A_QUITAR}
    if req.content_type and "content-type" not in {h.lower() for h in headers}:
        headers["Content-Type"] = req.content_type
    _STATS["peticiones"] += 1
    try:
        r = sesion.request(req.method.upper(), req.url,
                           headers=headers,
                           data=req.body if req.body else None,
                           timeout=cfg.timeout, allow_redirects=False)
        texto = r.text or ""
        resp = Resp(r.status_code, texto, len(texto),
                    r.headers.get("Content-Type", ""),
                    r.elapsed.total_seconds(),
                    location=r.headers.get("Location", ""))
    except Exception as e:
        resp = Resp(error=str(e))
    finally:
        time.sleep(cfg.rate)
    if VERBOSE:
        p = urlparse(req.url)
        ruta = (p.path or "/") + (("?" + p.query) if p.query else "")
        print(f"{C.D}    >> {req.method} {ruta[:90]} -> "
              f"{resp.error or resp.status} ({resp.length}b){C.RST}")
    return resp


# =========================================================================
#  Comparación y puntuación
# =========================================================================
_RE_VOLATIL = re.compile(
    r"(csrf[^\"'>]*|_token|nonce|timestamp|[0-9a-f]{32,})", re.I)


def _normaliza(txt):
    txt = _RE_VOLATIL.sub("", txt)
    return re.sub(r"\s+", " ", txt).strip()


def similitud(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(
        None, _normaliza(a)[:20000], _normaliza(b)[:20000]).ratio()


def _denegado(resp: Resp):
    if resp.error:
        return True
    if resp.status in (401, 403):
        return True
    cuerpo = resp.text.lower()
    if any(t in cuerpo for t in ("acceso denegado", "no autorizado",
                                 "unauthorized", "forbidden", "acceso no permitido")):
        return True
    return False


def analizar_autorize(cfg, req, rA, rB, rAnon, marcadores_A):
    """Compara la respuesta de A contra la de B y la anónima."""
    hallazgos = []
    sim_AB = similitud(rA.text, rB.text)
    fuga_marcador = any(m and m in rB.text for m in marcadores_A)

    # --- Cruce A vs B ---
    if rA.status == 200 and not rA.error:
        if _denegado(rB):
            nivel = "Segura"
            detalle = f"B recibió {rB.status or rB.error} — autorización aplicada."
        elif rB.status == 200 and fuga_marcador:
            nivel = "Alta"
            detalle = ("La respuesta a B contiene marcadores únicos de A "
                       "(fuga de datos confirmada).")
        elif rB.status == 200 and sim_AB >= cfg.umbral:
            nivel = "Media"
            detalle = (f"Respuesta a B casi idéntica a la de A "
                       f"(similitud {sim_AB:.2f}).")
        elif rB.status == 200:
            nivel = "Baja"
            detalle = (f"B obtuvo 200 pero contenido distinto "
                       f"(similitud {sim_AB:.2f}); revisar manualmente.")
        else:
            nivel = "Segura"
            detalle = f"B recibió estado {rB.status}."
        hallazgos.append(("A→B", nivel, detalle, sim_AB, fuga_marcador))

    # --- Chequeo anónimo (roto sin autenticación) ---
    if rA.status == 200 and not rA.error:
        sim_An = similitud(rA.text, rAnon.text)
        fuga_an = any(m and m in rAnon.text for m in marcadores_A)
        if not _denegado(rAnon) and rAnon.status == 200 and \
           (sim_An >= cfg.umbral or fuga_an):
            hallazgos.append(("A→anónimo", "Alta",
                              "Recurso accesible SIN autenticación.",
                              sim_An, fuga_an))
    return hallazgos


# =========================================================================
#  Motor principal
# =========================================================================
class Idora:
    def __init__(self, cfg: Config, modo="read", permitir_delete=False,
                 relogin=True):
        self.cfg = cfg
        self.modo = modo
        self.permitir_delete = permitir_delete
        self.relogin_activo = relogin
        self.hallazgos = []
        self.omitidas = []
        self.sesiones = {}
        self.relogins = 0
        self._ultimo_relogin = {}
        self._relogin_fallos = {}
        self._sin_reintentar = set()
        self.autorizacion_alcance = None
        self.autorizacion_escritura = None  # texto de confirmación

    # -- Guardas de seguridad (Bloque 4) --------------------------------
    def _metodo_permitido(self, req: Req):
        m = req.method.upper()
        if m in ("GET", "HEAD", "OPTIONS"):
            return True
        if m == "DELETE" and not self.permitir_delete:
            self.omitidas.append((_clave_redactada(req),
                                  "DELETE bloqueado (usa --allow-delete)"))
            return False
        if self.modo != "write":
            self.omitidas.append((_clave_redactada(req),
                                  f"{m} omitido (modo lectura)"))
            return False
        return True

    def confirmar_autorizacion_escritura(self):
        """Pregunta ética antes de operaciones que modifican estado."""
        print()
        warn("Solicitaste modo ESCRITURA (crear/modificar registros).")
        warn("Estas operaciones alteran datos en el objetivo.")
        resp = input(f"{C.Y}¿Cuentas con aprobación previa por escrito dentro "
                     f"del alcance de la auditoría? Escribe 'SI AUTORIZADO' "
                     f"para continuar: {C.RST}").strip()
        if resp == "SI AUTORIZADO":
            self.autorizacion_escritura = {
                "confirmado": resp,
                "fecha": _dt.datetime.now().isoformat(timespec="seconds"),
                "audit_id": self.cfg.aud_id,
            }
            ok("Autorización registrada. Continuando en modo escritura.")
            return True
        warn("No se confirmó autorización. Se continúa en modo LECTURA.")
        self.modo = "read"
        return False

    # -- Preparación ----------------------------------------------------
    def preparar(self, metodo="both"):
        # enum usa una sola cuenta (A); autorize/both usan A, B y anónimo.
        necesarias = ["A"] if metodo == "enum" else ["A", "B"]
        for nombre in necesarias:
            if nombre in self.cfg.identidades:
                self.sesiones[nombre] = construir_sesion(
                    self.cfg, self.cfg.identidades[nombre])
        if metodo in ("autorize", "both"):
            self.sesiones["anon"] = construir_sesion(
                self.cfg, Identity(nombre="anon", tipo="none"))

    # -- Envío con re-login automático (paso 2) -------------------------
    def _sesion_expirada(self, resp: Resp):
        """Solo señales inequívocas: 401, o redirección explícita a login.

        Se evita deliberadamente detectar por el texto del cuerpo (palabras como
        "login"/"password"), porque muchas páginas legítimas las contienen aun
        estando autenticado, y eso disparaba re-logins falsos.
        """
        if resp.error:
            return False
        if resp.status == 401:
            return True
        if resp.status in (301, 302, 303, 307, 308) and re.search(
                r"(login|signin|sign-in|autentic)", resp.location or "", re.I):
            return True
        return False

    def _relogin(self, nombre):
        """Reconstruye la sesión de una identidad autenticada (con límite)."""
        if not self.relogin_activo:
            return False
        ident = self.cfg.identidades.get(nombre)
        if not ident or ident.tipo == "none" or nombre in self._sin_reintentar:
            return False
        if time.time() - self._ultimo_relogin.get(nombre, 0) < 10:
            return False  # evita re-logins en ráfaga
        self._ultimo_relogin[nombre] = time.time()
        self._relogin_fallos[nombre] = self._relogin_fallos.get(nombre, 0) + 1
        if self._relogin_fallos[nombre] > 2:
            self._sin_reintentar.add(nombre)
            warn(f"Identidad {nombre}: no se pudo mantener la sesión tras "
                 f"varios intentos; se deja como NO autenticada y no se "
                 f"reintentará más.")
            return False
        warn(f"Sesión de {nombre} parece expirada; reautenticando...")
        self.sesiones[nombre] = construir_sesion(self.cfg, ident)
        self.relogins += 1
        return True

    def _enviar_como(self, nombre, req):
        """Envía con la sesión de 'nombre'; reautentica una vez si expiró."""
        r = enviar(self.cfg, self.sesiones.get(nombre), req)
        ident = self.cfg.identidades.get(nombre)
        if ident and ident.tipo != "none" and self._sesion_expirada(r):
            if self._relogin(nombre):
                r = enviar(self.cfg, self.sesiones.get(nombre), req)
        return r

    # -- Métodos de escaneo --------------------------------------------
    def escanear_autorize(self, reqs):
        cfg = self.cfg
        idA = self.sesiones.get("A")
        idB = self.sesiones.get("B")
        marc_A = cfg.identidades.get("A").marcadores if "A" in cfg.identidades else []
        if not idA or not idB:
            err("La metodología Autorize requiere las identidades A y B en la config.")
            return
        paso(f"Metodología Autorize sobre {len(reqs)} peticiones...")
        for i, req in enumerate(reqs, 1):
            motivo = cfg.motivo_bloqueo(req.url)
            if motivo:
                self.omitidas.append((_clave_redactada(req), motivo))
                continue
            if not self._metodo_permitido(req):
                continue
            print(f"{C.D}    [{i}/{len(reqs)}] {req.method} "
                  f"{urlparse(req.url).path}{C.RST}")
            rA = self._enviar_como("A", req)
            rB = self._enviar_como("B", req)
            rAnon = self._enviar_como("anon", req)
            for etiqueta, nivel, detalle, sim, fuga in \
                    analizar_autorize(cfg, req, rA, rB, rAnon, marc_A):
                self._registrar(req, "autorize", etiqueta, nivel, detalle,
                                sim, fuga, rA, rB, rAnon)

    def escanear_enum(self, reqs):
        cfg = self.cfg
        # Enumeración con la identidad principal A (una sola cuenta).
        nombre_id = "A" if "A" in self.sesiones else next(
            (n for n in self.sesiones if n != "anon"), None)
        if not nombre_id:
            err("No hay identidad disponible para enumeración.")
            return
        paso(f"Metodología de enumeración (identidad {nombre_id})...")
        for i, req in enumerate(reqs, 1):
            motivo = cfg.motivo_bloqueo(req.url)
            if motivo:
                self.omitidas.append((_clave_redactada(req), motivo))
                continue
            if not self._metodo_permitido(req):
                continue
            cands = detectar_candidatos(req, cfg.extra_nombres)
            enteros = [c for c in cands if c.tipo_valor == "int"]
            print(f"{C.D}    [{i}/{len(reqs)}] {req.method} "
                  f"{urlparse(req.url).path} — {len(enteros)} candidato(s) "
                  f"numérico(s){C.RST}")
            for c in enteros:
                _STATS["candidatos"] += 1
                base = self._enviar_como(nombre_id, req)  # objeto original (válido)
                if base.status != 200 or base.error:
                    continue
                inval = self._enviar_como(nombre_id,
                               _sustituir(req, c, valor_invalido(c.valor, c.tipo_valor)))
                for nv in vecinos(c.valor, c.tipo_valor):
                    prueba = _sustituir(req, c, nv)
                    r = self._enviar_como(nombre_id, prueba)
                    if r.status == 200 and not _denegado(r):
                        sim_base = similitud(base.text, r.text)
                        sim_inval = similitud(inval.text, r.text)
                        # Parece un objeto válido y NO un "no encontrado"
                        if sim_inval < 0.85 and 0.4 < sim_base < 0.999:
                            self._registrar(
                                prueba, "enum",
                                f"{c.localizacion}:{c.nombre} {c.valor}→{nv}",
                                "Media",
                                (f"Acceso a un objeto vecino ({c.valor}→{nv}) "
                                 f"que parece de otro usuario."),
                                sim_base, False, base, r, None)

    def _registrar(self, req, metodo, etiqueta, nivel, detalle,
                   sim, fuga, rBase, rAtaque, rAnon):
        if nivel == "Segura":
            return
        url_red = _redactar_url(req.url)
        self.hallazgos.append({
            "metodo": metodo,
            "peticion": f"{req.method} {url_red}",
            "url": url_red,
            "metodo_http": req.method,
            "cuerpo": _redactar_cuerpo(req.body, req.content_type),
            "origen": req.origen,
            "etiqueta": etiqueta,
            "nivel": nivel,
            "detalle": detalle,
            "similitud": round(sim, 3),
            "fuga_marcador": fuga,
            "estado_base": rBase.status,
            "estado_ataque": rAtaque.status,
            "estado_anon": rAnon.status if rAnon else None,
            "content_type": rAtaque.content_type,
        })
        color = {"Alta": C.R, "Media": C.Y, "Baja": C.D}.get(nivel, C.W)
        print(f"    {color}[{nivel}]{C.RST} {req.method} "
              f"{urlparse(req.url).path}  — {detalle}")


# =========================================================================
#  Informe  (Bloques 5 y 6)
# =========================================================================
def _redactar(headers):
    out = {}
    for k, v in headers.items():
        if k.lower() in ("cookie", "authorization", "x-api-key"):
            out[k] = "***REDACTADO***"
        else:
            out[k] = v
    return out


def gate_autorizacion(cfg):
    """Exige autorización declarada antes de cualquier actividad de red activa."""
    aut = cfg.autorizacion or {}
    if aut.get("referencia"):
        ok(f"Autorización de alcance: {aut.get('referencia')} "
           f"({aut.get('responsable', 's/responsable')}, "
           f"{aut.get('fecha', 's/fecha')}).")
        return dict(aut)
    if not sys.stdin.isatty():
        err("Falta 'autorizacion.referencia' en la config. Idora no realiza "
            "actividad activa sin autorización declarada. Abortando.")
        return None
    warn("La config no declara un bloque 'autorizacion'.")
    resp = input(f"{C.Y}Confirma que cuentas con autorización por escrito "
                 f"dentro del alcance. Escribe 'SI AUTORIZADO': {C.RST}").strip()
    if resp == "SI AUTORIZADO":
        return {"referencia": "confirmacion-interactiva",
                "fecha": _dt.datetime.now().isoformat(timespec="seconds"),
                "responsable": "interactivo"}
    err("Autorización no confirmada. Abortando.")
    return None


# Reglas SARIF (una por tipo de hallazgo)
_REGLAS_SARIF = {
    "IDOR-CROSS-ACCOUNT": "Acceso entre cuentas: una identidad accede a objetos de otra",
    "IDOR-UNAUTH": "Recurso accesible sin autenticación",
    "BOLA-ENUM": "Enumeración de objetos por identificador",
}


def _regla_sarif(h):
    if h["metodo"] == "enum":
        return "BOLA-ENUM"
    if str(h.get("etiqueta", "")).startswith("A→anónimo"):
        return "IDOR-UNAUTH"
    return "IDOR-CROSS-ACCOUNT"


def escribir_sarif(idora, ruta):
    """Escribe los hallazgos en formato SARIF 2.1.0 (para CI / GitHub / DefectDojo)."""
    nivel_map = {"Alta": "error", "Media": "warning", "Baja": "note"}
    reglas = [{
        "id": rid,
        "name": rid.replace("-", ""),
        "shortDescription": {"text": desc},
        "defaultConfiguration": {"level": "warning"},
    } for rid, desc in _REGLAS_SARIF.items()]
    resultados = []
    for h in idora.hallazgos:
        resultados.append({
            "ruleId": _regla_sarif(h),
            "level": nivel_map.get(h["nivel"], "note"),
            "message": {"text": f"[{h['nivel']}] {h['detalle']} "
                                f"(similitud {h.get('similitud')})"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": h.get("url", h["peticion"])}}}],
            "properties": {
                "metodo": h["metodo"],
                "nivel_idora": h["nivel"],
                "metodo_http": h.get("metodo_http", ""),
                "fuga_marcador": h.get("fuga_marcador", False),
            },
        })
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                   "master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Idora",
                "version": __version__,
                "informationUri": "https://github.com/Arkuma69/idora",
                "rules": reglas,
            }},
            "results": resultados,
        }],
    }
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)


def escribir_informe(idora: Idora, salida_dir):
    os.makedirs(salida_dir, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(salida_dir, f"idora_{ts}")
    h = idora.hallazgos

    # JSON
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump({
            "idora_version": __version__,
            "auditoria": idora.cfg.aud_id,
            "contacto": idora.cfg.aud_contacto,
            "fecha": _dt.datetime.now().isoformat(timespec="seconds"),
            "modo": idora.modo,
            "relogins": idora.relogins,
            "autorizacion_alcance": idora.autorizacion_alcance,
            "autorizacion_escritura": idora.autorizacion_escritura,
            "total_hallazgos": len(h),
            "hallazgos": h,
            "omitidas": idora.omitidas,
        }, f, ensure_ascii=False, indent=2)

    # CSV
    with open(base + ".csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["nivel", "metodo", "peticion", "etiqueta", "detalle",
                    "similitud", "fuga_marcador", "estado_ataque"])
        for x in h:
            w.writerow([x["nivel"], x["metodo"], x["peticion"], x["etiqueta"],
                        x["detalle"], x["similitud"], x["fuga_marcador"],
                        x["estado_ataque"]])

    # Markdown
    orden = {"Alta": 0, "Media": 1, "Baja": 2}
    h_ord = sorted(h, key=lambda x: orden.get(x["nivel"], 9))
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write(f"# Informe Idora v{__version__} — IDOR / BOLA\n\n")
        f.write(f"- **Auditoría:** {idora.cfg.aud_id}\n")
        f.write(f"- **Contacto:** {idora.cfg.aud_contacto}\n")
        f.write(f"- **Fecha:** {_dt.datetime.now():%Y-%m-%d %H:%M}\n")
        f.write(f"- **Modo:** {idora.modo}\n")
        if idora.autorizacion_alcance:
            a = idora.autorizacion_alcance
            f.write(f"- **Autorización:** {a.get('referencia')} "
                    f"({a.get('responsable', 's/r')}, {a.get('fecha', 's/f')})\n")
        f.write(f"- **Hallazgos:** {len(h)} | **Peticiones omitidas:** "
                f"{len(idora.omitidas)}\n\n")
        if idora.autorizacion_escritura:
            f.write(f"> Autorización de escritura registrada: "
                    f"{idora.autorizacion_escritura}\n\n")
        conteo = {}
        for x in h:
            conteo[x["nivel"]] = conteo.get(x["nivel"], 0) + 1
        f.write("## Resumen\n\n")
        for niv in ("Alta", "Media", "Baja"):
            f.write(f"- {niv}: {conteo.get(niv, 0)}\n")
        f.write("\n## Detalle\n\n")
        for x in h_ord:
            f.write(f"### [{x['nivel']}] {x['peticion']}\n\n")
            f.write(f"- Método de prueba: `{x['metodo']}` ({x['etiqueta']})\n")
            f.write(f"- {x['detalle']}\n")
            f.write(f"- Similitud de respuesta: {x['similitud']} | "
                    f"Fuga de marcador: {x['fuga_marcador']}\n")
            f.write(f"- Estados HTTP — base: {x['estado_base']}, "
                    f"ataque: {x['estado_ataque']}, anónimo: {x['estado_anon']}\n")
            if x.get("cuerpo"):
                f.write(f"- Cuerpo (redactado): `{x['cuerpo']}`\n")
            f.write(f"- Origen: {x['origen']}\n\n")
        f.write("---\n\n## Recomendación general\n\n")
        f.write("Aplicar controles de autorización a nivel de objeto en el "
                "servidor: verificar en cada petición que el recurso "
                "solicitado pertenece (o es accesible) a la identidad "
                "autenticada, en lugar de confiar en el identificador "
                "recibido. Preferir identificadores no predecibles no "
                "sustituye a la verificación de autorización.\n")
    escribir_sarif(idora, base + ".sarif")
    return base


# =========================================================================
#  CLI
# =========================================================================
def _elegir_metodo():
    """Pregunta el método de autenticación; 'form' por defecto o sin terminal."""
    if not sys.stdin.isatty():
        return "form"
    print("Método de autenticación de las cuentas A y B:")
    print("  1) form   — usuario y contraseña (Idora inicia sesión)")
    print("  2) cookie — cookie de sesión ya obtenida")
    print("  3) bearer — token / JWT")
    r = input("Elige [1-3] (Enter = 1, form): ").strip()
    return {"2": "cookie", "3": "bearer"}.get(r, "form")


def cmd_init():
    if not os.path.exists("idora.yaml"):
        metodo = _elegir_metodo()
        contenido = (CONFIG_TEMPLATE + _IDENT_HEADER.format(metodo=metodo)
                     + _IDENT_BLOQUES[metodo])
        with open("idora.yaml", "w", encoding="utf-8") as f:
            f.write(contenido)
        ok(f"Creado: idora.yaml (método de autenticación: {metodo})")
        info("Exporta las variables de ese método (o usa --pedir-credenciales).")
    else:
        warn("idora.yaml ya existe; no se sobrescribe.")
    if not os.path.exists("endpoints.txt"):
        with open("endpoints.txt", "w", encoding="utf-8") as f:
            f.write(LISTA_TEMPLATE)
        ok("Creado: endpoints.txt (lista de ejemplo)")


def cmd_detect(cfg, reqs):
    """Modo --detect-only: muestra los candidatos sin enviar nada."""
    paso("Análisis estático de candidatos (no se envía ninguna petición):")
    for req in reqs:
        cands = detectar_candidatos(req, cfg.extra_nombres)
        en_alcance = cfg.en_alcance(req.url)
        marca_alcance = f"{C.G}en alcance{C.RST}" if en_alcance else f"{C.R}FUERA de alcance{C.RST}"
        print(f"\n{C.BOLD}{req.method} {req.url}{C.RST}  [{marca_alcance}]")
        if not cands:
            print(f"    {C.D}(sin candidatos detectados){C.RST}")
        for c in cands:
            print(f"    {C.Cy}•{C.RST} {c.localizacion}:{c.nombre} = "
                  f"{c.valor}  {C.D}({c.tipo_valor}){C.RST}")


def detectar_tipo_auth(headers):
    """Deduce el tipo de autenticación a partir de las cabeceras de una petición."""
    h = {k.lower(): v for k, v in headers.items()}
    auth = h.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return {"tipo": "bearer", "token": auth.split(None, 1)[1]}
    if auth.lower().startswith("basic "):
        return {"tipo": "basic", "_nota": "Basic auth: configura usuario/clave manualmente."}
    for k in ("x-api-key", "apikey", "api-key", "x-auth-token", "x-access-token"):
        if k in h:
            return {"tipo": "apikey", "header": k, "valor": h[k]}
    if h.get("cookie"):
        cookies = dict(p.split("=", 1) for p in
                       [c.strip() for c in h["cookie"].split(";") if "=" in c])
        sesion = None
        for nombre in cookies:
            if re.search(r"(session|sess|sid|token|auth|phpsessid|laravel|"
                         r"csrftoken|connect)", nombre, re.I):
                sesion = nombre
                break
        sesion = sesion or (next(iter(cookies), None))
        return {"tipo": "cookie", "cookies": cookies, "_cookie_sesion": sesion}
    return {"tipo": "desconocido"}


def _imprimir_sugerencia_yaml(sug):
    t = sug.get("tipo")
    if t == "bearer":
        print('  A:')
        print('    tipo: "bearer"')
        print(f'    token: "{sug["token"]}"')
    elif t == "apikey":
        print('  A:')
        print('    tipo: "apikey"')
        print(f'    header: "{sug["header"]}"')
        print(f'    valor: "{sug["valor"]}"')
    elif t == "cookie":
        print('  A:')
        print('    tipo: "cookie"')
        print('    cookies:')
        for k, v in sug["cookies"].items():
            marca = "   # <- cookie de sesión probable" if k == sug.get("_cookie_sesion") else ""
            print(f'      "{k}": "{v}"{marca}')
    else:
        warn(f"Tipo detectado: {t}. {sug.get('_nota', 'Configúralo manualmente.')}")
        return
    print()
    warn("Este fragmento contiene secretos de sesión: no lo compartas.")
    info("Repite el proceso con una petición de la cuenta B para su bloque.")


def cmd_detect_auth(spec):
    """Lee una petición (HAR o cabeceras crudas) y sugiere la config de auth."""
    ruta = spec.split(":", 1)[1] if spec.startswith(("har:", "headers:")) else spec
    if not os.path.exists(ruta):
        err(f"No existe el archivo: {ruta}")
        return
    headers = {}
    if ruta.endswith(".har") or spec.startswith("har:"):
        with open(ruta, "r", encoding="utf-8") as f:
            har = json.load(f)
        for e in har.get("log", {}).get("entries", []):
            hs = {x["name"]: x["value"]
                  for x in e.get("request", {}).get("headers", [])
                  if not x["name"].startswith(":")}
            hl = {k.lower() for k in hs}
            if ("authorization" in hl or "cookie" in hl
                    or hl & {"x-api-key", "apikey", "api-key"}):
                headers = hs
                break
    else:
        with open(ruta, "r", encoding="utf-8") as f:
            for ln in f:
                if ":" in ln and not ln.startswith(("GET", "POST", "PUT", "#")):
                    k, v = ln.split(":", 1)
                    headers[k.strip()] = v.strip()
    if not headers:
        warn("No se hallaron cabeceras de autenticación en la fuente.")
        return
    sug = detectar_tipo_auth(headers)
    paso("Configuración de autenticación sugerida (pégala en idora.yaml, bajo "
         "'identidades'):")
    print()
    _imprimir_sugerencia_yaml(sug)


def main():
    ap = argparse.ArgumentParser(
        description="Idora — escáner de IDOR/BOLA para auditorías autorizadas.")
    ap.add_argument("--version", action="version",
                    version=f"Idora {__version__}")
    ap.add_argument("--config", help="Archivo de configuración YAML.")
    ap.add_argument("--pedir-credenciales", action="store_true",
                    help="Pregunta por pantalla (oculto) los ${VAR} que falten, "
                         "sin escribirlos en disco ni exportarlos.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Muestra cada petición enviada (método, URL, estado).")
    ap.add_argument("--sin-relogin", action="store_true",
                    help="Desactiva la reautenticación automática (útil con "
                         "cookie o si el sitio confunde al detector).")
    ap.add_argument("--source", action="append", default=[],
                    help="Fuente de peticiones (repetible): list:archivo.txt | "
                         "har:captura.har | json:reqs.json | "
                         "openapi:spec.json (o una URL de la spec).")
    ap.add_argument("--method", choices=["autorize", "enum", "both"],
                    default="both", help="Metodología de prueba.")
    ap.add_argument("--mode", choices=["read", "write"], default="read",
                    help="read (solo lectura) o write (crear/modificar).")
    ap.add_argument("--allow-delete", action="store_true",
                    help="Permite peticiones DELETE (requiere modo write).")
    ap.add_argument("--detect-only", action="store_true",
                    help="Solo detecta candidatos; no envía peticiones.")
    ap.add_argument("--out", default="./idora_out",
                    help="Directorio de salida del informe.")
    ap.add_argument("--out-sarif", metavar="ARCHIVO",
                    help="Escribe los hallazgos en SARIF en esta ruta fija "
                         "(para CI / GitHub code scanning).")
    ap.add_argument("--init", action="store_true",
                    help="Genera idora.yaml y endpoints.txt de ejemplo.")
    ap.add_argument("--detect-auth", metavar="FUENTE",
                    help="Sugiere la config de autenticación a partir de una "
                         "petición: har:captura.har o un .txt con cabeceras.")
    ap.add_argument("--crawl", action="append", default=[], metavar="URL",
                    help="Rastrea (crawler) desde esta URL semilla para "
                         "descubrir endpoints. Repetible. Solo lectura y "
                         "acotado a dominios_permitidos.")
    ap.add_argument("--crawl-depth", type=int, default=2,
                    help="Profundidad máxima del rastreo (por defecto 2).")
    ap.add_argument("--crawl-max", type=int, default=120,
                    help="Máximo de páginas a visitar (por defecto 120).")
    ap.add_argument("--save-endpoints", metavar="ARCHIVO",
                    help="Guarda los endpoints (fuentes + rastreo) en un .txt "
                         "para revisarlos o reutilizarlos.")
    args = ap.parse_args()
    global VERBOSE
    VERBOSE = args.verbose

    print(BANNER)

    if args.init:
        cmd_init()
        return

    if args.detect_auth:
        cmd_detect_auth(args.detect_auth)
        return

    if not args.config:
        err("Falta --config. Genera una plantilla con: python idora.py --init")
        return
    if yaml is None:
        err("Falta PyYAML. Instala con: pip install pyyaml")
        return
    with open(args.config, "r", encoding="utf-8") as f:
        datos = _expandir_env(yaml.safe_load(f))
    relevantes = _vars_pendientes(_datos_relevantes(datos, args.method))
    if args.pedir_credenciales:
        datos = _pedir_credenciales(datos, solo=set(relevantes))
    else:
        for var in relevantes:
            warn(f"Variable de entorno no definida: ${{{var}}}")
    cfg = Config(datos)

    if not cfg.dominios:
        err("La config no define 'alcance.dominios_permitidos'. Abortando "
            "por seguridad (no se permite escanear sin alcance definido).")
        return
    if not cfg.alcance_valido():
        err("Alcance inválido; corrige estas entradas antes de continuar:")
        for e in cfg.errores:
            err(f"  - {e}")
        return

    if not args.source and not args.crawl:
        err("Falta al menos una --source o una --crawl URL.")
        return

    reqs = cargar_fuentes(args.source, cfg) if args.source else []

    # Guarda ética: toda actividad de red activa exige autorización declarada
    habra_red = bool(args.crawl) or (not args.detect_only)
    registro_aut = None
    if habra_red:
        registro_aut = gate_autorizacion(cfg)
        if registro_aut is None:
            return

    # Descubrimiento automático por rastreo (opcional)
    if args.crawl:
        semillas = [u for u in args.crawl if cfg.en_alcance(u)]
        for u in args.crawl:
            if u not in semillas:
                err(f"Semilla fuera de alcance, se ignora: {u}")
        if semillas:
            if "A" in cfg.identidades:
                ses_crawl = construir_sesion(cfg, cfg.identidades["A"])
            else:
                warn("Rastreo sin autenticar (no hay identidad A).")
                ses_crawl = _nueva_sesion(cfg)
            try:
                reqs += rastrear(cfg, ses_crawl, semillas,
                                 args.crawl_depth, args.crawl_max)
            except SystemExit:
                pass

    if not reqs:
        err("No se cargó ninguna petición.")
        return

    # Deduplicar por método+URL
    vistos, unicas = set(), []
    for r in reqs:
        if r.clave() not in vistos:
            vistos.add(r.clave())
            unicas.append(r)
    reqs = unicas
    if len(reqs) > cfg.max_peticiones:
        warn(f"{len(reqs)} peticiones supera el tope de {cfg.max_peticiones}; "
             f"se recorta (sube red.max_peticiones para ampliar).")
        reqs = reqs[:cfg.max_peticiones]
    ok(f"{len(reqs)} petición(es) única(s) a evaluar.")
    info(f"Alcance permitido: {', '.join(cfg.dominios)}")

    if args.save_endpoints:
        guardar_endpoints(reqs, args.save_endpoints)

    # Modo detección: no envía nada (Bloque 2)
    if args.detect_only:
        cmd_detect(cfg, reqs)
        return

    idora = Idora(cfg, modo=args.mode, permitir_delete=args.allow_delete,
                  relogin=not args.sin_relogin)
    idora.autorizacion_alcance = registro_aut

    if args.mode == "write":
        idora.confirmar_autorizacion_escritura()

    idora.preparar(args.method)

    try:
        if args.method in ("autorize", "both"):
            idora.escanear_autorize(reqs)
        if args.method in ("enum", "both"):
            idora.escanear_enum(reqs)
    except SystemExit:
        pass

    print()
    info(f"Resumen: {len(reqs)} endpoint(s) evaluado(s), "
         f"{_STATS['candidatos']} candidato(s) numérico(s) probado(s), "
         f"{_STATS['peticiones']} petición(es) enviada(s).")
    base = escribir_informe(idora, args.out)
    if args.out_sarif:
        escribir_sarif(idora, args.out_sarif)
    if idora.hallazgos:
        ok(f"{len(idora.hallazgos)} hallazgo(s). Informe: "
           f"{base}.md / .json / .csv / .sarif")
    else:
        ok(f"Sin hallazgos por encima del umbral. Informe: {base}.json / .sarif")
    if idora.omitidas:
        info(f"{len(idora.omitidas)} petición(es) omitida(s) "
             f"(fuera de alcance, excluidas o método no permitido).")
    return 1 if idora.hallazgos else 0


if __name__ == "__main__":
    sys.exit(main())
