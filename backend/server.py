from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import io
import re
import json
import asyncio
import uuid
import random
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Literal

import jwt
import bcrypt
import pandas as pd
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, UploadFile, File, Form
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr

import servicios as _svc
import mtc as _mtc
import atu as _atu
from storage import save_object, download_response

# ---------- Config ----------
JWT_ALGORITHM = "HS256"
JWT_ACCESS_MINUTES = 60 * 8  # 8 hours
JWT_REFRESH_DAYS = 7

import dns.resolver
dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI(title="ENERED API")
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("enered")


# ---------- Utils ----------
# Conectores que en nombres de ciudad/lugar van en minúscula (excepto al inicio)
_CITY_MINOR_WORDS = {"de", "del", "la", "las", "los", "y", "el", "en", "a"}


def normalize_city(value: Optional[str]) -> str:
    """
    Unifica la escritura de una ciudad para reportes:
    'TRUJILLO', 'trujillo', 'tRujilLo', '  trujillo ' -> 'Trujillo'.
    'SAN MARTIN DE PORRES' -> 'San Martin de Porres'.
    Respeta caracteres separadores (espacios, guiones) y deja vacío si no hay dato.
    """
    if not value:
        return ""
    s = re.sub(r"\s+", " ", str(value).strip())
    if not s:
        return ""

    def _cap_word(w: str, first: bool) -> str:
        if not w:
            return w
        low = w.lower()
        if not first and low in _CITY_MINOR_WORDS:
            return low
        return low[0].upper() + low[1:]

    # Capitaliza respetando separadores internos (espacio y guion)
    tokens = re.split(r"([ \-])", s)
    out = []
    word_idx = 0
    for tok in tokens:
        if tok in (" ", "-"):
            out.append(tok)
            continue
        out.append(_cap_word(tok, first=(word_idx == 0)))
        word_idx += 1
    return "".join(out)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bool(bcrypt.checkpw(password.encode("utf-8"), (hashed or "").encode("utf-8")))
    except Exception:
        return False


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def create_access_token(user_id: str, email: str, role: str, empresa: Optional[str]) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "empresa": empresa,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_ACCESS_MINUTES),
        "type": "access",
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def create_download_token(user_id: str, minutes: int = 5) -> str:
    """Token efímero SOLO para URLs de descarga/preview (iframes, links directos).
    Dura pocos minutos → si se filtra en un log o Referer, caduca casi de inmediato,
    a diferencia del token de sesión de 8 h."""
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes),
        "type": "download",
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def create_conductor_token(dni: str, empresa: str, nombre: str) -> str:
    """Sesión del conductor (app móvil de Checklist): identificación por DNI, sin
    contraseña — igual mecanismo que la sesión invitada del subsidio (token con los
    datos adentro, no crea un usuario en la BD). Dura un turno largo (16h)."""
    payload = {
        "type": "conductor", "dni": dni, "empresa": empresa, "nombre": nombre,
        "exp": datetime.now(timezone.utc) + timedelta(hours=16),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_REFRESH_DAYS),
        "type": "refresh",
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def _cookie_extra() -> dict:
    """Atributos de cookie según el dominio en uso.
    Hoy (enered.netlify.app + enered-api.onrender.com) la cookie viaja entre dominios
    distintos y necesita SameSite=None. Con enered.pe + api.enered.pe se configura en
    Render: COOKIE_DOMAIN=.enered.pe y COOKIE_SAMESITE=lax (mismo dominio padre)."""
    dom = (os.environ.get("COOKIE_DOMAIN") or "").strip()
    ss = (os.environ.get("COOKIE_SAMESITE") or "none").strip().lower()
    out = {"samesite": ss if ss in ("lax", "strict", "none") else "none"}
    if dom:
        out["domain"] = dom
    return out


def set_auth_cookies(response: Response, access: str, refresh: str):
    response.set_cookie("access_token", access, httponly=True, secure=True, **_cookie_extra(),
                        max_age=JWT_ACCESS_MINUTES * 60, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=True, **_cookie_extra(),
                        max_age=JWT_REFRESH_DAYS * 86400, path="/")


def clear_auth_cookies(response: Response):
    _dom = _cookie_extra().get("domain")
    response.delete_cookie("access_token", path="/", domain=_dom)
    response.delete_cookie("refresh_token", path="/", domain=_dom)


def user_public(u: dict) -> dict:
    return {
        "id": u["id"],
        "email": u["email"],
        "name": u.get("name", ""),
        "role": u["role"],
        "empresa": u.get("empresa"),
        "ruc": u.get("ruc", ""),
        "acceso_etapa0": u.get("acceso_etapa0", False),
        "registrado_etapa0": u.get("registrado_etapa0", False),
        "es_guest": u.get("es_guest", False),
        # Multi-empresa: lista de empresas que puede alternar y cuál está activa.
        "empresas_asignadas": u.get("empresas_asignadas", []),
        "empresa_activa": u.get("_empresa_activa") or u.get("empresa"),
        "created_at": u.get("created_at"),
        "documentos_completos": u.get("documentos_completos", True),
        "expediente_status": u.get("expediente_status", "confirmed"),
        # Permisos por módulo (equipo ENERED). None = acceso total (super-admin).
        "permisos": u.get("permisos"),
        # Impersonación: True si un admin está actuando como esta empresa.
        "impersonando": u.get("_impersonando", False),
        "impersonado_por": u.get("_impersonado_por"),
    }


CONSTANCIA_VERSION = "2.0"  # Constancia de Información y Términos del Servicio (subir versión = re-aceptación)


async def _es_cliente_subsidio(u: dict) -> bool:
    """True si la cuenta es un cliente del servicio de subsidio: rol cliente_subsidio, o un
    administrador/representante cuya empresa tiene el servicio de subsidio activo (muchos
    clientes que ya firmaron su DJ tienen rol 'administrador', no 'cliente_subsidio')."""
    role = u.get("role")
    if role == "cliente_subsidio":
        return True
    if role in ("administrador", "logistica", "contabilidad") and u.get("empresa"):
        cfg = await db.empresas_config.find_one(
            {"empresa": u["empresa"], "servicios.subsidio": True}, {"_id": 1})
        return bool(cfg)
    return False


async def _tiene_dj_firmada(u: dict) -> bool:
    """¿El cliente ya firmó su declaración jurada del subsidio en la plataforma?"""
    q = {"$or": [{"user_id": u.get("id")}]}
    if u.get("empresa"):
        q["$or"].append({"empresa": u["empresa"]})
    return bool(await db.subsidio_declaraciones.find_one(q, {"_id": 1}))


async def _constancia_pendiente(u: dict) -> bool:
    """True si hay que mostrar el COMUNICADO EMERGENTE al iniciar sesión. Es obligatorio y solo
    para clientes de subsidio que YA firmaron su declaración jurada (muchos ya no vuelven a la
    plataforma). Los que aún NO la firmaron ven la constancia como apartado dentro de la Etapa 4,
    no como emergente. No aplica a invitados, admin_enered ni a un admin que impersona."""
    if u.get("es_guest") or u.get("_impersonando") or u.get("_admin_id"):
        return False
    if u.get("role") == "admin_enered":
        return False
    if not await _es_cliente_subsidio(u):
        return False
    if (u.get("constancia_aceptada") or {}).get("version") == CONSTANCIA_VERSION:
        return False  # ya la aceptó
    return await _tiene_dj_firmada(u)


async def user_public_with_servicios(u: dict) -> dict:
    """Igual que user_public pero enriquecido con servicios de la empresa."""
    base = user_public(u)
    # Sesión invitada del subsidio: solo subsidio, sin plataforma (sidebar recortado a 5 módulos).
    if u.get("es_guest"):
        base["servicios"] = {"plataforma": False, "combustible": False, "gps": False, "subsidio": True}
        base["tipo_cliente"] = "subsidio"
        base["wialon_configurado"] = False
        base["constancia_version"] = CONSTANCIA_VERSION
        base["constancia_pendiente"] = False
        return base
    # admin_enered no está atado a una empresa; tiene todos los servicios habilitados por default
    if u.get("role") == "admin_enered":
        base["servicios"] = {"plataforma": True, "combustible": True, "gps": True, "subsidio": True}
        base["tipo_cliente"] = "enered"
        base["wialon_configurado"] = False
        base["constancia_version"] = CONSTANCIA_VERSION
        base["constancia_pendiente"] = False
        return base
    empresa = u.get("empresa")
    info = await _svc.get_empresa_servicios(db, empresa)
    base["servicios"] = info["servicios"]
    base["tipo_cliente"] = info["tipo_cliente"]
    base["wialon_configurado"] = info["wialon_configurado"]
    base["modulos_habilitados"] = info.get("modulos_habilitados")
    # Usuarios creados sin RUC propio: heredan el de su empresa (empresas_config o
    # cualquier usuario hermano que sí lo tenga) para que el diagnóstico Etapa 0 cargue.
    if not base.get("ruc") and empresa:
        cfg = await db.empresas_config.find_one({"empresa": empresa}, {"_id": 0, "ruc": 1})
        ruc_emp = (cfg or {}).get("ruc") or ""
        if not ruc_emp:
            hermano = await db.users.find_one(
                {"empresa": empresa, "ruc": {"$nin": [None, ""]}}, {"_id": 0, "ruc": 1})
            ruc_emp = (hermano or {}).get("ruc") or ""
        if ruc_emp:
            base["ruc"] = ruc_emp
    base["constancia_version"] = CONSTANCIA_VERSION
    base["constancia_pendiente"] = await _constancia_pendiente(u)
    ca = u.get("constancia_aceptada")
    base["constancia_aceptada_at"] = (ca or {}).get("at") if ca else None
    base["constancia_ok"] = bool(ca and ca.get("version") == CONSTANCIA_VERSION)
    return base


async def _impersonate_context(admin: dict, empresa: str) -> Optional[dict]:
    """Devuelve el contexto efectivo para que un admin_enered actúe como una empresa.
    Usa un usuario representativo real (prefiere cliente_subsidio, luego administrador);
    si no hay, sintetiza según tipo_cliente. Conserva la identidad admin para auditoría."""
    if not empresa:
        return None
    rep = (await db.users.find_one({"empresa": empresa, "role": "cliente_subsidio"}, {"_id": 0, "password_hash": 0})
           or await db.users.find_one({"empresa": empresa, "role": "administrador"}, {"_id": 0, "password_hash": 0})
           or await db.users.find_one({"empresa": empresa}, {"_id": 0, "password_hash": 0}))
    if rep:
        rep = dict(rep)
    else:
        cfg = await db.empresas_config.find_one({"empresa": empresa}, {"_id": 0, "tipo_cliente": 1})
        role = "cliente_subsidio" if (cfg or {}).get("tipo_cliente") == "subsidio" else "administrador"
        rep = {"id": admin["id"], "email": admin["email"], "name": empresa, "role": role, "empresa": empresa}
    rep["_impersonando"] = True
    rep["_impersonado_por"] = admin.get("email")
    return rep


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        token = request.query_params.get("t") or request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="No autenticado")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") == "guest_subsidio":
            # Sesión invitada del subsidio (no existe en BD): usuario sintético.
            _rc = payload.get("ruc", "")
            _emp = payload.get("empresa") or f"RUC {_rc}"
            return {"id": f"guest:{_rc}", "email": f"{_rc}@invitado.subsidio", "name": _emp,
                    "role": "cliente_subsidio", "empresa": _emp, "ruc": _rc,
                    "acceso_etapa0": True, "registrado_etapa0": False, "es_guest": True,
                    "documentos_completos": False, "permisos": None}
        if payload.get("type") == "conductor":
            # Sesión de conductor (Checklist móvil): sintética, no existe en db.users.
            _dni = payload.get("dni", "")
            return {"id": f"conductor:{_dni}", "email": "", "name": payload.get("nombre") or _dni,
                    "role": "conductor", "empresa": payload.get("empresa"), "dni": _dni, "permisos": None}
        if payload.get("type") == "download":
            # Token efímero de descarga: SOLO lecturas (GET). Nunca autoriza escrituras.
            if request.method != "GET":
                raise HTTPException(status_code=401, detail="Token de descarga no válido para esta operación")
            user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
            if not user:
                raise HTTPException(status_code=401, detail="Usuario no encontrado")
            return user
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Token inválido")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
        # Cambio de empresa (header X-Impersonate-Empresa):
        imp = request.headers.get("X-Impersonate-Empresa")
        if imp:
            imp = imp.strip()
            # a) admin_enered puede actuar como cualquier empresa.
            if user.get("role") == "admin_enered":
                eff = await _impersonate_context(user, imp)
                if eff:
                    # Identidad real del admin: los endpoints exclusivos del panel
                    # (require_roles/require_permiso) la recuperan aunque el header
                    # de impersonación siga activo en otra pestaña.
                    eff["_admin_id"] = user.get("id")
                    eff["_admin_role"] = user.get("role")
                    return eff
            else:
                # b) Cliente con varias empresas: SOLO puede alternar entre las asignadas.
                asignadas = user.get("empresas_asignadas") or []
                match = next((e for e in asignadas if (e or {}).get("empresa") == imp), None)
                if match:
                    eff = dict(user)
                    eff["empresa"] = match.get("empresa")
                    eff["ruc"] = match.get("ruc", "")
                    eff["_empresa_activa"] = match.get("empresa")
                    return eff
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sesión expirada")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


async def get_current_user_optional(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        token = request.query_params.get("t") or request.query_params.get("token")
    if token:
        try:
            payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
            user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
            if user:
                return user
        except Exception:
            pass
    # Sin token válido NO se concede identidad: quien consume esto debe exigir auth.
    raise HTTPException(status_code=401, detail="No autenticado")


async def _admin_real(user: dict) -> Optional[dict]:
    """Si el usuario efectivo es una empresa impersonada por un admin_enered,
    devuelve al admin real (para endpoints del panel que no son de la empresa)."""
    if user.get("_impersonando") and user.get("_admin_role") == "admin_enered" and user.get("_admin_id"):
        original = await db.users.find_one({"id": user["_admin_id"]}, {"_id": 0, "password_hash": 0})
        if original and original.get("role") == "admin_enered":
            return original
    return None


def require_roles(*roles):
    async def checker(user: dict = Depends(get_current_user)):
        if user["role"] in roles:
            return user
        # Admin ENERED "dentro de una empresa": para el panel sigue siendo admin.
        if "admin_enered" in roles:
            original = await _admin_real(user)
            if original:
                return original
        raise HTTPException(status_code=403, detail="Permiso denegado")
    return checker


def user_has_module(user: dict, module: str) -> bool:
    """True si el usuario puede acceder al módulo. admin_enered sin `permisos`
    (None) = super-admin con acceso total. Con lista = solo esos módulos."""
    if user.get("role") != "admin_enered":
        return False
    permisos = user.get("permisos")
    if permisos is None:
        return True  # super-admin
    return module in permisos


def require_permiso(module: str):
    """Requiere admin_enered CON permiso al módulo (o super-admin)."""
    async def checker(user: dict = Depends(get_current_user)):
        if user_has_module(user, module):
            return user
        # Admin ENERED "dentro de una empresa": valida con su identidad real.
        original = await _admin_real(user)
        if original and user_has_module(original, module):
            return original
        raise HTTPException(status_code=403, detail=f"Sin permiso para el módulo '{module}'")
    return checker


# Alias usado por endpoints de Infracciones (estilo: u = await require_auth(req))
async def require_auth(request: Request) -> dict:
    return await get_current_user(request)

# Alias usado por endpoints de Infracciones (estilo: u = await require_auth(req))
async def require_auth(request: Request) -> dict:
    return await get_current_user(request)


# ---------- Models ----------
ROLES = ["admin_enered", "administrador", "logistica", "contabilidad"]


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ForgotIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str
    password: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: Literal["admin_enered", "administrador", "logistica", "contabilidad", "cliente_subsidio"]
    empresa: Optional[str] = None
    ruc: Optional[str] = None
    # Módulos permitidos para miembros del equipo ENERED (admin_enered).
    # None/ausente = acceso total (super-admin). Lista = solo esos módulos.
    permisos: Optional[List[str]] = None
    # Cliente con varias empresas: lista de {empresa, ruc} que podrá alternar.
    empresas_asignadas: Optional[List[dict]] = None


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[Literal["admin_enered", "administrador", "logistica", "contabilidad"]] = None
    empresa: Optional[str] = None
    password: Optional[str] = None
    permisos: Optional[List[str]] = None
    # Empresas que este usuario (cliente con varias empresas) puede ver y alternar.
    # Cada item: {"empresa": "...", "ruc": "..."}.
    empresas_asignadas: Optional[List[dict]] = None


class InvoiceCreate(BaseModel):
    empresa: str
    numero: str
    fecha_emision: str
    fecha_vencimiento: str
    monto: float
    estado: Literal["pendiente", "pagada", "vencida", "tercero"] = "pendiente"
    pdf_url: Optional[str] = None


class InvoiceUpdate(BaseModel):
    estado: Optional[Literal["pendiente", "pagada", "vencida", "tercero"]] = None
    pdf_url: Optional[str] = None


class ControlRequestIn(BaseModel):
    tipo: Literal["tope_mensual_galones", "tope_diario", "estaciones_permitidas",
                  "ciudades_permitidas", "combustible_permitido", "limite_por_carga"]
    placa: Optional[str] = None
    detalle: str
    valor: Optional[str] = None


class ControlStatusUpdate(BaseModel):
    estado: Literal["pendiente", "realizada", "rechazada"]
    nota: Optional[str] = None


class CourseCreate(BaseModel):
    titulo: str
    descripcion: str
    video_url: Optional[str] = None
    pdf_url: Optional[str] = None
    puntaje_minimo: int = 70
    preguntas: List[dict] = []  # {pregunta, opciones:[], correcta:int}


class CourseSubmit(BaseModel):
    respuestas: List[int]
def normalizar_combustible(raw: str) -> str:
    if not raw:
        return "Diesel B5 UV"
    s = str(raw).upper().strip()
    if any(k in s for k in ["PREMIUM", "95", "97", "98"]):
        return "Gasohol Premium"
    elif any(k in s for k in ["REGULAR", "84", "90"]):
        return "Gasohol Regular"
    elif any(k in s for k in ["DIESEL", "DB5", "B5", "S-50", "S50"]):
        return "Diesel B5 UV"
    return "Gasohol Regular"


# ---------- Precios de Combustible (Facilito OSINERGMIN + Google Sheets) ----------

@api.get("/precios")
async def get_precios(
    user: dict = Depends(get_current_user),
    empresa: Optional[str] = None,
    combustible: Optional[str] = None,
    departamento: Optional[str] = None,
    provincia: Optional[str] = None,
    distrito: Optional[str] = None,
    solo_enered: bool = False,
    limite: int = 500,
):
    """Devuelve precios de estaciones de servicio con soporte para 4 filtros:
    departamento, provincia, distrito y combustible.
    `limite`: tope de registros. La tabla usa 500 (los más baratos); el mapa pide
    muchos más para pintar TODO el país, no solo la franja más barata.
    """
    facilito_count = await db.precios_facilito.count_documents({})
    if facilito_count < 1:
        try:
            from seed_facilito_precios import seed
            await seed()
        except Exception as se:
            logger.warning(f"Auto-seed Facilito exception: {se}")

    query: dict = {}
    if combustible:
        c_upper = combustible.strip().upper()
        if "PREMIUM" in c_upper:
            query["combustible"] = {"$regex": "PREMIUM|95|97|98", "$options": "i"}
        elif "REGULAR" in c_upper or "84" in c_upper:
            query["combustible"] = {"$regex": "REGULAR|84|90", "$options": "i"}
        elif "DIESEL" in c_upper or "DB5" in c_upper or "B5" in c_upper:
            query["combustible"] = {"$regex": "DB5|DIESEL|B5|S-50|UV", "$options": "i"}
        else:
            query["combustible"] = {"$regex": combustible, "$options": "i"}

    if departamento:
        dpto_norm = departamento.strip().upper().replace("Á", "A").replace("É", "E").replace("Í", "I").replace("Ó", "O").replace("Ú", "U")
        query["departamento"] = {"$regex": dpto_norm, "$options": "i"}
    if provincia:
        prov_norm = provincia.strip().upper().replace("PACASMALLO", "PACASMA").replace("PACASMAYO", "PACASMA")
        query["provincia"] = {"$regex": prov_norm, "$options": "i"}
    if distrito:
        dist_norm = distrito.strip().upper()
        query["$or"] = [
            {"distrito": {"$regex": dist_norm, "$options": "i"}},
            {"ciudad": {"$regex": dist_norm, "$options": "i"}},
            {"direccion": {"$regex": dist_norm, "$options": "i"}}
        ]
    if solo_enered:
        # El flag es_enered de precios_facilito se pierde en cada scrape (reemplaza la colección).
        # Filtramos por los nombres registrados en estaciones_enered (fuente de verdad).
        _enered_names = await db.estaciones_enered.distinct("nombre_facilito")
        query["establecimiento"] = {"$in": _enered_names or ["__NINGUNA__"]}

    # 1. Consulta estricta
    cursor = db.precios_facilito.find(query, {"_id": 0}).sort("precio_venta", 1).limit(limite)
    precios = await cursor.to_list(limite)

    # 2. Si no hay resultados para provincia/distrito específico, relajar a Departamento
    if not precios and departamento:
        dpto_norm = departamento.strip().upper().replace("Á", "A").replace("É", "E").replace("Í", "I").replace("Ó", "O").replace("Ú", "U")
        fallback_query = {"departamento": {"$regex": dpto_norm, "$options": "i"}}
        if combustible:
            fallback_query["combustible"] = query.get("combustible", {"$regex": combustible, "$options": "i"})
        if solo_enered:
            _en = await db.estaciones_enered.distinct("nombre_facilito")
            fallback_query["establecimiento"] = {"$in": _en or ["__NINGUNA__"]}
        cursor = db.precios_facilito.find(fallback_query, {"_id": 0}).sort("precio_venta", 1).limit(limite)
        precios = await cursor.to_list(limite)

    # Dedup defensivo: si un mismo grifo (nombre + dirección) y combustible quedó cargado
    # más de una vez (cargas viejas apiladas), se muestra SOLO el mejor registro (con GPS y
    # más reciente). Claves NORMALIZADAS para que coincidan aunque las cargas viejas tengan
    # el combustible con otro nombre ("DB5 S-50 UV" vs "Diesel B5 UV") o la dirección con
    # caracteres corruptos de encoding ("N�" vs "N°"). Los locales distintos de una misma
    # cadena tienen direcciones distintas y se conservan.
    def _alfanum(s):
        return re.sub(r"[^A-Z0-9]", "", (s or "").upper())
    _dedup = {}
    for _p in precios:
        _k = (_alfanum(_p.get("establecimiento")),
              _alfanum(_p.get("direccion"))[:30],
              normalizar_combustible(_p.get("combustible")))
        _ex = _dedup.get(_k)
        if _ex is None:
            _dedup[_k] = _p; continue
        _mejor = (_p.get("lat") is not None, _p.get("scraped_at") or "")
        _actual = (_ex.get("lat") is not None, _ex.get("scraped_at") or "")
        if _mejor > _actual:
            _dedup[_k] = _p
    precios = list(_dedup.values())

    # Cruzar con precios ENERED de db.estaciones_enered por (nombre, combustible)
    enered_map = {}
    enered_docs = await db.estaciones_enered.find({}, {"_id": 0}).to_list(500)
    for e in enered_docs:
        key_name = e.get("nombre_facilito", "").strip().upper()
        key_comb = normalizar_combustible(e.get("combustible") or "")
        if key_comb:
            enered_map[(key_name, key_comb)] = e
        enered_map[key_name] = e

    REDES_CONOCIDAS = {"REPSOL", "PRIMAX", "AVA", "PETROPERU", "SHELL", "MOBIL", "VALERO", "PECSA", "TERPEL", "COSTI"}
    user_empresa = (empresa or user.get("empresa") or "").strip().upper()

    for p in precios:
        p["combustible"] = normalizar_combustible(p.get("combustible"))
        nombre_est = p.get("establecimiento", "").strip().upper()
        comb_norm = p["combustible"]

        enered_info = enered_map.get((nombre_est, comb_norm))
        if not enered_info:
            for (k_key), val in enered_map.items():
                if isinstance(k_key, tuple):
                    k_name, k_comb = k_key
                    if (k_name in nombre_est or nombre_est in k_name) and k_comb == comb_norm:
                        enered_info = val
                        break

        precio_pizarra = float(p.get("precio_venta") or 0)
        p["precio_pizarra"] = precio_pizarra

        if enered_info:
            p["es_enered"] = True
            precios_cliente = enered_info.get("precios_cliente") or {}

            if user_empresa and user_empresa in precios_cliente:
                precio_e = float(precios_cliente[user_empresa])
            elif "GENERAL" in precios_cliente:
                precio_e = float(precios_cliente["GENERAL"])
            else:
                precio_e = float(enered_info.get("precio_enered") or precio_pizarra)

            p["precio_enered"] = precio_e
            ahorro = round(precio_pizarra - precio_e, 2)
            p["ahorro"] = max(ahorro, 0)
            p["porcentaje_ahorro"] = round((p["ahorro"] / precio_pizarra) * 100, 1) if precio_pizarra > 0 else 0
            p["acepta_factura"] = True
            p["acepta_tarjeta"] = True
            p["calidad"] = 5
            p["cliente_asignado"] = enered_info.get("cliente_asignado", "GENERAL")
        else:
            p["precio_enered"] = None
            p["ahorro"] = 0.0
            p["porcentaje_ahorro"] = 0.0
            p["acepta_factura"] = True
            p["acepta_tarjeta"] = False
            
            is_red = any(r in nombre_est for r in REDES_CONOCIDAS)
            p["calidad"] = 4 if is_red else 2

    # Deduplicar por (establecimiento, dirección, combustible) para eliminar filas repetidas
    seen = set()
    dedup_precios = []
    for p in precios:
        est = (p.get("establecimiento") or p.get("estacion") or "").strip().upper()
        dir_sub = (p.get("direccion") or "").strip().upper()[:20]
        comb = (p.get("combustible") or "").strip().upper()
        key = (est, dir_sub, comb)
        if key not in seen:
            seen.add(key)
            dedup_precios.append(p)
    precios = dedup_precios

    mejor_precio = min(
        [p.get("precio_enered") or p.get("precio_pizarra", 9999) for p in precios if (p.get("precio_pizarra") or 0) > 0] or [0]
    )
    last_sync = await db.precios_facilito.find_one({}, {"scraped_at": 1, "_id": 0}, sort=[("scraped_at", -1)])
    return {
        "precios": precios,
        "mejor_precio": mejor_precio if mejor_precio != 9999 else 0,
        "fuente": "facilito",
        "last_sync": last_sync.get("scraped_at") if last_sync else None,
        "total": len(precios),
    }


@api.get("/precios/clientes-list")
async def get_clientes_list(user: dict = Depends(get_current_user)):
    """Retorna la lista de clientes/empresas para la asignación de precios ENERED."""
    users_empresas = await db.users.distinct("empresa")
    subsidio_empresas = await db.clientes_subsidio.distinct("empresa")
    config_empresas = await db.empresas_config.distinct("empresa")
    
    all_empresas = sorted(list(set(
        [e.strip().upper() for e in (users_empresas + subsidio_empresas + config_empresas) if e and str(e).strip()]
    )))
    return {"clientes": all_empresas}


@api.get("/precios/ubicaciones")
async def get_ubicaciones(user: dict = Depends(get_current_user)):
    """Retorna la lista de departamentos, provincias y distritos disponibles."""
    from services.facilito_scraper import DEPARTAMENTOS
    dptos_facilito = [d["name"] for d in DEPARTAMENTOS]
    
    dptos_db = await db.precios_facilito.distinct("departamento")
    if not dptos_db:
        dptos_db = await db.precios.distinct("departamento")
    
    all_dptos = sorted(list(set(dptos_facilito + [d for d in dptos_db if d])))
    
    provincias_db = await db.precios_facilito.distinct("provincia")
    distritos_db = await db.precios_facilito.distinct("distrito")
    
    return {
        "departamentos": all_dptos,
        "provincias": [p for p in provincias_db if p],
        "distritos": [dist for dist in distritos_db if dist]
    }


@api.get("/precios/combustibles")
async def get_combustibles_disponibles(user: dict = Depends(get_current_user)):
    """Retorna estrictamente los 3 tipos de combustible normalizados."""
    return {"combustibles": ["Diesel B5 UV", "Gasohol Regular", "Gasohol Premium"]}


async def _geocodificar(consulta: str) -> Optional[dict]:
    """Dirección → {lat, lon} usando Nominatim (OpenStreetMap, gratis). Con caché en Mongo
    (las coordenadas de un grifo no cambian) para respetar el límite de 1 consulta/seg."""
    consulta = " ".join((consulta or "").split()).strip()
    if len(consulta) < 4:
        return None
    hit = await db.geocode_cache.find_one({"q": consulta.upper()}, {"_id": 0, "lat": 1, "lon": 1})
    if hit:
        return hit if hit.get("lat") is not None else None
    import httpx as _hx
    coords = None
    try:
        async with _hx.AsyncClient(timeout=12.0, headers={"User-Agent": "ENERED/1.0 (soporte@enered.pe)"}) as c:
            r = await c.get("https://nominatim.openstreetmap.org/search",
                            params={"format": "json", "limit": 1, "countrycodes": "pe", "q": consulta})
            if r.status_code == 200 and r.json():
                d = r.json()[0]
                coords = {"lat": float(d["lat"]), "lon": float(d["lon"])}
    except Exception as e:
        logger.warning(f"[geocode] {consulta[:40]}: {e}")
    # Cachea también el fallo (lat=None) para no reintentar direcciones imposibles cada vez.
    await db.geocode_cache.update_one(
        {"q": consulta.upper()},
        {"$set": {"q": consulta.upper(), "lat": (coords or {}).get("lat"),
                  "lon": (coords or {}).get("lon"), "at": datetime.now(timezone.utc).isoformat()}},
        upsert=True)
    return coords


@api.get("/precios/mapa")
async def precios_mapa(
    user: dict = Depends(get_current_user),
    combustible: Optional[str] = None,
    departamento: Optional[str] = None,
    provincia: Optional[str] = None,
    distrito: Optional[str] = None,
    solo_enered: bool = False,
    max_geo: int = 12,
):
    """Grifos con COORDENADAS para pintarlos en el mapa. Reutiliza el filtro de /precios y
    geocodifica (con caché) las direcciones. Para no exceder el límite de Nominatim (1/seg),
    geocodifica pocas direcciones nuevas por llamada y reporta cuántas quedan pendientes; el
    frontend reintenta hasta completar (a partir de la 2ª vez todo sale de la caché, instantáneo)."""
    # El mapa pinta TODO el país (con agrupación por zoom en el front), no solo los 500
    # más baratos: pide un tope alto para no quedarse con la franja de Lima/Ica.
    datos = await get_precios(user=user, combustible=combustible, departamento=departamento,
                              provincia=provincia, distrito=distrito, solo_enered=solo_enered,
                              limite=20000)
    precios = datos.get("precios") or []

    # Vía rápida: si los precios ya traen coordenadas GPS reales (sincronizadas desde el mapa
    # de Facilito), se usan directo — nada de geocodificar ni aproximar.
    con_gps = [p for p in precios if p.get("lat") is not None and p.get("lon") is not None]
    sin_gps = [p for p in precios if p.get("lat") is None or p.get("lon") is None]

    # Los que YA traen GPS real (sincronizado de Facilito) entran directo, descartando
    # outliers por provincia. Los que NO traen GPS se geocodifican abajo (incremental),
    # así el mapa termina mostrando TODAS las estaciones, no solo las que traen GPS.
    salida = []
    if con_gps:
        # Algunos operadores reportan a Facilito un GPS equivocado (p. ej. un grifo de la sierra
        # con coordenadas en la costa). Se descartan esos outliers: dentro de una misma provincia
        # los grifos están cerca, así que se compara cada uno con la mediana de su provincia.
        import statistics as _st
        def _km(a_lat, a_lon, b_lat, b_lon):
            import math
            return math.hypot((a_lat - b_lat) * 111, (a_lon - b_lon) * 111 * math.cos(math.radians(a_lat)))
        por_prov = {}
        for p in con_gps:
            por_prov.setdefault((p.get("provincia") or "").upper(), []).append(p)
        limpios = []
        for prov, grupo in por_prov.items():
            if len(grupo) < 5:
                limpios.extend(grupo)   # muy pocos para juzgar outliers
                continue
            mlat = _st.median(g["lat"] for g in grupo)
            mlon = _st.median(g["lon"] for g in grupo)
            for g in grupo:
                if _km(g["lat"], g["lon"], mlat, mlon) <= 80:   # dentro de la provincia
                    limpios.append(g)
                else:
                    logger.info(f"[precios_mapa] outlier GPS descartado: {g.get('establecimiento')} "
                                f"({g['lat']},{g['lon']}) lejos de {prov}")
        salida = [{
            "preciso": True,
            "establecimiento": p.get("establecimiento"), "direccion": p.get("direccion"),
            "distrito": p.get("distrito") or p.get("ciudad"), "provincia": p.get("provincia"),
            "departamento": p.get("departamento"),
            "precio_venta": p.get("precio_venta"), "precio_enered": p.get("precio_enered"),
            "combustible": p.get("combustible"), "es_enered": bool(p.get("es_enered")),
            "acepta_factura": p.get("acepta_factura", True),
            "lat": p["lat"], "lon": p["lon"],
        } for p in limpios]

    presupuesto = {"n": max_geo}   # llamadas nuevas a Nominatim permitidas en esta request

    async def resolver(consulta):
        """Devuelve {lat,lon} de una consulta. 'PENDIENTE' si no hay presupuesto para geocodificarla."""
        consulta = " ".join((consulta or "").split()).strip()
        if len(consulta) < 4:
            return None
        hit = await db.geocode_cache.find_one({"q": consulta.upper()}, {"_id": 0, "lat": 1, "lon": 1})
        if hit is not None:
            return hit if hit.get("lat") is not None else None
        if presupuesto["n"] <= 0:
            return "PENDIENTE"
        presupuesto["n"] -= 1
        coords = await _geocodificar(consulta)   # ya cachea el resultado (coords o null)
        await asyncio.sleep(1.1)                 # respeta el límite de Nominatim (1/seg)
        return coords

    pendientes = 0
    for p in sin_gps:
        direccion = p.get("direccion") or ""
        dist = p.get("distrito") or p.get("ciudad") or ""
        prov = p.get("provincia") or ""
        dep = p.get("departamento") or ""
        # Cascada: dirección exacta → centro del distrito → centro de la provincia.
        # 'preciso' = la coordenada vino de la dirección exacta (posición real). Si cayó al
        # centro del distrito/provincia, es aproximada → el frontend la agrupa por zona en vez
        # de fingir una posición individual.
        coords, preciso, hubo_pendiente = None, False, False
        intentos = [
            (f"{direccion}, {dist}, {prov}, {dep}", True),
            (f"{dist}, {prov}, {dep}", False),
            (f"{prov}, {dep}", False),
        ]
        for consulta, es_exacta in intentos:
            if not consulta.replace(",", "").strip():
                continue
            r = await resolver(consulta)
            if r == "PENDIENTE":
                # Sin presupuesto para este intento: seguimos a la zona (barata por caché).
                # La dirección exacta se refina en una carga posterior.
                hubo_pendiente = True
                continue
            if r:
                coords, preciso = r, es_exacta
                break
        if not coords:
            if hubo_pendiente:
                pendientes += 1
            continue
        # Si aún no tenemos la posición exacta pero sí la de zona, y quedó presupuesto pendiente,
        # avisamos que hay refinamiento posible.
        if not preciso and hubo_pendiente:
            pendientes += 1
        salida.append({
            "preciso": preciso,
            "establecimiento": p.get("establecimiento"), "direccion": p.get("direccion"),
            "distrito": p.get("distrito") or p.get("ciudad"), "provincia": p.get("provincia"),
            "departamento": p.get("departamento"),
            "precio_venta": p.get("precio_venta"), "precio_enered": p.get("precio_enered"),
            "combustible": p.get("combustible"), "es_enered": bool(p.get("es_enered")),
            "acepta_factura": p.get("acepta_factura", True),
            "lat": coords["lat"], "lon": coords["lon"],
        })

    return {"ok": True, "grifos": salida, "total": len(precios),
            "con_coordenadas": len(salida), "pendientes": pendientes}


@api.get("/precios/ruta")
async def precios_ruta(
    origen_lat: float, origen_lon: float,
    direccion: str = "", distrito: str = "", provincia: str = "", departamento: str = "",
    dest_lat: Optional[float] = None, dest_lon: Optional[float] = None,
    user: dict = Depends(get_current_user),
):
    """Ruta en auto desde la ubicación del usuario hasta un grifo: distancia (km), tiempo
    estimado (min) y el trazo del camino. Geocodifica el grifo si no llegan sus coordenadas.
    Fuentes gratuitas: Nominatim (geocodificación) + OSRM (ruteo)."""
    destino = None
    if dest_lat is not None and dest_lon is not None:
        destino = {"lat": dest_lat, "lon": dest_lon}
    else:
        # Intentos de menor a mayor especificidad; el grifo suele estar en carretera.
        for consulta in (
            f"{direccion}, {distrito}, {provincia}, {departamento}",
            f"{direccion}, {distrito}, {departamento}",
            f"{distrito}, {provincia}, {departamento}",
        ):
            if consulta.replace(",", "").strip():
                destino = await _geocodificar(consulta)
                if destino:
                    break
    if not destino:
        raise HTTPException(status_code=404,
                            detail="No pudimos ubicar este grifo en el mapa por su dirección.")

    import httpx as _hx
    try:
        url = (f"https://router.project-osrm.org/route/v1/driving/"
               f"{origen_lon},{origen_lat};{destino['lon']},{destino['lat']}"
               f"?overview=full&geometries=geojson")
        async with _hx.AsyncClient(timeout=15.0) as c:
            r = await c.get(url)
        data = r.json()
        ruta = (data.get("routes") or [None])[0]
        if not ruta:
            raise ValueError("sin ruta")
    except Exception as e:
        logger.warning(f"[ruta] OSRM: {e}")
        # Sin ruteo: al menos devolvemos el destino para marcarlo en el mapa.
        return {"ok": True, "destino": destino, "distancia_km": None, "duracion_min": None, "camino": []}

    # GeoJSON entrega [lon, lat]; el mapa (Leaflet) usa [lat, lon].
    camino = [[p[1], p[0]] for p in ruta["geometry"]["coordinates"]]
    km = ruta["distance"] / 1000
    # OSRM da el tiempo en "flujo libre" (vía vacía), irreal en ciudad. Ajuste por tráfico:
    # más fuerte en tramos cortos/urbanos (semáforos, congestión) y menor en carretera.
    base_min = ruta["duration"] / 60
    factor = 2.0 if km <= 5 else 1.7 if km <= 20 else 1.35
    duracion_real = round(base_min * factor)
    return {
        "ok": True,
        "destino": destino,
        "distancia_km": round(km, 1),
        "duracion_min": duracion_real,
        "duracion_libre_min": round(base_min),
        "camino": camino,
    }


@api.post("/admin/precios/sync")
async def sync_precios(user: dict = Depends(require_roles("admin_enered"))):
    """Dispara el scraping de precios desde Facilito OSINERGMIN."""
    from services.facilito_scraper import scrape_all_precios_async, COMBUSTIBLES
    from seed_facilito_precios import seed

    enered_docs = await db.estaciones_enered.find({}, {"nombre_facilito": 1}).to_list(500)
    enered_stations = {e.get("nombre_facilito", "") for e in enered_docs if e.get("nombre_facilito")}

    results = []
    try:
        results = await scrape_all_precios_async(enered_stations)
    except Exception as e:
        logger.error(f"Facilito scrape error: {e}")

    if results:
        # Reemplazar solo los departamentos que se scrapearon exitosamente
        # (conserva zonas que fallaron o no se incluyeron en esta corrida)
        dptos_scraped = set(r.get("departamento") for r in results if r.get("departamento"))
        for dpto in dptos_scraped:
            await db.precios_facilito.delete_many({"departamento": dpto})
        await db.precios_facilito.insert_many(results)
        logger.info(f"[sync_precios] {len(results)} registros insertados para {len(dptos_scraped)} departamentos")
    else:
        # Scraping retornó 0 resultados: aplicar semilla SOLO si la colección está vacía
        existing_count = await db.precios_facilito.count_documents({})
        if existing_count == 0:
            await seed(db)
            logger.warning("[sync_precios] Scraping fallido. Semilla de respaldo aplicada.")
        else:
            logger.warning(
                f"[sync_precios] Scraping retornó 0 resultados. "
                f"Conservando {existing_count} registros existentes."
            )

    await db.precios_facilito.create_index("combustible")
    await db.precios_facilito.create_index("departamento")
    await db.precios_facilito.create_index("es_enered")

    count = await db.precios_facilito.count_documents({})
    return {
        "ok": True,
        "total_synced": len(results),
        "total_en_db": count,
        "combustibles": COMBUSTIBLES,
        "message": (
            f"{len(results)} precios actualizados desde Facilito OSINERGMIN"
            if results else "Scraping sin resultados; base de datos previa conservada."
        ),
    }


@api.post("/admin/precios/importar-html")
async def importar_precios_html(
    files: List[UploadFile] = File(...),
    departamento: str = Form(""),
    provincia: str = Form(""),
    combustible: str = Form(""),
    user: dict = Depends(require_roles("admin_enered")),
):
    """
    Importación ASISTIDA de precios: Facilito bloqueó el scraping con reCAPTCHA, así que el
    admin hace la búsqueda en su navegador (resuelve el captcha como humano), guarda la página
    de resultados (⌘+S) y la sube aquí. Se parsea con el mismo parser del scraper y se
    reemplazan SOLO los precios del ámbito importado (departamento[+provincia]+combustible).
    """
    from services.facilito_scraper import parsear_html_guardado

    enered_docs = await db.estaciones_enered.find({}, {"nombre_facilito": 1}).to_list(500)
    enered_stations = {e.get("nombre_facilito", "") for e in enered_docs if e.get("nombre_facilito")}

    detalle, total = [], 0
    for f in files:
        try:
            crudo = await f.read()
            # Facilito sirve la página en windows-1252 (así la guarda el navegador).
            try:
                html = crudo.decode("utf-8")
            except UnicodeDecodeError:
                html = crudo.decode("cp1252", errors="replace")
            r = parsear_html_guardado(html, enered_stations, departamento, provincia, combustible)
        except Exception as e:
            detalle.append({"archivo": f.filename, "ok": False, "error": f"No se pudo leer: {str(e)[:120]}"})
            continue
        if not r.get("ok"):
            detalle.append({"archivo": f.filename, "ok": False, "error": r.get("error")})
            continue
        if not r["registros"]:
            detalle.append({"archivo": f.filename, "ok": False,
                            "error": "El archivo no contiene la tabla de resultados de Facilito. "
                                     "Guarda la página DESPUÉS de hacer la búsqueda."})
            continue
        filtro = {"departamento": r["departamento"], "combustible": r["combustible"]}
        if r.get("provincia"):
            filtro["provincia"] = r["provincia"]
        await db.precios_facilito.delete_many(filtro)
        await db.precios_facilito.insert_many(r["registros"])
        total += len(r["registros"])
        detalle.append({"archivo": f.filename, "ok": True, "registros": len(r["registros"]),
                        "departamento": r["departamento"], "provincia": r.get("provincia"),
                        "combustible": r["combustible"]})
        logger.info(f"[importar_precios_html] {f.filename}: {len(r['registros'])} precios "
                    f"({r['departamento']}/{r.get('provincia') or '-'}/{r['combustible']})")

    await db.precios_facilito.create_index("combustible")
    await db.precios_facilito.create_index("departamento")
    count = await db.precios_facilito.count_documents({})
    return {"ok": True, "importados": total, "total_en_db": count, "detalle": detalle}


@api.post("/admin/precios/sync-mapa")
async def sync_precios_mapa(payload: dict = None, user: dict = Depends(require_roles("admin_enered"))):
    """Sincroniza precios Y coordenadas GPS reales desde el mapa de Facilito (sin captcha).
    Body opcional: {"departamentos": ["LA LIBERTAD", ...]}; sin él, trae todo el Perú.
    Reemplaza cada departamento traído. Esta es la fuente correcta: ubica los grifos donde
    de verdad están (no una aproximación por dirección)."""
    from services.facilito_mapa import traer_precios_con_gps, DEPARTAMENTOS

    deps = (payload or {}).get("departamentos") or None
    try:
        registros = await traer_precios_con_gps(deps)
    except Exception as e:
        logger.error(f"[sync_precios_mapa] {e}")
        raise HTTPException(status_code=502, detail=f"No se pudo consultar el mapa de Facilito: {str(e)[:120]}")
    if not registros:
        raise HTTPException(status_code=404, detail="Facilito no devolvió grifos para ese ámbito.")

    # Marca es_enered por nombre y normaliza combustible.
    enered_names = {(n or "").upper() for n in await db.estaciones_enered.distinct("nombre_facilito")}

    # Provincia/distrito reales cruzando el código OSINERGMIN con el padrón. Si el padrón
    # está vacío, se sincroniza primero (así el distrito sale correcto, no el departamento).
    if await db.grifos_osinergmin.estimated_document_count() == 0:
        try:
            from services.padron_grifos import sincronizar as _sync_padron
            await _sync_padron(db)
        except Exception as e:
            logger.warning(f"[sync_precios_mapa] no se pudo cargar el padrón OSINERGMIN: {e}")

    # Índice por código (para el cruce) — la carga del padrón solo indexa 'ruc'.
    try:
        await db.grifos_osinergmin.create_index("codigo_osinergmin")
    except Exception:
        pass

    # El código de Facilito y el del padrón pueden diferir en ceros a la izquierda/espacios;
    # se normaliza para que el cruce no falle. Se mapea por departamento (más tolerante que $in).
    def _ncod(c):
        return str(c or "").strip().lstrip("0")
    deps_sync = {(r.get("departamento") or "").upper() for r in registros}
    padron = {}
    async for g in db.grifos_osinergmin.find(
        {"departamento": {"$in": list(deps_sync)}},
        {"_id": 0, "codigo_osinergmin": 1, "provincia": 1, "distrito": 1}):
        k = _ncod(g.get("codigo_osinergmin"))
        if k:
            padron[k] = g

    # Fuente PRINCIPAL del distrito: point-in-polygon con el GPS del grifo (límites
    # distritales INEI, 1834 distritos). Cubre el 100% y no depende del padrón (que está
    # desactualizado). El padrón queda solo como respaldo si el GPS cae fuera de todo.
    from services.geo_distritos import ubicar as _ubicar_distrito

    dptos = set()
    for r in registros:
        r["combustible"] = normalizar_combustible(r["combustible"])
        r["es_enered"] = (r["establecimiento"] or "").upper() in enered_names
        r["preciso"] = True   # coordenada GPS real
        dep_scraper = (r["departamento"] or "").upper()
        loc = _ubicar_distrito(r.get("lat"), r.get("lon"))
        ref = padron.get(_ncod(r.get("codigo_osinergmin")), {})
        if loc and loc["departamento"] == dep_scraper:
            r["provincia"] = loc["provincia"]
            r["distrito"] = loc["distrito"]
        else:
            r["provincia"] = (ref.get("provincia") or dep_scraper).upper()
            r["distrito"] = (ref.get("distrito") or "").upper()
        r["ciudad"] = r["distrito"] or dep_scraper
        dptos.add(r["departamento"])

    # Borra TODO lo viejo del departamento (regex case-insensitive para cubrir variantes de
    # nombre/acentos) antes de insertar lo fresco → sin residuos ni duplicados.
    borrados = 0
    for dep in dptos:
        r = await db.precios_facilito.delete_many(
            {"departamento": {"$regex": f"^{re.escape(dep)}$", "$options": "i"}})
        borrados += r.deleted_count
    await db.precios_facilito.insert_many(registros)
    await db.precios_facilito.create_index("combustible")
    await db.precios_facilito.create_index("departamento")

    count = await db.precios_facilito.count_documents({})
    grifos = len({(r["establecimiento"], r["lat"], r["lon"]) for r in registros})
    # Diagnóstico del cruce de distrito con el padrón OSINERGMIN.
    con_distrito = sum(1 for r in registros
                       if r["distrito"] and r["distrito"] != (r["departamento"] or "").upper())
    padron_total = await db.grifos_osinergmin.estimated_document_count()
    sin_match = list({str(r.get("codigo_osinergmin") or "") for r in registros
                      if not (r["distrito"] and r["distrito"] != (r["departamento"] or "").upper())})[:5]
    padron_muestra = [g.get("codigo_osinergmin") async for g in
                      db.grifos_osinergmin.find({}, {"_id": 0, "codigo_osinergmin": 1}).limit(5)]
    return {"ok": True, "grifos_con_gps": grifos, "registros": len(registros),
            "borrados_viejos": borrados, "departamentos": sorted(dptos), "total_en_db": count,
            "diagnostico": {
                "padron_total": padron_total,
                "con_distrito_real": con_distrito,
                "sin_distrito": len(registros) - con_distrito,
                "codigos_facilito_sin_match": sin_match,
                "codigos_padron_muestra": padron_muestra,
            }}


@api.post("/admin/precios/importar-json")
async def importar_precios_json(payload: dict, user: dict = Depends(require_roles("admin_enered"))):
    """
    Importación en bloque desde el recolector de consola de Facilito (un solo archivo .json
    con TODO lo recorrido). Reemplaza cada (departamento + combustible) presente en el lote.
    Cada registro: {departamento, provincia, distrito, establecimiento, direccion, telefono,
    precio_venta, combustible}.
    """
    registros = payload.get("registros") or payload.get("precios") or []
    if not isinstance(registros, list) or not registros:
        raise HTTPException(status_code=400, detail="El archivo no contiene registros")

    enered_docs = await db.estaciones_enered.find({}, {"nombre_facilito": 1}).to_list(500)
    enered_stations = {(e.get("nombre_facilito") or "").upper() for e in enered_docs if e.get("nombre_facilito")}

    scraped_at = datetime.now(timezone.utc).isoformat()
    limpios, ambitos = [], set()
    for r in registros:
        est = (r.get("establecimiento") or "").strip()
        try:
            precio = float(r.get("precio_venta"))
        except (TypeError, ValueError):
            precio = None
        if not est or precio is None or not (5.0 < precio < 100.0):
            continue
        dpto = (r.get("departamento") or "").strip().upper()
        if dpto.startswith("PROV. CONST"):
            dpto = "CALLAO"
        comb = (r.get("combustible") or "").strip()
        limpios.append({
            "establecimiento": est,
            "direccion": (r.get("direccion") or "").strip(),
            "telefono": (r.get("telefono") or "").strip(),
            "precio_venta": precio, "precio_pizarra": precio,
            "combustible": comb,
            "departamento": dpto,
            "provincia": (r.get("provincia") or "").strip().upper() or dpto,
            "distrito": (r.get("distrito") or "").strip().upper(),
            "ciudad": (r.get("distrito") or r.get("provincia") or "").strip().upper(),
            "fuente": "facilito.gob.pe", "scraped_at": scraped_at,
            "es_enered": est.upper() in enered_stations,
            "calidad": 4, "acepta_factura": True, "acepta_tarjeta": False,
        })
        if dpto and comb:
            ambitos.add((dpto, comb))

    if not limpios:
        raise HTTPException(status_code=400, detail="Ningún registro válido en el archivo")

    for dpto, comb in ambitos:
        await db.precios_facilito.delete_many({"departamento": dpto, "combustible": comb})
    await db.precios_facilito.insert_many(limpios)
    await db.precios_facilito.create_index("combustible")
    await db.precios_facilito.create_index("departamento")

    count = await db.precios_facilito.count_documents({})
    resumen = {}
    for r in limpios:
        resumen[r["departamento"]] = resumen.get(r["departamento"], 0) + 1
    logger.info(f"[importar_precios_json] {len(limpios)} precios en {len(ambitos)} ámbitos")
    return {"ok": True, "importados": len(limpios), "total_en_db": count,
            "por_departamento": [{"departamento": k, "registros": v} for k, v in sorted(resumen.items())]}



@api.get("/admin/precios/estaciones-enered")
async def list_estaciones_enered(user: dict = Depends(require_roles("admin_enered"))):
    """Lista las estaciones ENERED registradas con precio especial."""
    docs = await db.estaciones_enered.find({}, {"_id": 0}).to_list(500)
    return {"estaciones": docs}


@api.post("/admin/precios/estaciones-enered")
async def upsert_estacion_enered(
    data: dict,
    user: dict = Depends(require_roles("admin_enered"))
):
    """Agrega o actualiza una estacion ENERED con su precio especial por cliente."""
    nombre = data.get("nombre_facilito", "").strip()
    if not nombre:
        raise HTTPException(status_code=400, detail="nombre_facilito es requerido")

    comb = normalizar_combustible(data.get("combustible") or "Diesel B5 UV")
    precio = float(data.get("precio_enered") or 0)
    cliente = (data.get("cliente") or "GENERAL").strip().upper()

    existing = await db.estaciones_enered.find_one({"nombre_facilito": nombre, "combustible": comb})
    precios_cliente = existing.get("precios_cliente", {}) if existing else {}
    
    if cliente and cliente != "GENERAL":
        precios_cliente[cliente] = precio
    else:
        precios_cliente["GENERAL"] = precio

    doc = {
        "nombre_facilito": nombre,
        "combustible": comb,
        "precio_enered": precio if not cliente or cliente == "GENERAL" else (existing.get("precio_enered", precio) if existing else precio),
        "cliente_asignado": cliente,
        "precios_cliente": precios_cliente,
        "departamento": data.get("departamento", ""),
        "provincia": data.get("provincia", ""),
        "distrito": data.get("distrito", ""),
        "acepta_factura": True,
        "acepta_tarjeta": True,
        "activa": True,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    await db.estaciones_enered.update_one(
        {"nombre_facilito": nombre, "combustible": comb},
        {"$set": doc},
        upsert=True,
    )
    await db.precios_facilito.update_many(
        {"establecimiento": {"$regex": nombre, "$options": "i"}},
        {"$set": {"es_enered": True, "acepta_tarjeta": True, "calidad": 5}}
    )
    return {"ok": True, "nombre_facilito": nombre, "precio_enered": precio, "cliente": cliente}


@api.post("/admin/precios/estaciones-enered/masivo")
async def upsert_estaciones_enered_masivo(data: dict, user: dict = Depends(require_roles("admin_enered"))):
    """Asigna el MISMO precio ENERED (corporativo) a VARIAS estaciones de una vez.
    Body: {estaciones: [{nombre_facilito|establecimiento, departamento, provincia, distrito}],
           combustible, precio_enered, cliente}. El precio puede ser por cliente."""
    estaciones = data.get("estaciones") or []
    if not estaciones:
        raise HTTPException(status_code=400, detail="No hay estaciones seleccionadas")
    comb = normalizar_combustible(data.get("combustible") or "Diesel B5 UV")
    precio = float(data.get("precio_enered") or 0)
    if precio <= 0:
        raise HTTPException(status_code=400, detail="Ingresa un precio válido mayor a 0")
    cliente = (data.get("cliente") or "GENERAL").strip().upper()

    nombres = []
    for est in estaciones:
        nombre = (est.get("nombre_facilito") or est.get("establecimiento") or "").strip()
        if not nombre:
            continue
        existing = await db.estaciones_enered.find_one({"nombre_facilito": nombre, "combustible": comb})
        precios_cliente = existing.get("precios_cliente", {}) if existing else {}
        if cliente and cliente != "GENERAL":
            precios_cliente[cliente] = precio
        else:
            precios_cliente["GENERAL"] = precio
        doc = {
            "nombre_facilito": nombre,
            "combustible": comb,
            "precio_enered": precio if not cliente or cliente == "GENERAL" else (existing.get("precio_enered", precio) if existing else precio),
            "cliente_asignado": cliente,
            "precios_cliente": precios_cliente,
            "departamento": est.get("departamento", ""),
            "provincia": est.get("provincia", ""),
            "distrito": est.get("distrito", "") or est.get("ciudad", ""),
            "acepta_factura": True, "acepta_tarjeta": True, "activa": True,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.estaciones_enered.update_one(
            {"nombre_facilito": nombre, "combustible": comb}, {"$set": doc}, upsert=True)
        nombres.append(nombre)

    if nombres:
        await db.precios_facilito.update_many(
            {"establecimiento": {"$in": nombres}},
            {"$set": {"es_enered": True, "acepta_tarjeta": True, "calidad": 5}})
    return {"ok": True, "asignadas": len(nombres), "precio_enered": precio, "cliente": cliente}


@api.get("/admin/sire/compras")
async def admin_sire_compras(periodo: str = "202606", user: dict = Depends(require_roles("admin_enered"))):
    """
    Trae del API SIRE (SUNAT) todos los comprobantes que le emitieron al cliente conectado
    (credenciales en .env) y marca cuáles son de grifos inscritos en OSINERGMIN.
    Solo lectura — nunca se llama aceptar/reemplazar propuesta.
    """
    import os as _os
    from dotenv import dotenv_values as _dv
    from services import sire as _sire
    # Releer el .env en cada consulta (permite conectar un cliente sin reiniciar el backend)
    _envf = _dv(ROOT_DIR / ".env") if (ROOT_DIR / ".env").exists() else {}
    creds = {k: (_envf.get(f"SIRE_{k.upper()}") or _os.getenv(f"SIRE_{k.upper()}") or "").strip()
             for k in ("client_id", "client_secret", "ruc", "usuario", "clave")}
    faltan = [k for k, v in creds.items() if not v]
    if faltan:
        raise HTTPException(status_code=400,
                            detail=f"Faltan credenciales SIRE en el .env: {', '.join('SIRE_'+f.upper() for f in faltan)}")
    try:
        data = await _sire.compras_periodo(**creds, periodo=periodo)
    except _sire.SireError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Cruce con el padrón de grifos (OSINERGMIN) → identificar facturas de combustible
    rucs = {c["ruc_emisor"] for c in data["comprobantes"]}
    grifos = {}
    if rucs:
        async for g in db.grifos_osinergmin.find({"ruc": {"$in": list(rucs)}},
                                                 {"_id": 0, "ruc": 1, "razon_social": 1, "distrito": 1,
                                                  "provincia": 1, "departamento": 1}):
            grifos.setdefault(g["ruc"], g)
    # Rubro del emisor: grifos por padrón OSINERGMIN; el resto por el nombre (heurística).
    _RUBROS = [
        ("Combustible", r"GRIFO|ESTACION DE SERVICIO|COMBUSTIBLE|PETROL|COESTI|PRIMAX|REPSOL|SERVICENTRO|GASOCENTRO"),
        ("Llantas", r"LLANTA|NEUMATIC|REENCAUCH"),
        ("Repuestos / Mantenimiento", r"REPUESTO|AUTOMOTRIZ|AUTOPART|MOTORS?|FRENOS|LUBRICANT|TALLER|MECANIC|DIESEL PARTS"),
        ("Seguros", r"SEGURO|RIMAC|PACIFICO|MAPFRE|LA POSITIVA|INTERSEGURO"),
        ("Financiero", r"BANCO|CAJA |FINANCIER|LEASING|FACTORING|SCOTIA|INTERBANK|BBVA|BCP\b"),
        ("Telecom", r"TELEFON|CLARO|ENTEL|MOVISTAR|BITEL|AMERICA MOVIL|WIN\b"),
        ("Peajes / Concesiones", r"PEAJE|RUTAS DE|COVI|CONCESION|AUTOPISTA|LAMSAC|DEVIANDES"),
        ("Luz / Agua", r"ELECTR|ENEL|LUZ DEL SUR|HIDRANDINA|ELECTRONORTE|SEDALIB|SEDAPAL|AGUA"),
        ("Transporte / Logística", r"TRANSPORTE|LOGISTIC|CARGO|COURIER"),
    ]
    def _rubro(c):
        if c["es_grifo"]:
            return "Combustible"
        n = (c.get("razon_social") or "").upper()
        for nombre, patron in _RUBROS:
            if re.search(patron, n):
                return nombre
        return "Otros"

    for c in data["comprobantes"]:
        g = grifos.get(c["ruc_emisor"])
        c["es_grifo"] = bool(g)
        if g:
            c["grifo"] = g
        c["rubro"] = _rubro(c)
    data["de_grifos"] = sum(1 for c in data["comprobantes"] if c["es_grifo"])
    # Resumen por rubro (cantidad y monto) para los chips del frontend
    _rs = {}
    for c in data["comprobantes"]:
        d = _rs.setdefault(c["rubro"], {"rubro": c["rubro"], "cantidad": 0, "total": 0.0})
        d["cantidad"] += 1
        d["total"] += c.get("total") or 0
    data["rubros"] = sorted(_rs.values(), key=lambda x: -x["total"])
    data["ruc_cliente"] = creds["ruc"]
    return data


@api.get("/precios/publico")
async def precios_publico(combustible: Optional[str] = None):
    """PÚBLICO (sin login): TODOS los precios de Facilito (mercado), marcando las estaciones
    de la Red ENERED con su precio especial (mismo cruce que el módulo admin)."""
    query = {}
    if combustible:
        query["combustible"] = {"$regex": combustible.strip(), "$options": "i"}
    rows = await db.precios_facilito.find(query, {"_id": 0}).sort("precio_venta", 1).limit(6000).to_list(6000)

    # Cruce con estaciones ENERED (mismo criterio que /precios: nombre + combustible normalizado, con fallback difuso).
    enered_map = {}
    async for e in db.estaciones_enered.find({"activa": {"$ne": False}}, {"_id": 0}):
        key_name = (e.get("nombre_facilito") or "").strip().upper()
        key_comb = normalizar_combustible(e.get("combustible") or "")
        if key_comb:
            enered_map[(key_name, key_comb)] = e
        enered_map[key_name] = e

    REDES = {"REPSOL", "PRIMAX", "PETROPERU", "SHELL", "MOBIL", "PECSA", "TERPEL", "COESTI"}
    out = []
    for p in rows:
        comb_norm = normalizar_combustible(p.get("combustible"))
        nombre_est = (p.get("establecimiento") or p.get("estacion") or "").strip().upper()
        info = enered_map.get((nombre_est, comb_norm))
        if not info:
            for k, val in enered_map.items():
                if isinstance(k, tuple) and k[1] == comb_norm and (k[0] in nombre_est or nombre_est in k[0]):
                    info = val
                    break
        piz = float(p.get("precio_venta") or p.get("precio_pizarra") or 0) or None
        precio_e = None
        if info:
            pc = info.get("precios_cliente") or {}
            precio_e = float(pc.get("GENERAL") or info.get("precio_enered") or 0) or None
        out.append({
            "estacion": p.get("establecimiento") or p.get("estacion") or "", "combustible": comb_norm,
            "precio_pizarra": round(piz, 2) if piz else None,
            "precio_enered": round(precio_e, 2) if precio_e else None,
            "es_enered": bool(precio_e),
            "ahorro": round(piz - precio_e, 2) if (piz and precio_e and piz > precio_e) else None,
            "departamento": p.get("departamento") or "", "provincia": p.get("provincia") or "",
            "distrito": p.get("distrito") or p.get("ciudad") or "", "direccion": p.get("direccion") or "",
            "calidad": (5 if precio_e else (4 if any(r in nombre_est for r in REDES) else 2)),
            "acepta_factura": bool(precio_e or p.get("acepta_factura")),
            "acepta_tarjeta": bool(precio_e or p.get("acepta_tarjeta")),
            # GPS de Facilito: los botones "Ver en mapa" / "Cómo llegar" abren el punto exacto.
            "lat": p.get("lat"), "lon": p.get("lon"),
        })
    # Dedup por (estación, dirección COMPLETA, distrito, combustible). Antes usaba dirección[:20]
    # y colapsaba sedes distintas de una misma cadena (mismo prefijo de dirección) → grifos perdidos.
    seen, dedup = set(), []
    for o in out:
        k = (o["estacion"].upper(), (o["direccion"] or "").strip().upper(), (o["distrito"] or "").upper(), o["combustible"].upper())
        if k not in seen:
            seen.add(k); dedup.append(o)
    dedup.sort(key=lambda x: (not x["es_enered"], x.get("precio_enered") or x.get("precio_pizarra") or 9999))
    combustibles = sorted({o["combustible"] for o in dedup if o["combustible"]})
    return {"estaciones": dedup, "total": len(dedup), "enered": sum(1 for o in dedup if o["es_enered"]), "combustibles": combustibles}


@api.get("/precios/mapa-publico")
async def precios_mapa_publico(combustible: Optional[str] = None, departamento: Optional[str] = None,
                               provincia: Optional[str] = None, distrito: Optional[str] = None):
    """PÚBLICO (sin login): grifos con GPS real para el mapa de la landing /precios.
    Marca es_enered (Red ENERED). Mismo pintado que el mapa del módulo con login, pero abierto."""
    query = {"lat": {"$ne": None}, "lon": {"$ne": None}}
    if combustible:
        c = combustible.strip().upper()
        if "PREMIUM" in c:
            query["combustible"] = {"$regex": "PREMIUM|95|97|98", "$options": "i"}
        elif "REGULAR" in c or "84" in c:
            query["combustible"] = {"$regex": "REGULAR|84|90", "$options": "i"}
        elif "DIESEL" in c or "DB5" in c or "B5" in c:
            query["combustible"] = {"$regex": "DB5|DIESEL|B5|S-50|UV", "$options": "i"}
        else:
            query["combustible"] = {"$regex": combustible, "$options": "i"}
    if departamento:
        dep = departamento.strip().upper().replace("Á", "A").replace("É", "E").replace("Í", "I").replace("Ó", "O").replace("Ú", "U")
        query["departamento"] = {"$regex": dep, "$options": "i"}
    if provincia:
        query["provincia"] = {"$regex": provincia.strip().upper(), "$options": "i"}
    if distrito:
        d = distrito.strip().upper()
        query["$or"] = [{"distrito": {"$regex": d, "$options": "i"}},
                        {"ciudad": {"$regex": d, "$options": "i"}}]

    rows = await db.precios_facilito.find(query, {"_id": 0}).limit(20000).to_list(20000)
    enered_up = {(n or "").strip().upper() for n in await db.estaciones_enered.distinct("nombre_facilito")}

    grifos = []
    for p in rows:
        lat, lon = p.get("lat"), p.get("lon")
        if lat is None or lon is None:
            continue
        # descarta coordenadas fuera de Perú (GPS basura)
        if not (-18.6 <= lat <= 0.1 and -81.5 <= lon <= -68.5):
            continue
        nombre = (p.get("establecimiento") or p.get("estacion") or "")
        grifos.append({
            "preciso": True, "establecimiento": nombre, "direccion": p.get("direccion"),
            "distrito": p.get("distrito") or p.get("ciudad"), "provincia": p.get("provincia"),
            "departamento": p.get("departamento"),
            "precio_venta": p.get("precio_venta"), "combustible": p.get("combustible"),
            "es_enered": nombre.strip().upper() in enered_up,
            "lat": lat, "lon": lon,
        })
    return {"ok": True, "grifos": grifos, "total": len(grifos),
            "con_coordenadas": len(grifos), "pendientes": 0}


app.include_router(api)


@api.delete("/admin/consumptions/cleanup")
async def cleanup_consumptions(
    estacion: Optional[str] = None,
    empresa: Optional[str] = None,
    user: dict = Depends(require_roles("admin_enered"))
):
    """Delete consumption records by filter from both consumptions and consumos_subsidio."""
    q_cons = {}
    q_sub = {}
    if estacion:
        q_cons["ESTACION"] = estacion
        q_sub["estacion"] = estacion
    if empresa:
        q_cons["EMPRESA"] = empresa
        q_sub["empresa"] = empresa
    if not q_cons:
        raise HTTPException(status_code=400, detail="Debes especificar al menos un filtro (estacion o empresa)")
    
    r1 = await db.consumptions.delete_many(q_cons)
    r2 = await db.consumos_subsidio.delete_many(q_sub)
    
    total_deleted = r1.deleted_count + r2.deleted_count
    return {
        "deleted": total_deleted,
        "consumptions_deleted": r1.deleted_count,
        "consumos_subsidio_deleted": r2.deleted_count,
        "filter": {"estacion": estacion, "empresa": empresa}
    }

@api.get("/admin/precios/debug")
async def debug_precios(user: dict = Depends(require_roles("admin_enered"))):
    """Diagnostic endpoint — reads the sheet and returns raw + normalized data without inserting."""
    import google_sheets_sync
    sheet_id = os.environ.get("GOOGLE_SHEETS_ID")
    tab = os.environ.get("GOOGLE_SHEETS_TAB_PRECIOS", "PRECIOS")
    
    debug = {"sheet_id": sheet_id, "tab_configured": tab, "env_vars_set": {
        "GOOGLE_SHEETS_ID": bool(sheet_id),
        "GOOGLE_SHEETS_TAB_PRECIOS": bool(os.environ.get("GOOGLE_SHEETS_TAB_PRECIOS")),
    }}
    
    try:
        records, actual_tab = await google_sheets_sync.fetch_rows(sheet_id, tab)
        debug["actual_tab"] = actual_tab
        debug["total_rows_read"] = len(records)
        debug["first_3_raw"] = records[:3] if records else []
        
        # Show column headers from first row
        if records:
            debug["column_headers"] = list(records[0].keys())
            normalized_headers = {k: google_sheets_sync._normalize_col(k) for k in records[0].keys()}
            debug["normalized_headers"] = normalized_headers
        
        # Try normalizing first 3 rows
        sample_normalized = []
        for r in records[:3]:
            norm = {}
            for k, v in r.items():
                key = google_sheets_sync._normalize_col(k)
                if key:
                    norm[key] = v
            pv = google_sheets_sync._parse_number(norm.get("PRECIO_VENTA"))
            if pv is None:
                pv = google_sheets_sync._parse_number(norm.get("ENERED"))
            pp = google_sheets_sync._parse_number(norm.get("PRECIO_PIZARRA"))
            if pp is None:
                pp = google_sheets_sync._parse_number(norm.get("PIZARRA"))
            sample_normalized.append({
                "norm_keys": list(norm.keys()),
                "empresa": norm.get("EMPRESA", "?"),
                "estacion": norm.get("ESTACION", "?"),
                "combustible": norm.get("COMBUSTIBLE", "?"),
                "precio_venta_parsed": pv,
                "precio_pizarra_parsed": pp,
                "raw_enered": norm.get("ENERED"),
                "raw_pizarra": norm.get("PIZARRA"),
            })
        debug["first_3_normalized"] = sample_normalized
        
        # Count how many precios are in DB right now
        count = await db.precios.count_documents({})
        debug["precios_in_db"] = count
        
    except Exception as e:
        debug["error"] = str(e)
    
    return debug


# ---------- Auth Endpoints ----------
@api.post("/auth/login")
async def login(data: LoginIn, response: Response):
    email = data.email.lower().strip()
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    access = create_access_token(user["id"], user["email"], user["role"], user.get("empresa"))
    refresh = create_refresh_token(user["id"])
    set_auth_cookies(response, access, refresh)
    response.headers["X-Access-Token"] = access  # fallback for clients
    user_data = await user_public_with_servicios(user)
    return {"user": user_data, "access_token": access}


@api.post("/auth/logout")
async def logout(response: Response, user: dict = Depends(get_current_user)):
    clear_auth_cookies(response)
    return {"ok": True}


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return await user_public_with_servicios(user)


@api.get("/constancia")
async def constancia_estado(user: dict = Depends(get_current_user)):
    """Versión vigente de la constancia y si el usuario ya la aceptó."""
    return {
        "version": CONSTANCIA_VERSION,
        "pendiente": await _constancia_pendiente(user),
        "aceptada": user.get("constancia_aceptada"),
        "no_mostrar": user.get("constancia_no_mostrar"),
        "cliente": await _constancia_datos_cliente(user),
    }


async def _constancia_datos_cliente(user: dict) -> dict:
    """Datos del cliente para rellenar el preámbulo de la constancia: razón social, RUC,
    representante legal, DNI y cargo. Se toman de la declaración jurada del cliente (donde el
    propio cliente los declaró), o del representante legal en SUNAT, o de los datos del usuario."""
    empresa = user.get("empresa")
    ruc = user.get("ruc")
    representante = dni = cargo = None
    # 1) Lo que el cliente declaró en su DJ (lo más fiable, es su propia declaración)
    dj = await db.subsidio_declaraciones.find_one(
        {"$or": [{"user_id": user.get("id")}, {"empresa": empresa}], "representante": {"$nin": [None, ""]}},
        {"_id": 0, "representante": 1, "representante_dni": 1},
        sort=[("accepted_at", -1)])
    if dj:
        representante = (dj.get("representante") or "").strip() or None
        dni = (dj.get("representante_dni") or "").strip() or None
    # 2) Representante legal en SUNAT (por RUC)
    if (not representante or not dni) and ruc:
        cache = await db.representantes_ruc.find_one({"ruc": ruc}, {"_id": 0, "representantes": 1})
        reps = (cache or {}).get("representantes") or []
        if reps:
            principal = next((r for r in reps if any(k in (r.get("cargo") or "").upper()
                             for k in ("GERENTE", "TITULAR", "REPRESENTANTE"))), reps[0])
            representante = representante or (principal.get("nombre") or "").strip() or None
            dni = dni or (principal.get("numero_documento") or "").strip() or None
            cargo = cargo or (principal.get("cargo") or "").strip().title() or None
    # 3) Fallbacks a los datos del usuario
    representante = representante or user.get("contacto") or user.get("name")
    cargo = cargo or "Representante legal"
    return {"razon_social": empresa, "ruc": ruc, "representante": representante, "dni": dni, "cargo": cargo}


class ConstanciaAceptarIn(BaseModel):
    no_volver_a_mostrar: bool = False


@api.post("/constancia/aceptar")
async def constancia_aceptar(request: Request, body: ConstanciaAceptarIn = ConstanciaAceptarIn(),
                             user: dict = Depends(get_current_user)):
    """Registra la aceptación de la constancia (prueba del consentimiento). Si el cliente marca
    'no volver a mostrar', deja de aparecer en próximos inicios de sesión (para esta versión)."""
    if user.get("es_guest") or user.get("_impersonando") or user.get("_admin_id"):
        raise HTTPException(status_code=403, detail="Solo el propio cliente puede aceptar la constancia")
    uid = user.get("id")
    now = datetime.now(timezone.utc).isoformat()
    registro = {
        "version": CONSTANCIA_VERSION,
        "at": now,
        "ip": (request.client.host if request.client else None),
        "user_agent": request.headers.get("user-agent", "")[:300],
        "empresa": user.get("empresa"),
        "ruc": user.get("ruc"),
        "email": user.get("email"),
        "medio": "plataforma_web",
    }
    setter = {"constancia_aceptada": registro}
    if body.no_volver_a_mostrar:
        setter["constancia_no_mostrar"] = {"version": CONSTANCIA_VERSION, "at": now}
    await db.users.update_one({"id": uid}, {"$set": setter})
    # Bitácora de auditoría: guarda TODAS las aceptaciones (cada inicio de sesión que la acepta),
    # con una entrada por usuario/versión/fecha-hora, para probar el consentimiento reiterado.
    await db.constancia_aceptaciones.update_one(
        {"user_id": uid, "version": CONSTANCIA_VERSION, "at": now},
        {"$set": {**registro, "user_id": uid, "no_volver_a_mostrar": body.no_volver_a_mostrar}}, upsert=True)
    return {"ok": True, "aceptada": registro, "no_volver_a_mostrar": body.no_volver_a_mostrar}


class ConstanciaResetIn(BaseModel):
    email: Optional[str] = None
    ruc: Optional[str] = None
    todos: bool = False


@api.post("/admin/constancia/reset")
async def constancia_reset(body: ConstanciaResetIn, user: dict = Depends(require_roles("admin_enered"))):
    """Borra la aceptación de la constancia de un cliente (por email o RUC) o de todos,
    para que vuelva a pedirse. La bitácora de auditoría se conserva. Solo admin ENERED."""
    unset = {"$unset": {"constancia_aceptada": "", "constancia_no_mostrar": ""}}
    if body.todos:
        r = await db.users.update_many({"constancia_aceptada": {"$exists": True}}, unset)
        return {"ok": True, "reseteados": r.modified_count, "alcance": "todos"}
    q = {}
    if body.email:
        q["email"] = body.email.strip().lower()
    elif body.ruc:
        q["$or"] = [{"ruc": body.ruc.strip()}, {"empresas_asignadas.ruc": body.ruc.strip()}]
    else:
        raise HTTPException(status_code=400, detail="Indica email, ruc o todos")
    r = await db.users.update_many(q, unset)
    return {"ok": True, "reseteados": r.modified_count}


@api.get("/auth/download-token")
async def auth_download_token(user: dict = Depends(get_current_user)):
    """Emite un token efímero (5 min) para poner en URLs de descarga/preview,
    evitando exponer el token de sesión de 8 h en iframes/logs."""
    uid = user.get("_admin_id") or user.get("id")
    if not uid:
        raise HTTPException(status_code=400, detail="Sesión sin usuario")
    return {"token": create_download_token(uid)}


@api.post("/auth/refresh")
async def refresh_token(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="Sin token de refresco")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Token inválido")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
        access = create_access_token(user["id"], user["email"], user["role"], user.get("empresa"))
        response.set_cookie("access_token", access, httponly=True, secure=True, **_cookie_extra(),
                            max_age=JWT_ACCESS_MINUTES * 60, path="/")
        return {"access_token": access}
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


@api.post("/auth/forgot-password")
async def forgot_password(data: ForgotIn):
    email = data.email.lower().strip()
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if user:
        token = secrets.token_urlsafe(32)
        await db.password_reset_tokens.insert_one({
            "token": token,
            "user_id": user["id"],
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "used": False,
        })
        logger.info(f"[PASSWORD RESET] {email} token={token}")
    return {"message": "Si el correo existe, recibirás un enlace de recuperación."}


@api.post("/auth/reset-password")
async def reset_password(data: ResetIn):
    rec = await db.password_reset_tokens.find_one({"token": data.token, "used": False}, {"_id": 0})
    if not rec:
        raise HTTPException(status_code=400, detail="Token inválido o ya usado")
    expires = rec["expires_at"]
    if isinstance(expires, str):
        expires = datetime.fromisoformat(expires)
    if expires.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token expirado")
    await db.users.update_one({"id": rec["user_id"]},
                              {"$set": {"password_hash": hash_password(data.password)}})
    await db.password_reset_tokens.update_one({"token": data.token}, {"$set": {"used": True}})
    return {"message": "Contraseña actualizada"}


# ---------- Users Management ----------
@api.get("/users")
async def list_users(user: dict = Depends(require_permiso("usuarios"))):
    users = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(1000)
    return users


@api.post("/users")
async def create_user(data: UserCreate, user: dict = Depends(require_permiso("usuarios"))):
    email = data.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Correo ya registrado")
    asignadas = data.empresas_asignadas or []
    # Cliente multi-empresa: empresa/ruc principal = el primero de la lista si no vino explícito.
    empresa = data.empresa or (asignadas[0].get("empresa") if asignadas else None)
    ruc = data.ruc or (asignadas[0].get("ruc") if asignadas else None)
    doc = {
        "id": str(uuid.uuid4()),
        "email": email,
        "name": data.name,
        "role": data.role,
        "empresa": empresa,
        "permisos": data.permisos,  # None = acceso total; lista = módulos permitidos
        "password_hash": hash_password(data.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if data.role == "cliente_subsidio":
        doc["ruc"] = ruc or ""
        doc["empresas_asignadas"] = asignadas
        doc["acceso_etapa0"] = False        # creado por admin → ya habilitado (no arranca en Etapa 0 bloqueado)
        doc["registrado_etapa0"] = True
        doc["tipo_cliente"] = "subsidio"
    elif asignadas:
        doc["empresas_asignadas"] = asignadas
    await db.users.insert_one(doc)
    doc.pop("password_hash", None)
    doc.pop("_id", None)
    return doc


@api.put("/users/{uid}")
async def update_user(uid: str, data: UserUpdate, user: dict = Depends(require_permiso("usuarios"))):
    raw = data.model_dump(exclude_unset=True)
    patch = {k: v for k, v in raw.items() if v is not None}
    if "permisos" in raw:  # permitir setear permisos a null (acceso total) o a lista
        patch["permisos"] = raw["permisos"]
    if "password" in patch:
        patch["password_hash"] = hash_password(patch.pop("password"))
    if not patch:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    res = await db.users.update_one({"id": uid}, {"$set": patch})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    u = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0})
    return u


@api.delete("/users/{uid}")
async def delete_user(uid: str, user: dict = Depends(require_permiso("usuarios"))):
    if uid == user["id"]:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")
    await db.users.delete_one({"id": uid})
    return {"ok": True}


@api.get("/admin/audit-log")
async def get_audit_log(
    user: dict = Depends(require_permiso("bitacora")),
    q: Optional[str] = None,
    modulo: Optional[str] = None,
    accion: Optional[str] = None,
    limit: int = 200,
):
    """Bitácora de acciones (escrituras). Filtros: q (texto libre), modulo, accion."""
    query: dict = {}
    if modulo:
        query["modulo"] = modulo
    if accion:
        query["action"] = accion
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [
            {"user_email": rx}, {"user_name": rx}, {"path": rx}, {"empresa": rx},
        ]
    limit = max(1, min(limit, 1000))
    items = await db.audit_log.find(query, {"_id": 0}).sort("at", -1).limit(limit).to_list(limit)
    return {"items": items, "total": len(items)}


@api.get("/empresas")
async def list_empresas(user: dict = Depends(get_current_user)):
    consumptions_empresas = await db.consumptions.distinct("EMPRESA")
    config_empresas = await db.empresas_config.distinct("empresa")
    todas = set((consumptions_empresas or []) + (config_empresas or []))
    return sorted([e for e in todas if e])


# ---------- Consumptions ----------
def tenant_filter(user: dict) -> dict:
    if user["role"] == "admin_enered":
        return {}
    return {"EMPRESA": user.get("empresa")}


# ---------- Facturas de terceros vs. facturas ENERGIX ----------
# Regla (Giuliana, 26/09/2026): solo lo que emite ENERGIX PERÚ es deuda del cliente y consume
# línea de crédito. Todo lo demás (comprobantes que suben los clientes del subsidio, cargas
# manuales con factura de un grifo) es de TERCEROS: se lista, se descarga, pero saldo 0.
ENERGIX_RUC = "20609304082"
_TERCERO_VIAS = {"subsidio_confirm", "subsidio_backfill", "subsidio_dynamic", "consumption_sync"}


def _es_factura_tercero(inv: dict) -> bool:
    if (inv.get("estado") or "").strip().lower() == "tercero":
        return True
    ruc = str(inv.get("ruc_emisor") or "").strip()
    if ruc and ruc == ENERGIX_RUC:
        return False
    return (inv.get("created_via") or "") in _TERCERO_VIAS


# ---------- Normalización del producto (cargas del subsidio) ----------
# El OCR devuelve "DIESEL B5 S50 UV 21.61 25.", "Disel B5", "DB5", "SIESEL B5"... Para reportes,
# dashboard y filtros se lleva a un catálogo corto: DIESEL B5 / GASOHOL 95 / GASOHOL REGULAR /
# GASOHOL PREMIUM / GLP / GNV. Lo que no se reconoce se limpia de números y se deja tal cual.
_PROD_DIESEL_RE = re.compile(r"D[IEO]?[IE]?S+[EI]?L|BIODI|\bDB5\b|\bD2\b|\bB5\b|\bB50\b", re.I)


def normalizar_producto(value: Optional[str]) -> str:
    s = re.sub(r"\s+", " ", str(value or "")).strip().upper()
    if not s:
        return ""
    if "GNV" in s:
        return "GNV"
    if "GLP" in s:
        return "GLP"
    if _PROD_DIESEL_RE.search(s):
        return "DIESEL B5"
    if re.search(r"GASOHOL|GASOLINA|\bG-|^G ", s) or re.search(r"\b(84|90|95|97|98)\b", s):
        m = re.search(r"\b(84|90|95|97|98)\b", s)
        if m:
            return f"GASOHOL {m.group(1)}"
        if "PREM" in s:
            return "GASOHOL PREMIUM"
        if "REG" in s:
            return "GASOHOL REGULAR"
        return "GASOHOL"
    # Desconocido: fuera tokens con dígitos/puntos (restos de precio o cantidad)
    limpio = " ".join(t for t in re.split(r"[ _\-]+", s) if t and not re.search(r"\d", t)).strip(" .")
    return limpio or s


# ---------- Unificación de estación / ciudad (cargas del subsidio) ----------
# El OCR escribe el mismo grifo de varias formas ("SERVICENTROS MARIELENA   S.A.C.",
# "SERVICENTROS MARIELENA", "MARIELENA") y la ciudad a veces truncada o como región
# ("Trujil", "La Libertad"). Para el dashboard y los filtros, un mismo RUC emisor es UNA
# estación con UNA ciudad; las filas sin RUC se pegan al nombre canónico si coinciden.
_EST_SUFIJOS_RE = re.compile(r"\b(S\.?\s?A\.?\s?C\.?|S\.?\s?A\.?|E\.?\s?I\.?\s?R\.?\s?L\.?|S\.?\s?R\.?\s?L\.?|SAC|EIRL|SRL|SA)\b\.?", re.I)


def _clave_estacion(nombre: Optional[str]) -> str:
    s = re.sub(r"\s+", " ", str(nombre or "")).strip().upper()
    if not s:
        return ""
    s = _EST_SUFIJOS_RE.sub(" ", s)
    s = re.sub(r"[^A-Z0-9ÁÉÍÓÚÑ ]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _unificar_estaciones(rows: list) -> list:
    """Muta ESTACION y CIUDAD de las filas (formato UPPERCASE de /consumptions)."""
    from collections import Counter, defaultdict
    if not rows:
        return rows
    por_ruc_nom, por_ruc_ciu = defaultdict(Counter), defaultdict(Counter)
    for r in rows:
        ruc = str(r.get("RUC_EMISOR") or "").strip()
        nom = re.sub(r"\s+", " ", str(r.get("ESTACION") or "")).strip()
        if ruc and nom:
            por_ruc_nom[ruc][nom] += 1
        if ruc:
            c = normalize_city(r.get("CIUDAD"))
            if c:
                por_ruc_ciu[ruc][c] += 1
    # Nombre canónico por RUC: el más frecuente; empate → el más completo (más largo).
    canon_ruc = {ruc: max(cnt.items(), key=lambda kv: (kv[1], len(kv[0])))[0] for ruc, cnt in por_ruc_nom.items()}
    ciudad_ruc = {ruc: cnt.most_common(1)[0][0] for ruc, cnt in por_ruc_ciu.items()}
    clave_a_canon = {}
    for ruc, nom in canon_ruc.items():
        clave_a_canon.setdefault(_clave_estacion(nom), (nom, ruc))
    # Filas sin RUC: misma clave → mismo nombre; si la clave está contenida en una canónica
    # (o al revés) y hay una sola candidata, se pega a esa.
    sin_ruc = Counter(re.sub(r"\s+", " ", str(r.get("ESTACION") or "")).strip()
                      for r in rows if not str(r.get("RUC_EMISOR") or "").strip() and r.get("ESTACION"))
    canon_libre = {}
    for nom, _ in sin_ruc.most_common():
        k = _clave_estacion(nom)
        if not k or k in canon_libre:
            continue
        if k in clave_a_canon:
            canon_libre[k] = clave_a_canon[k]
            continue
        cand = [v for ck, v in clave_a_canon.items() if len(k) >= 5 and (k in ck or ck in k)]
        canon_libre[k] = cand[0] if len(cand) == 1 else (nom, "")
    # Ciudades: una truncada ("Trujil") se pega a la ciudad conocida que la contiene.
    ciudades = Counter(normalize_city(r.get("CIUDAD")) for r in rows if normalize_city(r.get("CIUDAD")))
    ciudad_fix = {}
    for c in ciudades:
        if len(c) < 4:
            continue
        largas = [o for o in ciudades if o != c and len(o) > len(c) and o.lower().startswith(c.lower())]
        if len(largas) == 1:
            ciudad_fix[c] = largas[0]
    for r in rows:
        ruc = str(r.get("RUC_EMISOR") or "").strip()
        nom = re.sub(r"\s+", " ", str(r.get("ESTACION") or "")).strip()
        if ruc and ruc in canon_ruc:
            r["ESTACION"] = canon_ruc[ruc]
        elif nom:
            k = _clave_estacion(nom)
            if k in canon_libre:
                r["ESTACION"], ruc_c = canon_libre[k]
                if ruc_c and not ruc:
                    ruc = ruc_c
        else:
            r["ESTACION"] = "Sin estación"
        # "Red"/proveedor (RAZON_SOCIAL_EMISOR): si la factura no traía razón social, el
        # mapper cae al nombre crudo o al RUC; aquí se reemplaza por el nombre unificado.
        if r["ESTACION"] != "Sin estación" and "RAZON_SOCIAL_EMISOR" in r:
            rs = re.sub(r"\s+", " ", str(r.get("RAZON_SOCIAL_EMISOR") or "")).strip()
            if not rs or rs == ruc or rs == nom or _clave_estacion(rs) == _clave_estacion(r["ESTACION"]):
                r["RAZON_SOCIAL_EMISOR"] = r["ESTACION"]
        c = normalize_city(r.get("CIUDAD"))
        if ruc and ruc in ciudad_ruc:
            c = ciudad_ruc[ruc]
        elif c in ciudad_fix:
            c = ciudad_fix[c]
        r["CIUDAD"] = c
    return rows


# Rango plausible de precio por galón en Perú (diésel/gasohol ~S/ 12-25; GLP ~S/ 6-10).
# Fuera de esto, el importe o los galones están mal cargados.
PRECIO_GAL_MIN = 1.0
PRECIO_GAL_MAX = 60.0


def _subsidio_row_to_consumption(r: dict) -> dict:
    """Map consumos_subsidio doc → schema esperado por el frontend (UPPERCASE keys)."""
    gal = float(r.get("galones") or 0)
    imp = float(r.get("importe_total") or 0)
    pre = float(r.get("precio_unitario") or 0)
    fecha = r.get("fecha") or ""
    # Semana ISO desde fecha
    semana = ""
    try:
        from datetime import date as _date
        y, m, d = (int(x) for x in fecha[:10].split("-"))
        wk = _date(y, m, d).isocalendar()
        semana = f"{wk.year}-W{wk.week:02d}"
    except Exception:
        pass
    return {
        "id": r.get("id") or str(r.get("_id")) or "",
        "EMPRESA": r.get("empresa") or "",
        "FECHA": fecha,
        "HORA": r.get("hora") or "",
        "PLACA": r.get("placa") or "",
        "CIUDAD": normalize_city(r.get("ciudad")),
        "ESTACION": r.get("estacion") or "",
        "PRODUCTO": normalizar_producto(r.get("producto")),
        "CANTIDAD_GL": gal,
        "PRECIO_UNITARIO": pre,
        "IMPORTE_TOTAL": imp,
        "KILOMETRAJE": r.get("kilometraje") or 0,
        "AHORRO": round(gal * 1.5, 2),  # MOCKED: S/ 1.5 por galón (alineado con dashboard subsidio)
        "SEMANA": semana,
        "RUC_EMISOR": r.get("ruc_emisor") or "",
        "RAZON_SOCIAL_EMISOR": r.get("razon_social_emisor") or r.get("proveedor") or r.get("estacion") or r.get("ruc_emisor") or "",
        "NUMERO_DOCUMENTO": r.get("numero_documento") or "",
        "ESTADO": "FACTURADO",
        "_origen": "subsidio",
        "CONDUCTOR": r.get("conductor") or "",
        "pdf_filename": r.get("pdf_filename") or "",
    }


@api.get("/consumptions")
async def list_consumptions(
    user: dict = Depends(get_current_user),
    empresa: Optional[str] = None,
    fecha_desde: Optional[str] = None,
    fecha_hasta: Optional[str] = None,
    placa: Optional[str] = None,
    ciudad: Optional[str] = None,
    estacion: Optional[str] = None,
    producto: Optional[str] = None,
    semana: Optional[str] = None,
    limit: int = 2000,
):
    rows = []
    
    # 1. Fetch from db.consumptions
    fetch_combustible = True
    if user.get("role") == "cliente_subsidio" and not user.get("empresa"):
        fetch_combustible = False

    if fetch_combustible:
        q = {}
        target_emp = empresa if (empresa and user["role"] == "admin_enered") else user.get("empresa")
        if user["role"] != "admin_enered" and target_emp:
            q["$or"] = [
                {"EMPRESA": target_emp},
                {"_origen": "manual"},
                {"EMPRESA": {"$exists": False}}
            ]
        elif target_emp:
            q["EMPRESA"] = target_emp

        if fecha_desde: q.setdefault("FECHA", {})["$gte"] = fecha_desde
        if fecha_hasta: q.setdefault("FECHA", {})["$lte"] = fecha_hasta
        if placa: q["PLACA"] = placa
        if ciudad: q["CIUDAD"] = ciudad
        if estacion: q["ESTACION"] = estacion
        if producto: q["PRODUCTO"] = producto
        if semana: q["SEMANA"] = semana
        
        raw = await db.consumptions.find(q).sort("FECHA", -1).to_list(limit)
        for r in raw:
            if "id" not in r:
                r["id"] = str(r["_id"])
            r.pop("_id", None)
            rows.append(r)

    # 2. Fetch fuel consumptions uploaded by client via Subsidio (excluding admin_ocr)
    target_emp = empresa if (empresa and user["role"] == "admin_enered") else user.get("empresa")
    is_subsidio = user.get("role") == "cliente_subsidio"
    if not is_subsidio and target_emp:
        cfg = await db.empresas_config.find_one({"empresa": target_emp}, {"_id": 0, "servicios": 1})
        if cfg and cfg.get("servicios", {}).get("subsidio"):
            is_subsidio = True

    if is_subsidio:
        uid_filter = {
            "status": "confirmed",
            "origin": {"$ne": "admin_ocr"},
            "estacion": {"$ne": "ENERED"}
        }
        if user.get("role") == "cliente_subsidio":
            uid_filter["user_id"] = user["id"]
            # Multi-empresa: el mismo usuario puede tener varias empresas; manda la
            # empresa activa del doc (los antiguos sin empresa caen al user_id).
            if user.get("empresa"):
                uid_filter["$or"] = [{"empresa": user["empresa"]}, {"empresa": {"$in": [None, ""]}}]
        elif target_emp:
            uid_filter["empresa"] = target_emp

        raw_sub = await db.consumos_subsidio.find(uid_filter, {"raw_ocr_response": 0, "factura_storage_key": 0}).sort("fecha", -1).to_list(limit)
        # Mismas correcciones que el detalle admin: una factura con varias placas no repite el
        # total en cada fila (galones × precio, o reparto por galones si no hay precio). Sin esto
        # el precio derivado salía disparatado (S/ 9,795 en 60 gal → "163/gal").
        try:
            from subsidio import _repartir_importes_por_placa as _rep_pl, _importe_por_placa as _imp_pl
            _rep = _rep_pl(raw_sub)
            for r in raw_sub:
                _imp = _imp_pl(r)
                if _imp is not None:
                    r["importe_total"] = _imp
                elif r.get("id") in _rep:
                    r.update(_rep[r["id"]])
        except Exception as _e:
            logger.warning(f"Reparto de importes por placa en /consumptions falló: {_e}")
        mapped = _unificar_estaciones([_subsidio_row_to_consumption(r) for r in raw_sub])
        
        def keep(row):
            if fecha_desde and (row.get("FECHA") or "") < fecha_desde: return False
            if fecha_hasta and (row.get("FECHA") or "") > fecha_hasta: return False
            if placa and row.get("PLACA") != placa: return False
            if ciudad and row.get("CIUDAD") != ciudad: return False
            if estacion and row.get("ESTACION") != estacion: return False
            if producto and row.get("PRODUCTO") != producto: return False
            if semana and row.get("SEMANA") != semana: return False
            return True
            
        rows.extend([r for r in mapped if keep(r)])
        rows.sort(key=lambda x: x.get("FECHA") or "", reverse=True)

    # Precio unitario: si la fila no lo trae pero sí galones e importe, se deriva (importe ÷ galones).
    # Muchas cargas (OCR, Excel, QR) traen total y galones sin precio y la columna salía "—".
    # Además se marca PRECIO_INCOHERENTE cuando el precio por galón sale fuera de todo rango
    # razonable (p. ej. S/ 449/gal en CASALI): casi siempre es un importe mal leído por el OCR
    # o una factura de varias placas cuyo total se pegó a una sola fila. La fila se muestra
    # igual, con aviso, para que el cliente/admin la corrija en vez de inflar los reportes.
    for r in rows:
        try:
            gal = float(r.get("CANTIDAD_GL") or 0)
            imp = float(r.get("IMPORTE_TOTAL") or 0)
            if not float(r.get("PRECIO_UNITARIO") or 0):
                if gal > 0 and imp > 0:
                    r["PRECIO_UNITARIO"] = round(imp / gal, 2)
                    r["PRECIO_DERIVADO"] = True
            pre = float(r.get("PRECIO_UNITARIO") or 0)
            if gal > 0 and pre > 0 and not (PRECIO_GAL_MIN <= pre <= PRECIO_GAL_MAX):
                r["PRECIO_INCOHERENTE"] = True
        except (TypeError, ValueError):
            pass

    return rows


class ConsumptionCreate(BaseModel):
    PLACA: str
    EMPRESA: Optional[str] = None
    FECHA: str
    HORA: Optional[str] = None
    CIUDAD: Optional[str] = None
    ESTACION: Optional[str] = None
    PRODUCTO: str
    CANTIDAD_GL: float
    PRECIO_UNITARIO: float
    IMPORTE_TOTAL: float
    CONDUCTOR: Optional[str] = None
    KILOMETRAJE: Optional[int] = None
    RUC_EMISOR: Optional[str] = None
    NUMERO_DOCUMENTO: Optional[str] = None


@api.post("/consumptions")
async def create_consumption(
    PLACA: str = Form(...),
    EMPRESA: Optional[str] = Form(None),
    FECHA: str = Form(...),
    HORA: Optional[str] = Form(None),
    CIUDAD: Optional[str] = Form(None),
    ESTACION: Optional[str] = Form(None),
    PRODUCTO: str = Form(...),
    CANTIDAD_GL: float = Form(...),
    PRECIO_UNITARIO: float = Form(...),
    IMPORTE_TOTAL: float = Form(...),
    CONDUCTOR: Optional[str] = Form(None),
    KILOMETRAJE: Optional[int] = Form(None),
    RUC_EMISOR: Optional[str] = Form(None),
    NUMERO_DOCUMENTO: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user)
):
    cid = str(uuid.uuid4())
    empresa_target = EMPRESA or user.get("empresa") or ""
    
    # Guardar comprobante PDF si es provisto
    pdf_filename = None
    if file and file.filename:
        content = await file.read()
        pdf_filename = f"inv_{cid}_{file.filename}"
        key = _inv_key(empresa_target, pdf_filename)
        storage.save_object(key, content, content_type="application/pdf")

    f_venc = FECHA[:10]
    try:
        from datetime import datetime as _datetime, timedelta
        f_dt = _datetime.strptime(FECHA[:10], "%Y-%m-%d")
        f_venc = (f_dt + timedelta(days=30)).date().isoformat()
    except Exception:
        pass

    # Crear factura relacionada
    if NUMERO_DOCUMENTO:
        existing_inv = await db.invoices.find_one({"empresa": empresa_target, "n_doc": NUMERO_DOCUMENTO.upper()})
        if not existing_inv:
            inv_doc = {
                "id": cid,
                "empresa": empresa_target,
                "n_doc": NUMERO_DOCUMENTO.upper(),
                "tipo_doc": "factura",
                "producto": PRODUCTO,
                "f_emision": FECHA[:10],
                "f_vencimiento": f_venc,
                "moneda": "PEN",
                "monto_total": IMPORTE_TOTAL,
                "saldo": IMPORTE_TOTAL,
                "estado": "pendiente",
                "atraso_dias": 0,
                "pdf_filename": pdf_filename,
                "xml_filename": None,
                "uploaded_at": datetime.now(timezone.utc).isoformat(),
                "uploaded_by": user["email"],
                "created_via": "consumption_sync",
                "ruc_emisor": (RUC_EMISOR or "").strip(),
            }
            if _es_factura_tercero(inv_doc):  # factura de un grifo, no de ENERGIX
                inv_doc["estado"] = "TERCERO"
                inv_doc["saldo"] = 0.0
            await db.invoices.insert_one(inv_doc)

    if user.get("role") == "cliente_subsidio":
        doc = {
            "id": cid,
            "user_id": user["id"],
            "empresa": empresa_target,
            "placa": PLACA.upper(),
            "fecha": FECHA[:10],
            "hora": HORA or "00:00",
            "ciudad": normalize_city(CIUDAD),
            "estacion": ESTACION or "",
            "producto": PRODUCTO,
            "galones": CANTIDAD_GL,
            "precio_unitario": PRECIO_UNITARIO,
            "importe_total": IMPORTE_TOTAL,
            "kilometraje": KILOMETRAJE or 0,
            "conductor": CONDUCTOR or "",
            "ruc_emisor": RUC_EMISOR or "",
            "numero_documento": NUMERO_DOCUMENTO or "",
            "status": "confirmed",
            "pdf_filename": pdf_filename,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.consumos_subsidio.insert_one(doc)

        # Sync: crear factura en db.invoices para Facturación/Cuenta
        n_doc_sub = (NUMERO_DOCUMENTO or "").upper().strip()
        if n_doc_sub:
            existing_inv = await db.invoices.find_one({"empresa": empresa_target, "n_doc": n_doc_sub})
            if not existing_inv:
                f_venc_sub = FECHA[:10]
                try:
                    from datetime import timedelta as _td
                    f_dt_sub = datetime.strptime(FECHA[:10], "%Y-%m-%d")
                    f_venc_sub = (f_dt_sub + _td(days=30)).date().isoformat()
                except Exception:
                    pass
                inv_doc_sub = {
                    "id": cid,
                    "empresa": empresa_target,
                    "n_doc": n_doc_sub,
                    "tipo_doc": "factura",
                    "producto": PRODUCTO,
                    "f_emision": FECHA[:10],
                    "f_vencimiento": f_venc_sub,
                    "moneda": "PEN",
                    "monto_total": IMPORTE_TOTAL,
                    "saldo": IMPORTE_TOTAL,
                    "estado": "pendiente",
                    "atraso_dias": 0,
                    "pdf_filename": pdf_filename,
                    "xml_filename": None,
                    "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    "uploaded_by": user["email"],
                    "created_via": "subsidio_consumption",
                }
                await db.invoices.insert_one(inv_doc_sub)

        return _subsidio_row_to_consumption(doc)
    else:
        semana = ""
        try:
            from datetime import date as _date
            y, m, d = (int(x) for x in FECHA[:10].split("-"))
            wk = _date(y, m, d).isocalendar()
            semana = f"{wk.year}-W{wk.week:02d}"
        except Exception:
            pass
            
        doc = {
            "id": cid,
            "EMPRESA": empresa_target,
            "PLACA": PLACA.upper(),
            "FECHA": FECHA,
            "HORA": HORA or "",
            "CIUDAD": normalize_city(CIUDAD),
            "ESTACION": ESTACION or "",
            "PRODUCTO": PRODUCTO,
            "CANTIDAD_GL": CANTIDAD_GL,
            "PRECIO_UNITARIO": PRECIO_UNITARIO,
            "IMPORTE_TOTAL": IMPORTE_TOTAL,
            "AHORRO": round(CANTIDAD_GL * 1.5, 2),
            "SEMANA": semana,
            "CONDUCTOR": CONDUCTOR or "",
            "KILOMETRAJE": KILOMETRAJE or 0,
            "RUC_EMISOR": RUC_EMISOR or "",
            "NUMERO_DOCUMENTO": NUMERO_DOCUMENTO or "",
            "ESTADO": "FACTURADO",
            "_origen": "manual",
            "pdf_filename": pdf_filename,
        }
        await db.consumptions.insert_one(doc)
        if "_id" in doc:
            doc.pop("_id")
        return doc


@api.put("/consumptions/{cid}")
async def update_consumption(
    cid: str,
    PLACA: str = Form(...),
    EMPRESA: Optional[str] = Form(None),
    FECHA: str = Form(...),
    HORA: Optional[str] = Form(None),
    CIUDAD: Optional[str] = Form(None),
    ESTACION: Optional[str] = Form(None),
    PRODUCTO: str = Form(...),
    CANTIDAD_GL: float = Form(...),
    PRECIO_UNITARIO: float = Form(...),
    IMPORTE_TOTAL: float = Form(...),
    CONDUCTOR: Optional[str] = Form(None),
    KILOMETRAJE: Optional[int] = Form(None),
    RUC_EMISOR: Optional[str] = Form(None),
    NUMERO_DOCUMENTO: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user)
):
    empresa_target = EMPRESA or user.get("empresa") or ""
    
    coll = db.consumptions
    try:
        from bson import ObjectId
        oid = ObjectId(cid)
    except:
        oid = None

    if user.get("role") == "cliente_subsidio":
        coll = db.consumos_subsidio
        q = {"user_id": user["id"]}
        if user.get("empresa"):
            # Multi-empresa: solo consumos de la empresa activa (o antiguos sin empresa)
            q["$and"] = [{"$or": [{"empresa": user["empresa"]}, {"empresa": {"$in": [None, ""]}}]}]
        if oid: q["$or"] = [{"id": cid}, {"_id": oid}]
        else: q["id"] = cid
    else:
        q = {"$or": [{"id": cid}, {"_id": oid}]} if oid else {"id": cid}
        if user["role"] != "admin_enered" and user.get("empresa"):
            q["$and"] = [
                {"$or": [
                    {"EMPRESA": user["empresa"]},
                    {"_origen": "manual"},
                    {"EMPRESA": {"$exists": False}}
                ]}
            ]
            
    c_doc = await coll.find_one(q)
    if not c_doc:
        raise HTTPException(status_code=404, detail="Consumo no encontrado")

    pdf_filename = c_doc.get("pdf_filename")
    if file and file.filename:
        content = await file.read()
        pdf_filename = f"inv_{cid}_{file.filename}"
        key = _inv_key(empresa_target, pdf_filename)
        storage.save_object(key, content, content_type="application/pdf")
        
    update_fields = {
        "placa" if user.get("role") == "cliente_subsidio" else "PLACA": PLACA.upper(),
        "fecha" if user.get("role") == "cliente_subsidio" else "FECHA": FECHA[:10] if user.get("role") == "cliente_subsidio" else FECHA,
        "hora" if user.get("role") == "cliente_subsidio" else "HORA": HORA or ("00:00" if user.get("role") == "cliente_subsidio" else ""),
        "ciudad" if user.get("role") == "cliente_subsidio" else "CIUDAD": normalize_city(CIUDAD),
        "estacion" if user.get("role") == "cliente_subsidio" else "ESTACION": ESTACION or "",
        "producto" if user.get("role") == "cliente_subsidio" else "PRODUCTO": PRODUCTO,
        "galones" if user.get("role") == "cliente_subsidio" else "CANTIDAD_GL": CANTIDAD_GL,
        "precio_unitario" if user.get("role") == "cliente_subsidio" else "PRECIO_UNITARIO": PRECIO_UNITARIO,
        "importe_total" if user.get("role") == "cliente_subsidio" else "IMPORTE_TOTAL": IMPORTE_TOTAL,
        "conductor" if user.get("role") == "cliente_subsidio" else "CONDUCTOR": CONDUCTOR or "",
        "kilometraje" if user.get("role") == "cliente_subsidio" else "KILOMETRAJE": KILOMETRAJE or 0,
        "ruc_emisor" if user.get("role") == "cliente_subsidio" else "RUC_EMISOR": RUC_EMISOR or "",
        "numero_documento" if user.get("role") == "cliente_subsidio" else "NUMERO_DOCUMENTO": NUMERO_DOCUMENTO or "",
        "pdf_filename": pdf_filename,
    }
    
    if user.get("role") != "cliente_subsidio":
        update_fields["AHORRO"] = round(CANTIDAD_GL * 1.5, 2)
        try:
            from datetime import date as _date
            y, m, d = (int(x) for x in FECHA[:10].split("-"))
            wk = _date(y, m, d).isocalendar()
            update_fields["SEMANA"] = f"{wk.year}-W{wk.week:02d}"
        except:
            pass

    await coll.update_one(q, {"$set": update_fields})
    
    updated_doc = await coll.find_one(q)
    if "_id" in updated_doc:
        updated_doc.pop("_id")
        
    if user.get("role") == "cliente_subsidio":
        return _subsidio_row_to_consumption(updated_doc)
    return updated_doc


@api.delete("/consumptions/{cid}")
async def delete_consumption(cid: str, user: dict = Depends(get_current_user)):
    try:
        from bson import ObjectId
        oid = ObjectId(cid)
    except:
        oid = None

    if user.get("role") == "cliente_subsidio":
        q_sub = {"user_id": user["id"]}
        if user.get("empresa"):
            # Multi-empresa: solo consumos de la empresa activa (o antiguos sin empresa)
            q_sub["$and"] = [{"$or": [{"empresa": user["empresa"]}, {"empresa": {"$in": [None, ""]}}]}]
        if oid: q_sub["$or"] = [{"id": cid}, {"_id": oid}]
        else: q_sub["id"] = cid
        c_doc = await db.consumos_subsidio.find_one(q_sub)
        if not c_doc:
            raise HTTPException(status_code=404, detail="Consumo no encontrado")
        
        n_doc = c_doc.get("numero_documento")
        empresa = c_doc.get("empresa") or user.get("empresa") or ""
        if n_doc and empresa:
            await db.invoices.delete_one({"n_doc": n_doc, "empresa": empresa})
            
        await db.consumos_subsidio.delete_one(q_sub)
        return {"ok": True, "deleted": 1}
    else:
        q = {"$or": [{"id": cid}, {"_id": oid}]} if oid else {"id": cid}
        if user["role"] != "admin_enered" and user.get("empresa"):
            q["$and"] = [
                {"$or": [
                    {"EMPRESA": user["empresa"]},
                    {"_origen": "manual"},
                    {"EMPRESA": {"$exists": False}}
                ]}
            ]
        c_doc = await db.consumptions.find_one(q)
        if not c_doc:
            raise HTTPException(status_code=404, detail="Consumo no encontrado")
            
        n_doc = c_doc.get("NUMERO_DOCUMENTO")
        empresa = c_doc.get("EMPRESA") or user.get("empresa") or ""
        if n_doc and empresa:
            await db.invoices.delete_one({"n_doc": n_doc, "empresa": empresa})
            
        await db.consumptions.delete_one(q)
        return {"ok": True, "deleted": 1}



@api.get("/consumptions/{cid}/download/pdf")
async def download_consumption_pdf(cid: str, user: dict = Depends(get_current_user)):
    try:
        from bson import ObjectId
        oid = ObjectId(cid)
    except:
        oid = None

    c_doc = None
    q = {"$or": [{"id": cid}, {"_id": oid}]} if oid else {"id": cid}
    c_doc = await db.consumos_subsidio.find_one(q)
    if not c_doc:
        c_doc = await db.consumptions.find_one(q)
    if not c_doc:
        n_doc_esc = re.escape(cid)
        c_doc = await db.consumos_subsidio.find_one({"$or": [{"numero_documento": {"$regex": f"^{n_doc_esc}$", "$options": "i"}}, {"n_doc": {"$regex": f"^{n_doc_esc}$", "$options": "i"}}]})
        
    if not c_doc:
        raise HTTPException(status_code=404, detail="Consumo no encontrado")

    candidate_keys = []
    if c_doc.get("factura_storage_key"): candidate_keys.append(c_doc["factura_storage_key"])
    if c_doc.get("pdf_key"): candidate_keys.append(c_doc["pdf_key"])
    if c_doc.get("storage_key"): candidate_keys.append(c_doc["storage_key"])

    fname = c_doc.get("pdf_filename") or c_doc.get("factura_filename") or c_doc.get("factura_key")
    empresa = c_doc.get("EMPRESA") or c_doc.get("empresa") or user.get("empresa") or ""
    n_doc = c_doc.get("NUMERO_DOCUMENTO") or c_doc.get("numero_documento") or c_doc.get("n_doc") or "Factura"

    if fname:
        if empresa:
            candidate_keys.append(_inv_key(empresa, fname))
            candidate_keys.append(f"invoices/{empresa}/{fname}")
        candidate_keys.append(f"tmp_admin/{fname}")
        candidate_keys.append(fname)

    seen = set()
    valid_key = None
    for k in candidate_keys:
        if k:
            k_clean = str(k).lstrip("/")
            for alt_k in (k_clean, f"uploads/{k_clean}" if not k_clean.startswith("uploads/") else k_clean):
                if alt_k not in seen:
                    seen.add(alt_k)
                    if storage.object_exists(alt_k):
                        valid_key = alt_k
                        break
            if valid_key:
                break

    download_name = fname or f"{n_doc}.pdf"
    if valid_key:
        return storage.download_response(valid_key, download_name, "application/pdf")

    DUMMY_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n4 0 obj\n<< /Length 67 >>\nstream\nBT\n/F1 24 Tf\n100 700 Td\n(Documento Simulado - Sin Archivo Real) Tj\nET\nendstream\nendobj\n5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\nxref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000223 00000 n \n0000000341 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n429\n%%EOF\n"
    return Response(content=DUMMY_PDF, media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="{download_name}"'})


@api.get("/dashboard/filter-options")
async def dashboard_filter_options(user: dict = Depends(get_current_user), empresa: Optional[str] = None):
    # cliente_subsidio or users with servicios.subsidio: opciones desde consumos_subsidio confirmados
    is_subsidio_fo = user.get("role") == "cliente_subsidio"
    if not is_subsidio_fo and user.get("empresa"):
        cfg_fo = await db.empresas_config.find_one({"empresa": user["empresa"]}, {"_id": 0, "servicios": 1})
        if cfg_fo and cfg_fo.get("servicios", {}).get("subsidio"):
            is_subsidio_fo = True

    if is_subsidio_fo:
        fo_filter = {"status": "confirmed"}
        if user.get("role") == "cliente_subsidio":
            fo_filter["user_id"] = user["id"]
        else:
            fo_filter["empresa"] = user.get("empresa")
        raw = await db.consumos_subsidio.find(
            fo_filter,
            {"_id": 0, "placa": 1, "estacion": 1, "ruc_emisor": 1, "producto": 1, "fecha": 1},
        ).to_list(100000)
        from datetime import date as _date
        # Nombres de estación unificados (mismo criterio que /consumptions y el dashboard)
        _uni = _unificar_estaciones([{"ESTACION": r.get("estacion"), "RUC_EMISOR": r.get("ruc_emisor"), "CIUDAD": ""} for r in raw])
        for r, u in zip(raw, _uni):
            r["estacion"] = u["ESTACION"] if u["ESTACION"] != "Sin estación" else ""
        placas, estaciones, productos, semanas = set(), set(), set(), set()
        for r in raw:
            if r.get("placa"): placas.add(r["placa"])
            if r.get("estacion"): estaciones.add(r["estacion"])
            if r.get("producto"): productos.add(normalizar_producto(r["producto"]))
            f = (r.get("fecha") or "")[:10]
            try:
                y, m, d = (int(x) for x in f.split("-"))
                wk = _date(y, m, d).isocalendar()
                semanas.add(f"{wk.year}-W{wk.week:02d}")
            except Exception:
                pass
        return {
            "placas": sorted(placas), "semanas": sorted(semanas),
            "estaciones": sorted(estaciones), "productos": sorted(productos),
        }

    q = tenant_filter(user)
    if empresa and user["role"] == "admin_enered":
        q["EMPRESA"] = empresa
    rows = await db.consumptions.find(q, {"_id": 0, "PLACA": 1, "SEMANA": 1, "ESTACION": 1, "PRODUCTO": 1}).to_list(100000)
    placas = sorted({r["PLACA"] for r in rows if r.get("PLACA")})
    semanas = sorted({r["SEMANA"] for r in rows if r.get("SEMANA")})
    estaciones = sorted({r["ESTACION"] for r in rows if r.get("ESTACION")})
    productos = sorted({r["PRODUCTO"] for r in rows if r.get("PRODUCTO")})
    return {"placas": placas, "semanas": semanas, "estaciones": estaciones, "productos": productos}


# ---------- Empresa Config (plan, línea crédito, unidades, RUC, días crédito, servicios) ----------
class EmpresaServicios(BaseModel):
    plataforma: bool = True
    combustible: bool = True
    gps: bool = False
    subsidio: bool = False


class EmpresaConfig(BaseModel):
    empresa: str
    ruc: Optional[str] = ""
    plan: Literal["tracking", "advanced", "integral"] = "tracking"
    linea_credito: float = 0.0
    unidades_contratadas: int = 0
    dias_credito: int = 0  # condición de crédito (días)
    tipo_cliente: Optional[Literal["enered", "subsidio"]] = "enered"
    servicios: Optional[EmpresaServicios] = None


class ServiciosUpdate(BaseModel):
    servicios: EmpresaServicios
    tipo_cliente: Optional[Literal["enered", "subsidio"]] = None
    # None = sin restricción (todos los módulos opcionales visibles). Una lista (incluso
    # vacía) restringe a exactamente esos módulos opcionales — los módulos base nunca
    # dependen de esto. Omitir el campo en el body no lo toca.
    modulos_habilitados: Optional[List[str]] = None


class WialonConfigIn(BaseModel):
    token: str
    host: Optional[str] = None


class WialonReportRunIn(BaseModel):
    empresa: Optional[str] = None          # solo admin_enered
    resource_id: int
    template_id: int
    unit_id: int
    date_from: int                          # epoch seconds
    date_to: int                            # epoch seconds


class WialonFuelGraphIn(BaseModel):
    empresa: Optional[str] = None          # solo admin_enered
    unit_id: int
    date_from: int                          # epoch seconds
    date_to: int                            # epoch seconds


@api.get("/empresas-config")
async def list_empresas_config(user: dict = Depends(require_roles("admin_enered"))):
    configs = await db.empresas_config.find({}, {"_id": 0}).to_list(500)
    # Mask wialon tokens
    for c in configs:
        w = c.get("wialon") or {}
        if w.get("token"):
            c["wialon"] = {"host": w.get("host") or _svc.DEFAULT_WIALON_HOST, "configurado": True, "token_mask": _svc.mask_wialon_token(_svc.decrypt_wialon_token(w["token"]))}
        else:
            c["wialon"] = {"host": w.get("host") or _svc.DEFAULT_WIALON_HOST, "configurado": False, "token_mask": ""}
        # Normalize servicios defensively
        c["servicios"] = _svc._normalize_servicios(c.get("servicios"))
        c["tipo_cliente"] = c.get("tipo_cliente") or _svc.DEFAULT_TIPO_CLIENTE
    return configs


async def _sunat_ficha_ruc(ruc: str) -> dict:
    """Ficha RUC (SUNAT vía json.pe): razón social, estado, condición, dirección."""
    jp = await _jsonpe("ruc", {"ruc": ruc})
    if not jp or not jp.get("nombre_o_razon_social"):
        return {}
    return {"razon_social": jp.get("nombre_o_razon_social", "").strip(), "estado": jp.get("estado", ""),
            "condicion": jp.get("condicion", ""), "direccion": jp.get("direccion_completa") or jp.get("direccion", ""),
            "departamento": jp.get("departamento", ""), "provincia": jp.get("provincia", ""), "distrito": jp.get("distrito", "")}


@api.get("/admin/empresas/validar-ruc")
async def admin_validar_ruc(ruc: str, user: dict = Depends(require_roles("admin_enered"))):
    """Valida un RUC al crear la empresa: razón social/estado desde SUNAT y representante(s)
    legal(es). Lo que devuelve se usa para autollenar el formulario y la declaración jurada."""
    ruc = (ruc or "").strip()
    if len(ruc) != 11 or not ruc.isdigit():
        raise HTTPException(400, "RUC inválido (11 dígitos)")
    ficha = await _sunat_ficha_ruc(ruc)
    reps = await _ruc_representantes(ruc)
    if not ficha and not reps:
        raise HTTPException(404, "SUNAT no devolvió datos para este RUC")
    principal = next((r for r in reps if "GERENTE" in r["cargo"].upper() or "TITULAR" in r["cargo"].upper()), reps[0] if reps else None)
    if reps:
        ahora = datetime.now(timezone.utc).isoformat()
        await db.representantes_ruc.update_one({"ruc": ruc}, {"$set": {"ruc": ruc, "representantes": reps, "consultado_en": ahora}}, upsert=True)
    return {"ruc": ruc, **ficha, "representantes": reps, "representante_legal": principal}


@api.post("/empresas-config")
async def upsert_empresa_config(data: EmpresaConfig, user: dict = Depends(require_roles("admin_enered"))):
    doc = data.model_dump(exclude_none=True)
    if "servicios" in doc and isinstance(doc["servicios"], dict):
        doc["servicios"] = _svc._normalize_servicios(doc["servicios"])
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()
    existing = await db.empresas_config.find_one({"empresa": data.empresa}, {"_id": 0})
    # Con RUC: razón social SUNAT + representante legal quedan en la ficha (si SUNAT responde)
    ruc_n = (doc.get("ruc") or "").strip()
    if len(ruc_n) == 11 and ruc_n.isdigit() and not (existing or {}).get("representante_legal"):
        try:
            ficha = await _sunat_ficha_ruc(ruc_n)
            if ficha:
                doc["sunat"] = ficha
            reps = await _ruc_representantes(ruc_n)
            if not reps:
                cache = await db.representantes_ruc.find_one({"ruc": ruc_n}, {"_id": 0})
                reps = (cache or {}).get("representantes") or []
            if reps:
                doc["representantes"] = reps
                doc["representante_legal"] = next((r for r in reps if "GERENTE" in r["cargo"].upper() or "TITULAR" in r["cargo"].upper()), reps[0])
                doc["representantes_actualizado_en"] = doc["updated_at"]
        except Exception:
            pass
    if existing:
        await db.empresas_config.update_one({"empresa": data.empresa}, {"$set": doc})
    else:
        doc["id"] = str(uuid.uuid4())
        doc["created_at"] = doc["updated_at"]
        if "servicios" not in doc:
            doc["servicios"] = dict(_svc.DEFAULT_SERVICIOS)
            # Default "solo subsidio" clients without plataforma
            if doc.get("tipo_cliente") == "subsidio":
                doc["servicios"]["plataforma"] = False
                doc["servicios"]["combustible"] = False
                doc["servicios"]["subsidio"] = True
        if "tipo_cliente" not in doc:
            doc["tipo_cliente"] = _svc.DEFAULT_TIPO_CLIENTE
        await db.empresas_config.insert_one(doc)
    return await db.empresas_config.find_one({"empresa": data.empresa}, {"_id": 0})


# ---------- Admin: Empresas & Servicios ----------
@api.put("/admin/empresas/{empresa}/servicios")
async def update_empresa_servicios(empresa: str, data: ServiciosUpdate, user: dict = Depends(require_roles("admin_enered"))):
    patch = {
        "servicios": _svc._normalize_servicios(data.servicios.model_dump()),
        "modulos_habilitados": data.modulos_habilitados,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if data.tipo_cliente:
        patch["tipo_cliente"] = data.tipo_cliente
    existing = await db.empresas_config.find_one({"empresa": empresa}, {"_id": 0})
    if not existing:
        # crear config mínima
        await db.empresas_config.insert_one({
            "id": str(uuid.uuid4()),
            "empresa": empresa,
            "ruc": "",
            "plan": "tracking",
            "linea_credito": 0.0,
            "unidades_contratadas": 0,
            "created_at": patch["updated_at"],
            **patch,
        })
    else:
        await db.empresas_config.update_one({"empresa": empresa}, {"$set": patch})
    return {"ok": True, "empresa": empresa, "servicios": patch["servicios"],
            "modulos_habilitados": patch["modulos_habilitados"],
            "tipo_cliente": patch.get("tipo_cliente", existing.get("tipo_cliente") if existing else _svc.DEFAULT_TIPO_CLIENTE)}


@api.put("/admin/empresas/{empresa}/wialon")
async def set_empresa_wialon(empresa: str, data: WialonConfigIn, user: dict = Depends(require_roles("admin_enered"))):
    token = (data.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token vacío")
    host = (data.host or _svc.DEFAULT_WIALON_HOST).strip()
    enc = _svc.encrypt_wialon_token(token)
    patch = {
        "wialon": {"host": host, "token": enc, "updated_at": datetime.now(timezone.utc).isoformat()},
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    existing = await db.empresas_config.find_one({"empresa": empresa}, {"_id": 0})
    if not existing:
        await db.empresas_config.insert_one({
            "id": str(uuid.uuid4()),
            "empresa": empresa,
            "created_at": patch["updated_at"],
            "servicios": {**_svc.DEFAULT_SERVICIOS, "gps": True},
            "tipo_cliente": _svc.DEFAULT_TIPO_CLIENTE,
            **patch,
        })
    else:
        # activar gps automáticamente al configurar wialon
        current_servicios = _svc._normalize_servicios(existing.get("servicios"))
        current_servicios["gps"] = True
        patch["servicios"] = current_servicios
        await db.empresas_config.update_one({"empresa": empresa}, {"$set": patch})
    return {"ok": True, "empresa": empresa, "host": host, "token_mask": _svc.mask_wialon_token(token)}


@api.delete("/admin/empresas/{empresa}/wialon")
async def delete_empresa_wialon(empresa: str, user: dict = Depends(require_roles("admin_enered"))):
    await db.empresas_config.update_one(
        {"empresa": empresa},
        {"$unset": {"wialon": ""}, "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}},
    )
    return {"ok": True}


@api.post("/admin/empresas/{empresa}/wialon/test")
async def test_empresa_wialon(empresa: str, data: WialonConfigIn, user: dict = Depends(require_roles("admin_enered"))):
    """Probar un token Wialon sin guardarlo (o guardado). Si viene token en el body, prueba ese; si no, prueba el guardado."""
    if data.token:
        return await _svc.test_wialon_connection(data.token, data.host or _svc.DEFAULT_WIALON_HOST)
    cfg = await _svc.get_empresa_wialon_config(db, empresa)
    if not cfg:
        raise HTTPException(status_code=404, detail="Wialon no configurado para esta empresa")
    return await _svc.test_wialon_connection(cfg["token"], cfg["host"])


@api.get("/dashboard/overview")
async def dashboard_overview(
    user: dict = Depends(get_current_user),
    empresa: Optional[str] = None,
):
    # Determinar empresa visible
    if user["role"] == "admin_enered":
        target_empresa = empresa or None
    else:
        target_empresa = user.get("empresa")

    # Config de la empresa
    cfg = None
    if target_empresa:
        cfg = await db.empresas_config.find_one({"empresa": target_empresa}, {"_id": 0})
    if not cfg:
        cfg = {
            "empresa": target_empresa or "Todas las empresas",
            "ruc": "",
            "plan": "tracking",
            "linea_credito": 0,
            "unidades_contratadas": 0,
        }

    # Consumos
    q = tenant_filter(user)
    if target_empresa and user["role"] == "admin_enered":
        q["EMPRESA"] = target_empresa
    proj = {"_id": 0, "CANTIDAD_GL": 1, "IMPORTE_TOTAL": 1, "PRECIO_UNITARIO": 1, "AHORRO": 1, "EMPRESA": 1, "FECHA": 1, "PLACA": 1, "KILOMETRAJE": 1}
    rows = await db.consumptions.find(q, proj).to_list(100000)

    # Fetch subsidio consumptions
    sub_q = {"status": "confirmed"}
    if target_empresa and user["role"] == "admin_enered":
        sub_q["empresa"] = target_empresa
    elif user["role"] != "admin_enered":
        sub_q["empresa"] = user.get("empresa")
    sub_proj = {"_id": 0, "galones": 1, "importe_total": 1, "precio_unitario": 1, "empresa": 1, "fecha": 1, "placa": 1, "kilometraje": 1}
    sub_rows = await db.consumos_subsidio.find(sub_q, sub_proj).to_list(100000)
    mapped_sub = [_subsidio_row_to_consumption(r) for r in sub_rows]
    rows.extend(mapped_sub)

    def _f(x, d=0):
        try: return float(x) if x not in (None, "") else d
        except Exception: return d

    total_gal = sum(_f(r.get("CANTIDAD_GL")) for r in rows)
    total_gasto = sum(_f(r.get("IMPORTE_TOTAL")) for r in rows)
    cargas = len(rows)

    # Precio promedio ponderado
    sum_pu = sum(_f(r.get("PRECIO_UNITARIO")) * _f(r.get("CANTIDAD_GL")) for r in rows if _f(r.get("CANTIDAD_GL")) > 0 and _f(r.get("PRECIO_UNITARIO")) > 0)
    sum_gl = sum(_f(r.get("CANTIDAD_GL")) for r in rows if _f(r.get("PRECIO_UNITARIO")) > 0)
    precio_prom = (sum_pu / sum_gl) if sum_gl > 0 else 0

    ticket_prom = total_gasto / cargas if cargas else 0
    gal_por_carga = total_gal / cargas if cargas else 0

    # Ahorro calculation based on services
    if target_empresa:
        svc_info = await _svc.get_empresa_servicios(db, target_empresa)
        has_comb = svc_info.get("servicios", {}).get("combustible", True)
        if not has_comb:
            total_ahorro = 0
            ahorro_gl = 0
        else:
            total_ahorro = sum(_f(r.get("AHORRO")) for r in rows)
            ahorro_gl = (total_ahorro / precio_prom) if precio_prom > 0 else 0
    else:
        cursor = db.empresas_config.find({})
        comb_companies = set()
        async for c in cursor:
            if c.get("servicios", {}).get("combustible", True):
                comb_companies.add(c.get("empresa"))
        total_ahorro = sum(_f(r.get("AHORRO")) for r in rows if r.get("EMPRESA") in comb_companies)
        ahorro_gl = (total_ahorro / precio_prom) if precio_prom > 0 else 0

    # Línea de crédito: usa exactamente la misma función account_state que el Estado de Cuenta
    ac_state = await account_state(user=user, empresa=target_empresa)
    total_credito = ac_state.get("linea_credito_total", 0.0)
    utilizada = ac_state.get("linea_credito_utilizada", 0.0)
    disponible = ac_state.get("disponible", 0.0)

    # Unidades (placas únicas reales)
    placas_reales = len({r.get("PLACA") for r in rows if r.get("PLACA")})

    # Cargas de la última semana (últimos 7 días)
    from datetime import datetime, timedelta
    seven_days_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    cargas_semana = sum(1 for r in rows if r.get("FECHA") and r.get("FECHA") >= seven_days_ago)

    # Cargas inválidas (desactivado temporalmente - fijado en 0)
    cargas_invalidas = 0

    # Unidades / Vehículos
    veh_q = {}
    if target_empresa:
        veh_q["empresa"] = target_empresa
    total_vehicles = await db.vehiculos.count_documents(veh_q)

    # Subsidio vehicles count
    user_ids = []
    if target_empresa:
        cursor = db.users.find({"empresa": target_empresa}, {"_id": 0, "id": 1})
        async for u in cursor:
            if u.get("id"):
                user_ids.append(u["id"])
    elif user["role"] != "admin_enered":
        cursor = db.users.find({"empresa": user.get("empresa")}, {"_id": 0, "id": 1})
        async for u in cursor:
            if u.get("id"):
                user_ids.append(u["id"])
    if user.get("id"):
        user_ids.append(user["id"])
    user_ids = list(set(user_ids))

    subsidio_vehicles_count = 0
    if target_empresa or user["role"] != "admin_enered":
        subsidio_vehicles_count = await db.subsidio_vehicles.count_documents({"user_id": {"$in": user_ids}})
    else:
        subsidio_vehicles_count = await db.subsidio_vehicles.count_documents({})
    
    total_vehicles = max(total_vehicles, subsidio_vehicles_count)

    # Active GPS units count via Wialon
    und_con_gps = 0
    if target_empresa:
        svc_info = await _svc.get_empresa_servicios(db, target_empresa)
        if svc_info.get("servicios", {}).get("gps"):
            cfg_w = await _svc.get_empresa_wialon_config(db, target_empresa)
            if cfg_w:
                try:
                    import json as _json, httpx as _httpx
                    host = cfg_w["host"]
                    base = f"https://{host}/wialon/ajax.html"
                    async with _httpx.AsyncClient(timeout=4.0) as client:
                        r = await client.get(base, params={"svc": "token/login", "params": _json.dumps({"token": cfg_w["token"]})})
                        d = r.json()
                        if "eid" in d:
                            sid = d["eid"]
                            search_params = {
                                "spec": {"itemsType":"avl_unit","propName":"sys_name","propValueMask":"*","sortType":"sys_name","propType":"property"},
                                "force": 1, "flags": 1, "from": 0, "to": 500,
                            }
                            r2 = await client.get(base, params={"svc":"core/search_items", "params": _json.dumps(search_params), "sid": sid})
                            d2 = r2.json()
                            und_con_gps = len(d2.get("items") or [])
                except Exception:
                    und_con_gps = total_vehicles
        else:
            und_con_gps = 0
    else:
        cursor = db.empresas_config.find({})
        gps_companies = []
        async for c in cursor:
            if c.get("servicios", {}).get("gps"):
                gps_companies.append(c.get("empresa"))
        und_con_gps = await db.vehiculos.count_documents({"empresa": {"$in": gps_companies}})

    # Unidades activas is the units with GPS
    unidades_activas = und_con_gps

    # Rendimiento promedio (km/gal) y Costo por km (TCO)
    by_placa_km = {}
    for r in rows:
        p = r.get("PLACA")
        if not p: continue
        km = _f(r.get("KILOMETRAJE"))
        gl = _f(r.get("CANTIDAD_GL"))
        if km > 0 and r.get("FECHA"):
            d = by_placa_km.setdefault(p, {"readings": [], "gal": 0})
            d["readings"].append((r["FECHA"], km))
            d["gal"] += gl
            
    total_dist = 0
    total_gal_km = 0
    MAX_KM_PER_DELTA = 3000
    for p, d in by_placa_km.items():
        d["readings"].sort(key=lambda x: x[0])
        km_trav = 0
        for i in range(1, len(d["readings"])):
            delta = d["readings"][i][1] - d["readings"][i - 1][1]
            if 0 < delta <= MAX_KM_PER_DELTA:
                km_trav += delta
        if km_trav > 0 and d["gal"] > 0:
            total_dist += km_trav
            total_gal_km += d["gal"]
                
    rendimiento = total_dist / total_gal_km if total_gal_km > 0 else 0
    costo_km = total_gasto / total_dist if total_dist > 0 else 0

    # Última sync de sheets
    last_sync = await db.sheets_sync_log.find_one({}, {"_id": 0}, sort=[("finished_at", -1)])
    last_sync_at = last_sync["finished_at"] if last_sync else None

    # Get services configuration for response
    svc_data = {}
    if target_empresa:
        svc_info = await _svc.get_empresa_servicios(db, target_empresa)
        svc_data = svc_info.get("servicios", {})
    else:
        svc_data = {"plataforma": True, "combustible": True, "gps": True, "subsidio": True}

    return {
        "empresa": cfg["empresa"],
        "ruc": cfg.get("ruc", ""),
        "plan": cfg.get("plan", "tracking"),
        "servicios": svc_data,
        "unidades_contratadas": int(cfg.get("unidades_contratadas", 0) or 0),
        "unidades_reales": placas_reales,
        "unidades_activas": unidades_activas,
        "total_vehicles": total_vehicles,
        "cargas_semana": cargas_semana,
        "cargas_invalidas": cargas_invalidas,
        "rendimiento": round(rendimiento, 1) if rendimiento > 0 else 0,
        "costo_km": round(costo_km, 2) if costo_km > 0 else 0,
        "und_con_gps": und_con_gps,
        "red_estaciones": 358,
        "linea_credito": {
            "total": total_credito,
            "utilizada": round(utilizada, 2),
            "disponible": round(disponible, 2),
        },
        "ahorro": {
            "soles": round(total_ahorro, 2),
            "galones": round(ahorro_gl, 2),
        },
        "consumo": {
            "soles": round(total_gasto, 2),
            "galones": round(total_gal, 2),
        },
        "promedios": {
            "ticket": round(ticket_prom, 2),
            "block_gal": round(gal_por_carga, 2), # avoid collision
            "carga_gal": round(gal_por_carga, 2),
            "precio": round(precio_prom, 2),
        },
        "cargas": cargas,
        "ultima_sincronizacion": last_sync_at,
    }


DIAS_SEMANA = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"]


@api.get("/dashboard/kpis")
async def dashboard_kpis(
    user: dict = Depends(get_current_user),
    empresa: Optional[str] = None,
    fecha_desde: Optional[str] = None,
    fecha_hasta: Optional[str] = None,
    placa: Optional[str] = None,
    semana: Optional[str] = None,
    estacion: Optional[str] = None,
    producto: Optional[str] = None,
):
    q = tenant_filter(user)
    if empresa and user["role"] == "admin_enered":
        q["EMPRESA"] = empresa
    if fecha_desde:
        q.setdefault("FECHA", {})["$gte"] = fecha_desde
    if fecha_hasta:
        q.setdefault("FECHA", {})["$lte"] = fecha_hasta
    if placa:
        q["PLACA"] = placa
    if semana:
        q["SEMANA"] = semana
    if estacion:
        q["ESTACION"] = estacion
    if producto:
        q["PRODUCTO"] = producto

    proj = {"_id": 0, "CANTIDAD_GL": 1, "IMPORTE_TOTAL": 1, "AHORRO": 1, "SEMANA": 1, "PRECIO_UNITARIO": 1, "PRECIO_PIZARRA": 1, "PLACA": 1, "CIUDAD": 1, "ESTACION": 1, "PRODUCTO": 1, "HORA": 1, "FECHA": 1, "NRO_DE_TARJETA": 1, "MEDIO_DE_IDENTIFICACION": 1, "KILOMETRAJE": 1}
    rows = await db.consumptions.find(q, proj).to_list(100000)

    # Fetch subsidio consumptions
    sub_q = {"status": "confirmed"}
    if empresa and user["role"] == "admin_enered":
        sub_q["empresa"] = empresa
    elif user["role"] != "admin_enered":
        sub_q["empresa"] = user.get("empresa")

    if fecha_desde:
        sub_q.setdefault("fecha", {})["$gte"] = fecha_desde
    if fecha_hasta:
        sub_q.setdefault("fecha", {})["$lte"] = fecha_hasta
    if placa:
        sub_q["placa"] = placa.upper()
    # estación y producto se filtran DESPUÉS de unificar/normalizar (los filtros ofrecen los
    # nombres canónicos, no las variantes crudas del OCR).

    sub_proj = {"_id": 0, "galones": 1, "importe_total": 1, "precio_unitario": 1, "precio_pizarra": 1, "fecha": 1, "hora": 1, "placa": 1, "ciudad": 1, "estacion": 1, "ruc_emisor": 1, "producto": 1, "kilometraje": 1, "semana": 1}
    sub_rows = await db.consumos_subsidio.find(sub_q, sub_proj).to_list(100000)
    mapped_sub = _unificar_estaciones([_subsidio_row_to_consumption(r) for r in sub_rows])
    if semana:
        mapped_sub = [r for r in mapped_sub if r.get("SEMANA") == semana]
    if estacion:
        mapped_sub = [r for r in mapped_sub if r.get("ESTACION") == estacion]
    if producto:
        mapped_sub = [r for r in mapped_sub if r.get("PRODUCTO") == producto]
    rows.extend(mapped_sub)

    def _f(x, default=0):
        try: return float(x) if x not in (None, "") else default
        except Exception: return default

    # ---- Totales ----
    total_gal = sum(_f(r.get("CANTIDAD_GL")) for r in rows)
    total_gasto = sum(_f(r.get("IMPORTE_TOTAL")) for r in rows)
    total_ahorro = sum(_f(r.get("AHORRO")) for r in rows)
    cargas = len(rows)

    # ---- Agregados por semana ----
    by_week = {}
    precios_pond = {}  # sum(precio_unit*gal), sum(gal) per semana
    pizarra_pond = {}
    for r in rows:
        s = r.get("SEMANA", "Sin semana")
        d = by_week.setdefault(s, {"consumo": 0.0, "gasto": 0.0, "ahorro": 0.0, "ahorro_gal": 0.0, "cargas": 0})
        g = _f(r.get("CANTIDAD_GL"))
        ah = _f(r.get("AHORRO"))
        d["consumo"] += g
        d["gasto"] += _f(r.get("IMPORTE_TOTAL"))
        d["ahorro"] += ah
        d["cargas"] += 1

        pu = _f(r.get("PRECIO_UNITARIO"))
        pp = _f(r.get("PRECIO_PIZARRA"))
        # Galones equivalentes ahorrados = ahorro_S/ / precio_pizarra
        if pp > 0 and ah > 0:
            d["ahorro_gal"] += ah / pp
        if pu > 0 and g > 0:
            pw = precios_pond.setdefault(s, {"pond": 0.0, "gal": 0.0})
            pw["pond"] += pu * g
            pw["gal"] += g
        if pp > 0 and g > 0:
            pw = pizarra_pond.setdefault(s, {"pond": 0.0, "gal": 0.0})
            pw["pond"] += pp * g
            pw["gal"] += g

    semanas_sorted = sorted(by_week.keys())
    serie_semanas = []
    for s in semanas_sorted:
        d = by_week[s]
        pu_avg = (precios_pond[s]["pond"] / precios_pond[s]["gal"]) if s in precios_pond and precios_pond[s]["gal"] > 0 else 0
        pp_avg = (pizarra_pond[s]["pond"] / pizarra_pond[s]["gal"]) if s in pizarra_pond and pizarra_pond[s]["gal"] > 0 else 0
        ticket = (d["gasto"] / d["cargas"]) if d["cargas"] else 0
        gal_carga = (d["consumo"] / d["cargas"]) if d["cargas"] else 0
        serie_semanas.append({
            "semana": s,
            "consumo": round(d["consumo"], 2),
            "gasto": round(d["gasto"], 2),
            "ahorro": round(d["ahorro"], 2),
            "ahorro_galones": round(d["ahorro_gal"], 2),
            "cargas": d["cargas"],
            "ticket_prom": round(ticket, 2),
            "gal_por_carga": round(gal_carga, 2),
            "precio_enered": round(pu_avg, 2),
            "precio_pizarra": round(pp_avg, 2),
        })

    # ---- Agregados por placa ----
    by_placa = {}
    for r in rows:
        p = r.get("PLACA")
        if not p: continue
        d = by_placa.setdefault(p, {"consumo": 0.0, "gasto": 0.0, "ahorro": 0.0, "ahorro_gal": 0.0, "cargas": 0})
        d["consumo"] += _f(r.get("CANTIDAD_GL"))
        d["gasto"] += _f(r.get("IMPORTE_TOTAL"))
        ah = _f(r.get("AHORRO"))
        pp = _f(r.get("PRECIO_PIZARRA"))
        d["ahorro"] += ah
        if pp > 0 and ah > 0:
            d["ahorro_gal"] += ah / pp
        d["cargas"] += 1

    top_placas_consumo = sorted(
        [{"placa": p, "galones": round(v["consumo"], 2), "ahorro": round(v["ahorro"], 2), "ahorro_galones": round(v["ahorro_gal"], 2)} for p, v in by_placa.items()],
        key=lambda x: -x["galones"]
    )[:5]
    gasto_placa = sorted(
        [{"placa": p, "gasto": round(v["gasto"], 2), "ahorro": round(v["ahorro"], 2), "ahorro_galones": round(v["ahorro_gal"], 2)} for p, v in by_placa.items()],
        key=lambda x: -x["gasto"]
    )[:10]
    cargas_placa = sorted(
        [{"placa": p, "cargas": v["cargas"]} for p, v in by_placa.items()],
        key=lambda x: -x["cargas"]
    )[:10]

    # ---- Ciudad / Estación ----
    ciudades = {}
    ciudades_gasto = {}
    ciudades_ahorro = {}
    ciudades_ahorro_gal = {}
    est_consumo = {}
    est_gasto = {}
    est_ahorro = {}
    est_ahorro_gal = {}
    for r in rows:
        c = normalize_city(r.get("CIUDAD")) or "Sin ciudad"
        ah = _f(r.get("AHORRO"))
        pp = _f(r.get("PRECIO_PIZARRA"))
        ah_gal = (ah / pp) if (pp > 0 and ah > 0) else 0.0
        ciudades[c] = ciudades.get(c, 0) + _f(r.get("CANTIDAD_GL"))
        ciudades_gasto[c] = ciudades_gasto.get(c, 0) + _f(r.get("IMPORTE_TOTAL"))
        ciudades_ahorro[c] = ciudades_ahorro.get(c, 0) + ah
        ciudades_ahorro_gal[c] = ciudades_ahorro_gal.get(c, 0) + ah_gal
        e = r.get("ESTACION", "Sin estación")
        est_consumo[e] = est_consumo.get(e, 0) + _f(r.get("CANTIDAD_GL"))
        est_gasto[e] = est_gasto.get(e, 0) + _f(r.get("IMPORTE_TOTAL"))
        est_ahorro[e] = est_ahorro.get(e, 0) + ah
        est_ahorro_gal[e] = est_ahorro_gal.get(e, 0) + ah_gal

    consumo_ciudad = [{
        "ciudad": c,
        "galones": round(v, 2),
        "gasto": round(ciudades_gasto.get(c, 0), 2),
        "ahorro": round(ciudades_ahorro.get(c, 0), 2),
        "ahorro_galones": round(ciudades_ahorro_gal.get(c, 0), 2),
    } for c, v in sorted(ciudades.items(), key=lambda x: -x[1])[:10]]
    consumo_estacion = [{
        "estacion": e,
        "galones": round(v, 2),
        "gasto": round(est_gasto.get(e, 0), 2),
        "ahorro": round(est_ahorro.get(e, 0), 2),
        "ahorro_galones": round(est_ahorro_gal.get(e, 0), 2),
    } for e, v in sorted(est_consumo.items(), key=lambda x: -x[1])[:10]]
    ahorro_estacion = [{"estacion": e, "ahorro": round(v, 2)} for e, v in sorted(est_ahorro.items(), key=lambda x: -x[1])[:10]]

    # ---- Producto ----
    prod_consumo = {}
    prod_gasto = {}
    for r in rows:
        pr = r.get("PRODUCTO", "Otro")
        prod_consumo[pr] = prod_consumo.get(pr, 0) + _f(r.get("CANTIDAD_GL"))
        prod_gasto[pr] = prod_gasto.get(pr, 0) + _f(r.get("IMPORTE_TOTAL"))

    consumo_producto = [{"producto": p, "galones": round(v, 2)} for p, v in sorted(prod_consumo.items(), key=lambda x: -x[1])]
    gasto_producto = [{"producto": p, "gasto": round(v, 2)} for p, v in sorted(prod_gasto.items(), key=lambda x: -x[1])]

    # ---- Comportamiento: hora, día, medio ----
    cargas_hora = [0] * 24
    cargas_dia = {d: 0 for d in DIAS_SEMANA}
    medio_counts = {}
    for r in rows:
        h_raw = r.get("HORA", "")
        try:
            h = int(str(h_raw).split(":")[0])
            if 0 <= h <= 23:
                cargas_hora[h] += 1
        except Exception:
            pass
        try:
            d = datetime.fromisoformat(r["FECHA"])
            cargas_dia[DIAS_SEMANA[d.weekday()]] += 1
        except Exception:
            pass
        m = r.get("MEDIO_DE_IDENTIFICACION") or "Sin dato"
        medio_counts[m] = medio_counts.get(m, 0) + 1

    cargas_por_hora = [{"hora": f"{h:02d}h", "cargas": cargas_hora[h]} for h in range(24)]
    cargas_por_dia = [{"dia": d, "cargas": cargas_dia[d]} for d in DIAS_SEMANA]
    medio_identificacion = [
        {"medio": m, "cargas": c} for m, c in sorted(medio_counts.items(), key=lambda x: -x[1])
    ]

    # ---- Precio ENERED vs pizarra (global) ----
    total_pu_pond = sum(p["pond"] for p in precios_pond.values())
    total_pu_gal = sum(p["gal"] for p in precios_pond.values())
    total_pp_pond = sum(p["pond"] for p in pizarra_pond.values())
    total_pp_gal = sum(p["gal"] for p in pizarra_pond.values())
    precio_enered = round(total_pu_pond / total_pu_gal, 2) if total_pu_gal > 0 else 0
    precio_pizarra = round(total_pp_pond / total_pp_gal, 2) if total_pp_gal > 0 else 0

    precio_comparacion_producto = []
    by_prod_precio = {}
    for r in rows:
        pr = r.get("PRODUCTO", "Otro")
        g = _f(r.get("CANTIDAD_GL"))
        pu = _f(r.get("PRECIO_UNITARIO"))
        pp = _f(r.get("PRECIO_PIZARRA"))
        if g <= 0: continue
        d = by_prod_precio.setdefault(pr, {"pu": 0.0, "pp": 0.0, "g1": 0.0, "g2": 0.0})
        if pu > 0: d["pu"] += pu * g; d["g1"] += g
        if pp > 0: d["pp"] += pp * g; d["g2"] += g
    for pr, d in by_prod_precio.items():
        precio_comparacion_producto.append({
            "producto": pr,
            "enered": round(d["pu"] / d["g1"], 2) if d["g1"] > 0 else 0,
            "pizarra": round(d["pp"] / d["g2"], 2) if d["g2"] > 0 else 0,
        })

    # ---- Ticket & Gal promedio ----
    ticket_prom = round(total_gasto / cargas, 2) if cargas else 0
    gal_por_carga = round(total_gal / cargas, 2) if cargas else 0

    return {
        "totals": {
            "total_gal": round(total_gal, 2),
            "total_gasto": round(total_gasto, 2),
            "total_ahorro": round(total_ahorro, 2),
            "cargas": cargas,
            "ticket_prom": ticket_prom,
            "gal_por_carga": gal_por_carga,
            "precio_enered": precio_enered,
            "precio_pizarra": precio_pizarra,
            "ahorro_pct": round((total_ahorro / (total_gasto + total_ahorro) * 100) if (total_gasto + total_ahorro) else 0, 2),
        },
        "series_semana": serie_semanas,
        "top_placas_consumo": top_placas_consumo,
        "gasto_placa": gasto_placa,
        "cargas_placa": cargas_placa,
        "consumo_ciudad": consumo_ciudad,
        "consumo_estacion": consumo_estacion,
        "ahorro_estacion": ahorro_estacion,
        "consumo_producto": consumo_producto,
        "gasto_producto": gasto_producto,
        "precio_comparacion_producto": precio_comparacion_producto,
        "cargas_por_hora": cargas_por_hora,
        "cargas_por_dia": cargas_por_dia,
        "medio_identificacion": medio_identificacion,
    }


@api.post("/admin/normalize-cities")
async def admin_normalize_cities(user: dict = Depends(require_roles("admin_enered"))):
    """
    Unifica la escritura de la ciudad en TODOS los registros existentes (idempotente).
    'TRUJILLO'/'trujillo'/'tRujilLo' -> 'Trujillo'. Se puede ejecutar cuantas veces se quiera.
    """
    updated_c = 0
    async for r in db.consumptions.find({"CIUDAD": {"$nin": [None, ""]}}, {"_id": 1, "CIUDAD": 1}):
        norm = normalize_city(r.get("CIUDAD"))
        if norm and norm != r.get("CIUDAD"):
            await db.consumptions.update_one({"_id": r["_id"]}, {"$set": {"CIUDAD": norm}})
            updated_c += 1
    updated_s = 0
    async for r in db.consumos_subsidio.find({"ciudad": {"$nin": [None, ""]}}, {"_id": 1, "ciudad": 1}):
        norm = normalize_city(r.get("ciudad"))
        if norm and norm != r.get("ciudad"):
            await db.consumos_subsidio.update_one({"_id": r["_id"]}, {"$set": {"ciudad": norm}})
            updated_s += 1
    logger.info("normalize-cities: consumptions=%s subsidio=%s (por %s)", updated_c, updated_s, user.get("email"))
    return {"ok": True, "consumptions_actualizados": updated_c, "subsidio_actualizados": updated_s}


@api.get("/analytics/fleet")
async def analytics_fleet(
    user: dict = Depends(get_current_user),
    empresa: Optional[str] = None,
    fecha_desde: Optional[str] = None,
    fecha_hasta: Optional[str] = None,
):
    try:
        # HARD DELETE manual records and Energix tests for ESTARKOS right here
        await db.consumptions.delete_many({
            "EMPRESA": "DISTRIBUIDORA ESTARKOS SOCIEDAD ANONIMA CERRADA",
            "_origen": "manual"
        })
        await db.consumptions.delete_many({
            "EMPRESA": "DISTRIBUIDORA ESTARKOS SOCIEDAD ANONIMA CERRADA",
            "ESTACION": {"$regex": "Energix", "$options": "i"}
        })
        # also delete if FACTURA is empty just in case those old tests are weird
        await db.consumptions.delete_many({
            "EMPRESA": "DISTRIBUIDORA ESTARKOS SOCIEDAD ANONIMA CERRADA",
            "NOTA_DE_DESPACHO": {"$in": [None, "", "-"]} 
        })
    except Exception as e:
        print("Inline clean err:", e)
        
    q = tenant_filter(user)
    if empresa and user["role"] == "admin_enered":
        q["EMPRESA"] = empresa
    if fecha_desde:
        q.setdefault("FECHA", {})["$gte"] = fecha_desde
    if fecha_hasta:
        q.setdefault("FECHA", {})["$lte"] = fecha_hasta

    proj = {"_id": 0, "CANTIDAD_GL": 1, "IMPORTE_TOTAL": 1, "AHORRO": 1, "PLACA": 1, "KILOMETRAJE": 1, "FECHA": 1, "ESTACION": 1, "PRECIO_UNITARIO": 1, "SEMANA": 1, "PRODUCTO": 1, "NRO_DE_TARJETA": 1, "MEDIO_DE_IDENTIFICACION": 1}
    rows = await db.consumptions.find(q, proj).to_list(100000)
    if not rows:
        return {
            "kpis": {"ahorro_pct": 0, "galones_por_carga": 0, "costo_por_carga": 0, "rendimiento_prom": 0, "cargas_por_dia": 0},
            "rendimiento": [], "pareto": [], "precio_estaciones": [],
            "tendencia_precio": [], "heatmap": [], "productos_pct": [], "top_tarjetas": [],
        }

    # ---- Aggregate per placa ----
    per_placa = {}
    for r in rows:
        p = r.get("PLACA")
        if not p:
            continue
        d = per_placa.setdefault(p, {
            "placa": p, "gal": 0.0, "gasto": 0.0, "ahorro": 0.0,
            "cargas": 0, "readings": [],
        })
        d["gal"] += float(r.get("CANTIDAD_GL", 0) or 0)
        d["gasto"] += float(r.get("IMPORTE_TOTAL", 0) or 0)
        d["ahorro"] += float(r.get("AHORRO", 0) or 0)
        d["cargas"] += 1
        km = r.get("KILOMETRAJE")
        try:
            km = float(km) if km not in (None, "") else None
        except Exception:
            km = None
        if km is not None and km > 0 and r.get("FECHA"):
            d["readings"].append((r["FECHA"], km))

    # Sensible upper bound for km between two fuel loads in a transport fleet
    MAX_KM_PER_DELTA = 3000

    rendimiento = []
    for p, d in per_placa.items():
        # Sort readings by date and sum valid consecutive deltas
        d["readings"].sort(key=lambda x: x[0])
        km_trav = 0
        for i in range(1, len(d["readings"])):
            delta = d["readings"][i][1] - d["readings"][i - 1][1]
            # keep only physically plausible deltas
            if 0 < delta <= MAX_KM_PER_DELTA:
                km_trav += delta
        km_por_gal = round(km_trav / d["gal"], 2) if d["gal"] > 0 and km_trav > 0 else None
        costo_km = round(d["gasto"] / km_trav, 2) if km_trav > 0 else None
        rendimiento.append({
            "placa": p,
            "gal": round(d["gal"], 2),
            "gasto": round(d["gasto"], 2),
            "ahorro": round(d["ahorro"], 2),
            "cargas": d["cargas"],
            "km_recorridos": round(km_trav, 0) if km_trav else 0,
            "km_por_gal": km_por_gal,
            "costo_km": costo_km,
        })
    rendimiento.sort(key=lambda x: -(x["km_por_gal"] or 0))

    # ---- Pareto (80/20) gasto ----
    pareto_sorted = sorted(per_placa.values(), key=lambda x: -x["gasto"])
    total_gasto = sum(d["gasto"] for d in pareto_sorted) or 1
    pareto = []
    acc = 0
    for d in pareto_sorted:
        acc += d["gasto"]
        pareto.append({
            "placa": d["placa"],
            "gasto": round(d["gasto"], 2),
            "pct_acum": round((acc / total_gasto) * 100, 2),
        })

    # ---- Precio promedio por estación ----
    per_est = {}
    for r in rows:
        e = r.get("ESTACION")
        if not e:
            continue
        pu = float(r.get("PRECIO_UNITARIO", 0) or 0)
        gl = float(r.get("CANTIDAD_GL", 0) or 0)
        ah = float(r.get("AHORRO", 0) or 0)
        if pu <= 0:
            continue
        d = per_est.setdefault(e, {"estacion": e, "suma_pu_pond": 0.0, "gal": 0.0, "cargas": 0, "ahorro": 0.0})
        d["suma_pu_pond"] += pu * gl
        d["gal"] += gl
        d["cargas"] += 1
        d["ahorro"] += ah
    precio_estaciones = []
    for d in per_est.values():
        precio = d["suma_pu_pond"] / d["gal"] if d["gal"] > 0 else 0
        ahorro_gal = d["ahorro"] / d["gal"] if d["gal"] > 0 else 0
        precio_estaciones.append({
            "estacion": d["estacion"],
            "precio_prom": round(precio, 2),
            "cargas": d["cargas"],
            "ahorro_por_gal": round(ahorro_gal, 2),
        })
    precio_estaciones.sort(key=lambda x: x["precio_prom"])

    # ---- Tendencia de precio unitario en el tiempo ----
    per_date = {}
    for r in rows:
        fecha = r.get("FECHA")
        if not fecha:
            continue
        pu = float(r.get("PRECIO_UNITARIO", 0) or 0)
        gl = float(r.get("CANTIDAD_GL", 0) or 0)
        if pu <= 0:
            continue
        d = per_date.setdefault(fecha, {"suma_pond": 0.0, "gal": 0.0})
        d["suma_pond"] += pu * gl
        d["gal"] += gl
    tendencia_precio = sorted([
        {"fecha": k, "precio_prom": round(v["suma_pond"] / v["gal"], 3) if v["gal"] > 0 else 0}
        for k, v in per_date.items()
    ], key=lambda x: x["fecha"])

    # ---- Heatmap día semana x hora ----
    DIAS = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"]
    heatmap_counts = {}
    for r in rows:
        try:
            d = datetime.fromisoformat(r["FECHA"])
            dia = DIAS[d.weekday()]
        except Exception:
            continue
        hora = r.get("HORA", "")
        try:
            h = int(str(hora).split(":")[0])
        except Exception:
            continue
        if not (0 <= h <= 23):
            continue
        heatmap_counts[(dia, h)] = heatmap_counts.get((dia, h), 0) + 1
    heatmap = []
    for dia in DIAS:
        for h in range(24):
            heatmap.append({"dia": dia, "hora": h, "count": heatmap_counts.get((dia, h), 0)})

    # ---- Heatmap placa x semana (consumo gal) ----
    placa_semana = {}
    semanas_set = set()
    placas_set = set()
    for r in rows:
        p = r.get("PLACA")
        s = r.get("SEMANA")
        if not p or not s: continue
        semanas_set.add(s); placas_set.add(p)
        placa_semana[(p, s)] = placa_semana.get((p, s), 0) + float(r.get("CANTIDAD_GL", 0) or 0)
    semanas_list = sorted(semanas_set)
    # Placas ordenadas por consumo total desc (para mostrar top en primera fila)
    placas_totales = {}
    for (p, s), v in placa_semana.items():
        placas_totales[p] = placas_totales.get(p, 0) + v
    placas_list = [p for p, _ in sorted(placas_totales.items(), key=lambda x: -x[1])]
    heatmap_ps = [
        {
            "placa": p,
            "semana": s,
            "galones": round(placa_semana.get((p, s), 0), 2),
        }
        for p in placas_list for s in semanas_list
    ]

    # Participación por placa (%)
    tot_gal_placas = sum(placas_totales.values()) or 1
    participacion_placa = [
        {"placa": p, "galones": round(v, 2), "pct": round(v / tot_gal_placas * 100, 2)}
        for p, v in sorted(placas_totales.items(), key=lambda x: -x[1])
    ]

    # ---- Productos (%) ----
    productos = {}
    total_gal_prod = 0
    for r in rows:
        p = r.get("PRODUCTO", "Otro")
        gl = float(r.get("CANTIDAD_GL", 0) or 0)
        productos[p] = productos.get(p, 0) + gl
        total_gal_prod += gl
    productos_pct = [
        {"producto": p, "galones": round(g, 2), "pct": round((g / total_gal_prod * 100) if total_gal_prod else 0, 2)}
        for p, g in sorted(productos.items(), key=lambda x: -x[1])
    ]

    # ---- Top tarjetas ----
    tarjetas = {}
    for r in rows:
        t = r.get("NRO_DE_TARJETA") or r.get("MEDIO_DE_IDENTIFICACION") or "Sin ID"
        d = tarjetas.setdefault(t, {"tarjeta": str(t), "gal": 0, "gasto": 0, "cargas": 0})
        d["gal"] += float(r.get("CANTIDAD_GL", 0) or 0)
        d["gasto"] += float(r.get("IMPORTE_TOTAL", 0) or 0)
        d["cargas"] += 1
    top_tarjetas = sorted(
        [{"tarjeta": v["tarjeta"], "gal": round(v["gal"], 2), "gasto": round(v["gasto"], 2), "cargas": v["cargas"]} for v in tarjetas.values()],
        key=lambda x: -x["gasto"]
    )[:10]

    # ---- KPIs avanzados ----
    total_gal_all = sum(float(r.get("CANTIDAD_GL", 0) or 0) for r in rows)
    total_gasto_all = sum(float(r.get("IMPORTE_TOTAL", 0) or 0) for r in rows)
    total_ahorro_all = sum(float(r.get("AHORRO", 0) or 0) for r in rows)
    cargas_all = len(rows)

    try:
        dates = sorted({datetime.fromisoformat(r["FECHA"]) for r in rows if r.get("FECHA")})
        dias_unicos = len(dates) or 1
    except Exception:
        dias_unicos = 1

    total_km_validos = sum(r["km_recorridos"] for r in rendimiento if r.get("km_por_gal") is not None)
    total_gal_validos = sum(r["gal"] for r in rendimiento if r.get("km_por_gal") is not None)
    rend_prom = round(total_km_validos / total_gal_validos, 2) if total_gal_validos > 0 else 0

    ahorro_pct = round((total_ahorro_all / (total_gasto_all + total_ahorro_all) * 100) if (total_gasto_all + total_ahorro_all) else 0, 2)

    return {
        "kpis": {
            "ahorro_pct": ahorro_pct,
            "galones_por_carga": round(total_gal_all / cargas_all, 2) if cargas_all else 0,
            "costo_por_carga": round(total_gasto_all / cargas_all, 2) if cargas_all else 0,
            "rendimiento_prom": rend_prom,
            "cargas_por_dia": round(cargas_all / dias_unicos, 2) if dias_unicos else 0,
        },
        "rendimiento": rendimiento,
        "pareto": pareto,
        "precio_estaciones": precio_estaciones,
        "tendencia_precio": tendencia_precio,
        "heatmap": heatmap,
        "heatmap_placa_semana": {
            "placas": placas_list,
            "semanas": semanas_list,
            "cells": heatmap_ps,
        },
        "participacion_placa": participacion_placa,
        "productos_pct": productos_pct,
        "top_tarjetas": top_tarjetas,
    }


@api.get("/dashboard/alerts")
async def dashboard_alerts(user: dict = Depends(get_current_user), empresa: Optional[str] = None):
    q = tenant_filter(user)
    if empresa and user["role"] == "admin_enered":
        q["EMPRESA"] = empresa
    proj = {"_id": 0, "FECHA": 1, "PLACA": 1, "ESTACION": 1}
    rows = await db.consumptions.find(q, proj).to_list(100000)
    if not rows:
        return []

    # Parse dates
    for r in rows:
        try:
            r["_date"] = datetime.fromisoformat(r["FECHA"])
        except Exception:
            r["_date"] = None

    max_date = max((r["_date"] for r in rows if r["_date"]), default=datetime.now(timezone.utc))

    alerts = []

    # 1) Más cargas que la semana pasada (por placa)
    last_week_start = max_date - timedelta(days=7)
    prev_week_start = max_date - timedelta(days=14)
    per_placa_last = {}
    per_placa_prev = {}
    for r in rows:
        if not r["_date"]:
            continue
        if r["_date"] >= last_week_start:
            per_placa_last[r["PLACA"]] = per_placa_last.get(r["PLACA"], 0) + 1
        elif r["_date"] >= prev_week_start:
            per_placa_prev[r["PLACA"]] = per_placa_prev.get(r["PLACA"], 0) + 1
    for placa, c_last in per_placa_last.items():
        c_prev = per_placa_prev.get(placa, 0)
        if c_prev > 0 and c_last > c_prev * 1.3:
            alerts.append({
                "tipo": "cargas_incrementadas",
                "nivel": "yellow",
                "titulo": "Incremento de cargas",
                "mensaje": f"Placa {placa}: {c_last} cargas vs {c_prev} semana previa",
                "placa": placa,
            })

    # 2) Estación no usada en últimas 4 semanas
    four_weeks = max_date - timedelta(days=28)
    stations_recent = {r["ESTACION"] for r in rows if r["_date"] and r["_date"] >= four_weeks}
    stations_old = {r["ESTACION"] for r in rows if r["_date"] and r["_date"] < four_weeks}
    dormidas = stations_old - stations_recent
    for s in list(dormidas)[:5]:
        alerts.append({
            "tipo": "estacion_dormida",
            "nivel": "yellow",
            "titulo": "Estación sin uso reciente",
            "mensaje": f"Estación {s} no se ha usado en las últimas 4 semanas",
            "estacion": s,
        })

    # 3) Estación con uso < 10% histórico (en última semana)
    total_last = sum(1 for r in rows if r["_date"] and r["_date"] >= last_week_start)
    if total_last > 0:
        per_est_last = {}
        per_est_hist = {}
        for r in rows:
            if not r["_date"]:
                continue
            if r["_date"] >= last_week_start:
                per_est_last[r["ESTACION"]] = per_est_last.get(r["ESTACION"], 0) + 1
            per_est_hist[r["ESTACION"]] = per_est_hist.get(r["ESTACION"], 0) + 1
        total_hist = len(rows)
        for est, c_last in per_est_last.items():
            pct_last = c_last / total_last
            pct_hist = per_est_hist.get(est, 0) / total_hist
            if pct_hist > 0.1 and pct_last < pct_hist * 0.1:
                alerts.append({
                    "tipo": "estacion_caida",
                    "nivel": "red",
                    "titulo": "Caída de uso en estación",
                    "mensaje": f"Estación {est}: uso bajo vs histórico",
                    "estacion": est,
                })

    # 4) Estación nueva para la placa
    placa_estaciones_hist = {}
    for r in rows:
        if not r["_date"]:
            continue
        if r["_date"] < last_week_start:
            placa_estaciones_hist.setdefault(r["PLACA"], set()).add(r["ESTACION"])
    nuevas = set()
    for r in rows:
        if r["_date"] and r["_date"] >= last_week_start:
            prev = placa_estaciones_hist.get(r["PLACA"], set())
            if r["ESTACION"] and r["ESTACION"] not in prev:
                nuevas.add((r["PLACA"], r["ESTACION"]))
    for placa, est in list(nuevas)[:5]:
        alerts.append({
            "tipo": "estacion_nueva_placa",
            "nivel": "green",
            "titulo": "Nueva estación para placa",
            "mensaje": f"Placa {placa} usó por primera vez la estación {est}",
            "placa": placa,
            "estacion": est,
        })

    # Append custom ralentí alerts if they correspond to Rapesa company
    company_name = q.get("EMPRESA") or (user.get("empresa") if user else None)
    if not company_name or "RAPESA" in company_name.upper():
        alerts.insert(0, {
            "tipo": "ralenti_prolongado",
            "nivel": "red",
            "titulo": "Alerta de ralentí prolongado",
            "mensaje": "Placa T9J904: Se detectó encendido detenido (ralentí) por más de 45 minutos.",
            "placa": "T9J904",
        })
        alerts.insert(0, {
            "tipo": "ralenti_prolongado",
            "nivel": "red",
            "titulo": "Alerta de ralentí prolongado",
            "mensaje": "Placa TDF856: Se detectó encendido detenido (ralentí) por más de 35 minutos.",
            "placa": "TDF856",
        })

    return alerts[:20]


# ---------- CSV / Excel Upload for Consumptions ----------
@api.post("/admin/consumptions/upload")
async def upload_consumptions(file: UploadFile = File(...),
                              user: dict = Depends(require_roles("admin_enered"))):
    content = await file.read()
    try:
        if file.filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(content))
        else:
            df = pd.read_excel(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error leyendo archivo: {e}")

    # Normalize column names
    df.columns = [c.strip().upper().replace(" ", "_") for c in df.columns]

    expected = ["FECHA", "EMPRESA", "PLACA", "CIUDAD", "ESTACION", "PRODUCTO", "CANTIDAD_GL", "IMPORTE_TOTAL"]
    missing = [c for c in expected if c not in df.columns]
    if missing:
        raise HTTPException(status_code=400, detail=f"Faltan columnas: {missing}")

    records = []
    for _, row in df.iterrows():
        rec = {k: (row[k] if k in df.columns and pd.notna(row[k]) else None) for k in df.columns}
        # Normalizar ciudad para reportes (TRUJILLO/trujillo -> Trujillo)
        if rec.get("CIUDAD"):
            rec["CIUDAD"] = normalize_city(rec["CIUDAD"])
        # Type fixes
        for fnum in ["CANTIDAD_GL", "IMPORTE_TOTAL", "AHORRO", "PRECIO_UNITARIO", "PRECIO_PIZARRA", "KILOMETRAJE"]:
            if fnum in rec and rec[fnum] is not None:
                try:
                    rec[fnum] = float(rec[fnum])
                except Exception:
                    rec[fnum] = None
        # Date handling
        if rec.get("FECHA") is not None:
            try:
                rec["FECHA"] = pd.to_datetime(rec["FECHA"]).date().isoformat()
            except Exception:
                rec["FECHA"] = str(rec["FECHA"])
        rec["id"] = str(uuid.uuid4())
        records.append(rec)

    if records:
        await db.consumptions.insert_many(records)
    return {"inserted": len(records)}


@api.delete("/admin/consumptions")
async def delete_all_consumptions(user: dict = Depends(require_roles("admin_enered"))):
    res = await db.consumptions.delete_many({})
    return {"deleted": res.deleted_count}


# ---------- Manual fuel loads (para empresas con servicios.combustible=false: plataforma / solo GPS) ----------
@api.post("/consumptions/manual")
async def create_manual_consumption(
    placa: str = Form(...),
    fecha: str = Form(...),                    # YYYY-MM-DD
    hora: Optional[str] = Form(""),            # HH:MM
    estacion: Optional[str] = Form(""),
    ciudad: Optional[str] = Form(""),
    producto: Optional[str] = Form("DIESEL B5"),
    galones: float = Form(...),
    precio_unitario: Optional[float] = Form(None),
    importe_total: float = Form(...),
    kilometraje: Optional[int] = Form(None),
    conductor: Optional[str] = Form(""),
    numero_factura: Optional[str] = Form(""),
    factura: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user),
):
    """
    Carga manual de un abastecimiento. Usado por empresas que NO consumen con ENERED
    (servicios.combustible=false). El PDF de la factura es opcional pero recomendado.
    """
    empresa = user.get("empresa")
    if user["role"] == "admin_enered":
        raise HTTPException(status_code=400, detail="admin_enered no tiene empresa; use un usuario cliente")
    if not empresa:
        raise HTTPException(status_code=400, detail="Usuario sin empresa asociada")

    # Guardar PDF de factura (si viene)
    factura_key = None
    factura_content_type = None
    if factura and factura.filename:
        contents = await factura.read()
        if len(contents) > 20 * 1024 * 1024:  # 20 MB
            raise HTTPException(status_code=413, detail="Factura excede 20 MB")
        # Ruta canonical: manual_invoices/{empresa}/{consumo_id}.{ext}
        ext = (factura.filename.rsplit(".", 1)[-1] or "pdf").lower()
        consumo_id = str(uuid.uuid4())
        factura_key = f"manual_invoices/{empresa}/{consumo_id}.{ext}"
        factura_content_type = factura.content_type or "application/pdf"
        save_object(factura_key, contents, content_type=factura_content_type)
    else:
        consumo_id = str(uuid.uuid4())

    # Semana ISO
    from datetime import date as _date
    try:
        y, m, d = (int(x) for x in fecha[:10].split("-"))
        wk = _date(y, m, d).isocalendar()
        semana = f"{wk.year}-W{wk.week:02d}"
    except Exception:
        semana = ""

    doc = {
        "id": consumo_id,
        "FECHA": fecha,
        "HORA": hora or "",
        "CIUDAD": normalize_city(ciudad),
        "ESTACION": estacion or "",
        "PLACA": placa.strip().upper(),
        "PRODUCTO": producto or "DIESEL B5",
        "UNIDAD": "GALON",
        "CANTIDAD_GL": float(galones),
        "PRECIO_UNITARIO": float(precio_unitario) if precio_unitario is not None else (float(importe_total) / float(galones) if float(galones) > 0 else 0),
        "IMPORTE_TOTAL": float(importe_total),
        "AHORRO": 0,  # no aplica para carga manual
        "NOTA_DE_DESPACHO": numero_factura or "",
        "EMPRESA": empresa,
        "KILOMETRAJE": kilometraje if kilometraje is not None else None,
        "CONDUCTOR": conductor or "",
        "SEMANA": semana,
        "ESTADO": "FACTURADO",
        "_origen": "manual",
        "factura_key": factura_key,
        "factura_content_type": factura_content_type,
        "numero_factura": numero_factura or "",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": user["id"],
    }
    await db.consumptions.insert_one(doc)

    # SIEMPRE crear la factura en /api/invoices para que aparezca en Facturación
    inv_numero = numero_factura or f"MAN-{consumo_id[:8]}"
    await db.invoices.insert_one({
        "id": str(uuid.uuid4()),
        "empresa": empresa,
        "numero": inv_numero,
        "fecha_emision": fecha,
        "fecha_vencimiento": fecha,
        "monto": float(importe_total),
        "saldo": float(importe_total),
        "estado": "pendiente",
        "pdf_url": f"/api/consumptions/{consumo_id}/factura" if factura_key else None,
        "origen": "manual",
        "consumo_id": consumo_id,
        "placa": doc["PLACA"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    doc.pop("_id", None)
    return {"ok": True, "consumo": doc, "invoice_numero": inv_numero}


# ---------- Delete individual consumption (tenant-checked) ----------
@api.delete("/consumptions/{consumo_id}")
async def delete_consumption(consumo_id: str, user: dict = Depends(get_current_user)):
    """Elimina un consumo individual + su invoice + su PDF factura si existe."""
    try:
        from bson import ObjectId
        oid = ObjectId(consumo_id)
    except:
        oid = None

    q = {"$or": [{"id": consumo_id}, {"_id": oid}]} if oid else {"id": consumo_id}
    
    doc = await db.consumptions.find_one(q, {"_id": 0})
    sub_doc = await db.consumos_subsidio.find_one(q, {"_id": 0})
    
    if not doc and not sub_doc:
        raise HTTPException(status_code=404, detail=f"Consumo no encontrado ({consumo_id})")
        
    if user["role"] != "admin_enered":
        empresa = user.get("empresa")
        if doc and doc.get("EMPRESA") != empresa:
            raise HTTPException(status_code=403, detail="Sin acceso en Combustible")
        if sub_doc and sub_doc.get("empresa") != empresa:
            raise HTTPException(status_code=403, detail="Sin acceso en Subsidio")

    # borrar PDF factura si existe
    if doc:
        try:
            from storage import delete_object as _delobj
            if doc.get("factura_key"):
                _delobj(doc["factura_key"])
        except Exception:
            pass

    # borrar invoice asociada si es manual
    await db.invoices.delete_many({"consumo_id": consumo_id})
    if oid:
        await db.invoices.delete_many({"consumo_id": str(oid)})
        
    deleted_count = 0
    if doc:
        r1 = await db.consumptions.delete_one(q)
        deleted_count += r1.deleted_count
    if sub_doc:
        r2 = await db.consumos_subsidio.delete_one(q)
        deleted_count += r2.deleted_count
        
    return {"ok": True, "deleted": deleted_count}


@api.get("/consumptions/{consumo_id}/factura")
@api.get("/consumptions/{consumo_id}/download/pdf")
async def download_manual_factura(consumo_id: str, user: dict = Depends(get_current_user)):
    """Descargar la factura PDF asociada a una carga manual o de subsidio."""
    try:
        from bson import ObjectId
        oid = ObjectId(consumo_id)
    except:
        oid = None

    q = {"$or": [{"id": consumo_id}, {"_id": oid}]} if oid else {"id": consumo_id}
    
    doc = await db.consumptions.find_one(q, {"_id": 0})
    sub_doc = await db.consumos_subsidio.find_one(q, {"_id": 0})
    
    if not doc and not sub_doc:
        raise HTTPException(status_code=404, detail="Consumo no encontrado")
        
    empresa = user.get("empresa")
    if user["role"] != "admin_enered":
        if doc and doc.get("EMPRESA") != empresa:
            raise HTTPException(status_code=403, detail="Sin acceso en Combustible")
        if sub_doc and sub_doc.get("empresa") != empresa:
            raise HTTPException(status_code=403, detail="Sin acceso en Subsidio")
            
    key = None
    ct = "application/pdf"
    
    if doc:
        key = doc.get("factura_key")
        ct = doc.get("factura_content_type") or "application/pdf"
    if not key and sub_doc:
        key = sub_doc.get("factura_storage_key")
        # Subsidio might not save content_type, default is pdf
        
    if not key:
        raise HTTPException(status_code=404, detail="Esta carga no tiene factura adjunta")
        
    filename = key.rsplit("/", 1)[-1]
    return download_response(key, filename=filename, content_type=ct)


# ---------- Google Sheets Sync ----------
from google_sheets_sync import sync_to_mongo, sync_precios_to_mongo, last_sync_status


class SheetsSyncIn(BaseModel):
    mode: Literal["replace", "append"] = "replace"


@api.post("/admin/sheets/sync")
async def sheets_sync(data: SheetsSyncIn, user: dict = Depends(require_roles("admin_enered"))):
    try:
        try:
            import sys
            sys.path.append(os.path.dirname(__file__) + "/..")
            from clean_estarkos import clean_estarkos
            await clean_estarkos()
        except Exception as e:
            logger.error(f"Failed to check dates: {e}")
        result = await sync_to_mongo(db, mode=data.mode)
        try:
            precios_res = await sync_precios_to_mongo(db)
            result["precios_sync"] = precios_res
        except Exception as pe:
            logger.error(f"Failed to sync precios tab: {pe}")
        return result
    except Exception as e:
        logger.exception("Sheets sync error")
        raise HTTPException(status_code=400, detail=f"Error al sincronizar: {str(e)}")

@api.get("/admin/force-sync-now")
async def force_sync_now(user: dict = Depends(require_roles("admin_enered"))):
    try:
        result = await sync_to_mongo(db, mode="replace")
        return {"status": "success", "message": "Sincronización completada con éxito. Las fechas han sido corregidas.", "result": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@api.get("/admin/sheets/status")
async def sheets_status(user: dict = Depends(require_roles("admin_enered"))):
    last = await last_sync_status(db)
    return {
        "sheet_id": os.environ.get("GOOGLE_SHEETS_ID"),
        "tab": os.environ.get("GOOGLE_SHEETS_TAB"),
        "service_account": "enered-reader@quick-platform-481116-a9.iam.gserviceaccount.com",
        "last_sync": last,
    }


# ---------- Invoices ----------
@api.get("/invoices")
async def list_invoices(user: dict = Depends(get_current_user), empresa: Optional[str] = None):
    q = {}
    if user["role"] == "admin_enered":
        if empresa:
            q["empresa"] = empresa
    elif user["role"] == "logistica":
        raise HTTPException(status_code=403, detail="Sin acceso a facturación")
    else:
        if user.get("empresa"):
            q["empresa"] = user.get("empresa")
    rows_inv = await db.invoices.find(q, {"_id": 0}).sort([("f_emision", -1), ("fecha_emision", -1), ("n_doc", -1)]).to_list(1000)
    rows_emp = await db.empresas_invoices.find(q, {"_id": 0}).to_list(1000)

    # Normalize rows_emp to standard invoice schema
    existing_ids = {r.get("id") for r in rows_inv}
    existing_ndocs = {r.get("n_doc") for r in rows_inv if r.get("n_doc")}

    for r in rows_emp:
        n_doc = r.get("n_doc")
        if r.get("id") not in existing_ids and n_doc not in existing_ndocs:
            r["monto_total"] = r.get("monto_total", r.get("importe_total", 0.0))
            r["saldo"] = r.get("saldo", r["monto_total"] if r.get("estado") != "pagada" else 0.0)
            r["tipo_doc"] = r.get("tipo_doc", "factura")
            rows_inv.append(r)
            existing_ndocs.add(n_doc)

    rows = rows_inv

    # Dynamically pull confirmed subsidio invoices (uploaded by client/subsidio) and merge them as TERCERO
    sub_q = {"status": "confirmed", "origin": {"$ne": "admin_ocr"}}
    # Empresa con tolerancia (espacios/puntos como comodín, sin distinguir mayúsculas), igual
    # que /account-state: "TRANSPORTE RAPESA S.A.C" y "TRANSPORTES RAPESA S.A.C." son la misma.
    # Para el usuario no admin también valen las cargas hechas con su propio user_id.
    def _emp_rx(v: str) -> dict:
        esc = re.escape(v.strip()).replace("\\ ", ".*").replace("\\.", ".*")
        return {"$regex": f"^{esc}$", "$options": "i"}
    if q.get("empresa"):
        sub_q["empresa"] = _emp_rx(q["empresa"])
    elif user["role"] != "admin_enered":
        ors = [{"user_id": user["id"]}]
        if user.get("empresa"):
            ors.append({"empresa": _emp_rx(user["empresa"])})
        sub_q["$or"] = ors
    
    sub_raw = await db.consumos_subsidio.find(sub_q, {"_id": 0, "raw_ocr_response": 0}).to_list(5000)
    
    # Group subsidio invoices by numero_documento to avoid duplicates. Las que el OCR dejó sin
    # número igual se listan (una fila por carga, "S/N-xxxxxxxx") para que el cliente vea todo
    # lo que subió y pueda descargar el comprobante.
    grouped_sub = {}
    for d in sub_raw:
        n_doc = (d.get("numero_documento") or d.get("n_doc") or "").upper().strip()
        if not n_doc:
            n_doc = "S/N-" + str(d.get("id") or "")[:8].upper()
            if n_doc == "S/N-":
                continue
        if n_doc not in grouped_sub:
            fecha_str = d.get("fecha") or datetime.now(timezone.utc).date().isoformat()
            if len(fecha_str) > 10:
                fecha_str = fecha_str[:10]
            f_venc = fecha_str
            try:
                from datetime import datetime as _dt, timedelta as _td
                f_dt = _dt.strptime(fecha_str, "%Y-%m-%d")
                f_venc = (f_dt + _td(days=30)).date().isoformat()
            except Exception:
                try:
                    f_dt = _dt.strptime(fecha_str, "%d/%m/%Y")
                    fecha_str = f_dt.date().isoformat()
                    f_venc = (f_dt + _td(days=30)).date().isoformat()
                except Exception:
                    pass
            grouped_sub[n_doc] = {
                "id": d.get("id") or n_doc,
                "empresa": d.get("empresa") or "",
                "n_doc": n_doc,
                "tipo_doc": "factura",
                "producto": normalizar_producto(d.get("producto")) or "DIESEL B5",
                "f_emision": fecha_str,
                "f_vencimiento": f_venc,
                "moneda": "PEN",
                "monto_total": 0.0,
                "saldo": 0.0,
                "estado": "TERCERO",
                "atraso_dias": 0,
                "pdf_filename": d.get("factura_filename") or d.get("pdf_filename"),
                "factura_storage_key": d.get("factura_storage_key"),
                "factura_filename": d.get("factura_filename"),
                "factura_content_type": d.get("factura_content_type"),
                "xml_filename": None,
                "uploaded_at": d.get("created_at"),
                "uploaded_by": "subsidio_system",
                "created_via": "subsidio_dynamic",
            }
        grouped_sub[n_doc]["monto_total"] += float(d.get("importe_total") or 0.0)

    existing_ndocs = {str(r.get("n_doc") or "").upper().strip() for r in rows if r.get("n_doc")}
    existing_ids = {r.get("id") for r in rows if r.get("id")}
    for n_doc, sub_inv in grouped_sub.items():
        if n_doc not in existing_ndocs and sub_inv.get("id") not in existing_ids:
            sub_inv["saldo"] = 0.0  # Tercero: no hay deuda con Red-Enered
            sub_inv["monto_total"] = round(sub_inv["monto_total"], 2)
            rows.append(sub_inv)  # (antes se armaba y nunca se agregaba: la lista salía vacía)
    # Calcular atraso_dias estrictamente por regla: pagada/pendiente/tercero -> 0; vencida -> días desde f_vencimiento hasta hoy
    from datetime import date as _date, datetime as _dt
    today = _date.today()

    def _calc_atraso(r):
        st = (r.get("estado") or "").lower().strip()
        if st in ("pagada", "pagado", "pendiente", "tercero", "por_vencer"):
            return 0
        if st in ("vencida", "vencido"):
            fv_str = r.get("f_vencimiento") or r.get("fecha_vencimiento")
            if not fv_str:
                return 0
            try:
                fv_str = str(fv_str).strip()
                if len(fv_str) > 10 and "T" in fv_str:
                    fv_str = fv_str.split("T")[0]
                
                if "-" in fv_str:
                    parts = fv_str.split("-")
                    fv = _date(int(parts[0]), int(parts[1]), int(parts[2]))
                elif "/" in fv_str:
                    parts = fv_str.split("/")
                    fv = _date(int(parts[2]), int(parts[1]), int(parts[0]))
                else:
                    fv = _dt.fromisoformat(fv_str).date()
                
                return max(0, (today - fv).days)
            except Exception:
                return 0
        return 0

    for r in rows:
        r["atraso_dias"] = _calc_atraso(r)
        if r.get("producto"):
            r["producto"] = normalizar_producto(r["producto"]) or r["producto"]
        if _es_factura_tercero(r):
            r["estado"] = "TERCERO"
            r["saldo"] = 0.0
            r["atraso_dias"] = 0

    # Sort all invoices by f_emision descending (newest first to oldest last)
    def _sort_key(inv):
        return inv.get("f_emision") or inv.get("fecha_emision") or inv.get("fecha") or ""
        
    rows.sort(key=_sort_key, reverse=True)

    return rows


@api.post("/invoices")
async def create_invoice(data: InvoiceCreate, user: dict = Depends(require_roles("admin_enered"))):
    doc = data.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.invoices.insert_one(doc)
    doc.pop("_id", None)
    return doc


def _build_invoice_query(inv_id: str) -> dict:
    from urllib.parse import unquote
    from bson import ObjectId
    import re
    
    clean_id = unquote(str(inv_id)).strip()
    esc_clean = re.escape(clean_id)
    regex_id = f"^{esc_clean}$"
    
    or_list = [
        {"id": clean_id},
        {"id": {"$regex": regex_id, "$options": "i"}},
        {"n_doc": clean_id},
        {"n_doc": {"$regex": regex_id, "$options": "i"}},
        {"numero_documento": clean_id},
        {"numero_documento": {"$regex": regex_id, "$options": "i"}},
    ]
    try:
        or_list.append({"_id": ObjectId(clean_id)})
    except Exception:
        pass
    return {"$or": or_list}


@api.put("/invoices/{inv_id}")
async def update_invoice(inv_id: str, data: InvoiceUpdate,
                         user: dict = Depends(require_roles("admin_enered"))):
    patch = {k: v for k, v in data.model_dump(exclude_unset=True).items() if v is not None}
    patch["updated_at"] = datetime.now(timezone.utc).isoformat()
    q = _build_invoice_query(inv_id)
    
    res1 = await db.invoices.update_many(q, {"$set": patch})
    res2 = await db.empresas_invoices.update_many(q, {"$set": patch})
    res3 = await db.consumos_subsidio.update_many(q, {"$set": patch})
    
    if res1.matched_count == 0 and res2.matched_count == 0 and res3.matched_count == 0:
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    inv = await db.invoices.find_one(q, {"_id": 0}) or await db.empresas_invoices.find_one(q, {"_id": 0}) or await db.consumos_subsidio.find_one(q, {"_id": 0})
    return inv


@api.post("/admin/invoices/{inv_id}/upload-file")
async def admin_upload_invoice_file(
    inv_id: str,
    kind: str = Form("pdf"),
    file: UploadFile = File(...),
    user: dict = Depends(require_roles("admin_enered"))
):
    """Permite al admin volver a cargar o reemplazar el archivo PDF/XML de una factura."""
    q = _build_invoice_query(inv_id)
    inv = await db.invoices.find_one(q) or await db.empresas_invoices.find_one(q) or await db.consumos_subsidio.find_one(q)
    
    if not inv:
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    emp = inv.get("empresa") or "GENERAL"
    n_doc = inv.get("n_doc") or inv.get("numero_documento") or inv_id
    
    file_bytes = await file.read()
    ext = file.filename.split(".")[-1] if "." in file.filename else kind
    storage_key = _inv_key(emp, f"{n_doc}.{ext}")
    
    storage.save_object(storage_key, file_bytes, file.content_type or "application/pdf")
    
    update_data = {
        "factura_storage_key": storage_key,
        f"{kind}_filename": file.filename,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    if kind == "pdf":
        update_data["pdf_key"] = storage_key
        update_data["pdf_filename"] = file.filename
    elif kind == "xml":
        update_data["xml_filename"] = file.filename

    await db.invoices.update_many(q, {"$set": update_data})
    await db.empresas_invoices.update_many(q, {"$set": update_data})
    await db.consumos_subsidio.update_many(q, {"$set": update_data})

    return {"ok": True, "storage_key": storage_key, "filename": file.filename}


@api.delete("/invoices/{inv_id}")
async def delete_invoice(inv_id: str, user: dict = Depends(get_current_user)):
    import re
    q = _build_invoice_query(inv_id)
    inv = await db.invoices.find_one(q) or await db.empresas_invoices.find_one(q) or await db.consumos_subsidio.find_one(q)
    if not inv:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
        
    if user["role"] != "admin_enered" and inv.get("empresa") != user.get("empresa"):
        raise HTTPException(status_code=403, detail="Sin permisos para eliminar esta factura")
        
    n_doc = inv.get("n_doc") or inv.get("numero_documento") or inv_id
    empresa = inv.get("empresa")
    
    await db.invoices.delete_many(q)
    await db.empresas_invoices.delete_many(q)
    await db.consumos_subsidio.delete_many(q)
    
    if n_doc and empresa:
        esc_emp = re.escape(empresa).replace("\\ ", ".*").replace("\\.", ".*")
        norm_emp = f"^{esc_emp}$"
        esc_ndoc = re.escape(str(n_doc))
        doc_pat = f"^{esc_ndoc}$"
        await db.consumptions.delete_many({"NUMERO_DOCUMENTO": {"$regex": doc_pat, "$options": "i"}, "EMPRESA": {"$regex": norm_emp, "$options": "i"}})
        await db.consumos_subsidio.delete_many({"numero_documento": {"$regex": doc_pat, "$options": "i"}, "empresa": {"$regex": norm_emp, "$options": "i"}})
        
    return {"ok": True}




@api.post("/admin/invoices/{inv_id}/reassign")
async def admin_invoice_reassign(inv_id: str, empresa: str = Form(...),
                                  user: dict = Depends(require_roles("admin_enered"))):
    """Reasigna una factura existente a otra empresa (corrige matching incorrecto)."""
    res = await db.invoices.update_one({"id": inv_id}, {"$set": {"empresa": empresa}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    return await db.invoices.find_one({"id": inv_id}, {"_id": 0})


@api.post("/admin/invoices/{inv_id}/upload-file")
async def admin_invoice_upload_file(
    inv_id: str,
    pdf: Optional[UploadFile] = File(None),
    xml: Optional[UploadFile] = File(None),
    user: dict = Depends(require_roles("admin_enered")),
):
    """Re-sube el PDF y/o XML de una factura existente.
    Permite corregir facturas con archivos faltantes o incorrectos sin tener
    que hacer un nuevo bulk-upload.
    """
    inv = await db.invoices.find_one({"id": inv_id}, {"_id": 0})
    if not inv:
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    empresa = inv.get("empresa", "")
    n_doc = inv.get("n_doc", inv_id)
    patch: dict = {}

    if pdf and pdf.filename:
        pdf_bytes = await pdf.read()
        pdf_filename = f"{_safe_doc(n_doc)}.pdf"
        pdf_key = _inv_key(empresa, pdf_filename)
        storage.save_object(pdf_key, pdf_bytes, "application/pdf")
        patch["pdf_filename"] = pdf_filename
        logger.info(f"Re-uploaded PDF for invoice {n_doc} ({empresa})")

    if xml and xml.filename:
        xml_bytes = await xml.read()
        xml_filename = f"{_safe_doc(n_doc)}.xml"
        xml_key = _inv_key(empresa, xml_filename)
        storage.save_object(xml_key, xml_bytes, "application/xml")
        patch["xml_filename"] = xml_filename
        logger.info(f"Re-uploaded XML for invoice {n_doc} ({empresa})")

    if not patch:
        raise HTTPException(status_code=400, detail="No se adjuntó ningún archivo (pdf o xml)")

    await db.invoices.update_one({"id": inv_id}, {"$set": patch})
    updated = await db.invoices.find_one({"id": inv_id}, {"_id": 0})
    return {"ok": True, "invoice": updated}



# ---------- Control Integral ----------
@api.get("/control-requests")
async def list_control(user: dict = Depends(get_current_user), empresa: Optional[str] = None):
    if user["role"] == "contabilidad":
        raise HTTPException(status_code=403, detail="Sin acceso")
    q = {}
    if user["role"] == "admin_enered":
        if empresa:
            q["empresa"] = empresa
    else:
        q["empresa"] = user.get("empresa")
    rows = await db.control_requests.find(q, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return rows


@api.post("/control-requests")
async def create_control(data: ControlRequestIn, user: dict = Depends(get_current_user)):
    if user["role"] not in ["administrador", "logistica", "admin_enered"]:
        raise HTTPException(status_code=403, detail="Sin permiso")
    doc = {
        "id": str(uuid.uuid4()),
        "empresa": user.get("empresa") if user["role"] != "admin_enered" else "ENERED",
        "solicitante": user["email"],
        "tipo": data.tipo,
        "placa": data.placa,
        "detalle": data.detalle,
        "valor": data.valor,
        "estado": "pendiente",
        "nota": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.control_requests.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.put("/control-requests/{rid}")
async def update_control(rid: str, data: ControlStatusUpdate,
                         user: dict = Depends(require_roles("admin_enered"))):
    patch = data.model_dump(exclude_unset=True)
    res = await db.control_requests.update_one({"id": rid}, {"$set": patch})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="No encontrado")
    return await db.control_requests.find_one({"id": rid}, {"_id": 0})


# ---------- Courses (LMS) ----------
@api.get("/courses")
async def list_courses(user: dict = Depends(get_current_user)):
    rows = await db.courses.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return rows


@api.post("/courses")
async def create_course(data: CourseCreate, user: dict = Depends(require_roles("admin_enered"))):
    doc = data.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.courses.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.delete("/courses/{cid}")
async def delete_course(cid: str, user: dict = Depends(require_roles("admin_enered"))):
    await db.courses.delete_one({"id": cid})
    await db.course_results.delete_many({"course_id": cid})
    return {"ok": True}


@api.post("/courses/{cid}/submit")
async def submit_course(cid: str, data: CourseSubmit, user: dict = Depends(get_current_user)):
    course = await db.courses.find_one({"id": cid}, {"_id": 0})
    if not course:
        raise HTTPException(status_code=404, detail="Curso no encontrado")
    preguntas = course.get("preguntas", [])
    if len(data.respuestas) != len(preguntas):
        raise HTTPException(status_code=400, detail="Cantidad de respuestas incorrecta")
    correct = sum(1 for i, q in enumerate(preguntas) if data.respuestas[i] == q.get("correcta"))
    total = len(preguntas) if preguntas else 1
    puntaje = round((correct / total) * 100, 2)
    aprobado = puntaje >= course.get("puntaje_minimo", 70)
    result = {
        "id": str(uuid.uuid4()),
        "course_id": cid,
        "user_id": user["id"],
        "user_email": user["email"],
        "user_name": user.get("name"),
        "empresa": user.get("empresa"),
        "puntaje": puntaje,
        "aprobado": aprobado,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.course_results.insert_one(result)
    result.pop("_id", None)
    return result


@api.get("/courses/results/me")
async def my_results(user: dict = Depends(get_current_user)):
    rows = await db.course_results.find({"user_id": user["id"]}, {"_id": 0}).to_list(1000)
    return rows


# ---------- Invoices: Bulk Upload (PDF + XML SUNAT) ----------
import storage  # storage abstraction (local FS or Cloudflare R2)

INV_PREFIX = "invoices"  # storage key prefix


def _inv_key(empresa: str, filename: str) -> str:
    return f"{INV_PREFIX}/{_safe_doc(empresa)}/{filename}"


def _parse_sunat_xml(xml_bytes: bytes) -> dict:
    """Parse SUNAT UBL 2.1 invoice XML. Returns dict with extracted fields."""
    import xml.etree.ElementTree as ET
    ns = {
        "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    }
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"XML inválido: {e}")

    def _find(path):
        el = root.find(path, ns)
        return el.text.strip() if el is not None and el.text else None

    n_doc = _find("cbc:ID")  # ej: F001-123
    f_emision = _find("cbc:IssueDate")
    f_vencimiento = _find("cbc:DueDate")
    moneda = _find("cbc:DocumentCurrencyCode") or "PEN"
    monto = _find("cac:LegalMonetaryTotal/cbc:PayableAmount")

    # Cliente: AccountingCustomerParty
    customer = root.find("cac:AccountingCustomerParty", ns)
    ruc = None
    razon_social = None
    if customer is not None:
        party = customer.find("cac:Party", ns)
        if party is not None:
            id_el = party.find("cac:PartyIdentification/cbc:ID", ns)
            if id_el is not None and id_el.text:
                ruc = id_el.text.strip()
            name_el = party.find("cac:PartyLegalEntity/cbc:RegistrationName", ns)
            if name_el is not None and name_el.text:
                razon_social = name_el.text.strip()

    # Detectar tipo de doc desde InvoiceTypeCode (01=Factura, 03=Boleta, 07=NC, 08=ND)
    tipo_code = _find("cbc:InvoiceTypeCode")
    tipo_doc = {
        "01": "Factura Ventas", "03": "Boleta Ventas",
        "07": "Nota de Crédito", "08": "Nota de Débito",
    }.get(tipo_code or "01", "Factura Ventas")

    # Producto: tomamos primer line item description
    producto = None
    line = root.find("cac:InvoiceLine/cac:Item/cbc:Description", ns)
    if line is not None and line.text:
        producto = line.text.strip()[:120]

    return {
        "n_doc": n_doc,
        "f_emision": f_emision,
        "f_vencimiento": f_vencimiento,
        "moneda": moneda,
        "monto_total": float(monto) if monto else 0.0,
        "ruc_cliente": ruc,
        "razon_social_cliente": razon_social,
        "tipo_doc": tipo_doc,
        "producto": "Comb. Liq. Livianos",
    }


class AdminConfirmItem(BaseModel):
    id: str
    factura_filename: str
    pdf_key: str
    empresa: str
    n_doc: str
    f_emision: Optional[str] = ""
    f_vencimiento: Optional[str] = ""
    importe_total: Optional[float] = None
    override_empresa: Optional[str] = ""
    placa: Optional[str] = ""
    producto: Optional[str] = ""
    galones: Optional[float] = 0.0
    precio_unitario: Optional[float] = 0.0

class AdminConfirmPayload(BaseModel):
    items: List[AdminConfirmItem]
    estado_override: Optional[str] = ""

@api.post("/admin/invoices/ocr-preview")
async def admin_invoices_ocr_preview(
    files: List[UploadFile] = File(...),
    user: dict = Depends(require_roles("admin_enered")),
):
    from services.pdf_invoice_reader import extract_invoice_data
    from datetime import datetime, timezone
    import uuid

    rucs_to_empresa = {}
    name_to_empresa = {}
    cfgs = await db.empresas_config.find({}, {"_id": 0}).to_list(500)
    for c in cfgs:
        if c.get("ruc"):
            rucs_to_empresa[str(c["ruc"]).strip().lstrip("0")] = c["empresa"]

    items = []
    for f in files:
        content = await f.read()
        uid = str(uuid.uuid4())
        pdf_filename = _safe_doc(f.filename) + f"_{uid[:8]}.pdf"
        storage.save_object(f"tmp_admin/{pdf_filename}", content, "application/pdf")
        
        try:
            ocr = await extract_invoice_data(content, f.content_type, f"ocr-admin-{uid[:8]}")
            ext = ocr.get("extracted", {})
            
            empresa = ""
            ruc_cliente = ext.get("ruc_cliente")
            if ruc_cliente:
                ruc_clean = ruc_cliente.strip().lstrip("0")
                if ruc_clean in rucs_to_empresa:
                    empresa = rucs_to_empresa[ruc_clean]

            if ocr.get("error"):
                raise Exception(ocr["error"])

            items.append({
                "id": uid,
                "factura_filename": f.filename,
                "pdf_key": f"tmp_admin/{pdf_filename}",
                "empresa": empresa,
                "n_doc": ext.get("numero_documento") or "",
                "f_emision": ext.get("fecha") or "",
                "f_vencimiento": ext.get("fecha_vencimiento") or "",
                "importe_total": ext.get("importe_total"),
                "placa": ext.get("placa") or "",
                "producto": ext.get("producto") or "",
                "galones": ext.get("galones") or 0.0,
                "precio_unitario": ext.get("precio_unitario") or 0.0,
            })
        except Exception as e:
            logger.error(f"Error OCR: {e}")
            items.append({
                "id": uid,
                "factura_filename": f.filename,
                "pdf_key": f"tmp_admin/{pdf_filename}",
                "error": str(e)
            })
    return {"items": items}

@api.post("/admin/invoices/confirm-ocr")
async def admin_invoices_confirm_ocr(
    payload: AdminConfirmPayload,
    user: dict = Depends(require_roles("admin_enered"))
):
    from datetime import date as _date, datetime, timezone
    today = _date.today()
    saved = 0

    for it in payload.items:
        empresa = it.override_empresa or it.empresa
        if not empresa:
            continue
        
        pdf_bytes = None
        for candidate_key in [it.pdf_key, f"tmp_admin/{it.pdf_key}" if it.pdf_key and not it.pdf_key.startswith("tmp_admin/") else None, it.factura_filename, f"tmp_admin/{it.factura_filename}" if it.factura_filename else None]:
            if candidate_key:
                try:
                    pdf_bytes = storage.get_object_bytes(candidate_key)
                    if pdf_bytes:
                        break
                except Exception:
                    pass
            
        final_filename = _safe_doc(it.n_doc or it.factura_filename) + ".pdf"
        final_key = _inv_key(empresa, final_filename)
        if pdf_bytes:
            storage.save_object(final_key, pdf_bytes, "application/pdf")
        
        estado = "pendiente"
        atraso_dias = 0
        f_venc = it.f_vencimiento or it.f_emision
        
        if payload.estado_override in ("pagada", "pendiente", "vencida"):
            estado = payload.estado_override
            if estado == "vencida" and f_venc:
                try:
                    fv = _date.fromisoformat(f_venc)
                    atraso_dias = max(0, (today - fv).days)
                except Exception:
                    pass
        else:
            if f_venc:
                try:
                    fv = _date.fromisoformat(f_venc)
                    if fv < today:
                        estado = "vencida"
                        atraso_dias = (today - fv).days
                except Exception:
                    pass

        doc = {
            "id": it.id,
            "empresa": empresa,
            "match_source": "ocr_admin",
            "n_doc": it.n_doc,
            "numero_documento": it.n_doc,
            "f_emision": it.f_emision,
            "f_vencimiento": it.f_vencimiento,
            "moneda": "PEN",
            "importe_total": it.importe_total or 0.0,
            "monto_total": it.importe_total or 0.0,
            "saldo": it.importe_total or 0.0 if estado != "pagada" else 0.0,
            "tipo_doc": "factura",
            "estado": estado,
            "atraso_dias": atraso_dias,
            "placa": it.placa,
            "producto": it.producto,
            "xml_filename": None,
            "pdf_filename": final_filename,
            "factura_filename": final_filename,
            "factura_storage_key": final_key,
            "pdf_key": final_key,
            "storage_key": final_key,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.empresas_invoices.insert_one(doc)
        await db.invoices.insert_one(doc)
        saved += 1
        
        # --- MIRROR TO SUBSIDIO DOSSIER ---
        sub_user = await db.users.find_one({
            "empresa": empresa,
            "$or": [
                {"role": "cliente_subsidio"},
                {"servicios.subsidio": True}
            ]
        })
        if sub_user:
            import uuid
            sub_id = str(uuid.uuid4())
            programa_calc, periodo_calc = _programa_y_periodo_por_fecha(it.f_emision)
            sub_doc = {
                "id": sub_id,
                "user_id": sub_user["id"],
                "empresa": empresa,
                "empresa_id": empresa,
                "calc_id": sub_user.get("calc_id"),
                "factura_filename": it.factura_filename,
                "factura_storage_key": final_key,
                "factura_content_type": "application/pdf",
                "factura_size": len(pdf_bytes),
                "raw_ocr_response": "",
                "ocr_ok": True,
                "ocr_error": None,
                "placa_match": True if it.placa else False,
                "status": "confirmed",
                "created_at": doc["created_at"],
                "confirmed_at": doc["created_at"],
                "fecha": it.f_emision,
                "hora": None,
                "estacion": "ENERED",
                "ciudad": None,
                "ruc_emisor": "20609304082",
                "placa": it.placa,
                "producto": it.producto,
                "galones": it.galones or 0.0,
                "precio_unitario": it.precio_unitario or 0.0,
                "importe_total": it.importe_total,
                "numero_documento": it.n_doc,
                "confianza": 1.0,
                "origin": "admin_ocr",
                # Según la fecha de emisión: DU 004 o el periodo del DU 007 que le toque.
                "programa": programa_calc,
                "periodo_du007": periodo_calc,
            }
            await db.consumos_subsidio.insert_one(sub_doc)
        
    return {"saved": saved}


@api.post("/admin/invoices/sync-to-subsidio")
async def sync_admin_invoices_to_subsidio(user: dict = Depends(require_roles("admin_enered"))):
    """Backfills/syncs all existing admin invoices from empresas_invoices into db.consumos_subsidio for eligible clients."""
    all_admin_invs = await db.empresas_invoices.find({}, {"_id": 0}).to_list(2000)
    synced = 0
    import uuid
    for inv in all_admin_invs:
        empresa = inv.get("empresa")
        n_doc = inv.get("n_doc")
        if not empresa or not n_doc:
            continue
        
        sub_user = await db.users.find_one({
            "empresa": empresa,
            "$or": [
                {"role": "cliente_subsidio"},
                {"servicios.subsidio": True}
            ]
        })
        if not sub_user:
            continue

        existing = await db.consumos_subsidio.find_one({"empresa": empresa, "numero_documento": n_doc})
        if not existing:
            sub_id = str(uuid.uuid4())
            programa_calc, periodo_calc = _programa_y_periodo_por_fecha(inv.get("f_emision"))
            sub_doc = {
                "id": sub_id,
                "user_id": sub_user["id"],
                "empresa": empresa,
                "empresa_id": empresa,
                "calc_id": sub_user.get("calc_id"),
                "factura_filename": inv.get("pdf_filename") or f"{n_doc}.pdf",
                "factura_storage_key": _inv_key(empresa, inv.get("pdf_filename") or f"{n_doc}.pdf"),
                "factura_content_type": "application/pdf",
                "factura_size": 0,
                "raw_ocr_response": "",
                "ocr_ok": True,
                "ocr_error": None,
                "placa_match": True if inv.get("placa") else False,
                "status": "confirmed",
                "created_at": inv.get("created_at") or datetime.now(timezone.utc).isoformat(),
                "confirmed_at": inv.get("created_at") or datetime.now(timezone.utc).isoformat(),
                "fecha": inv.get("f_emision"),
                "hora": None,
                "estacion": "ENERED",
                "ciudad": None,
                "ruc_emisor": "20609304082",
                "placa": inv.get("placa"),
                "producto": inv.get("producto"),
                "galones": inv.get("galones") or 0.0,
                "precio_unitario": inv.get("precio_unitario") or 0.0,
                "importe_total": inv.get("importe_total") or 0.0,
                "numero_documento": n_doc,
                "confianza": 1.0,
                "origin": "admin_ocr",
                "programa": programa_calc,
                "periodo_du007": periodo_calc,
            }
            await db.consumos_subsidio.insert_one(sub_doc)
            synced += 1
            
    return {"synced": synced, "total_admin_invoices": len(all_admin_invs)}


@api.post("/admin/invoices/fix-programa")
async def admin_invoices_fix_programa(empresa: Optional[str] = None, incluir_sin_origen: bool = True,
                                       user: dict = Depends(require_roles("admin_enered"))):
    """Recalcula `programa`/`periodo_du007` según la fecha de emisión para facturas que
    quedaron sin ese campo (por eso caían siempre en el balde de DU 004, invisibles para
    DU 007, sin importar su fecha real): las del panel Admin (origin=admin_ocr) y —la
    causa real más común— registros viejos de consumos_subsidio a los que el campo
    `programa` directamente nunca se les puso (ni "du004" ni "du007").
    Nunca toca un doc que YA tiene programa correcto para su fecha."""
    q = {"$or": [{"origin": "admin_ocr"}]}
    if incluir_sin_origen:
        q["$or"].append({"programa": {"$exists": False}})
    if empresa:
        q = {"$and": [q, {"empresa": empresa}]}
    docs = await db.consumos_subsidio.find(q, {"_id": 0, "id": 1, "fecha": 1, "programa": 1, "empresa": 1, "numero_documento": 1}).to_list(5000)
    corregidas = []
    for d in docs:
        programa_calc, periodo_calc = _programa_y_periodo_por_fecha(d.get("fecha"))
        if d.get("programa") == programa_calc:
            continue  # ya está correcto, no la toca
        await db.consumos_subsidio.update_one({"id": d["id"]}, {"$set": {"programa": programa_calc, "periodo_du007": periodo_calc}})
        corregidas.append({"id": d["id"], "empresa": d.get("empresa"), "numero_documento": d.get("numero_documento"),
                            "fecha": d.get("fecha"), "programa_anterior": d.get("programa"), "programa_nuevo": programa_calc})
    return {"revisadas": len(docs), "corregidas": len(corregidas), "detalle": corregidas}


def _safe_doc(name: str) -> str:
    base = name.rsplit(".", 1)[0].strip()
    return "".join(c for c in base if c.isalnum() or c in ("-", "_"))


@api.post("/admin/invoices/upload-bulk")
async def admin_invoices_upload_bulk(
    files: List[UploadFile] = File(...),
    empresa_override: Optional[str] = Form(None),
    estado_override: Optional[str] = Form(None),
    user: dict = Depends(require_roles("admin_enered")),
):
    """Bulk upload pairs of PDF + XML files (or .zip from Odoo containing both).
    Files are matched by basename. Each XML is parsed (SUNAT UBL 2.1) to
    extract invoice metadata. Empresa is matched by RUC against empresas_config.
    If empresa_override is provided, all uploaded invoices are assigned to that
    empresa. If estado_override is one of (pagada/pendiente/vencida), it is
    used as the manual status; otherwise estado is auto-calculated by due date.
    """
    import io, zipfile

    # Separar XMLs (procesar primero) y PDFs (matching posterior)
    xmls: List[tuple] = []   # (filename_base, content, original_name)
    pdfs: dict = {}          # base_normalized -> (content, original_name)

    def _consume(filename: str, content: bytes):
        ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
        base = _safe_doc(filename)
        # Skip CDR (constancia de recepción SUNAT)
        if filename.upper().startswith("CDR-") or filename.upper().startswith("R-"):
            return
        if ext == "xml":
            xmls.append((base, content, filename))
        elif ext == "pdf":
            pdfs[base.upper()] = (content, filename)

    for f in files:
        ext = (f.filename.rsplit(".", 1)[-1] if "." in f.filename else "").lower()
        content = await f.read()
        if ext == "zip":
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    for zi in zf.infolist():
                        if zi.is_dir():
                            continue
                        inner_name = os.path.basename(zi.filename)
                        if not inner_name:
                            continue
                        _consume(inner_name, zf.read(zi))
            except Exception as e:
                logger.warning(f"ZIP inválido {f.filename}: {e}")
        else:
            _consume(f.filename, content)

    saved: List[dict] = []
    skipped: List[dict] = []

    # Build matching maps from empresas_config
    rucs_to_empresa: dict = {}
    name_to_empresa: dict = {}

    def _clean_name(n: str) -> str:
        """Lowercase, strip punctuation and corporate suffixes for fuzzy match."""
        if not n: return ""
        s = str(n).upper()
        s = "".join(c for c in s if c.isalnum() or c == " ")
        for suf in [" SAC", " S A C", " EIRL", " E I R L", " SA", " S A", " SRL", " S R L"]:
            if s.endswith(suf):
                s = s[: -len(suf)]
        return " ".join(s.split())

    cfgs = await db.empresas_config.find({}, {"_id": 0}).to_list(500)
    for c in cfgs:
        if c.get("ruc"):
            ruc_clean = str(c["ruc"]).strip().lstrip("0")
            rucs_to_empresa[ruc_clean] = c["empresa"]
        if c.get("empresa"):
            name_to_empresa[_clean_name(c["empresa"])] = c["empresa"]

    def _find_pdf_for(base: str, n_doc: str):
        """Try multiple strategies to match a PDF for the given XML."""
        # 1) Exact basename
        if base.upper() in pdfs:
            return pdfs[base.upper()]
        # 2) PDF whose normalized base contains n_doc (or vice versa)
        if n_doc:
            n = _safe_doc(n_doc).upper()
            for k, v in pdfs.items():
                if n and (n in k or k in n):
                    return v
        # 3) If only one XML and one PDF in this batch, pair them
        if len(xmls) == 1 and len(pdfs) == 1:
            return list(pdfs.values())[0]
        return None

    for base, xml_bytes, xml_orig in xmls:
        try:
            meta = _parse_sunat_xml(xml_bytes)
        except Exception as e:
            skipped.append({"base": base, "reason": f"XML no parseable: {e}"})
            continue

        # Resolve empresa: override > RUC match > razón social fuzzy match
        empresa = None
        match_source = "none"
        if empresa_override:
            empresa = empresa_override
            match_source = "override"
        else:
            ruc = (meta.get("ruc_cliente") or "").strip().lstrip("0")
            if ruc and ruc in rucs_to_empresa:
                empresa = rucs_to_empresa[ruc]
                match_source = "ruc"
            else:
                rs_clean = _clean_name(meta.get("razon_social_cliente") or "")
                if rs_clean and rs_clean in name_to_empresa:
                    empresa = name_to_empresa[rs_clean]
                    match_source = "razon_social"
        if not empresa:
            skipped.append({
                "base": base,
                "reason": f"No se encontró empresa para RUC={meta.get('ruc_cliente')!r} / Razón={meta.get('razon_social_cliente')!r}. Configura el RUC en 'Configuración por empresa' o usa el dropdown 'Asignar a empresa'.",
            })
            continue

        # Save files via storage abstraction
        n_doc = meta.get("n_doc") or base
        xml_filename = f"{_safe_doc(n_doc)}.xml"
        xml_key = _inv_key(empresa, xml_filename)
        storage.save_object(xml_key, xml_bytes, "application/xml")

        pdf_filename = None
        pdf_match = _find_pdf_for(base, n_doc)
        if pdf_match:
            pdf_bytes, pdf_orig = pdf_match
            pdf_filename = f"{_safe_doc(n_doc)}.pdf"
            pdf_key = _inv_key(empresa, pdf_filename)
            storage.save_object(pdf_key, pdf_bytes, "application/pdf")

        # Determine status & atraso
        from datetime import date as _date
        today = _date.today()
        f_venc = meta.get("f_vencimiento") or meta.get("f_emision")
        atraso_dias = 0
        # Manual override: pagada / pendiente / vencida
        if estado_override in ("pagada", "pendiente", "vencida"):
            estado = estado_override
            if estado == "vencida" and f_venc:
                try:
                    fv = _date.fromisoformat(f_venc)
                    atraso_dias = max(0, (today - fv).days)
                except Exception:
                    pass
        else:
            # Auto: por fecha de vencimiento
            estado = "pendiente"
            if f_venc:
                try:
                    fv = _date.fromisoformat(f_venc)
                    if fv < today:
                        estado = "vencida"
                        atraso_dias = (today - fv).days
                except Exception:
                    pass

        record = {
            "id": str(uuid.uuid4()),
            "empresa": empresa,
            "ruc_cliente": ruc,
            "razon_social_cliente": meta.get("razon_social_cliente"),
            "n_doc": n_doc,
            "tipo_doc": meta.get("tipo_doc"),
            "producto": meta.get("producto"),
            "f_emision": meta.get("f_emision"),
            "f_vencimiento": f_venc,
            "moneda": meta.get("moneda", "PEN"),
            "monto_total": meta.get("monto_total", 0.0),
            "saldo": meta.get("monto_total", 0.0),
            "estado": estado,  # vencido | por_vencer | pagado
            "atraso_dias": atraso_dias,
            "pdf_filename": pdf_filename,
            "xml_filename": xml_filename,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "uploaded_by": user["email"],
        }
        # Upsert by (empresa, n_doc)
        existing = await db.invoices.find_one({"empresa": empresa, "n_doc": n_doc}, {"_id": 0})
        if existing:
            record["id"] = existing.get("id", record["id"])
            await db.invoices.update_one({"empresa": empresa, "n_doc": n_doc}, {"$set": record})
        else:
            await db.invoices.insert_one(record)

        saved.append({"n_doc": n_doc, "empresa": empresa, "estado": estado, "match": match_source})

    return {"uploaded": len(saved), "saved": saved, "skipped": skipped}





@api.get("/account-state")
async def account_state(user: dict = Depends(get_current_user), empresa: Optional[str] = None):
    """Estado de Cuenta agregado por empresa.

    - linea_credito_total: de empresas_config
    - total_facturado: SUM monto_total de todas las invoices
    - facturas_pendientes: SUM saldo donde estado != pagado
    - notas_despacho: SUM IMPORTE_TOTAL de consumptions con facturado != true
    - linea_credito_utilizada: facturas_pendientes + notas_despacho
    - disponible: linea_credito_total - linea_credito_utilizada
    - pct_utilizada: %
    - total_vencido: SUM saldo donde estado == vencido
    """
    if user["role"] == "admin_enered":
        target = empresa
    else:
        target = user.get("empresa")

    cfg = None
    if target:
        cfg = await db.empresas_config.find_one({"empresa": target}, {"_id": 0})
    if not cfg:
        cfg = {"empresa": target or "", "linea_credito": 0.0, "dias_credito": 0, "ruc": ""}

    import re
    inv_q = {}
    if target:
        esc_t = re.escape(target).replace("\\ ", ".*").replace("\\.", ".*")
        inv_q["empresa"] = {"$regex": f"^{esc_t}$", "$options": "i"}

    invs = await db.invoices.find(inv_q, {"_id": 0}).to_list(5000)

    # Dynamically pull and merge confirmed subsidio invoices for the account state calculations
    sub_q = {"status": "confirmed"}
    if target:
        esc_t = re.escape(target).replace("\\ ", ".*").replace("\\.", ".*")
        sub_q["empresa"] = {"$regex": f"^{esc_t}$", "$options": "i"}
    elif user["role"] != "admin_enered" and user.get("empresa"):
        esc_u = re.escape(user['empresa']).replace("\\ ", ".*").replace("\\.", ".*")
        sub_q["empresa"] = {"$regex": f"^{esc_u}$", "$options": "i"}

    sub_raw = await db.consumos_subsidio.find(sub_q, {"_id": 0}).to_list(5000)
    
    # Group subsidio invoices by numero_documento to avoid duplicate invoices in statement
    grouped_sub = {}
    for d in sub_raw:
        n_doc = (d.get("numero_documento") or "").upper().strip()
        if not n_doc:
            continue
        if n_doc not in grouped_sub:
            fecha_str = d.get("fecha") or datetime.now(timezone.utc).date().isoformat()
            if len(fecha_str) > 10:
                fecha_str = fecha_str[:10]
            f_venc = fecha_str
            try:
                from datetime import datetime as _dt, timedelta as _td
                f_dt = _dt.strptime(fecha_str, "%Y-%m-%d")
                f_venc = (f_dt + _td(days=30)).date().isoformat()
            except Exception:
                try:
                    f_dt = _dt.strptime(fecha_str, "%d/%m/%Y")
                    fecha_str = f_dt.date().isoformat()
                    f_venc = (f_dt + _td(days=30)).date().isoformat()
                except Exception:
                    pass
            grouped_sub[n_doc] = {
                "id": d.get("id") or str(d.get("_id")) or "",
                "empresa": d.get("empresa") or "",
                "n_doc": n_doc,
                "tipo_doc": "factura",
                "producto": normalizar_producto(d.get("producto")) or "DIESEL B5",
                "f_emision": fecha_str,
                "f_vencimiento": f_venc,
                "moneda": "PEN",
                "monto_total": 0.0,
                "saldo": 0.0,
                "estado": "TERCERO" if d.get("origin") != "admin_ocr" else "pendiente",
                "origin": d.get("origin") or "subsidio",
                "atraso_dias": 0,
            }
        grouped_sub[n_doc]["monto_total"] += float(d.get("importe_total") or 0.0)

    existing_ndocs = {r.get("n_doc") for r in invs if r.get("n_doc")}
    for n_doc, sub_inv in grouped_sub.items():
        if n_doc not in existing_ndocs:
            if sub_inv.get("origin") == "admin_ocr":
                sub_inv["saldo"] = sub_inv["monto_total"]
                try:
                    from datetime import datetime as _dt
                    today = _dt.now(timezone.utc).date()
                    venc_dt = _dt.strptime(sub_inv["f_vencimiento"], "%Y-%m-%d").date()
                    if today > venc_dt:
                        sub_inv["atraso_dias"] = (today - venc_dt).days
                        sub_inv["estado"] = "vencida"
                except Exception:
                    pass
            else:
                sub_inv["estado"] = "TERCERO"
                sub_inv["saldo"] = 0.0
            invs.append(sub_inv)

    # Notas de despacho = consumos NO facturados (ESTADO != "FACTURADO" en el sheet)
    cons_q = {"ESTADO": {"$ne": "FACTURADO"}}
    if target:
        esc_t = re.escape(target).replace("\\ ", ".*").replace("\\.", ".*")
        cons_q["EMPRESA"] = {"$regex": f"^{esc_t}$", "$options": "i"}
    elif user["role"] != "admin_enered" and user.get("empresa"):
        esc_u = re.escape(user['empresa']).replace("\\ ", ".*").replace("\\.", ".*")
        cons_q["EMPRESA"] = {"$regex": f"^{esc_u}$", "$options": "i"}
    cons = await db.consumptions.find(cons_q, {"_id": 0, "IMPORTE_TOTAL": 1}).to_list(100000)

    def _f(x, d=0.0):
        try: return float(x) if x not in (None, "") else d
        except Exception: return d

    # Facturas de TERCERO (las que cargó el cliente, no emitidas por ENERED) NO son deuda
    # con ENERED → se excluyen de todos los cálculos del estado de cuenta.
    _es_tercero = _es_factura_tercero
    invs_reales = [i for i in invs if not _es_tercero(i)]

    total_facturado = sum(_f(i.get("monto_total")) for i in invs_reales)
    # Estados nuevos: pagada/pendiente/vencida. Compat con legacy: pagado/por_vencer/vencido.
    PAID = {"pagada", "pagado"}
    OVERDUE = {"vencida", "vencido"}
    facturas_pendientes = sum(_f(i.get("saldo")) for i in invs_reales if (i.get("estado") or "").lower() not in PAID)
    notas_despacho = sum(_f(c.get("IMPORTE_TOTAL")) for c in cons)
    notas_despacho_cnt = len(cons)
    total_vencido = sum(_f(i.get("saldo")) for i in invs_reales if (i.get("estado") or "").lower() in OVERDUE)
    total_pagado = sum(_f(i.get("monto_total")) for i in invs_reales if (i.get("estado") or "").lower() in PAID)

    linea_total = float(cfg.get("linea_credito") or 0)
    saldo_a_favor = float(cfg.get("saldo_a_favor") or 0.0)
    linea_utilizada = facturas_pendientes + notas_despacho
    disponible = max(0.0, linea_total + saldo_a_favor - linea_utilizada)
    pct = round((linea_utilizada / (linea_total + saldo_a_favor) * 100), 2) if (linea_total + saldo_a_favor) > 0 else 0.0

    return {
        "empresa": cfg.get("empresa") or target or "",
        "ruc": cfg.get("ruc") or "",
        "linea_credito_total": round(linea_total, 2),
        "saldo_a_favor": round(saldo_a_favor, 2),
        "disponible": round(disponible, 2),
        "linea_credito_utilizada": round(linea_utilizada, 2),
        "facturas_pendientes": round(facturas_pendientes, 2),
        "notas_despacho": round(notas_despacho, 2),
        "notas_despacho_cnt": notas_despacho_cnt,
        "total_facturado": round(total_facturado, 2),
        "total_pagado": round(total_pagado, 2),
        "total_vencido": round(total_vencido, 2),
        "pct_utilizada": pct,
        "dias_credito": int(cfg.get("dias_credito") or 0),
        "n_facturas": len(invs_reales),
    }


# ---------- Security / Training Documents ----------
SEC_PREFIX = "security"


def _sec_key(filename: str) -> str:
    return f"{SEC_PREFIX}/{filename}"


@api.get("/security-docs")
async def list_security_docs(
    q: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    """List all security/training documents. Available to all authenticated users."""
    query = {}
    if q:
        query["$or"] = [
            {"codigo": {"$regex": q, "$options": "i"}},
            {"nombre": {"$regex": q, "$options": "i"}},
            {"descripcion": {"$regex": q, "$options": "i"}},
        ]
    docs = await db.security_docs.find(query, {"_id": 0}).sort("created_at", -1).to_list(500)
    return docs


@api.post("/admin/security-docs")
async def upload_security_doc(
    nombre: str = Form(...),
    descripcion: str = Form(""),
    file: UploadFile = File(...),
    user: dict = Depends(require_roles("admin_enered")),
):
    """Upload a PDF training document (admin only)."""
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(400, "Solo se permiten archivos PDF")

    # Auto-generate código M00001, M00002...
    last = await db.security_docs.find_one({}, sort=[("counter", -1)])
    next_n = (last.get("counter", 0) + 1) if last else 1
    codigo = f"M{next_n:05d}"

    doc_id = str(uuid.uuid4())
    safe_name = "".join(c for c in file.filename if c.isalnum() or c in ("-", "_", "."))
    stored_filename = f"{doc_id}_{safe_name}"
    content = await file.read()
    storage.save_object(_sec_key(stored_filename), content, "application/pdf")

    record = {
        "id": doc_id,
        "counter": next_n,
        "codigo": codigo,
        "nombre": nombre.strip(),
        "descripcion": descripcion.strip(),
        "filename_original": file.filename,
        "filename_stored": stored_filename,
        "size_bytes": len(content),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": user.get("email"),
    }
    await db.security_docs.insert_one(record)
    return {k: v for k, v in record.items() if k not in ("filename_stored", "counter", "_id")}


@api.get("/security-docs/{doc_id}/download")
async def download_security_doc(
    doc_id: str,
    user: dict = Depends(get_current_user),
):
    record = await db.security_docs.find_one({"id": doc_id})
    if not record:
        raise HTTPException(404, "Documento no encontrado")
    return storage.download_response(
        _sec_key(record["filename_stored"]),
        record["filename_original"],
        "application/pdf",
    )


@api.delete("/admin/security-docs/{doc_id}")
async def delete_security_doc(
    doc_id: str,
    user: dict = Depends(require_roles("admin_enered")),
):
    record = await db.security_docs.find_one({"id": doc_id})
    if not record:
        raise HTTPException(404, "Documento no encontrado")
    storage.delete_object(_sec_key(record["filename_stored"]))
    await db.security_docs.delete_one({"id": doc_id})
    return {"ok": True}


# ---------- QR Code Bulk Upload / Download ----------
QR_PREFIX = "qr"


def _qr_key(empresa: str, filename: str) -> str:
    return f"{QR_PREFIX}/{_safe_placa(empresa)}/{filename}"


def _safe_placa(name: str) -> str:
    """Sanitize placa filename: alphanumeric, dash, underscore only."""
    base = name.rsplit(".", 1)[0].strip().upper()
    return "".join(c for c in base if c.isalnum() or c in ("-", "_"))


@api.post("/admin/qr/upload-bulk")
async def admin_qr_upload_bulk(
    empresa: str = Form(...),
    files: List[UploadFile] = File(...),
    user: dict = Depends(require_roles("admin_enered")),
):
    """Bulk upload QR images. Filename format: [PLACA].png/jpg/etc.
    Each file is associated with the placa (filename without extension)."""
    if not empresa:
        raise HTTPException(status_code=400, detail="empresa es requerida")

    saved: List[dict] = []
    skipped: List[dict] = []

    for f in files:
        try:
            placa = _safe_placa(f.filename)
            if not placa:
                skipped.append({"file": f.filename, "reason": "nombre inválido"})
                continue
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else "png"
            if ext not in ("png", "jpg", "jpeg", "webp", "svg"):
                skipped.append({"file": f.filename, "reason": "extensión no soportada"})
                continue
            content = await f.read()
            if len(content) > 5 * 1024 * 1024:
                skipped.append({"file": f.filename, "reason": "supera 5MB"})
                continue
            target_filename = f"{placa}.{ext}"
            content_type = {
                "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "webp": "image/webp", "svg": "image/svg+xml",
            }.get(ext, "application/octet-stream")
            storage.save_object(_qr_key(empresa, target_filename), content, content_type)
            # Upsert in mongo
            await db.qr_codes.update_one(
                {"empresa": empresa, "placa": placa},
                {"$set": {
                    "empresa": empresa,
                    "placa": placa,
                    "filename": target_filename,
                    "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    "uploaded_by": user["email"],
                }},
                upsert=True,
            )
            saved.append({"placa": placa, "file": target_filename})
        except Exception as e:
            skipped.append({"file": f.filename, "reason": str(e)})

    return {"uploaded": len(saved), "saved": saved, "skipped": skipped}


@api.get("/qr/list")
async def qr_list(user: dict = Depends(get_current_user), empresa: Optional[str] = None):
    """List QR codes available to current user (filtered by empresa for non-admin)."""
    q: dict = {}
    if user["role"] != "admin_enered":
        q["empresa"] = user.get("empresa")
    elif empresa:
        q["empresa"] = empresa
    rows = await db.qr_codes.find(q, {"_id": 0}).sort("placa", 1).to_list(2000)
    return rows


@api.get("/qr/download/{placa}")
async def qr_download(placa: str, user: dict = Depends(get_current_user), empresa: Optional[str] = None):
    """Download QR for a specific placa. Validates empresa for non-admin users."""
    placa = _safe_placa(placa)
    target_empresa = empresa if user["role"] == "admin_enered" else user.get("empresa")
    if not target_empresa:
        raise HTTPException(status_code=400, detail="empresa requerida")
    record = await db.qr_codes.find_one({"empresa": target_empresa, "placa": placa}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="QR no encontrado")
    fname = record["filename"]
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else "png"
    media = {
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
        "webp": "image/webp", "svg": "image/svg+xml",
    }.get(ext, "application/octet-stream")
    return storage.download_response(
        _qr_key(target_empresa, fname),
        f"QR_{placa}.{ext}",
        media,
    )


@api.delete("/admin/qr/{placa}")
async def admin_qr_delete(placa: str, empresa: str, user: dict = Depends(require_roles("admin_enered"))):
    placa = _safe_placa(placa)
    record = await db.qr_codes.find_one({"empresa": empresa, "placa": placa}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="QR no encontrado")
    storage.delete_object(_qr_key(empresa, record["filename"]))
    await db.qr_codes.delete_one({"empresa": empresa, "placa": placa})
    return {"ok": True}


# ---------- Root ----------
@api.get("/")
async def root():
    return {"service": "ENERED API", "status": "ok"}


@api.get("/health")
async def health():
    """Diagnostic endpoint for production monitoring."""
    try:
        await db.command("ping")
        mongo_ok = True
    except Exception as e:
        mongo_ok = False
    return {
        "status": "ok" if mongo_ok else "degraded",
        "mongo": "ok" if mongo_ok else "fail",
        "storage_backend": storage.current_backend(),
        # Subir en cada cambio relevante: permite confirmar qué versión corre en producción.
        "version": "1.9.46-ocr-cuota",
    }

# ============================================================
# INFRACCIONES - Vehículos, Conductores y Infracciones
# ============================================================

# --- MODELS ---
class VehiculoCreate(BaseModel):
    placa: str = Field(min_length=6, max_length=8)
    marca: Optional[str] = None
    modelo: Optional[str] = None
    año: Optional[int] = None
    chasis: Optional[str] = None
    estado: Optional[str] = "OPERATIVO"
    unidad: Optional[str] = None
    tipo: Optional[str] = None
    base: Optional[str] = None
    titular: Optional[str] = None
    cc: Optional[str] = None
    conductor_principal_id: Optional[str] = None
    empresa: Optional[str] = None
    kilometraje: Optional[int] = None
    proximo_mtto_fecha: Optional[str] = None
    proximo_mtto_km: Optional[int] = None
    categoria: Optional[str] = None
    constancia_mtc: Optional[str] = None
    ejes: Optional[str] = None
    carga_util: Optional[str] = None
    peso_seco: Optional[str] = None

class VehiculoUpdate(BaseModel):
    placa: Optional[str] = None
    marca: Optional[str] = None
    modelo: Optional[str] = None
    año: Optional[int] = None
    chasis: Optional[str] = None
    estado: Optional[str] = None
    unidad: Optional[str] = None
    tipo: Optional[str] = None
    base: Optional[str] = None
    titular: Optional[str] = None
    cc: Optional[str] = None
    conductor_principal_id: Optional[str] = None
    kilometraje: Optional[int] = None
    proximo_mtto_fecha: Optional[str] = None
    proximo_mtto_km: Optional[int] = None
    categoria: Optional[str] = None
    constancia_mtc: Optional[str] = None
    ejes: Optional[str] = None
    carga_util: Optional[str] = None
    peso_seco: Optional[str] = None

class ConductorCreate(BaseModel):
    dni: str = Field(min_length=8, max_length=8)
    nombre: str
    apellidos: str
    licencia: Optional[str] = None
    vencimiento_licencia: Optional[str] = None
    telefono: Optional[str] = None
    email: Optional[EmailStr] = None
    empresa: Optional[str] = None

class ConductorUpdate(BaseModel):
    nombre: Optional[str] = None
    apellidos: Optional[str] = None
    licencia: Optional[str] = None
    vencimiento_licencia: Optional[str] = None
    telefono: Optional[str] = None
    email: Optional[EmailStr] = None

class InfraccionCreate(BaseModel):
    vehiculo_id: str
    conductor_id: Optional[str] = None
    fecha: str
    codigo: str
    descripcion: str
    monto: float
    estado: Literal["pendiente", "pagada", "impugnada", "anulada"] = "pendiente"
    lugar: Optional[str] = None
    papeleta: Optional[str] = None
    observaciones: Optional[str] = None
    empresa: Optional[str] = None

class InfraccionUpdate(BaseModel):
    estado: Optional[Literal["pendiente", "pagada", "impugnada", "anulada"]] = None
    monto: Optional[float] = None
    observaciones: Optional[str] = None

# --- VEHICULOS ENDPOINTS ---
@api.get("/vehiculos/consulta-sunarp/{placa}")
async def consulta_sunarp_placa(req: Request, placa: str):
    await require_auth(req)
    placa_clean = placa.replace("-", "").upper()
    if not placa_clean:
        raise HTTPException(400, "Placa no válida")
        
    token = os.getenv("CONSULTADATOS_TOKEN", "").strip()
    if not token:
        raise HTTPException(status_code=503, detail="Servicio de placas no configurado (CONSULTADATOS_TOKEN)")
    url = f"https://api2.consultadatos.com/api/placa/leyenda/{placa_clean}"
    
    import urllib.request
    import json
    import ssl
    import asyncio
    
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json"
        }
        req_api = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        def fetch_api():
            with urllib.request.urlopen(req_api, context=ctx, timeout=5) as response:
                return response.read().decode('utf-8')
                
        raw_res = await asyncio.to_thread(fetch_api)
        res_data = json.loads(raw_res)
        
        if res_data.get("success") and "data" in res_data:
            v = res_data["data"].get("vehiculo", {})
            props = res_data["data"].get("propietarios", [])
            
            titular = ""
            if props:
                titular = props[0].get("propietario", "")
            
            año = None
            try:
                año_str = v.get("ano_fab") or v.get("an_mode")
                if año_str:
                    año = int(año_str)
            except:
                pass
                
            return {
                "placa": v.get("num_placa", placa_clean),
                "marca": v.get("marca", ""),
                "modelo": v.get("modelo", ""),
                "chasis": v.get("no_vin") or v.get("num_serie", ""),
                "año": año,
                "titular": titular,
                "tipo": v.get("desc_tipo_carr", "")
            }
        else:
            msg = res_data.get("message", "No se encontró información para esta placa")
            raise HTTPException(404, msg)
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode('utf-8')
            err_json = json.loads(err_body)
            err_msg = err_json.get("message", "Error consultando SUNARP")
        except:
            err_msg = "Error consultando SUNARP"
        raise HTTPException(e.code, f"{err_msg} (HTTP {e.code})")
    except Exception as e:
        raise HTTPException(500, f"Error de servidor: {str(e)}")


# WMI (3 primeras letras del VIN) → fabricante. Cubre las marcas comunes de las
# flotas peruanas; si el código no está, la marca queda para consultadatos/manual.
_WMI_MARCAS = {
    "9BS": "SCANIA", "YS2": "SCANIA",
    "93K": "VOLVO", "YV2": "VOLVO", "YB3": "VOLVO",
    "9BM": "MERCEDES-BENZ", "W1T": "MERCEDES-BENZ", "WDB": "MERCEDES-BENZ", "8AC": "MERCEDES-BENZ",
    "8AJ": "TOYOTA", "MR0": "TOYOTA", "JTF": "TOYOTA", "JTE": "TOYOTA",
    "MMB": "MITSUBISHI", "JMB": "MITSUBISHI", "JA4": "MITSUBISHI",
    "JHH": "HINO", "JHD": "HINO", "JHF": "HINO", "5PV": "HINO",
    "9BW": "VOLKSWAGEN",
    "3HA": "INTERNATIONAL", "1HT": "INTERNATIONAL", "3HS": "INTERNATIONAL",
    "JAL": "ISUZU", "JAA": "ISUZU",
    "KMH": "HYUNDAI", "KMF": "HYUNDAI",
    "LZZ": "SINOTRUK", "LGA": "DONGFENG", "LGB": "DONGFENG",
    "LVB": "FOTON", "LFN": "FAW", "LBZ": "JAC",
    "MHF": "TOYOTA", "8AD": "PEUGEOT", "3N6": "NISSAN", "JN1": "NISSAN",
    "KL5": "CHEVROLET", "9GA": "CHEVROLET",
}


def _marca_por_vin(vin: str) -> str:
    """Deduce la marca del vehículo por el WMI del VIN/chasis."""
    wmi = (vin or "").strip().upper()[:3]
    return _WMI_MARCAS.get(wmi, "")


_JSONPE_ULTIMO_ERROR: dict = {}


async def _jsonpe(recurso: str, body: dict) -> dict:
    """POST a api.json.pe (placa, soat, revision-tecnica, licencia). Devuelve el
    dict `data` o {} si no hay token, falla la red o el proveedor no tiene datos."""
    token = os.getenv("JSONPE_TOKEN", "").strip()
    if not token:
        return {}
    import json
    import urllib.request as _ur

    req = _ur.Request(f"https://api.json.pe/api/{recurso}",
                      data=json.dumps(body).encode(), method="POST",
                      headers={"Authorization": f"Bearer {token}",
                               "Content-Type": "application/json"})
    def _fetch():
        with _ur.urlopen(req, timeout=25) as r:
            return json.loads(r.read())

    def _fetch_por_ip(ip: str):
        """Respaldo cuando el DNS de api.json.pe no resuelve (07/09/2026: el dominio json.pe
        quedó 'inactive' en NIC.PE y Render no lo resolvía). Conecta a la IP conocida del
        proveedor manteniendo SNI y Host = api.json.pe, así el certificado sigue validándose."""
        import http.client, ssl, socket, io as _io
        ctx = ssl.create_default_context()

        class _Conn(http.client.HTTPSConnection):
            def connect(self):
                sock = socket.create_connection((ip, 443), timeout=25)
                self.sock = ctx.wrap_socket(sock, server_hostname="api.json.pe")

        conn = _Conn("api.json.pe", 443, timeout=25)
        cuerpo = json.dumps(body).encode()
        conn.request("POST", f"/api/{recurso}", body=cuerpo,
                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                              "Host": "api.json.pe", "Content-Length": str(len(cuerpo))})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        if resp.status >= 400:
            raise _ue.HTTPError(f"https://api.json.pe/api/{recurso}", resp.status, resp.reason, resp.headers, _io.BytesIO(data))
        return json.loads(data)

    import urllib.error as _ue
    global _JSONPE_ULTIMO_ERROR
    ip_respaldo = os.getenv("JSONPE_FALLBACK_IP", "178.156.192.142").strip()
    try:
        # Si el DNS falla ("Name or service not known"), se va directo por IP; si es otra
        # falla de red, se reintenta hasta 3 veces con espera corta.
        res = None
        for _intento in range(3):
            try:
                res = await asyncio.to_thread(_fetch)
                break
            except _ue.HTTPError:
                raise
            except (_ue.URLError, TimeoutError, OSError) as _e_red:
                es_dns = "not known" in str(_e_red).lower() or "nodename" in str(_e_red).lower() or "name resolution" in str(_e_red).lower()
                if es_dns and ip_respaldo:
                    _JSONPE_ULTIMO_ERROR = {"recurso": recurso, "via": f"ip {ip_respaldo}", "dns_error": str(_e_red)[:120],
                                            "en": datetime.now(timezone.utc).isoformat()}
                    res = await asyncio.to_thread(_fetch_por_ip, ip_respaldo)
                    break
                if _intento == 2:
                    raise
                _JSONPE_ULTIMO_ERROR = {"recurso": recurso, "reintento": _intento + 1, "error": str(_e_red)[:200],
                                        "en": datetime.now(timezone.utc).isoformat()}
                await asyncio.sleep(1.5 * (_intento + 1))
    except _ue.HTTPError as e:
        try:
            _JSONPE_ULTIMO_ERROR = {"recurso": recurso, "http": e.code, "msg": str(e.read()[:300], "utf-8", "ignore"),
                                    "en": datetime.now(timezone.utc).isoformat()}
        except Exception:
            _JSONPE_ULTIMO_ERROR = {"recurso": recurso, "http": e.code, "en": datetime.now(timezone.utc).isoformat()}
        # json.pe responde 404 tanto para "no hay registro" (unidad nueva sin CITV) como
        # para fallas del MTC ("Error de red MTC: 429"). Solo el primero se marca como
        # SIN REGISTRO; la falla es transitoria y se reintenta en la siguiente pasada.
        if e.code == 404:
            try:
                msg = str(json.loads(e.read()).get("message", ""))
            except Exception:
                msg = ""
            if re.search(r"no se encontr|no cuenta con", msg, re.I) and not re.search(r"error de red|429|timeout", msg, re.I):
                return {"_sin_registro": True}
        return {}
    except Exception as e:
        _JSONPE_ULTIMO_ERROR = {"recurso": recurso, "error": f"{type(e).__name__}: {str(e)[:200]}",
                                "en": datetime.now(timezone.utc).isoformat()}
        return {}
    if not res.get("success"):
        _JSONPE_ULTIMO_ERROR = {"recurso": recurso, "success": False, "msg": str(res.get("message", ""))[:300],
                                "en": datetime.now(timezone.utc).isoformat()}
        return {}
    data = res.get("data")
    # placa/soat devuelven un objeto; revision-tecnica devuelve una LISTA de inspecciones
    if isinstance(data, list):
        return {"_lista": data}
    return data if isinstance(data, dict) else {}


async def _placa_leyenda(placa: str) -> dict:
    """Ficha de la placa: json.pe primero (marca, modelo, VIN/serie, color, motor);
    consultadatos como respaldo si está configurado. Devuelve {} sin datos."""
    jp = await _jsonpe("placa", {"placa": placa})
    if jp:
        out = {k: x for k, x in {
            "marca": jp.get("marca", ""), "modelo": jp.get("modelo", ""),
            "chasis": (jp.get("vin") or jp.get("serie") or "").upper(),
            "color": jp.get("color", ""), "motor": jp.get("motor", ""),
        }.items() if x}
        try:
            a = int(jp.get("anio") or 0)
            if a > 1900:
                out["año"] = a
        except Exception:
            pass
        if out:
            return out
    token = os.getenv("CONSULTADATOS_TOKEN", "").strip()
    if not token:
        return {}
    import json
    import urllib.request as _ur
    import ssl as _ssl
    ctx = _ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
    req = _ur.Request(f"https://api2.consultadatos.com/api/placa/leyenda/{placa}",
                      headers={"Authorization": f"Bearer {token}", "User-Agent": "Mozilla/5.0",
                               "Accept": "application/json"})
    def _fetch():
        with _ur.urlopen(req, context=ctx, timeout=8) as r:
            return json.loads(r.read())
    try:
        res = await asyncio.to_thread(_fetch)
    except Exception:
        return {}
    if not (res.get("success") and res.get("data")):
        return {}
    v = res["data"].get("vehiculo", {}) or {}
    props = res["data"].get("propietarios", []) or []
    año = None
    try:
        año = int(v.get("ano_fab") or v.get("an_mode") or 0) or None
    except Exception:
        pass
    return {k: x for k, x in {
        "marca": v.get("marca", ""), "modelo": v.get("modelo", ""),
        "chasis": v.get("no_vin") or v.get("num_serie", ""), "año": año,
        "titular": (props[0].get("propietario", "") if props else ""),
        "tipo": v.get("desc_tipo_carr", ""),
    }.items() if x}


def _poliza_legible(numero: str) -> str:
    """json.pe devuelve el 'código único de póliza' de la SBS (~26 dígitos: relleno de
    ceros + el número real + más relleno + dígito verificador), no el número simple que
    se ve en el portal público del SOAT (ej. '143073789'). Solo se limpia para MOSTRAR —
    el valor crudo se guarda tal cual en soat_poliza, esto no lo toca.
    Heurística: el número real de póliza no trae 3+ ceros seguidos, así que se parte el
    código por cada corrida de 3+ ceros y se toma el trozo más largo (el relleno y el
    dígito verificador quedan siempre más cortos que la póliza real)."""
    s = (numero or "").strip()
    if not s or not s.isdigit() or len(s) <= 12:
        return s  # ya parece un número de póliza normal, no el código compuesto
    partes = [p for p in re.split(r"0{3,}", s) if p]
    return max(partes, key=len) if partes else s


async def _placa_soat(placa: str) -> dict:
    """SOAT vigente por placa: json.pe primero (compañía, vigencia, póliza, estado);
    consultadatos como respaldo. Devuelve {} sin datos."""
    jp = await _jsonpe("soat", {"placa": placa})
    if jp and (jp.get("fecha_fin") or jp.get("estado")):
        out = {k: x for k, x in {
            "soat_vencimiento": jp.get("fecha_fin", ""),
            "soat_compania": jp.get("nombre_compania", ""),
            "soat_poliza": jp.get("numero_poliza", ""),
            "soat_estado": jp.get("estado", ""),
        }.items() if x}
        # Inicio de vigencia: antes nunca se pedía, así que la ficha siempre mostraba "–"
        # aunque el portal público del SOAT sí trae esta fecha. El nombre exacto del campo
        # en json.pe no está confirmado — se prueban los candidatos más probables.
        for k in ("fecha_inicio", "inicio_vigencia", "fecha_ini", "vigencia_desde", "fecha_inicio_vigencia"):
            if jp.get(k):
                out["soat_desde"] = jp[k]
                break
        return out
    token = os.getenv("CONSULTADATOS_TOKEN", "").strip()
    if not token:
        return {}
    import json
    import urllib.request as _ur
    import ssl as _ssl
    ctx = _ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
    req = _ur.Request(f"https://api2.consultadatos.com/api/placa/soat/{placa}",
                      headers={"Authorization": f"Bearer {token}", "User-Agent": "Mozilla/5.0",
                               "Accept": "application/json"})
    def _fetch():
        with _ur.urlopen(req, context=ctx, timeout=8) as r:
            return json.loads(r.read())
    try:
        res = await asyncio.to_thread(_fetch)
    except Exception:
        return {}
    data = res.get("data") or res
    if not isinstance(data, dict):
        return {}
    soat = data.get("soat") or data
    venc = (soat.get("fecha_fin") or soat.get("fecha_vencimiento") or soat.get("vencimiento")
            or soat.get("fin_vigencia") or soat.get("end_date") or "")
    out = {}
    if venc:
        out["soat_vencimiento"] = str(venc)[:10]
    for k_dst, keys in (("soat_compania", ("compania", "aseguradora", "company")),
                        ("soat_poliza", ("poliza", "numero_poliza", "certificado"))):
        for k in keys:
            if soat.get(k):
                out[k_dst] = soat[k]
                break
    return out


def _fecha_tupla(v) -> Optional[tuple]:
    """'dd/mm/yyyy' o 'yyyy-mm-dd' (con o sin hora) → (yyyy, mm, dd) comparable; None si no parsea."""
    s = str(v or "").strip()
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})", s)
    if m:
        return (int(m.group(3)), int(m.group(2)), int(m.group(1)))
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})", s)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


async def _placa_revtec(placa: str) -> dict:
    """Revisión técnica (CITV) por placa vía json.pe (consulta al MTC). Devuelve {}
    si no hay datos o el MTC limita las consultas (reintentar luego)."""
    jp = await _jsonpe("revision-tecnica", {"placa": placa})
    if not jp:
        return {}
    if jp.get("_sin_registro"):
        return {"revtec_estado": "SIN REGISTRO",
                "revtec_consultado_en": datetime.now(timezone.utc).isoformat()}
    # json.pe devuelve la lista de inspecciones (orden ULTIMO/PENULTIMO...): tomamos la
    # última CON vigencia (un informe DESAPROBADO no tiene vigente_hasta).
    items = jp.get("_lista") if isinstance(jp.get("_lista"), list) else [jp]
    items = [i for i in items if isinstance(i, dict)]
    if not items:
        return {}
    # El orden de la lista NO es confiable (C9E932 recibió como "último" un certificado de
    # 2018 teniendo uno vigente de 2025): manda la FECHA. Certificado vigente = el de mayor
    # "vigente_hasta"; última inspección (aunque desaprobada) = la de mayor fecha de inicio.
    def _fk(*vals):
        for x in vals:
            f = _fecha_tupla(x)
            if f:
                return f
        return None
    def _k_hasta(i):
        return _fk(i.get("vigente_hasta"), i.get("fecha_vencimiento"), i.get("fecha_fin"))
    def _k_desde(i):
        return _fk(i.get("vigente_desde"), i.get("fecha_inspeccion"), i.get("fecha"), i.get("vigente_hasta"))
    con_hasta = [i for i in items if _k_hasta(i)]
    con_desde = [i for i in items if _k_desde(i)]
    if con_desde:
        ult = max(con_desde, key=_k_desde)
    else:
        ult = next((i for i in items if str(i.get("orden", "")).upper() == "ULTIMO"), items[0])
    src = max(con_hasta, key=_k_hasta) if con_hasta else ult
    venc = (src.get("vigente_hasta") or src.get("fecha_vencimiento") or src.get("fecha_fin") or "")
    out = {"revtec_fuente_version": 2}
    if venc:
        out["revtec_vencimiento"] = str(venc)[:10]
    for k_dst, keys in (("revtec_estado", ("estado", "vigencia")),
                        ("revtec_resultado", ("resultado_inspeccion", "resultado", "calificacion")),
                        ("revtec_centro", ("empresa_certificadora", "centro", "planta", "entidad")),
                        ("revtec_certificado", ("numero_certificado",)),
                        ("revtec_desde", ("vigente_desde",)),
                        ("revtec_observaciones", ("observaciones",))):
        for k in keys:
            if src.get(k):
                out[k_dst] = src[k]
                break
    # la última inspección (aunque sea desaprobada) manda en el resultado mostrado
    if ult is not src and ult.get("resultado_inspeccion"):
        out["revtec_ultimo_resultado"] = ult["resultado_inspeccion"]
        if ult.get("observaciones"):
            out["revtec_observaciones"] = ult["observaciones"]
    return out


@api.get("/vehiculos/ficha-pdf/{placa}")
async def ficha_vehiculo_pdf(req: Request, placa: str):
    """Ficha informativa de la unidad en PDF (documento interno ENERED, no es un
    comprobante oficial): identificación, permiso MTC, SOAT, revisión técnica (con
    historial), valor referencial MEF y documentos cargados con sus vigencias."""
    import io as _io
    import pymupdf
    from fastapi.responses import StreamingResponse
    u = await require_auth(req)
    p = (placa or "").replace("-", "").replace(" ", "").upper()
    filt = {"placa": p}
    if u.get("empresa"):
        filt["empresa"] = u["empresa"]
    elif u["role"] != "admin_enered":
        raise HTTPException(403, "Sin empresa activa")
    v = await db.vehiculos.find_one(filt, {"_id": 0})
    if not v:
        raise HTTPException(404, "Vehículo no encontrado")
    emp = v.get("empresa") or u.get("empresa") or ""
    docs = await db.documents.find({"placa": p, **({"empresa": emp} if emp else {})},
                                   {"_id": 0, "doc": 1, "emi": 1, "ven": 1, "est": 1, "filename": 1, "el": 1, "ref": 1}).to_list(200)
    sdocs = await db.subsidio_documents.find({"placa": p, **({"empresa": emp} if emp else {})},
                                             {"_id": 0, "categoria": 1, "filename": 1, "uploaded_at": 1}).to_list(200)

    def _s(x):
        return "-" if x in (None, "", 0) else str(x)

    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    y = 40
    W = 515
    MOR = (0.49, 0.23, 0.93)
    GRIS = (0.42, 0.45, 0.5)
    NEG = (0.07, 0.09, 0.15)

    def linea(y0, color=(0.9, 0.9, 0.92), w=0.6):
        page.draw_line((40, y0), (40 + W, y0), color=color, width=w)

    def titulo(txt, yy):
        page.draw_rect(pymupdf.Rect(40, yy - 2, 44, yy + 12), color=MOR, fill=MOR)
        page.insert_text((50, yy + 9), txt.upper(), fontsize=8.5, fontname="hebo", color=MOR)
        return yy + 20

    def fila(label, valor, yy, col=0):
        x = 40 + col * 258
        page.insert_text((x, yy), label, fontsize=7.5, fontname="helv", color=GRIS)
        page.insert_text((x, yy + 11), _s(valor)[:60], fontsize=10, fontname="hebo", color=NEG)

    def nueva_pagina():
        nonlocal page, y
        page = doc.new_page(width=595, height=842)
        y = 40

    def check(y_need):
        nonlocal y
        if y + y_need > 800:
            nueva_pagina()

    # Encabezado
    page.insert_text((40, y + 14), "ENERED", fontsize=20, fontname="hebo", color=MOR)
    page.insert_text((40, y + 28), "Ficha de la unidad", fontsize=10, fontname="helv", color=GRIS)
    page.insert_text((300, y + 14), f"Placa {p}", fontsize=20, fontname="hebo", color=NEG)
    page.insert_text((300, y + 28), (emp or "")[:60], fontsize=9, fontname="helv", color=GRIS)
    y += 44
    linea(y, MOR, 1.2)
    y += 14

    # Identificación
    y = titulo("Identificación de la unidad", y)
    for i, (l, vv) in enumerate((("Marca", v.get("marca")), ("Modelo", v.get("modelo")),
                                 ("Año de fabricación", v.get("año")), ("Categoría", v.get("categoria")),
                                 ("Chasis / VIN", v.get("chasis")), ("N° motor", v.get("motor")),
                                 ("Color", v.get("color")), ("Tipo", v.get("tipo")))):
        fila(l, vv, y + (i // 2) * 30, i % 2)
    y += 4 * 30 + 6
    fila("Titular", v.get("titular"), y); y += 30

    # Permiso MTC
    check(120)
    y = titulo("Habilitación MTC", y)
    for i, (l, vv) in enumerate((("Constancia / TUC", v.get("constancia_mtc")), ("Ejes", v.get("ejes")),
                                 ("Carga útil (kg)", v.get("carga_util")), ("Peso seco (kg)", v.get("peso_seco")))):
        fila(l, vv, y + (i // 2) * 30, i % 2)
    y += 2 * 30 + 6

    # SOAT
    check(110)
    y = titulo("SOAT", y)
    for i, (l, vv) in enumerate((("Aseguradora", v.get("soat_compania")), ("Estado", v.get("soat_estado")),
                                 ("N° de póliza", v.get("soat_poliza")), ("Vence", v.get("soat_vencimiento")))):
        fila(l, vv, y + (i // 2) * 30, i % 2)
    y += 2 * 30 + 6

    # Revisión técnica
    check(140)
    y = titulo("Revisión técnica (CITV)", y)
    for i, (l, vv) in enumerate((("Resultado", v.get("revtec_resultado")), ("Estado", v.get("revtec_estado")),
                                 ("N° certificado", v.get("revtec_certificado")), ("Vigente hasta", v.get("revtec_vencimiento")),
                                 ("Vigente desde", v.get("revtec_desde")), ("", None))):
        if l:
            fila(l, vv, y + (i // 2) * 30, i % 2)
    y += 3 * 30
    fila("Centro de inspección", (v.get("revtec_centro") or "")[:80], y); y += 32
    hist = v.get("revtec_historial") or []
    if hist:
        check(20 + 14 * len(hist))
        page.insert_text((40, y + 8), "Historial de inspecciones", fontsize=7.5, fontname="helv", color=GRIS); y += 16
        for h in hist[:6]:
            page.insert_text((44, y + 8), f"{_s(h.get('orden')).title():14} {_s(h.get('numero')):26} {_s(h.get('desde'))} → {_s(h.get('hasta'))}   {_s(h.get('resultado'))}",
                             fontsize=8.5, fontname="cour", color=NEG)
            y += 13
            if h.get("observaciones") and h["observaciones"] != "Sin observaciones":
                page.insert_text((60, y + 6), f"Obs.: {h['observaciones'][:90]}", fontsize=7.5, fontname="helv", color=(0.86, 0.15, 0.15)); y += 12
        y += 6

    # Valorización
    check(70)
    y = titulo("Valor referencial (MEF · Tabla de Valores Referenciales 2026)", y)
    vr = v.get("valor_referencial")
    det = v.get("valor_ref_detalle") or {}
    fila("Valor referencial", f"S/ {int(vr):,}" if vr else None, y)
    fila("Modelo de la tabla MEF", f"{det.get('modelo_tabla','-')} ({det.get('match','')})"[:44] if det else None, y, 1)
    y += 30
    if det.get("regla"):
        page.insert_text((40, y + 6), f"Regla aplicada: {det.get('regla')}", fontsize=8, fontname="helv", color=GRIS); y += 16
    y += 6

    # Seguro vehicular (póliza contra todo riesgo) — documento subido por el cliente
    pol_docs = [d for d in docs if "poliza" in re.sub(r"[^a-z0-9]", "", __import__("unicodedata").normalize("NFKD", d.get("doc") or "").encode("ascii", "ignore").decode().lower())]
    if pol_docs:
        check(80)
        y = titulo("Seguro vehicular (Póliza)", y)
        pd0 = sorted(pol_docs, key=lambda d: d.get("ven") or "", reverse=True)[0]
        for i, (l, vv) in enumerate((("N° de póliza / aseguradora", (pd0.get("ref") or "").replace("Póliza N° ", "") or "-"),
                                     ("Estado", pd0.get("est")), ("Emisión", pd0.get("emi")), ("Vence", pd0.get("ven")))):
            fila(l, vv, y + (i // 2) * 30, i % 2)
        y += 2 * 30 + 6

    # Documentos cargados
    check(60)
    y = titulo("Documentos cargados en ENERED", y)
    filas_docs = [(d.get("doc"), d.get("emi"), d.get("ven"), d.get("est"), d.get("filename")) for d in docs]
    mapa_sub = {"tarjeta_propiedad": "Tarjeta de propiedad", "tarjeta_habilitacion": "TUC / Tarjeta de habilitación",
                "soat": "SOAT", "revision_tecnica": "Revisión técnica"}
    for sd in sdocs:
        filas_docs.append((mapa_sub.get(sd.get("categoria"), sd.get("categoria")), "—", "—", "Cargado (subsidio)", sd.get("filename")))
    if not filas_docs:
        page.insert_text((44, y + 8), "Sin documentos cargados.", fontsize=9, fontname="helv", color=GRIS); y += 16
    for (dn, emi, ven, est, fn) in filas_docs[:25]:
        check(16)
        page.insert_text((44, y + 8), f"{_s(dn)[:28]:28} emi {_s(emi):10} vence {_s(ven):10} {_s(est):12} {(_s(fn))[:34]}",
                         fontsize=8, fontname="cour", color=NEG)
        y += 13
    y += 8

    # Pie
    for pg in doc:
        pg.insert_text((40, 820), f"Documento informativo generado por ENERED el {datetime.now(timezone.utc).strftime('%d/%m/%Y')} · "
                       f"Fuentes: MTC, SUNAT, OSINERGMIN, APESEG/SOAT, CITV, MEF · No es un comprobante oficial.",
                       fontsize=6.8, fontname="helv", color=GRIS)
    buf = _io.BytesIO(doc.tobytes()); doc.close()
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="ENERED_ficha_{p}.pdf"'})


async def _ruc_representantes(ruc: str) -> list:
    """Representantes legales del RUC (SUNAT vía json.pe): nombre, cargo, documento, desde."""
    jp = await _jsonpe("ruc/representantes", {"ruc": ruc})
    items = jp.get("_lista") if isinstance(jp.get("_lista"), list) else ([jp] if jp and jp.get("nombre") else [])
    out = []
    for it in items:
        if not isinstance(it, dict) or not it.get("nombre"):
            continue
        out.append({"nombre": it.get("nombre", "").strip(), "cargo": it.get("cargo", "").strip(),
                    "tipo_documento": it.get("tipo_de_documento") or it.get("tipo_documento") or "",
                    "numero_documento": it.get("numero_de_documento") or it.get("numero_documento") or "",
                    "desde": it.get("fecha_desde") or ""})
    return out


@api.get("/empresas/representantes")
async def empresa_representantes(req: Request, ruc: Optional[str] = None, refresh: int = 0):
    """Representante(s) legal(es) de la empresa activa (o del RUC indicado) desde SUNAT.
    Se cachea 90 días por RUC para no gastar créditos; refresh=1 fuerza la consulta."""
    u = await require_auth(req)
    ruc = (ruc or u.get("ruc") or "").strip()
    if not ruc and u.get("empresa"):
        cfg = await db.empresas_config.find_one({"empresa": u["empresa"]}, {"_id": 0, "ruc": 1})
        ruc = ((cfg or {}).get("ruc") or "").strip()
        if not ruc:
            usr = await db.users.find_one({"empresa": u["empresa"], "ruc": {"$nin": [None, ""]}}, {"_id": 0, "ruc": 1})
            ruc = ((usr or {}).get("ruc") or "").strip()
    if len(ruc) != 11 or not ruc.isdigit():
        raise HTTPException(400, "RUC de la empresa no disponible")
    cache = await db.representantes_ruc.find_one({"ruc": ruc}, {"_id": 0})
    if cache and not refresh:
        try:
            edad = (datetime.now(timezone.utc) - datetime.fromisoformat(cache["consultado_en"])).days
        except Exception:
            edad = 10**6
        if edad <= 90 and cache.get("representantes"):
            return {"ruc": ruc, "representantes": cache["representantes"], "fuente": "SUNAT (json.pe)",
                    "consultado_en": cache["consultado_en"], "cache": True}
    reps = await _ruc_representantes(ruc)
    if not reps:
        if cache and cache.get("representantes"):
            return {"ruc": ruc, "representantes": cache["representantes"], "fuente": "SUNAT (json.pe)",
                    "consultado_en": cache["consultado_en"], "cache": True,
                    "aviso": "SUNAT no respondió ahora; se muestra la última consulta guardada."}
        raise HTTPException(503, "SUNAT no devolvió representantes para este RUC en este momento. Intenta más tarde.")
    ahora = datetime.now(timezone.utc).isoformat()
    await db.representantes_ruc.update_one({"ruc": ruc}, {"$set": {"ruc": ruc, "representantes": reps, "consultado_en": ahora}}, upsert=True)
    # el principal (gerente general / titular) queda también en la ficha de la empresa
    principal = next((r for r in reps if "GERENTE" in r["cargo"].upper() or "TITULAR" in r["cargo"].upper()), reps[0])
    await db.empresas_config.update_many({"ruc": ruc}, {"$set": {"representante_legal": principal, "representantes_actualizado_en": ahora}})
    return {"ruc": ruc, "representantes": reps, "fuente": "SUNAT (json.pe)", "consultado_en": ahora, "cache": False}


@api.get("/vehiculos/ficha/{placa}")
async def ficha_vehiculo(req: Request, placa: str):
    """Ficha completa de una placa para autollenar el formulario: MTC (chasis/VIN,
    categoría, año, ejes, carga útil, peso seco, constancia) + marca por el VIN +
    consultadatos si está activo (marca, modelo, titular, tipo)."""
    import mtc as _mtc3
    await require_auth(req)
    p = (placa or "").replace("-", "").replace(" ", "").upper()
    if len(p) < 6:
        raise HTTPException(400, "Placa no válida")
    ficha: dict = {"placa": p, "fuentes": []}
    try:
        m = await _mtc3.consultar("placa", p)
        for a in m.get("autorizaciones", []):
            for veh in a.get("vehiculos", []):
                if (veh.get("placa") or "").replace("-", "").replace(" ", "").upper() != p:
                    continue
                ficha.update({k: x for k, x in {
                    "chasis": (veh.get("chasis") or "").upper(),
                    "categoria": (veh.get("categoria") or "").upper(),
                    "constancia_mtc": veh.get("constancia"),
                    "ejes": veh.get("ejes"), "carga_util": veh.get("carga_util"),
                    "peso_seco": veh.get("peso_seco"),
                }.items() if x})
                try:
                    a_int = int(veh.get("anio") or 0)
                    if a_int > 1900:
                        ficha["año"] = a_int
                except Exception:
                    pass
                if not ficha.get("titular") and a.get("razon_social"):
                    ficha["titular"] = a["razon_social"]
                ficha["fuentes"].append("MTC")
                break
    except Exception:
        pass
    ley = await _placa_leyenda(p)
    for campo in ("marca", "modelo", "chasis", "año", "titular", "tipo"):
        if ley.get(campo) and not ficha.get(campo):
            ficha[campo] = ley[campo]
            if "SUNARP" not in ficha["fuentes"]:
                ficha["fuentes"].append("SUNARP")
    if not ficha.get("marca"):
        m_vin = _marca_por_vin(ficha.get("chasis", ""))
        if m_vin:
            ficha["marca"] = m_vin
            ficha["fuentes"].append("VIN")
    soat = await _placa_soat(p)
    if soat:
        ficha.update(soat)
        ficha["fuentes"].append("SOAT")
    revtec = await _placa_revtec(p)
    if revtec:
        ficha.update(revtec)
        ficha["fuentes"].append("CITV")
    if ficha.get("marca") and ficha.get("modelo"):
        try:
            from services.valorizacion import valorizar as _valorizar
            val = await _valorizar(db, ficha["marca"], ficha["modelo"], ficha.get("año"), ficha.get("categoria"))
            if val:
                ficha.update(val)
                ficha["fuentes"].append("MEF")
        except Exception:
            pass
    if len(ficha) <= 2:
        raise HTTPException(404, "No se encontró información para esta placa")
    return ficha


@api.post("/vehiculos/valores-referenciales/sync")
async def sync_valores_referenciales(req: Request):
    """Descarga la Tabla de Valores Referenciales del MEF (anexo Excel oficial) y la
    carga en la base. Correr una vez por ejercicio (se publica cada enero)."""
    u = await require_auth(req)
    if u["role"] != "admin_enered":
        raise HTTPException(403, "Solo administradores ENERED")
    from services.valorizacion import sincronizar as _sync_val
    try:
        return await _sync_val(db)
    except Exception as e:
        raise HTTPException(503, f"No se pudo sincronizar la tabla del MEF: {e}")


@api.get("/vehiculos/valor-flota")
async def valor_flota(req: Request):
    """Suma del valor referencial de la flota de la empresa activa."""
    u = await require_auth(req)
    # unidades INACTIVAS (vendidas/de baja) no suman patrimonio
    filt = {"valor_referencial": {"$gt": 0}, "estado": {"$not": {"$regex": "^INACTIVO$", "$options": "i"}}}
    if u.get("empresa"):
        filt["empresa"] = u["empresa"]
    elif u["role"] != "admin_enered":
        return {"total": 0, "unidades": 0}
    total, n = 0.0, 0
    async for v in db.vehiculos.find(filt, {"_id": 0, "valor_referencial": 1}):
        total += float(v.get("valor_referencial") or 0)
        n += 1
    return {"total": round(total), "unidades": n, "fuente": "MEF · Tabla de Valores Referenciales 2026"}


class VerificacionManualIn(BaseModel):
    placa: str
    campo: Literal["revtec", "soat"] = "revtec"
    vencimiento: str  # dd/mm/yyyy
    estado: Optional[str] = None
    certificado: Optional[str] = None   # N° de certificado CITV / póliza (opcional)
    centro: Optional[str] = None        # empresa certificadora / aseguradora (opcional)
    desde: Optional[str] = None         # vigente desde dd/mm/yyyy (opcional)


@api.post("/vehiculos/verificacion-manual")
async def vehiculo_verificacion_manual(payload: VerificacionManualIn, req: Request):
    """Registra una vigencia consultada MANUALMENTE en el portal oficial (CITV del MTC,
    SOAT, etc.): la persona hace la consulta con captcha en el portal y pega aquí el
    resultado; ENERED lo guarda, lo muestra en Vehículos/Documentación y alerta el
    vencimiento. Complemento humano de las fuentes que no permiten automatización."""
    u = await require_auth(req)
    placa = (payload.placa or "").replace("-", "").replace(" ", "").upper()
    if not placa:
        raise HTTPException(400, "Placa requerida")
    ven = (payload.vencimiento or "").strip()
    if not re.fullmatch(r"\d{2}/\d{2}/\d{4}", ven):
        raise HTTPException(400, "La fecha debe ser dd/mm/aaaa")
    filt = {"placa": placa}
    if u["role"] != "admin_enered" or u.get("empresa"):
        filt["empresa"] = u.get("empresa")
    v = await db.vehiculos.find_one(filt)
    if not v:
        raise HTTPException(404, "Vehículo no encontrado en la empresa activa")
    pref = "revtec" if payload.campo == "revtec" else "soat"
    ahora = datetime.now(timezone.utc).isoformat()
    cambios = {
        f"{pref}_vencimiento": ven,
        f"{pref}_estado": (payload.estado or "VIGENTE").upper(),
        f"{pref}_fuente": "manual",
        f"{pref}_verificado_por": u.get("email") or u.get("name") or "",
        f"{pref}_verificado_en": ahora,
        f"{pref}_consultado_en": ahora,
    }
    # Datos del certificado/póliza: los nuevos si vienen; si no, se BORRAN los viejos para que
    # la fila no mezcle la fecha nueva con el certificado anterior (C9E932: 2026 con cert. 2018).
    if pref == "revtec":
        cambios["revtec_fuente_version"] = 2
        pares = {"revtec_certificado": (payload.certificado or "").strip(),
                 "revtec_centro": (payload.centro or "").strip(),
                 "revtec_desde": (payload.desde or "").strip()}
        cambios["revtec_resultado"] = "APROBADO" if cambios["revtec_estado"] == "VIGENTE" else cambios["revtec_estado"]
    else:
        pares = {"soat_poliza": (payload.certificado or "").strip(),
                 "soat_compania": (payload.centro or "").strip(),
                 "soat_desde": (payload.desde or "").strip()}
    quitar = {k: 1 for k, val in pares.items() if not val}
    cambios.update({k: val for k, val in pares.items() if val})
    op = {"$set": cambios}
    if quitar:
        op["$unset"] = quitar
    await db.vehiculos.update_one({"_id": v["_id"]} if "_id" in v else {"id": v.get("id")}, op)
    return {"ok": True, "placa": placa, "guardado": {k: cambios[k] for k in (f"{pref}_vencimiento", f"{pref}_estado")}}


@api.get("/vehiculos/citv-debug/{placa}")
async def citv_debug(req: Request, placa: str):
    """Admin: qué responde json.pe (crudo) para la revisión técnica de una placa, qué se
    deriva de ello y qué hay guardado. Para diagnosticar sin entrar al servidor. 5 créditos."""
    u = await require_auth(req)
    if u["role"] != "admin_enered" and u.get("_admin_role") != "admin_enered":
        raise HTTPException(403, "Solo administradores ENERED")
    p = (placa or "").replace("-", "").replace(" ", "").upper()
    crudo = await _jsonpe("revision-tecnica", {"placa": p})
    derivado = await _placa_revtec(p)
    guardado = await db.vehiculos.find_one({"placa": p}, {"_id": 0, "empresa": 1, "placa": 1, "revtec_vencimiento": 1,
                                                          "revtec_certificado": 1, "revtec_desde": 1, "revtec_centro": 1,
                                                          "revtec_estado": 1, "revtec_consultado_en": 1,
                                                          "revtec_fuente_version": 1, "enriquecido_en": 1})
    return {"placa": p, "hay_token": bool(os.getenv("JSONPE_TOKEN", "").strip()),
            "jsonpe_crudo": crudo, "derivado": derivado, "guardado": guardado,
            "ultimo_error_jsonpe": _JSONPE_ULTIMO_ERROR}


@api.post("/vehiculos/vigencias/reset")
async def reset_vigencias(req: Request, incluir_sin_registro: int = 0):
    """Admin: borra las marcas de 'ya consultado' de SOAT/CITV en unidades SIN vigencia,
    para que la próxima pasada las vuelva a consultar (p.ej. tras configurar el token o
    cuando el MTC estuvo bloqueado). Con incluir_sin_registro=1 también reintenta las
    marcadas SIN REGISTRO."""
    u = await require_auth(req)
    # admin real aunque esté "entrando como" una empresa (la identidad admin viaja en _admin_role)
    if u["role"] != "admin_enered" and u.get("_admin_role") != "admin_enered":
        raise HTTPException(403, "Solo administradores ENERED")
    filt = {}
    if u.get("empresa"):
        filt["empresa"] = u["empresa"]
    unset = {"soat_consultado_en": 1, "revtec_consultado_en": 1}
    if incluir_sin_registro:
        unset["revtec_estado"] = 1
    r1 = await db.vehiculos.update_many(
        {**filt, "soat_vencimiento": {"$in": [None, ""]}}, {"$unset": {"soat_consultado_en": 1}})
    q_rev = {**filt, "revtec_vencimiento": {"$in": [None, ""]}}
    if not incluir_sin_registro:
        q_rev["revtec_estado"] = {"$ne": "SIN REGISTRO"}
    r2 = await db.vehiculos.update_many(q_rev, {"$unset": {k: 1 for k in unset if k != "soat_consultado_en"}})
    return {"ok": True, "soat_reiniciadas": r1.modified_count, "revtec_reiniciadas": r2.modified_count}


@api.post("/vehiculos/enriquecer")
async def enriquecer_vehiculos(req: Request):
    """Completa automáticamente los campos vacíos de la flota a partir de la placa:
    consultadatos (marca, modelo, VIN/chasis, año, titular, tipo) + MTC (categoría y
    constancia de habilitación). NUNCA pisa un dato ya escrito. La placa es la llave:
    nada debe quedar vacío."""
    u = await require_auth(req)
    filt = {}
    if u.get("empresa"):
        filt["empresa"] = u["empresa"]
    elif u["role"] != "admin_enered":
        raise HTTPException(403, "Sin empresa activa")
    return await _enriquecer_flota(filt)


async def _enriquecer_flota(filt: dict) -> dict:
    """Núcleo del motor de placas (lo usan el botón y la tarea nocturna)."""
    import mtc as _mtc2
    CAMPOS = ["marca", "modelo", "chasis", "año", "titular", "tipo",
              "categoria", "constancia_mtc", "ejes", "carga_util", "peso_seco",
              "soat_vencimiento", "revtec_vencimiento", "valor_referencial"]
    vehiculos = await db.vehiculos.find(filt).to_list(2000)
    revisados, completados_total, detalle = 0, 0, []
    citv_consultadas, citv_ok, citv_fallidas = 0, 0, []
    leyenda_caida = False
    fallos_mtc, mtc_bloqueado = 0, False  # freno automático ante 429 del MTC (vía json.pe)
    # sin token de json.pe no hay SOAT/CITV que consultar (y no debe contar como bloqueo del MTC)
    hay_jsonpe = bool(os.getenv("JSONPE_TOKEN", "").strip())

    # El listado del MTC trae la FLOTA COMPLETA de la autorización en una sola consulta
    # (placa, constancia, categoría, chasis/VIN, año, ejes, carga útil, peso seco):
    # se cachea para no repetir el scrape por cada unidad.
    def _np(p):
        return (p or "").replace("-", "").replace(" ", "").upper()
    mtc_cache: dict = {}
    mtc_consultadas: set = set()

    async def _mtc_datos(placa: str) -> dict:
        if placa in mtc_cache:
            return mtc_cache[placa]
        if placa in mtc_consultadas:
            return {}
        mtc_consultadas.add(placa)
        try:
            m = await _mtc2.consultar("placa", placa)
            for a in m.get("autorizaciones", []):
                for veh in a.get("vehiculos", []):
                    pn = _np(veh.get("placa"))
                    if pn:
                        mtc_cache.setdefault(pn, veh)
        except Exception:
            pass
        return mtc_cache.get(placa) or {}

    # Consumo inteligente de créditos: SOAT y revisión técnica solo se (re)consultan si
    # no hay dato, si vencen en ≤30 días (posible renovación) o si el proveedor dijo
    # "sin registro" hace más de 30 días. Nunca se repite lo vigente.
    def _dias_para(fecha_ddmmyyyy: str):
        try:
            d, m, a = map(int, str(fecha_ddmmyyyy).split("/")[:3])
            return (datetime(a, m, d, tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        except Exception:
            return None

    def _hace_dias(iso: str):
        try:
            return (datetime.now(timezone.utc) - datetime.fromisoformat(iso.replace("Z", "+00:00"))).days
        except Exception:
            return 10**6

    def _necesita_vigencia(v, pref):
        venc = v.get(f"{pref}_vencimiento")
        ultima = _hace_dias(v.get(f"{pref}_consultado_en") or "")
        # CITV guardada con la selección antigua (podía quedarse con un certificado viejo
        # aunque hubiera uno vigente): se re-consulta una sola vez si figura vencida.
        if pref == "revtec" and venc and v.get("revtec_fuente_version") != 2:
            d0 = _dias_para(venc)
            if d0 is not None and d0 < 0:
                return True
        if not venc:
            if v.get(f"{pref}_estado") == "SIN REGISTRO":
                return ultima > 30
            return ultima > 7  # sin dato: reintentar como máximo semanalmente
        dias = _dias_para(venc)
        return dias is not None and dias <= 30 and ultima > 7

    for v in vehiculos:
        placa = _np(v.get("placa") or v.get("veh"))
        if not placa:
            continue
        vacios = [c for c in CAMPOS if not v.get(c) and c not in ("soat_vencimiento", "revtec_vencimiento")]
        if _necesita_vigencia(v, "soat"):
            vacios.append("soat_vencimiento")
        if _necesita_vigencia(v, "revtec"):
            vacios.append("revtec_vencimiento")
        if not vacios:
            continue
        revisados += 1
        nuevos: dict = {}
        # 1) MTC primero: gratis y trae el VIN/chasis oficial del permiso
        mv = await _mtc_datos(placa)
        if mv:
            if "categoria" in vacios and mv.get("categoria"):
                nuevos["categoria"] = mv["categoria"].upper()
            if "constancia_mtc" in vacios and mv.get("constancia"):
                nuevos["constancia_mtc"] = mv["constancia"]
            if "chasis" in vacios and mv.get("chasis"):
                nuevos["chasis"] = mv["chasis"].upper()
            if "año" in vacios and mv.get("anio"):
                try:
                    a_int = int(mv["anio"])
                    if a_int > 1900:
                        nuevos["año"] = a_int
                except Exception:
                    pass
            for campo in ("ejes", "carga_util", "peso_seco"):
                if campo in vacios and mv.get(campo) not in (None, "", "0"):
                    nuevos[campo] = mv[campo]
        # 2) ficha vehicular (marca, modelo, titular, tipo y lo que el MTC no cubrió)
        vacios_rest = [c for c in ("marca", "modelo", "chasis", "año", "titular", "tipo")
                       if c in vacios and c not in nuevos]
        if vacios_rest:
            ley = await _placa_leyenda(placa)
            if not ley and not os.getenv("JSONPE_TOKEN", "").strip():
                leyenda_caida = True
            for campo in vacios_rest:
                if ley.get(campo):
                    nuevos[campo] = ley[campo]
            await asyncio.sleep(0.3)  # no saturar al proveedor
        # 2b) marca por el VIN (WMI): no depende de ningún proveedor
        if "marca" in vacios and not nuevos.get("marca"):
            m_vin = _marca_por_vin(nuevos.get("chasis") or v.get("chasis"))
            if m_vin:
                nuevos["marca"] = m_vin
        # 2c) SOAT vigente (json.pe / consultadatos)
        if "soat_vencimiento" in vacios and hay_jsonpe:
            s = await _placa_soat(placa)
            nuevos["soat_consultado_en"] = datetime.now(timezone.utc).isoformat()
            if s:
                nuevos.update(s)
        # 2d) Revisión técnica CITV (json.pe → MTC)
        if "revtec_vencimiento" in vacios and hay_jsonpe and not mtc_bloqueado:
            rt = await _placa_revtec(placa)
            nuevos["revtec_consultado_en"] = datetime.now(timezone.utc).isoformat()
            citv_consultadas += 1
            if rt:
                fallos_mtc = 0
                citv_ok += 1
                # json.pe a veces trae solo un certificado viejo (C9E932: 2018 cuando el MTC
                # tiene uno de 2025). Nunca se reemplaza una vigencia por otra más antigua ni
                # se pisa una verificación manual con un dato de API de menor fecha.
                f_api = _fecha_tupla(rt.get("revtec_vencimiento"))
                f_act = _fecha_tupla(v.get("revtec_vencimiento"))
                if f_api and f_act and f_api < f_act:
                    nuevos["revtec_fuente_version"] = 2
                    detalle.append({"placa": placa, "revtec_ignorado": f"API trae {rt.get('revtec_vencimiento')} (más antiguo que {v.get('revtec_vencimiento')})"})
                else:
                    nuevos.update(rt)
            else:
                citv_fallidas.append(placa)
                # sin dato ni "sin registro" = el MTC rechazó (429). Tras 3 seguidos, se frena:
                # insistir solo quema créditos y alarga el bloqueo; el próximo ciclo reintenta.
                fallos_mtc += 1
                if fallos_mtc >= 3:
                    mtc_bloqueado = True
            await asyncio.sleep(6)  # el MTC (detrás de json.pe) limita ráfagas: gotear, no disparar
        # 2e) Valor referencial (tabla oficial MEF, gratis): necesita marca + modelo
        if "valor_referencial" in vacios:
            marca_v = nuevos.get("marca") or v.get("marca")
            modelo_v = nuevos.get("modelo") or v.get("modelo")
            if marca_v and modelo_v:
                try:
                    from services.valorizacion import valorizar as _valorizar
                    val = await _valorizar(db, marca_v, modelo_v, nuevos.get("año") or v.get("año"),
                                           nuevos.get("categoria") or v.get("categoria"))
                    if val:
                        nuevos.update(val)
                except Exception:
                    pass
        if nuevos:
            nuevos["enriquecido_en"] = datetime.now(timezone.utc).isoformat()
            await db.vehiculos.update_one({"id": v["id"]} if v.get("id") else {"_id": v["_id"]},
                                          {"$set": nuevos})
            completados_total += len([k for k in nuevos if k != "enriquecido_en"])
            detalle.append({"placa": placa, "completados": {k: x for k, x in nuevos.items() if k != "enriquecido_en"}})

    # 3) Unidades que solo existen en el expediente del subsidio (la tabla las muestra
    #    "prestadas" y salen vacías): se les crea su ficha completa en el módulo.
    empresa_f = filt.get("empresa")
    if empresa_f:
        placas_registradas = {_np(v.get("placa") or v.get("veh")) for v in vehiculos}
        async for sv in db.subsidio_vehicles.find({"empresa": empresa_f}):
            placa = _np(sv.get("placa"))
            if not placa or placa in placas_registradas:
                continue
            placas_registradas.add(placa)
            revisados += 1
            mv = await _mtc_datos(placa)
            ley = await _placa_leyenda(placa)
            if not ley and not os.getenv("JSONPE_TOKEN", "").strip():
                leyenda_caida = True
            nuevo_v = {
                "id": str(uuid.uuid4()), "placa": placa, "empresa": empresa_f,
                "estado": "OPERATIVO", "origen": "subsidio",
                "categoria": (mv.get("categoria") or sv.get("categoria") or "").upper() or None,
                "constancia_mtc": mv.get("constancia") or None,
                "chasis": (mv.get("chasis") or ley.get("chasis") or "").upper() or None,
                "ejes": mv.get("ejes") or None,
                "carga_util": mv.get("carga_util") or None,
                "peso_seco": mv.get("peso_seco") or None,
                "marca": ley.get("marca") or _marca_por_vin(mv.get("chasis") or ley.get("chasis")) or None,
                "modelo": ley.get("modelo") or None,
                "titular": ley.get("titular") or None,
                "tipo": ley.get("tipo") or None,
                "enriquecido_en": datetime.now(timezone.utc).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                a_raw = mv.get("anio") or ley.get("año")
                a_int = int(a_raw)
                if a_int > 1900:
                    nuevo_v["año"] = a_int
            except Exception:
                pass
            llenados = {k: x for k, x in nuevo_v.items()
                        if x and k not in ("id", "placa", "empresa", "estado", "origen", "enriquecido_en", "created_at")}
            await db.vehiculos.insert_one(nuevo_v)
            completados_total += len(llenados)
            detalle.append({"placa": placa, "completados": {"(ficha creada)": True, **llenados}})

    aviso = None
    if leyenda_caida:
        aviso = ("No hay token de json.pe configurado (JSONPE_TOKEN): solo se completó lo del "
                 "MTC y la marca por VIN. Configúralo para modelo, SOAT y revisión técnica.")
    elif mtc_bloqueado:
        aviso = ("El portal del MTC está limitando las consultas de revisión técnica en este momento; "
                 "se pausaron para no gastar créditos. Las pendientes se reintentan en el próximo ciclo.")
    # Diagnóstico de CITV para que el aviso del botón diga qué pasó (sin entrar al servidor)
    if citv_consultadas:
        resumen = f"Revisión técnica: {citv_ok} de {citv_consultadas} placas respondieron"
        if citv_fallidas:
            err = _JSONPE_ULTIMO_ERROR or {}
            msg_err = str(err.get("msg") or err.get("error") or err.get("dns_error") or "sin detalle")[:160]
            resumen += f"; sin respuesta: {', '.join(citv_fallidas[:8])}. Último error json.pe: {msg_err}"
        aviso = f"{aviso}\n{resumen}" if aviso else resumen
    return {"ok": True, "vehiculos_revisados": revisados, "campos_completados": completados_total,
            "detalle": detalle, "mtc_bloqueado": mtc_bloqueado, "aviso": aviso,
            "citv": {"consultadas": citv_consultadas, "ok": citv_ok, "fallidas": citv_fallidas}}


@api.get("/vehiculos")
async def list_vehiculos(req: Request):
    u = await require_auth(req)
    filt = {}
    if u["role"] != "admin_enered" and u.get("empresa"):
        filt["empresa"] = u["empresa"]
    
    cursor = db.vehiculos.find(filt)
    vehiculos_dict = {}
    async for v in cursor:
        v["_id"] = str(v["_id"])
        placa = (v.get("placa") or v.get("veh") or "").strip().upper()
        if placa:
            vehiculos_dict[placa] = v
        else:
            vehiculos_dict[str(uuid.uuid4())] = v
            
    # Traer también los vehículos creados en subsidio
    if u.get("empresa"):
        sub_veh = db.subsidio_vehicles.find({"empresa": u["empresa"]})
        async for sv in sub_veh:
            placa = (sv.get("placa") or "").strip().upper()
            if placa and placa not in vehiculos_dict:
                # Add to main vehicles list dynamically
                sv["_id"] = str(sv.get("_id", uuid.uuid4()))
                sv["veh"] = placa
                sv["categoria"] = sv.get("categoria", "N1")
                vehiculos_dict[placa] = sv
                
    return list(vehiculos_dict.values())


@api.get("/vehiculos/kpis")
async def vehiculos_kpis(req: Request):
    """KPIs resumen para el módulo Vehículos (tarjetas superiores)."""
    u = await require_auth(req)
    empresa = None if u["role"] == "admin_enered" else u.get("empresa")
    filt_emp = {"empresa": empresa} if empresa else {}

    total_veh = 0
    en_taller = 0
    sin_gps = 0
    veh_placas = set()
    async for v in db.vehiculos.find(filt_emp):
        total_veh += 1
        estado = (v.get("estado") or "").strip().upper()
        if estado == "TALLER":
            en_taller += 1
        if not (v.get("gps") or v.get("device_gps") or v.get("imei")):
            sin_gps += 1
        placa = v.get("placa") or v.get("veh")
        if placa:
            veh_placas.add(str(placa).upper().strip())
            
    # Include subsidio vehicles not in main fleet
    if empresa:
        async for sv in db.subsidio_vehicles.find({"empresa": empresa}):
            placa = (sv.get("placa") or "").upper().strip()
            if placa and placa not in veh_placas:
                total_veh += 1
                veh_placas.add(placa)
                sin_gps += 1 # subsidio vehicles usually don't have GPS tracking by default

    # Docs vencidos (vehículo y chofer) — solo cuenta placas/personas UNIQUE
    docs_veh_venc_placas = set()
    docs_chofer_venc_ids = set()

    # 1) Docs manuales (colección db.documents)
    async for d in db.documents.find({**filt_emp, "est": "Vencido"}):
        tipo = (d.get("tipo") or "").lower()
        if tipo in ("vehículos", "vehiculos"):
            placa = (d.get("placa") or "").upper().strip()
            if placa:
                docs_veh_venc_placas.add(placa)
        elif tipo == "personal":
            key = d.get("conductor_id") or d.get("dni") or d.get("por") or d.get("id")
            if key:
                docs_chofer_venc_ids.add(str(key))

    # 2) Docs de subsidio (vehículos): compara vigente_hasta contra hoy
    sub_veh_filter = {}
    if empresa:
        sub_veh_filter["empresa"] = empresa
    now_dt = datetime.now(timezone.utc)
    async for sv in db.subsidio_vehicles.find(sub_veh_filter):
        vh = sv.get("vigente_hasta")
        if not vh:
            continue
        try:
            if "-" in vh:
                parts = vh.split("-")
                y, m, d = int(parts[0]), int(parts[1]), int(parts[2][:2])
            else:
                dd, mm, yy = vh.split("/")[:3]
                y = int(yy) + (2000 if len(yy) == 2 else 0)
                m, d = int(mm), int(dd)
            exp_dt = datetime(y, m, d, tzinfo=timezone.utc)
            if exp_dt < now_dt:
                placa = (sv.get("placa") or "").upper().strip()
                if placa:
                    docs_veh_venc_placas.add(placa)
        except Exception:
            continue

    # Vehículos con infracciones
    veh_inf_ids = set()
    async for i in db.infracciones.find(filt_emp):
        vid = i.get("vehiculo_id") or i.get("placa")
        if vid:
            veh_inf_ids.add(str(vid).upper().strip())

    # Vehículos con cargas inválidas (galones<=0 o importe<=0 o sin placa)
    veh_cargas_inv = set()
    cons_filter = {}
    if empresa:
        cons_filter["EMPRESA"] = empresa
    async for c in db.consumptions.find(cons_filter, {"PLACA": 1, "GALONES": 1, "IMPORTE": 1}):
        gal = c.get("GALONES") or 0
        imp = c.get("IMPORTE") or 0
        placa = (c.get("PLACA") or "").upper().strip()
        try:
            gal = float(gal); imp = float(imp)
        except Exception:
            gal, imp = 0, 0
        if gal <= 0 or imp <= 0 or not placa:
            if placa:
                veh_cargas_inv.add(placa)

    return {
        "total_vehiculos": total_veh,
        "sin_gps": sin_gps,
        "en_taller": en_taller,
        "docs_vehiculo_vencidos": len(docs_veh_venc_placas),
        "docs_chofer_vencidos": len(docs_chofer_venc_ids),
        "vehiculos_con_infracciones": len(veh_inf_ids),
        "vehiculos_con_cargas_invalidas": 0,
    }


@api.post("/vehiculos")
async def create_vehiculo(req: Request, body: VehiculoCreate):
    u = await require_auth(req)
    
    # Validar placa única
    existing = await db.vehiculos.find_one({"placa": body.placa.upper()})
    if existing:
        raise HTTPException(400, f"La placa {body.placa} ya existe")
    
    doc = {
        "id": str(uuid.uuid4()),
        "placa": body.placa.upper(),
        "marca": body.marca,
        "modelo": body.modelo,
        "año": body.año,
        "chasis": body.chasis,
        "estado": body.estado or "OPERATIVO",
        "unidad": body.unidad,
        "tipo": body.tipo,
        "base": body.base,
        "titular": body.titular,
        "cc": body.cc,
        "conductor_principal_id": body.conductor_principal_id,
        "empresa": body.empresa or u.get("empresa"),
        "kilometraje": body.kilometraje,
        "proximo_mtto_fecha": body.proximo_mtto_fecha,
        "proximo_mtto_km": body.proximo_mtto_km,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": u["id"],
    }
    await db.vehiculos.insert_one(doc)
    doc.pop("_id", None)
    return doc

async def _buscar_vehiculo(vehiculo_id: str):
    """El módulo Vehículos lista dos colecciones: `vehiculos` (generales) y `subsidio_vehicles`
    (flota registrada en el subsidio). Editar/eliminar debe resolver en ambas; antes solo
    miraba la primera y una placa del subsidio daba "Vehículo no encontrado" al guardar."""
    v = await db.vehiculos.find_one({"id": vehiculo_id})
    if v:
        return db.vehiculos, v
    v = await db.subsidio_vehicles.find_one({"id": vehiculo_id})
    if v:
        return db.subsidio_vehicles, v
    try:
        from bson import ObjectId
        oid = ObjectId(vehiculo_id)
        for col in (db.vehiculos, db.subsidio_vehicles):
            v = await col.find_one({"_id": oid})
            if v:
                return col, v
    except Exception:
        pass
    return None, None


@api.put("/vehiculos/{vehiculo_id}")
async def update_vehiculo(req: Request, vehiculo_id: str, body: VehiculoUpdate):
    u = await require_auth(req)
    
    col, v = await _buscar_vehiculo(vehiculo_id)
    if not v:
        raise HTTPException(404, "Vehículo no encontrado")
    if u.get("role") != "admin_enered" and (v.get("empresa") or "") != (u.get("empresa") or ""):
        raise HTTPException(403, "No puedes editar vehículos de otra empresa")
    
    updates = {k: val for k, val in body.dict(exclude_unset=True).items() if val is not None}
    if "placa" in updates:
        updates["placa"] = (updates["placa"] or "").strip().upper()
        if not updates["placa"]:
            updates.pop("placa")
    if updates:
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        await col.update_one({"_id": v["_id"]}, {"$set": updates})
    
    updated = await col.find_one({"_id": v["_id"]})
    updated["_id"] = str(updated["_id"])
    if col is db.subsidio_vehicles:
        updated["veh"] = updated.get("placa")
        updated.setdefault("categoria", "N1")
    return updated

@api.delete("/vehiculos/{vehiculo_id}")
async def delete_vehiculo(req: Request, vehiculo_id: str):
    u = await require_auth(req)
    
    col, v = await _buscar_vehiculo(vehiculo_id)
    if not v:
        raise HTTPException(404, "Vehículo no encontrado")
    # Solo admin ENERED o alguien de la misma empresa puede borrar (antes bastaba con el id).
    if u.get("role") != "admin_enered" and (v.get("empresa") or "") != (u.get("empresa") or ""):
        raise HTTPException(403, "No puedes eliminar vehículos de otra empresa")
    await col.delete_one({"_id": v["_id"]})
    # Los documentos subidos de esa placa (SOAT, CITV, tarjeta…) se archivan para no dejar huérfanos.
    placa = (v.get("placa") or "").upper().strip()
    if placa:
        await db.documents.update_many(
            {"placa": placa, "empresa": v.get("empresa")},
            {"$set": {"archived": 1, "archived_at": datetime.now(timezone.utc).isoformat(),
                      "archived_reason": "vehículo eliminado"}})
    return {"ok": True}

# --- CONDUCTORES ENDPOINTS ---
@api.get("/conductores")
async def list_conductores(req: Request):
    u = await require_auth(req)
    filt = {}
    if u["role"] != "admin_enered" and u.get("empresa"):
        filt["empresa"] = u["empresa"]
    
    cursor = db.conductores.find(filt)
    conductores = []
    async for c in cursor:
        c["_id"] = str(c["_id"])
        conductores.append(c)
    return conductores

@api.post("/conductores")
async def create_conductor(req: Request, body: ConductorCreate):
    u = await require_auth(req)
    if u["role"] not in ["admin_enered", "administrador"]:
        raise HTTPException(403, "Solo administradores pueden crear conductores")
    
    # Validar DNI único
    existing = await db.conductores.find_one({"dni": body.dni})
    if existing:
        raise HTTPException(400, f"El DNI {body.dni} ya existe")
    
    doc = {
        "id": str(uuid.uuid4()),
        "dni": body.dni,
        "nombre": body.nombre,
        "apellidos": body.apellidos,
        "licencia": body.licencia,
        "vencimiento_licencia": body.vencimiento_licencia,
        "telefono": body.telefono,
        "email": body.email,
        "empresa": body.empresa or u.get("empresa"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": u["id"],
    }
    await db.conductores.insert_one(doc)
    doc.pop("_id")
    return doc

@api.put("/conductores/{conductor_id}")
async def update_conductor(req: Request, conductor_id: str, body: ConductorUpdate):
    u = await require_auth(req)
    if u["role"] not in ["admin_enered", "administrador"]:
        raise HTTPException(403, "Solo administradores pueden editar conductores")
    
    c = await db.conductores.find_one({"id": conductor_id})
    if not c:
        raise HTTPException(404, "Conductor no encontrado")
    
    if u["role"] != "admin_enered" and c.get("empresa") != u.get("empresa"):
        raise HTTPException(403, "No tienes acceso a este conductor")
    
    updates = {k: v for k, v in body.dict().items() if v is not None}
    if updates:
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        await db.conductores.update_one({"id": conductor_id}, {"$set": updates})
    
    updated = await db.conductores.find_one({"id": conductor_id})
    updated.pop("_id")
    return updated

@api.delete("/conductores/{conductor_id}")
async def delete_conductor(req: Request, conductor_id: str):
    u = await require_auth(req)
    if u["role"] not in ["admin_enered", "administrador"]:
        raise HTTPException(403, "Solo administradores pueden eliminar conductores")
    
    c = await db.conductores.find_one({"id": conductor_id})
    if not c:
        raise HTTPException(404, "Conductor no encontrado")
    
    if u["role"] != "admin_enered" and c.get("empresa") != u.get("empresa"):
        raise HTTPException(403, "No tienes acceso a este conductor")
    
    await db.conductores.delete_one({"id": conductor_id})
    return {"ok": True}

# --- INFRACCIONES ENDPOINTS ---
@api.get("/infracciones")
async def list_infracciones(req: Request):
    u = await require_auth(req)
    filt = {}
    if u["role"] != "admin_enered" and u.get("empresa"):
        filt["empresa"] = u["empresa"]
    
    cursor = db.infracciones.find(filt).sort("fecha", -1)
    infracciones = []
    async for i in cursor:
        i["_id"] = str(i["_id"])
        # Obtener datos del vehículo
        if i.get("vehiculo_id"):
            vehiculo = await db.vehiculos.find_one({"id": i["vehiculo_id"]})
            if vehiculo:
                i["vehiculo_placa"] = vehiculo.get("placa")
        # Obtener datos del conductor
        if i.get("conductor_id"):
            conductor = await db.conductores.find_one({"id": i["conductor_id"]})
            if conductor:
                i["conductor_nombre"] = f"{conductor.get('nombre')} {conductor.get('apellidos')}"
        infracciones.append(i)
    return infracciones

@api.post("/infracciones")
async def create_infraccion(req: Request, body: InfraccionCreate):
    u = await require_auth(req)
    if u["role"] not in ["admin_enered", "administrador"]:
        raise HTTPException(403, "Solo administradores pueden registrar infracciones")
    
    # Validar que el vehículo existe
    vehiculo = await db.vehiculos.find_one({"id": body.vehiculo_id})
    if not vehiculo:
        raise HTTPException(404, "Vehículo no encontrado")
    
    # Validar que el conductor existe (si se proporciona)
    if body.conductor_id:
        conductor = await db.conductores.find_one({"id": body.conductor_id})
        if not conductor:
            raise HTTPException(404, "Conductor no encontrado")
    
    doc = {
        "id": str(uuid.uuid4()),
        "vehiculo_id": body.vehiculo_id,
        "conductor_id": body.conductor_id,
        "fecha": body.fecha,
        "codigo": body.codigo,
        "descripcion": body.descripcion,
        "monto": body.monto,
        "estado": body.estado,
        "lugar": body.lugar,
        "papeleta": body.papeleta,
        "observaciones": body.observaciones,
        "empresa": body.empresa or u.get("empresa") or vehiculo.get("empresa"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": u["id"],
    }
    await db.infracciones.insert_one(doc)
    doc.pop("_id")
    return doc

@api.put("/infracciones/{infraccion_id}")
async def update_infraccion(req: Request, infraccion_id: str, body: InfraccionUpdate):
    u = await require_auth(req)
    if u["role"] not in ["admin_enered", "administrador"]:
        raise HTTPException(403, "Solo administradores pueden editar infracciones")
    
    i = await db.infracciones.find_one({"id": infraccion_id})
    if not i:
        raise HTTPException(404, "Infracción no encontrada")
    
    if u["role"] != "admin_enered" and i.get("empresa") != u.get("empresa"):
        raise HTTPException(403, "No tienes acceso a esta infracción")
    
    updates = {k: v for k, v in body.dict().items() if v is not None}
    if updates:
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        await db.infracciones.update_one({"id": infraccion_id}, {"$set": updates})
    
    updated = await db.infracciones.find_one({"id": infraccion_id})
    updated.pop("_id")
    return updated

@api.delete("/infracciones/{infraccion_id}")
async def delete_infraccion(req: Request, infraccion_id: str):
    u = await require_auth(req)
    if u["role"] not in ["admin_enered", "administrador"]:
        raise HTTPException(403, "Solo administradores pueden eliminar infracciones")
    
    i = await db.infracciones.find_one({"id": infraccion_id})
    if not i:
        raise HTTPException(404, "Infracción no encontrada")
    
    if u["role"] != "admin_enered" and i.get("empresa") != u.get("empresa"):
        raise HTTPException(403, "No tienes acceso a esta infracción")
    
    await db.infracciones.delete_one({"id": infraccion_id})
    return {"ok": True}

# --- DASHBOARD INFRACCIONES ---
@api.get("/infracciones/dashboard/stats")
async def infracciones_dashboard(req: Request):
    u = await require_auth(req)
    filt = {}
    if u["role"] != "admin_enered" and u.get("empresa"):
        filt["empresa"] = u["empresa"]
    
    # Total infracciones
    total = await db.infracciones.count_documents(filt)
    
    # Por estado
    pendientes = await db.infracciones.count_documents({**filt, "estado": "pendiente"})
    pagadas = await db.infracciones.count_documents({**filt, "estado": "pagada"})
    impugnadas = await db.infracciones.count_documents({**filt, "estado": "impugnada"})
    
    # Monto total pendiente
    cursor_pendiente = db.infracciones.find({**filt, "estado": "pendiente"})
    monto_pendiente = 0
    async for inf in cursor_pendiente:
        monto_pendiente += inf.get("monto", 0)
    
    # Monto total pagado
    cursor_pagada = db.infracciones.find({**filt, "estado": "pagada"})
    monto_pagado = 0
    async for inf in cursor_pagada:
        monto_pagado += inf.get("monto", 0)
    
    return {
        "total": total,
        "pendientes": pendientes,
        "pagadas": pagadas,
        "impugnadas": impugnadas,
        "monto_pendiente": monto_pendiente,
        "monto_pagado": monto_pagado,
    }


# ---------- Wialon: SID on-demand para iframe embed ----------
@api.get("/wialon/sid")
async def get_wialon_sid(empresa: Optional[str] = None, user: dict = Depends(get_current_user)):
    """
    Genera un session_id (sid) fresco de Wialon usando el token guardado.
    - Usuario cliente: usa el token de SU empresa (ignora ?empresa=).
    - admin_enered: debe pasar ?empresa=NOMBRE para elegir qué cliente monitorear.
    """
    if user.get("role") == "admin_enered":
        if not empresa:
            raise HTTPException(status_code=400, detail="admin_enered debe indicar ?empresa=<nombre>")
        target_empresa = empresa
    else:
        target_empresa = user.get("empresa")
        if not target_empresa:
            raise HTTPException(status_code=400, detail="Usuario sin empresa asociada")
    info = await _svc.get_empresa_servicios(db, target_empresa)
    if not info["servicios"].get("gps"):
        raise HTTPException(status_code=403, detail=f"Servicio GPS no habilitado para {target_empresa}")
    cfg = await _svc.get_empresa_wialon_config(db, target_empresa)
    if not cfg:
        raise HTTPException(status_code=404, detail="Token Wialon no configurado. Contacta al administrador de ENERED.")
    result = await _svc.test_wialon_connection(cfg["token"], cfg["host"])
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=f"Wialon rechazó el token: {result.get('error')}")
    import json as _json, httpx as _httpx
    host = cfg["host"]
    base = f"https://{host}/wialon/ajax.html"
    async with _httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(base, params={"svc": "token/login", "params": _json.dumps({"token": cfg["token"]})})
        data = r.json()
        sid = data.get("eid") if isinstance(data, dict) else None
    if not sid:
        raise HTTPException(status_code=502, detail="No se pudo generar sesión Wialon")
    api_base = (result.get("base_url") or f"https://{host}").rstrip("/")
    ui_base = api_base.replace("hst-api.", "hosting.").replace("http://", "https://")
    return {
        "empresa": target_empresa,
        "sid": sid,
        "host": host,
        "base_url": ui_base,
        "iframe_url": f"{ui_base}/?sid={sid}&lang=es",
        "total_unidades": result.get("total_unidades", 0),
        "user": result.get("user", ""),
    }


# ---------- Wialon: listar empresas con GPS configurado (para selector admin) ----------
@api.get("/wialon/empresas")
async def list_empresas_with_wialon(user: dict = Depends(require_roles("admin_enered"))):
    """Lista empresas con servicios.gps=true Y token Wialon guardado — usado por selector de admin."""
    out = []
    async for cfg in db.empresas_config.find({}, {"_id": 0}):
        serv = _svc._normalize_servicios(cfg.get("servicios"))
        if serv.get("gps") and (cfg.get("wialon") or {}).get("token"):
            out.append({"empresa": cfg["empresa"], "tipo_cliente": cfg.get("tipo_cliente", "enered")})
    return out


# ---------- Wialon: obtener unidades con última posición (reemplaza iframe bloqueado por X-Frame) ----------
@api.get("/wialon/units")
async def get_wialon_units(empresa: Optional[str] = None, user: dict = Depends(get_current_user)):
    """
    Retorna lista de unidades con última posición conocida.
    Cliente: usa su propia empresa. admin_enered: debe pasar ?empresa=X.
    """
    if user.get("role") == "admin_enered":
        if not empresa:
            raise HTTPException(status_code=400, detail="admin_enered debe indicar ?empresa=<nombre>")
        target_empresa = empresa
    else:
        target_empresa = user.get("empresa")
        if not target_empresa:
            raise HTTPException(status_code=400, detail="Usuario sin empresa asociada")
    info = await _svc.get_empresa_servicios(db, target_empresa)
    if not info["servicios"].get("gps"):
        raise HTTPException(status_code=403, detail=f"Servicio GPS no habilitado para {target_empresa}")
    cfg = await _svc.get_empresa_wialon_config(db, target_empresa)
    if not cfg:
        raise HTTPException(status_code=404, detail="Token Wialon no configurado")
    import json as _json, httpx as _httpx
    host = cfg["host"]
    base = f"https://{host}/wialon/ajax.html"
    try:
        async with _httpx.AsyncClient(timeout=15.0) as client:
            # 1) Login
            r = await client.get(base, params={"svc": "token/login", "params": _json.dumps({"token": cfg["token"]})})
            d = r.json()
            if not isinstance(d, dict) or "eid" not in d:
                raise HTTPException(status_code=502, detail=f"Login Wialon falló: {d.get('error') if isinstance(d,dict) else 'unknown'}")
            sid = d["eid"]
            # 2) search_items con flags para position + counters + lastMsg
            # 1 (sys) + 8 (pos) + 1024 (lmsg) + 4096 (cnm/cml counters) + 8192 (adv counters) = 13321
            search_params = {
                "spec": {"itemsType":"avl_unit","propName":"sys_name","propValueMask":"*","sortType":"sys_name","propType":"property"},
                "force": 1, "flags": 13321, "from": 0, "to": 500,
            }
            r2 = await client.get(base, params={"svc":"core/search_items", "params": _json.dumps(search_params), "sid": sid})
            d2 = r2.json()
    except _httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"No se pudo conectar a Wialon ({host}): {str(e)}")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=502, detail=f"Error inesperado consultando Wialon: {str(e)}")

    units = []
    for u in (d2.get("items") or []):
        pos = u.get("pos") or {}
        lmsg = u.get("lmsg") or {}
        lmsg_p = lmsg.get("p") or {}
        
        # Odometer / kilometraje de Wialon
        # Wialon cml = counter mileage value (en metros o km)
        cml_val = u.get("cml") or u.get("cnm")
        odometer = 0
        if isinstance(cml_val, (int, float)) and cml_val > 0:
            odometer = cml_val
        elif isinstance(cml_val, dict):
            odometer = cml_val.get("m") or cml_val.get("cml") or cml_val.get("mileage") or cml_val.get("odometer") or 0

        if not odometer:
            odometer = (
                lmsg_p.get("mileage") or 
                lmsg_p.get("odometer") or 
                lmsg_p.get("can_mileage") or 
                lmsg_p.get("can_odometer") or 
                lmsg_p.get("total_dist") or 
                lmsg_p.get("dist") or 
                lmsg_p.get("gps_mileage") or 
                0
            )

        # Fallback a la BD si Wialon reporta 0 para esa unidad
        unit_name = (u.get("nm") or "").strip().upper()
        if not odometer and unit_name:
            latest_cons = await db.consumptions.find_one(
                {"PLACA": unit_name},
                {"_id": 0, "KILOMETRAJE": 1},
                sort=[("FECHA", -1)]
            )
            if latest_cons and latest_cons.get("KILOMETRAJE"):
                try:
                    km_num = float(latest_cons["KILOMETRAJE"])
                    if km_num > 0:
                        odometer = km_num * 1000
                except Exception:
                    pass
        
        # Ignición / estado
        ignition = lmsg_p.get("engine_ignition")
        if ignition is None:
            ignition = lmsg_p.get("acc")
        if ignition is None:
            ignition = lmsg_p.get("ignition")
        if ignition is None:
            ignition = 1 if (pos.get("s") or 0) > 3 else 0

        # Conductor asignado en BD
        driver_name = None
        driver_dni = None
        if unit_name:
            veh = await db.vehiculos.find_one({"placa": unit_name}, {"_id": 0, "conductor_principal": 1, "conductor_principal_id": 1, "driver_name": 1, "driver_dni": 1, "dni": 1})
            if veh:
                driver_name = veh.get("conductor_principal") or veh.get("driver_name")
                driver_dni = veh.get("driver_dni") or veh.get("dni")
                if not driver_name and veh.get("conductor_principal_id"):
                    cond = await db.users.find_one({"id": veh["conductor_principal_id"]}, {"_id": 0, "nombre": 1, "name": 1, "dni": 1})
                    if cond:
                        driver_name = cond.get("nombre") or cond.get("name")
                        driver_dni = cond.get("dni")

        units.append({
            "id": u.get("id"),
            "name": u.get("nm") or "",
            "lat": pos.get("y"),
            "lon": pos.get("x"),
            "speed": pos.get("s"),
            "course": pos.get("c"),
            "timestamp": pos.get("t") or lmsg.get("t"),
            "sat_count": pos.get("sc"),
            "odometer": odometer,
            "ignition": bool(ignition),
            "driver_name": driver_name,
            "driver_dni": driver_dni,
            "params": lmsg_p
        })
    # Bounding box (para el mapa)
    lats = [u["lat"] for u in units if u.get("lat") is not None]
    lons = [u["lon"] for u in units if u.get("lon") is not None]
    bbox = None
    if lats and lons:
        # padding
        pad = 0.02
        bbox = {
            "min_lat": min(lats) - pad, "max_lat": max(lats) + pad,
            "min_lon": min(lons) - pad, "max_lon": max(lons) + pad,
        }
    return {"empresa": target_empresa, "total": len(units), "units": units, "bbox": bbox}


# ---------- Wialon: helpers de informes ----------
async def _resolve_wialon_target(user: dict, empresa: Optional[str]):
    """Resuelve la empresa objetivo + valida GPS + devuelve (target_empresa, cfg). Reutilizado por endpoints Wialon."""
    if user.get("role") == "admin_enered":
        if not empresa:
            raise HTTPException(status_code=400, detail="admin_enered debe indicar empresa")
        target = empresa
    else:
        target = user.get("empresa")
        if not target:
            raise HTTPException(status_code=400, detail="Usuario sin empresa asociada")
    info = await _svc.get_empresa_servicios(db, target)
    if not info["servicios"].get("gps"):
        raise HTTPException(status_code=403, detail=f"Servicio GPS no habilitado para {target}")
    cfg = await _svc.get_empresa_wialon_config(db, target)
    if not cfg:
        raise HTTPException(status_code=404, detail="Token Wialon no configurado. Contacta al administrador de ENERED.")
    return target, cfg


async def _wialon_login(cfg: dict):
    """Login a Wialon con el token guardado. Devuelve (client, base_url, sid). El caller debe cerrar el client."""
    import json as _json, httpx as _httpx
    host = cfg["host"]
    base = f"https://{host}/wialon/ajax.html"
    client = _httpx.AsyncClient(timeout=90.0)
    try:
        r = await client.get(base, params={"svc": "token/login", "params": _json.dumps({"token": cfg["token"]})})
        d = r.json()
    except _httpx.RequestError as e:
        await client.aclose()
        raise HTTPException(status_code=502, detail=f"No se pudo conectar a Wialon: {str(e)}")
    sid = d.get("eid") if isinstance(d, dict) else None
    if not sid:
        await client.aclose()
        raise HTTPException(status_code=502, detail=f"Login Wialon falló: {d.get('error') if isinstance(d, dict) else 'desconocido'}")
    return client, base, sid


def _classify_report(name: str) -> str:
    """Clasifica una plantilla de informe por su nombre para agrupar en la UI."""
    n = (name or "").upper()
    if any(k in n for k in ["COMBUSTIBLE", "FUEL", "CONSUMO", "ADBLUE", "FLS"]):
        return "combustible"
    if any(k in n for k in ["VIAJE", "RECORR", "TRIP", "KILOMET", "ESTACIONAM", "ACTIVIDAD DIARIA"]):
        return "viajes"
    if any(k in n for k in ["VELOCIDAD", "SPEED", "CONDUC", "EFICIEN", "ECO", "EVENTO"]):
        return "conduccion"
    if any(k in n for k in ["MANTENIM", "SERVICE", "SERVICIO"]):
        return "mantenimiento"
    return "otros"


# ---------- Wialon: listar plantillas de informe disponibles ----------
@api.get("/wialon/report/templates")
async def wialon_report_templates(empresa: Optional[str] = None, user: dict = Depends(get_current_user)):
    """
    Lista las plantillas de informe configuradas en la cuenta Wialon de la empresa,
    con una categoría estimada (combustible / viajes / conduccion / mantenimiento / otros).
    """
    import json as _json
    target, cfg = await _resolve_wialon_target(user, empresa)
    client, base, sid = await _wialon_login(cfg)
    try:
        # search_items de recursos con flag 0x2000 (report templates)
        params = {
            "spec": {"itemsType": "avl_resource", "propName": "sys_name", "propValueMask": "*", "sortType": "sys_name"},
            "force": 1, "flags": 0x00000001 | 0x00002000, "from": 0, "to": 200,
        }
        r = await client.get(base, params={"svc": "core/search_items", "params": _json.dumps(params), "sid": sid})
        d = r.json()
    finally:
        await client.aclose()
    out = []
    for rr in (d.get("items") or []):
        for rid, tpl in (rr.get("rep") or {}).items():
            nm = tpl.get("n") or ""
            ct = tpl.get("ct") or ""
            out.append({
                "resource_id": rr.get("id"),
                "template_id": int(rid),
                "name": nm,
                "object_type": ct,
                "single_unit": ct == "avl_unit",
                "category": _classify_report(nm),
            })
    # Priorizar informes de unidad individual y las categorías útiles
    orden = {"combustible": 0, "viajes": 1, "conduccion": 2, "mantenimiento": 3, "otros": 4}
    out.sort(key=lambda t: (0 if t["single_unit"] else 1, orden.get(t["category"], 9), t["name"].lower()))
    return {"empresa": target, "total": len(out), "templates": out}


# ---------- Wialon: ejecutar un informe y traer sus tablas ----------
@api.post("/wialon/report/run")
async def wialon_report_run(body: WialonReportRunIn, user: dict = Depends(get_current_user)):
    """
    Ejecuta un informe Wialon para UNA unidad en un rango de fechas y devuelve las tablas
    resultantes (cabeceras + filas). Wialon calcula internamente los sensores (nivel de
    combustible, cargas/robos, etc.), por eso maneja cualquier configuración de sensor.
    """
    import json as _json
    MAX_ROWS = 1500  # límite por tabla para no traer tablas gigantes (ej. seguimiento de mensajes)
    target, cfg = await _resolve_wialon_target(user, body.empresa)
    if body.date_to <= body.date_from:
        raise HTTPException(status_code=400, detail="Rango de fechas inválido")
    client, base, sid = await _wialon_login(cfg)
    try:
        # limpiar cualquier resultado previo en la sesión
        await client.get(base, params={"svc": "report/cleanup_result", "params": "{}", "sid": sid})
        exec_params = {
            "reportResourceId": body.resource_id,
            "reportTemplateId": body.template_id,
            "reportObjectId": body.unit_id,
            "reportObjectSecId": 0,
            "interval": {"from": body.date_from, "to": body.date_to, "flags": 0},
        }
        r = await client.get(base, params={"svc": "report/exec_report", "params": _json.dumps(exec_params), "sid": sid})
        ex = r.json()
        if isinstance(ex, dict) and ex.get("error"):
            raise HTTPException(status_code=502, detail=f"Wialon error {ex.get('error')} al ejecutar informe")
        tables_meta = (ex.get("reportResult") or {}).get("tables") or []
        tables = []
        for ti, tmeta in enumerate(tables_meta):
            nrows = int(tmeta.get("rows") or 0)
            header = tmeta.get("header") or []
            truncated = nrows > MAX_ROWS
            fetch_to = min(nrows, MAX_ROWS)
            rows = []
            if fetch_to > 0:
                rr = await client.get(base, params={
                    "svc": "report/get_result_rows",
                    "params": _json.dumps({"tableIndex": ti, "indexFrom": 0, "indexTo": fetch_to}),
                    "sid": sid,
                })
                raw_rows = rr.json()
                if isinstance(raw_rows, list):
                    for row in raw_rows:
                        cells = []
                        for c in (row.get("c") or []):
                            if isinstance(c, dict):
                                cells.append(c.get("t", ""))
                            else:
                                cells.append(c)
                        rows.append(cells)
            tables.append({
                "index": ti,
                "label": tmeta.get("label") or tmeta.get("n") or f"Tabla {ti+1}",
                "header": header,
                "rows": rows,
                "total_rows": nrows,
                "truncated": truncated,
            })
        # limpiar resultado en el servidor
        await client.get(base, params={"svc": "report/cleanup_result", "params": "{}", "sid": sid})
    finally:
        await client.aclose()
    return {
        "empresa": target,
        "unit_id": body.unit_id,
        "date_from": body.date_from,
        "date_to": body.date_to,
        "tables": tables,
    }


# ---------- Wialon: evaluador de sensores (para gráfica de combustible) ----------
def _wialon_parse_table(d):
    """Parsea la tabla de calibración de un sensor Wialon: 'label|x0:y0:x1:y1...' -> [(x,y),...]."""
    if not d:
        return None
    body = str(d).split("|")[-1] if "|" in str(d) else str(d)
    try:
        nums = [float(x) for x in body.split(":") if x.strip() != ""]
    except Exception:
        return None
    pts = [(nums[i], nums[i + 1]) for i in range(0, len(nums) - 1, 2)]
    return pts or None


def _wialon_interp(pts, x):
    """Interpolación lineal a trozos sobre la tabla de calibración."""
    if not pts:
        return x
    if x <= pts[0][0]:
        return pts[0][1]
    if x >= pts[-1][0]:
        return pts[-1][1]
    for i in range(len(pts) - 1):
        x0, y0 = pts[i]
        x1, y1 = pts[i + 1]
        if x0 <= x <= x1:
            return y0 if x1 == x0 else y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return pts[-1][1]


_SAFE_EXPR_RE = re.compile(r"^[\d\s\.\+\-\*/\(\)]+$")


def _wialon_eval_sensor(sensor, sensors_by_name, params, depth=0):
    """
    Evalúa el valor de un sensor Wialon para un mensaje, resolviendo fórmulas
    ([Otro Sensor]) y aplicando su tabla de calibración. Maneja cualquier
    configuración: parámetro directo (CANbus/%), fórmula de tanques, etc.
    """
    if depth > 6 or not sensor:
        return None
    p = str(sensor.get("p") or "").strip()
    raw = None
    if "[" in p:
        # fórmula que referencia otros sensores por nombre
        expr = re.sub(r"\[([^\]]+)\]",
                      lambda m: str(_wialon_eval_sensor(sensors_by_name.get(m.group(1)), sensors_by_name, params, depth + 1) or 0),
                      p)
        if _SAFE_EXPR_RE.match(expr or ""):
            try:
                raw = eval(expr, {"__builtins__": {}}, {})  # noqa: S307 — expr saneada a solo aritmética
            except Exception:
                raw = None
    elif p in params:
        raw = params.get(p)
    elif p:
        # expresión con nombres de parámetros (ej. "io_270*0.1")
        expr = re.sub(r"[a-zA-Z_]\w*", lambda m: str(params.get(m.group(0), 0)), p)
        if _SAFE_EXPR_RE.match(expr or ""):
            try:
                raw = eval(expr, {"__builtins__": {}}, {})  # noqa: S307
            except Exception:
                raw = None
    if raw is None:
        return None
    try:
        raw = float(raw)
    except Exception:
        return None
    pts = _wialon_parse_table(sensor.get("d"))
    val = _wialon_interp(pts, raw) if pts else raw
    try:
        return round(float(val), 2)
    except Exception:
        return None


def _is_fuel_sensor(s):
    t = (s.get("t") or "").lower()
    n = (s.get("n") or "").upper()
    if "fuel" in t:
        return True
    return any(k in n for k in ["COMBUSTIBLE", "TANQUE", "NIVEL DE COMB", "% TANQUE", "FUEL", "CAN_FUEL"])


# ---------- Wialon: serie temporal de nivel de combustible (gráfica) ----------
@api.post("/wialon/fuel-graph")
async def wialon_fuel_graph(body: WialonFuelGraphIn, user: dict = Depends(get_current_user)):
    """
    Devuelve la serie temporal de nivel de combustible de una unidad, calculada a
    partir de los mensajes crudos + la configuración de sensores (fórmulas y tablas
    de calibración). Auto-detecta los sensores de combustible de la unidad, por lo
    que funciona con cualquier configuración (CANbus, % de tanque, tanques izq/der).
    """
    import json as _json
    MAX_MSGS = 6000       # tope de mensajes a cargar
    MAX_POINTS = 500      # puntos por serie devueltos al frontend (downsample)
    target, cfg = await _resolve_wialon_target(user, body.empresa)
    if body.date_to <= body.date_from:
        raise HTTPException(status_code=400, detail="Rango de fechas inválido")
    client, base, sid = await _wialon_login(cfg)
    try:
        # 1) config de sensores de la unidad (flag 0x1000)
        r = await client.get(base, params={
            "svc": "core/search_item",
            "params": _json.dumps({"id": body.unit_id, "flags": 0x00000001 | 0x00001000}),
            "sid": sid,
        })
        item = (r.json() or {}).get("item") or {}
        unit_name = item.get("nm") or ""
        sens = item.get("sens") or {}
        by_name = {s.get("n"): s for s in sens.values()}
        # sensores de combustible: preferir los de tipo "fuel level" (el total calculado)
        fuel_sensors = [s for s in sens.values() if (s.get("t") or "").lower().find("fuel") >= 0]
        if not fuel_sensors:
            fuel_sensors = [s for s in sens.values() if _is_fuel_sensor(s)]
        if not fuel_sensors:
            raise HTTPException(status_code=404, detail=f"La unidad {unit_name or body.unit_id} no tiene sensores de combustible configurados en Wialon.")
        # 2) cargar mensajes del intervalo
        rr = await client.get(base, params={
            "svc": "messages/load_interval",
            "params": _json.dumps({"itemId": body.unit_id, "timeFrom": body.date_from, "timeTo": body.date_to,
                                   "flags": 0, "flagsMask": 0, "loadCount": MAX_MSGS}),
            "sid": sid,
        })
        msgs = (rr.json() or {}).get("messages") or []
        await client.get(base, params={"svc": "messages/unload", "params": "{}", "sid": sid})
    finally:
        await client.aclose()

    # 3) evaluar cada sensor de combustible por mensaje
    series = []
    for s in fuel_sensors:
        pts = []
        for m in msgs:
            t = m.get("t")
            v = _wialon_eval_sensor(s, by_name, m.get("p") or {})
            if t is not None and v is not None:
                pts.append((t, v))
        if len(pts) < 2:
            continue
        # downsample uniforme
        if len(pts) > MAX_POINTS:
            step = len(pts) / MAX_POINTS
            pts = [pts[int(i * step)] for i in range(MAX_POINTS)]
        ys = [v for _, v in pts]
        series.append({
            "name": s.get("n") or "Combustible",
            "unit": s.get("m") or "",
            "points": [{"t": t, "v": v} for t, v in pts],
            "min": round(min(ys), 2),
            "max": round(max(ys), 2),
            "first": ys[0],
            "last": ys[-1],
        })
    if not series:
        raise HTTPException(status_code=404, detail="No hay datos de combustible para ese rango de fechas.")
    return {
        "empresa": target,
        "unit_id": body.unit_id,
        "unit_name": unit_name,
        "date_from": body.date_from,
        "date_to": body.date_to,
        "series": series,
    }


# ---------- MTC/DGTT: consulta pública de transporte de mercancías ----------
@api.get("/mtc/consulta")
async def mtc_consulta(tipo: str, valor: str, user: dict = Depends(get_current_user)):
    """
    Consulta la habilitación de transporte de mercancías en el MTC (DGTT).
    tipo ∈ {ruc, placa, partida, constancia}. Devuelve estado (habilitado), N° de
    permiso, vigencia y las unidades/placas autorizadas.
    """
    try:
        return await _mtc.consultar(tipo, valor)
    except _mtc.MtcError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"No se pudo consultar el MTC: {str(e)}")


# ---------- ATU: diagnóstico de subsidio (TUC no reconocidos) ----------
class AtuDiagnosticoIn(BaseModel):
    ruc: Optional[str] = None
    token: Optional[str] = None       # access_token de sesión ATU (opcional)
    data: Optional[dict] = None       # respuesta cruda de la ATU pegada (opcional)


@api.post("/atu/diagnostico")
async def atu_diagnostico(body: AtuDiagnosticoIn, user: dict = Depends(get_current_user)):
    """
    Diagnóstico ATU: detecta unidades habilitadas sin TUC reconocido (que pierden subsidio).
    Acepta el JSON de la ATU pegado (data) o consulta en vivo con (token + ruc).
    """
    try:
        if body.data is not None:
            return _atu.diagnosticar_desde_json(body.data)
        if body.token and body.ruc:
            return await _atu.consultar_habilitaciones(body.token, body.ruc)
        raise _atu.AtuError("Envía el JSON de la ATU (data) o bien token + ruc.")
    except _atu.AtuError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"No se pudo procesar el diagnóstico ATU: {str(e)}")


class AtuConectarIn(BaseModel):
    ruc: str
    access_token: str
    refresh_token: Optional[str] = None


def _atu_pack(session: dict) -> dict:
    """Cifra los tokens de sesión ATU para guardarlos."""
    return {
        "access_token": _svc.encrypt_wialon_token(session["access_token"]),
        "refresh_token": _svc.encrypt_wialon_token(session["refresh_token"]) if session.get("refresh_token") else None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _atu_unpack(doc: dict) -> dict:
    return {
        "access_token": _svc.decrypt_wialon_token(doc["access_token"]),
        "refresh_token": _svc.decrypt_wialon_token(doc["refresh_token"]) if doc.get("refresh_token") else None,
    }


# La sesión ATU maestra de ENERED se guarda con esta clave (una sola sesión sirve para todos los RUCs)
_ATU_MASTER_KEY = "__MASTER__"


def _jwt_exp(token: str):
    """Lee el 'exp' (segundos epoch) de un JWT sin validar la firma."""
    try:
        import base64 as _b64, json as _j
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return _j.loads(_b64.urlsafe_b64decode(p)).get("exp")
    except Exception:
        return None


class AtuMaestraIn(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None


@api.post("/atu/maestra")
async def atu_maestra_conectar(body: AtuMaestraIn, user: dict = Depends(require_roles("admin_enered"))):
    """Conecta la sesión ATU MAESTRA de ENERED (una sola cuenta sirve para consultar cualquier RUC)."""
    acc = (body.access_token or "").strip()
    ref = (body.refresh_token or "").strip()
    if acc.count(".") != 2:
        raise HTTPException(status_code=400, detail="El access_token no parece válido (revisa que lo copiaste completo).")
    if ref and ref.count(".") != 2:
        raise HTTPException(status_code=400, detail="El refresh_token no parece válido (cópialo completo).")
    if not ref:
        raise HTTPException(status_code=400, detail="Falta el refresh_token — es necesario para mantener viva la sesión. Cópialo también.")
    doc = _atu_pack({"access_token": acc, "refresh_token": ref})
    doc["conectado_por"] = user.get("email")
    await db.atu_sessions.update_one({"ruc": _ATU_MASTER_KEY}, {"$set": {**doc, "ruc": _ATU_MASTER_KEY}}, upsert=True)
    return {"ok": True}


@api.get("/atu/maestra")
async def atu_maestra_estado(user: dict = Depends(get_current_user)):
    """Estado de la cuenta maestra: conectada y cuántos minutos de vida le quedan a la sesión."""
    import time as _t
    doc = await db.atu_sessions.find_one({"ruc": _ATU_MASTER_KEY})
    if not doc:
        return {"conectada": False}
    sess = _atu_unpack(doc)
    exp_acc = _jwt_exp(sess.get("access_token"))
    exp_ref = _jwt_exp(sess.get("refresh_token")) if sess.get("refresh_token") else None
    ahora = _t.time()
    return {
        "conectada": True,
        "actualizado": doc.get("updated_at"),
        "min_access": round((exp_acc - ahora) / 60) if exp_acc else None,
        "min_refresh": round((exp_ref - ahora) / 60) if exp_ref else None,
        "tiene_refresh": bool(sess.get("refresh_token")),
    }


@api.get("/atu/analisis")
async def atu_analisis(ruc: str, user: dict = Depends(get_current_user)):
    """
    Análisis por RUC usando la cuenta ATU MAESTRA de ENERED (auto-renueva la sesión si expiró).
    Detecta placas sin TUC y cruza con el MTC. Si el RUC no está inscrito en el subsidio, lo indica.
    """
    ruc = (ruc or "").strip()
    if not re.fullmatch(r"\d{11}", ruc):
        raise HTTPException(status_code=400, detail="El RUC debe tener 11 dígitos")
    doc = await db.atu_sessions.find_one({"ruc": _ATU_MASTER_KEY})
    if not doc:
        return {"ruc": ruc, "conectado": False, "sin_maestra": True}
    session = _atu_unpack(doc)
    try:
        try:
            diag = await _atu.consultar_habilitaciones(session["access_token"], ruc)
        except _atu.AtuError as e:
            msg = str(e).lower()
            if "rechaz" not in msg and "expir" not in msg:
                raise
            session = await _atu_refrescar_maestra(session)
            diag = await _atu.consultar_habilitaciones(session["access_token"], ruc)
    except _atu.AtuError as e:
        return {"ruc": ruc, "conectado": True, "maestra_vencida": True, "error": str(e)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error consultando ATU: {str(e)}")
    # ---- Vista unificada por placa: TODA la flota (MTC) + si la ATU la acepta o no + motivo ----
    import datetime as _dt

    def _norm_placa(p):
        return (p or "").replace("-", "").replace(" ", "").upper()

    def _vencida(vig):
        mm = re.match(r"(\d{2})/(\d{2})/(\d{4})", str(vig or ""))
        if not mm:
            return False
        try:
            return _dt.date(int(mm.group(3)), int(mm.group(2)), int(mm.group(1))) < _dt.date.today()
        except Exception:
            return False

    inscrito = not diag.get("sin_habilitaciones")
    atu_by_placa = {}
    if inscrito:
        for u in diag.get("unidades", []):
            atu_by_placa[_norm_placa(u.get("placa"))] = u

    # Flota completa desde el MTC (fuente de "todas tus placas") + vigencia por autorización
    mtc_vehiculos = []
    try:
        m = await _mtc.consultar("ruc", ruc)
        # Una fila por placa, regida por la autorización activa que APLICA al subsidio.
        for v in _mtc.unidades_para_subsidio(m):
            mtc_vehiculos.append((v, {"vigente_hasta": v.get("vigente_hasta"), "codigo": v.get("autorizacion"),
                                      "permiso": v.get("permiso"), "permiso_aplica": v.get("permiso_aplica")}))
    except Exception:
        pass

    unidades = []
    vistas = set()
    for v, a in mtc_vehiculos:
        pn = _norm_placa(v.get("placa"))
        vistas.add(pn)
        au = atu_by_placa.get(pn)
        aceptada = bool(au) and au.get("tuc_estado") == "ok"
        vig = a.get("vigente_hasta")
        # La ATU no da un motivo por placa (estadoValidacionAutorizacionNombre viene vacío),
        # así que usamos el mismo motivo salvo que la autorización esté vencida en el MTC.
        permiso_ok = a.get("permiso_aplica") is not False
        if aceptada and not permiso_ok:
            # La ATU la acepta, pero el tipo de permiso del MTC no aplica al subsidio.
            aceptada = False
            motivo = f"Permiso {a.get('permiso') or ''} del MTC no aplica al subsidio (solo CNG, MRP, URV, ERG, INT)"
        elif aceptada:
            motivo = None
        elif not permiso_ok:
            motivo = f"Permiso {a.get('permiso') or ''} del MTC no aplica al subsidio (solo CNG, MRP, URV, ERG, INT)"
        elif _vencida(vig):
            motivo = f"Autorización vencida ({vig})"
        else:
            motivo = "La ATU no reconoce su TUC (regularizable)"
        unidades.append({
            "placa": v.get("placa"),
            "categoria": v.get("categoria") or (au.get("categoria") if au else None),
            "tuc": (au.get("tuc") if au else None),
            "aceptada": aceptada,
            "motivo": motivo,
            "numero_autorizacion": (au.get("numero_autorizacion") if au else None) or a.get("codigo") or v.get("constancia"),
            "permiso": a.get("permiso") or "", "permiso_aplica": a.get("permiso_aplica"),
            "vigencia": vig,
        })
    # Placas que la ATU tiene pero no aparecen en el MTC (raras)
    for pn, au in atu_by_placa.items():
        if pn in vistas:
            continue
        aceptada = au.get("tuc_estado") == "ok"
        unidades.append({
            "placa": au.get("placa"), "categoria": au.get("categoria"),
            "tuc": au.get("tuc"), "aceptada": aceptada,
            "motivo": None if aceptada else "La ATU no reconoce su TUC (regularizable)",
            "numero_autorizacion": au.get("numero_autorizacion"), "vigencia": None,
        })

    unidades.sort(key=lambda u: (u["aceptada"], u.get("placa") or ""))
    aceptadas = sum(1 for u in unidades if u["aceptada"])
    return {
        "ruc": ruc, "conectado": True, "inscrito": inscrito,
        "total_unidades": len(unidades),
        "aceptadas": aceptadas,
        "no_aceptadas": len(unidades) - aceptadas,
        "unidades": unidades,
    }


@api.get("/atu/expediente")
async def atu_expediente(ruc: str, debug: int = 0, user: dict = Depends(require_roles("admin_enered"))):
    """Expediente del RUC en la ATU usando la cuenta maestra: comprobantes cargados,
    volumen (gal), monto de compras, subsidio referencial y estado de la DJ (cuando la
    ATU lo expone por RUC). Solo admin ENERED. ?debug=1 incluye las respuestas crudas."""
    ruc = (ruc or "").strip()
    if not re.fullmatch(r"\d{11}", ruc):
        raise HTTPException(status_code=400, detail="El RUC debe tener 11 dígitos")
    doc = await db.atu_sessions.find_one({"ruc": _ATU_MASTER_KEY})
    if not doc:
        return {"ruc": ruc, "conectado": False, "sin_maestra": True}
    session = _atu_unpack(doc)
    try:
        exp, actualizada = await _atu.expediente_con_sesion(session, ruc)
    except _atu.AtuError as e:
        return {"ruc": ruc, "conectado": True, "maestra_vencida": True, "error": str(e)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error consultando ATU: {str(e)}")
    if actualizada.get("access_token") != session.get("access_token"):
        await db.atu_sessions.update_one({"ruc": _ATU_MASTER_KEY}, {"$set": _atu_pack(actualizada)})
    raw = exp.pop("_raw", None)
    if debug:
        exp["_raw"] = raw
    exp["conectado"] = True
    fila = await db.atu_padron.find_one({"ruc": ruc}, {"_id": 0, "dj_manual": 1})
    exp["dj_manual"] = (fila or {}).get("dj_manual")
    exp["fondo_du004"] = 33_800_000  # S/ 33.8 millones asignados por el DU 004-2026 (MTC)
    return exp


async def _atu_sesion_maestra():
    """Sesión maestra ATU desde la BD (o None si no está conectada)."""
    doc = await db.atu_sessions.find_one({"ruc": _ATU_MASTER_KEY})
    return _atu_unpack(doc) if doc else None


_ATU_REFRESH_LOCK = asyncio.Lock()


async def _atu_refrescar_maestra(session_vieja: dict) -> dict:
    """Refresca la sesión maestra UNA sola vez aunque lleguen varias peticiones a la vez:
    bajo lock relee la BD; si otra petición ya la renovó, devuelve esa (el refresh_token
    de la ATU es de un solo uso: refrescar dos veces en paralelo tumbaba la sesión)."""
    async with _ATU_REFRESH_LOCK:
        actual = await _atu_sesion_maestra()
        if actual and actual.get("access_token") != session_vieja.get("access_token"):
            return actual
        if not session_vieja.get("refresh_token"):
            raise _atu.AtuError("La sesión ATU expiró y no hay refresh; vuelve a conectar la cuenta.")
        nuevos = await _atu.refresh_session(session_vieja["refresh_token"])
        nueva = {**session_vieja, **nuevos}
        await db.atu_sessions.update_one({"ruc": _ATU_MASTER_KEY}, {"$set": _atu_pack(nueva)})
        return nueva


async def _atu_con_refresh(fn, *args):
    """Ejecuta fn(access_token, *args) con la sesión maestra; si el token venció, refresca y reintenta."""
    session = await _atu_sesion_maestra()
    if not session:
        raise HTTPException(status_code=409, detail="No hay cuenta ATU maestra conectada")
    try:
        return await fn(session["access_token"], *args)
    except _atu.AtuError as e:
        msg = str(e).lower()
        if "rechaz" not in msg and "expir" not in msg:
            raise HTTPException(status_code=502, detail=str(e))
        try:
            nueva = await _atu_refrescar_maestra(session)
        except _atu.AtuError as e2:
            raise HTTPException(status_code=502, detail=str(e2))
        return await fn(nueva["access_token"], *args)


def _atu_precheck(cp: dict, det: dict, flota_by: dict, periodo: dict | None, grifo_ok) -> dict:
    """Pre-chequeo ENERED de un comprobante cargado en la ATU: anticipa observaciones
    antes de que la ATU lo valide (fechas del plazo, combustible, azufre, tipo SUNAT,
    placa reconocida, tope por unidad, grifo en OSINERGMIN, archivo, nota de crédito)."""
    avisos = []
    ini = (periodo or {}).get("fechaInicio") or "2026-05-29"
    fin = (periodo or {}).get("fechaFin") or "2026-07-29"
    f = cp.get("fecha") or ""
    if f and not (ini <= f <= fin):
        avisos.append(f"Fecha {f} fuera del plazo de compra ({ini} a {fin})")
    combs = det.get("combustibles") or []
    for c in combs:
        if (c.get("codigo") or "").upper() not in ("B5", "B20"):
            avisos.append(f"Combustible {c.get('nombre') or c.get('codigo')} no subsidiable (solo diésel B5/B20)")
    az = det.get("azufre_ppm")
    if az is not None and float(az) > 50:
        avisos.append(f"Azufre {az} ppm (máximo 50 ppm)")
    if (det.get("tipo_sunat") or cp.get("tipo_sunat")) not in (None, "", "01"):
        avisos.append("No es factura electrónica (tipo SUNAT 01)")
    if not (det.get("archivos") or cp.get("tiene_archivo")):
        avisos.append("Sin PDF adjunto")
    placas = det.get("placas") or []
    if cp.get("forma") == "FORMA_A" and not placas:
        avisos.append("Sin placa asignada")
    for pl in placas:
        pn = (pl.get("placa") or "").replace("-", "").upper()
        v = flota_by.get(pn)
        if not v:
            avisos.append(f"Placa {pl.get('placa')} no está en la flota reconocida por la ATU")
        else:
            if not v.get("tuc_vigente") or not v.get("autorizacion_vigente"):
                avisos.append(f"Placa {pl.get('placa')} sin TUC/autorización vigente")
            tope = float(v.get("tope_galones") or 0)
            if tope and float(pl.get("galones") or 0) > tope:
                avisos.append(f"Placa {pl.get('placa')}: {pl.get('galones')} gal supera su tope de {tope} gal")
    if grifo_ok is False:
        avisos.append("Grifo/distribuidor no figura en el padrón OSINERGMIN")
    if det.get("valida_sunat") is False and det.get("fecha_validacion_sunat"):
        avisos.append("SUNAT no validó el comprobante" + (f": {det.get('detalle_validacion_sunat')}" if det.get("detalle_validacion_sunat") else ""))
    if det.get("observacion"):
        avisos.append(f"Observación ATU: {det['observacion']}")
    est = det.get("estado") or cp.get("estado")
    if est == "CONFORME":
        veredicto = "aceptado"
    elif est in ("OBSERVADO", "INHABILITADO"):
        veredicto = "rechazado"
    elif avisos:
        veredicto = "riesgo"
    else:
        veredicto = "ok"
    return {"veredicto": veredicto, "avisos": avisos}


# ---------------------------------------------------------------------------
# Padrón macro: TODAS las empresas de subsidio de NUESTRA base vs. la ATU
# (cuánto puede reclamar cada una, cuánto le reconoce la ATU, si envió su DJ).
# La lista NACIONAL (las ~10,500 del país) NO es accesible con cuenta de
# transportista; esto cubre solo las empresas cargadas en ENERED.
# ---------------------------------------------------------------------------
async def _rucs_subsidio() -> list[dict]:
    """[{ruc, razon_social, user_id}] de todas las empresas con subsidio en la base."""
    empresas = [c.get("empresa") for c in await db.empresas_config.find(
        {"servicios.subsidio": True}, {"_id": 0, "empresa": 1}).to_list(10000) if c.get("empresa")]
    q = {"$or": [{"role": "cliente_subsidio"}]}
    if empresas:
        q["$or"].append({"empresa": {"$in": empresas}, "role": {"$ne": "admin_enered"}})
        q["$or"].append({"empresas_asignadas.empresa": {"$in": empresas}})
    vistos, out = set(), []
    async for u in db.users.find(q, {"_id": 0, "id": 1, "empresa": 1, "ruc": 1, "empresas_asignadas": 1}):
        pares = []
        if u.get("ruc"):
            pares.append((u["ruc"], u.get("empresa")))
        for a in (u.get("empresas_asignadas") or []):
            if a.get("ruc"):
                pares.append((a["ruc"], a.get("empresa")))
        for ruc, emp in pares:
            ruc = (ruc or "").strip()
            if re.fullmatch(r"\d{11}", ruc) and ruc not in vistos:
                vistos.add(ruc)
                out.append({"ruc": ruc, "razon_social": emp, "user_id": u.get("id")})
    return out


def _padron_fila(ruc: str, razon: str, exp: dict) -> dict:
    """Compacta un expediente ATU en una fila del padrón macro."""
    of = exp.get("oficial") or {}
    return {
        "ruc": ruc,
        "razon_social": (exp.get("empresa") or {}).get("razon_social") or razon,
        "inscrito_atu": bool(exp.get("inscrito")),
        "en_padron": (exp.get("empresa") or {}).get("registrado_en_padron"),
        "flota_reconocida": len(exp.get("flota") or []),
        "subsidio_maximo": exp.get("subsidio_maximo_flota"),          # tope flota × 4
        "volumen_galones": exp.get("volumen_galones"),
        "comprobantes": (exp.get("comprobantes") or {}).get("total", 0),
        "subsidio_reconocido": of.get("subsidio_total"),              # cálculo oficial ATU
        "subsidio_estimado": exp.get("subsidio_estimado"),            # S/4 × gal cargado (si no hay oficial)
        "galones_reconocidos": of.get("galones_reconocidos"),
        "galones_no_reconocidos": of.get("galones_no_reconocidos"),
        "entidad_uuid": exp.get("entidad_uuid"),
    }


_ATU_PADRON_SYNC = {"corriendo": False, "hechos": 0, "total": 0, "iniciado": None, "error": None}


async def _atu_padron_sync_run():
    """Recorre nuestras empresas de subsidio y cachea su expediente ATU en db.atu_padron."""
    import asyncio as _aio
    _ATU_PADRON_SYNC.update(corriendo=True, hechos=0, error=None,
                            iniciado=datetime.now(timezone.utc).isoformat())
    try:
        empresas = await _rucs_subsidio()
        _ATU_PADRON_SYNC["total"] = len(empresas)
        sem = _aio.Semaphore(5)

        async def _uno(e):
            async with sem:
                try:
                    exp = await _atu_con_refresh(_atu.consultar_expediente, e["ruc"])
                    fila = _padron_fila(e["ruc"], e.get("razon_social"), exp)
                    fila["error"] = None
                except HTTPException as ex:
                    fila = {"ruc": e["ruc"], "razon_social": e.get("razon_social"), "error": str(ex.detail)[:160]}
                except Exception as ex:
                    fila = {"ruc": e["ruc"], "razon_social": e.get("razon_social"), "error": str(ex)[:160]}
                fila["updated_at"] = datetime.now(timezone.utc).isoformat()
                await db.atu_padron.update_one({"ruc": e["ruc"]}, {"$set": fila}, upsert=True)
                _ATU_PADRON_SYNC["hechos"] += 1

        await _aio.gather(*[_uno(e) for e in empresas])
    except Exception as ex:
        _ATU_PADRON_SYNC["error"] = str(ex)[:200]
    finally:
        _ATU_PADRON_SYNC["corriendo"] = False


@api.post("/atu/padron/sync")
async def atu_padron_sync(user: dict = Depends(require_roles("admin_enered"))):
    """Dispara la actualización del padrón macro en segundo plano. Solo admin ENERED."""
    if _ATU_PADRON_SYNC["corriendo"]:
        return {"ok": True, "ya_corriendo": True, **_ATU_PADRON_SYNC}
    if not await _atu_sesion_maestra():
        raise HTTPException(status_code=409, detail="No hay cuenta ATU maestra conectada")
    asyncio.create_task(_atu_padron_sync_run())
    return {"ok": True, "iniciado": True}


class AtuPadronRucsIn(BaseModel):
    rucs: List[str]


@api.post("/atu/padron/agregar")
async def atu_padron_agregar(body: AtuPadronRucsIn, user: dict = Depends(require_roles("admin_enered"))):
    """Agrega al padrón un universo ARBITRARIO de RUCs (los que la dueña quiera comparar:
    su gremio, un padrón MTC, la competencia) y calcula su expediente ATU. Solo admin ENERED."""
    import asyncio as _aio
    rucs = []
    for r in (body.rucs or []):
        r = re.sub(r"\D", "", str(r or ""))
        if re.fullmatch(r"\d{11}", r) and r not in rucs:
            rucs.append(r)
    if not rucs:
        raise HTTPException(status_code=400, detail="No hay RUCs válidos (11 dígitos) en la lista")
    if not await _atu_sesion_maestra():
        raise HTTPException(status_code=409, detail="No hay cuenta ATU maestra conectada")
    sem = _aio.Semaphore(5)
    resultados = {"ok": 0, "sin_cuenta": 0, "error": 0}

    async def _uno(ruc):
        async with sem:
            try:
                exp = await _atu_con_refresh(_atu.consultar_expediente, ruc)
                fila = _padron_fila(ruc, None, exp); fila["error"] = None
                resultados["ok"] += 1
                if exp.get("inscrito") is False:
                    resultados["sin_cuenta"] += 1
            except Exception as ex:
                fila = {"ruc": ruc, "razon_social": None, "error": str(getattr(ex, "detail", ex))[:160]}
                resultados["error"] += 1
            fila["updated_at"] = datetime.now(timezone.utc).isoformat()
            fila["origen"] = "manual"
            await db.atu_padron.update_one({"ruc": ruc}, {"$set": fila}, upsert=True)

    await _aio.gather(*[_uno(r) for r in rucs])
    return {"ok": True, "procesados": len(rucs), **resultados}


class AtuDjManualIn(BaseModel):
    numero_expediente: Optional[str] = None
    numero_ticket: Optional[str] = None
    fecha: Optional[str] = None
    nota: Optional[str] = None


@api.put("/atu/padron/{ruc}/dj")
async def atu_padron_dj(ruc: str, body: AtuDjManualIn, user: dict = Depends(require_roles("admin_enered"))):
    """Registra a mano el envío de la DJ de un RUC (N.° de expediente y ticket que la ATU
    muestra al transportista). La ATU no lo expone por RUC, así que es nuestra propia info."""
    ruc = (ruc or "").strip()
    if not re.fullmatch(r"\d{11}", ruc):
        raise HTTPException(status_code=400, detail="RUC inválido")
    exp = (body.numero_expediente or "").strip() or None
    tk = re.sub(r"\D", "", body.numero_ticket or "") or None
    if not exp and not tk:
        await db.atu_padron.update_one({"ruc": ruc}, {"$unset": {"dj_manual": ""}})
        return {"ok": True, "dj_manual": None}
    dj = {"numero_expediente": exp, "numero_ticket": tk, "fecha": (body.fecha or "").strip() or None,
          "nota": (body.nota or "").strip() or None, "registrado_por": user.get("email"),
          "registrado_at": datetime.now(timezone.utc).isoformat()}
    await db.atu_padron.update_one({"ruc": ruc}, {"$set": {"ruc": ruc, "dj_manual": dj}}, upsert=True)
    return {"ok": True, "dj_manual": dj}


@api.delete("/atu/padron")
async def atu_padron_limpiar(solo_manual: int = 0, user: dict = Depends(require_roles("admin_enered"))):
    """Vacía el padrón (o solo las filas agregadas a mano con ?solo_manual=1)."""
    q = {"origen": "manual"} if solo_manual else {}
    r = await db.atu_padron.delete_many(q)
    return {"ok": True, "borradas": r.deleted_count}


@api.get("/atu/padron")
async def atu_padron(user: dict = Depends(require_roles("admin_enered"))):
    """Padrón macro: todas las empresas de subsidio de ENERED con lo que la ATU les
    reconoce y su estado de DJ (desde el caché; usa POST /atu/padron/sync para refrescar)."""
    filas = await db.atu_padron.find({}, {"_id": 0}).to_list(10000)
    filas.sort(key=lambda x: (x.get("subsidio_reconocido") or x.get("subsidio_estimado") or 0), reverse=True)
    def _n(x, k):
        return float(x.get(k) or 0)
    total_reclamado = sum(_n(f, "subsidio_reconocido") or _n(f, "subsidio_estimado") for f in filas)
    tickets = [int(f["dj_manual"]["numero_ticket"]) for f in filas
               if (f.get("dj_manual") or {}).get("numero_ticket", "").isdigit()]
    return {
        "items": filas,
        "total_empresas": len(filas),
        "con_dj": sum(1 for f in filas if f.get("dj_manual")),
        # El ticket de la ATU es el orden de prelación nacional: el mayor que tengamos
        # registrado ≈ cuántas solicitudes se han presentado en todo el país.
        "ticket_maximo": max(tickets) if tickets else None,
        "inscritas_atu": sum(1 for f in filas if f.get("inscrito_atu")),
        "sin_cuenta_atu": sum(1 for f in filas if f.get("inscrito_atu") is False),
        "total_reclamado": round(total_reclamado, 2),
        "total_maximo": round(sum(_n(f, "subsidio_maximo") for f in filas), 2),
        "fondo_du004": 33_800_000,
        "sync": _ATU_PADRON_SYNC,
        "actualizado": max((f.get("updated_at") for f in filas if f.get("updated_at")), default=None),
    }


@api.get("/atu/expediente/comprobantes")
async def atu_expediente_comprobantes(ruc: str, user: dict = Depends(require_roles("admin_enered"))):
    """Comprobantes del RUC en la ATU con detalle (placas, azufre, validaciones, PDF)
    y pre-chequeo ENERED de si serán aceptados. Solo admin ENERED."""
    ruc = (ruc or "").strip()
    if not re.fullmatch(r"\d{11}", ruc):
        raise HTTPException(status_code=400, detail="El RUC debe tener 11 dígitos")
    exp = await _atu_con_refresh(_atu.consultar_expediente, ruc)
    lista = exp.get("comprobantes_detalle") or []
    dets = await _atu_con_refresh(_atu.detalle_comprobantes, ruc, [c["uuid"] for c in lista])
    flota_by = {(v.get("placa") or "").replace("-", "").upper(): v for v in (exp.get("flota") or [])}
    # Grifos: una consulta por RUC distribuidor distinto
    from services.padron_grifos import buscar_por_ruc as _grifo
    grifos: dict = {}
    for c in lista:
        rd = c.get("ruc_distribuidor")
        if rd and rd not in grifos:
            try:
                g = await _grifo(db, rd, c.get("distribuidor"))
                grifos[rd] = bool(g and g.get("inscrito", True))
            except Exception:
                grifos[rd] = None
    # Acumulado por placa en TODO el expediente vs. tope de la unidad: la ATU paga solo
    # hasta el tope (así aparecen los "galones no reconocidos" del cálculo oficial).
    acum_placa: dict = {}
    for c in lista:
        for pl in (dets.get(c["uuid"]) or {}).get("placas") or []:
            pn = (pl.get("placa") or "").replace("-", "").upper()
            acum_placa[pn] = acum_placa.get(pn, 0.0) + float(pl.get("galones") or 0)
    out = []
    resumen = {"aceptado": 0, "rechazado": 0, "riesgo": 0, "ok": 0}
    for c in lista:
        d = dets.get(c["uuid"]) or {}
        pre = _atu_precheck(c, d, flota_by, exp.get("periodo"), grifos.get(c.get("ruc_distribuidor")))
        for pl in d.get("placas") or []:
            pn = (pl.get("placa") or "").replace("-", "").upper()
            tope = float((flota_by.get(pn) or {}).get("tope_galones") or 0)
            tot = acum_placa.get(pn, 0.0)
            if tope and tot > tope + 0.01:
                pre["avisos"].append(f"Placa {pl.get('placa')} acumula {tot:,.2f} gal en el expediente; tope {tope:,.2f} gal → {tot - tope:,.2f} gal no se pagarán")
                if pre["veredicto"] == "ok":
                    pre["veredicto"] = "riesgo"
        resumen[pre["veredicto"]] += 1
        out.append({**c, **{k: v for k, v in d.items() if k != "uuid"}, "grifo_osinergmin": grifos.get(c.get("ruc_distribuidor")), "precheck": pre})
    return {"ruc": ruc, "total": len(out), "resumen_precheck": resumen, "periodo": exp.get("periodo"), "comprobantes": out}


@api.get("/atu/cargo-dj")
async def atu_cargo_dj(ruc: str, entidad_uuid: str, user: dict = Depends(require_roles("admin_enered"))):
    """PDF del cargo de la DJ enviada por el transportista (si existe). Solo admin ENERED."""
    from fastapi.responses import Response as _Resp
    contenido, nombre, ct = await _atu_con_refresh(_atu.descargar_cargo_dj, ruc, entidad_uuid)
    return _Resp(content=contenido, media_type=ct, headers={"Content-Disposition": f'inline; filename="{nombre}"'})


@api.get("/atu/archivo/{archivo_uuid}")
async def atu_archivo(archivo_uuid: str, ruc: str, user: dict = Depends(require_roles("admin_enered"))):
    """Entrega el PDF de un comprobante cargado en la ATU (archivoUuid). Solo admin ENERED."""
    from fastapi.responses import Response as _Resp
    contenido, nombre, ct = await _atu_con_refresh(_atu.descargar_archivo, ruc, archivo_uuid)
    return _Resp(content=contenido, media_type=ct, headers={"Content-Disposition": f'inline; filename="{nombre}"'})


# Tope de galones máximos a reclamar por categoría de unidad (DU 004). × factor = monto.
_TOPES_GALONES = {"M2": 674.65, "M3": 1915.41, "N1": 552.52, "N2": 888.45, "N3": 1412.54}
from services.validador_facturas import clase_base_categoria, periodo_du007, PERIODO_INICIO, PERIODO_FIN


def _programa_y_periodo_por_fecha(fecha_str):
    """A qué decreto pertenece una factura de combustible, según su fecha de emisión:
    DU 004 (29/05–29/07/2026) o alguno de los 3 periodos del DU 007 (desde 16/08/2026).
    Devuelve (programa, periodo_du007 o None). Si la fecha no cae en ninguno, devuelve
    ("du004", None) por compatibilidad con lo que ya existía antes del DU 007."""
    from datetime import date as _date
    try:
        f = _date.fromisoformat(str(fecha_str)[:10])
    except (ValueError, TypeError):
        return "du004", None
    n = periodo_du007(f)
    if n is not None:
        return "du007", n
    if PERIODO_INICIO <= f <= PERIODO_FIN:
        return "du004", None
    return "du004", None
_FACTOR_SUBSIDIO = 4  # galones máximos × 4 = monto máximo a reclamar
_RESUMEN_CACHE = {}   # ruc -> (timestamp, payload, ttl) para /subsidio/resumen


def _detalle_ruc(ruc_activo, sunat):
    if ruc_activo:
        return "El RUC figura ACTIVO y HABIDO en SUNAT."
    if ruc_activo is False:
        if sunat:
            return f"En SUNAT figura: {sunat.get('estado')} / {sunat.get('condicion')}."
        return "El RUC no figura activo/habido."
    return "No se pudo verificar en este momento."


async def _sunat_estado(ruc: str):
    """Consulta pública de SUNAT (estado ACTIVO/BAJA y condición HABIDO/NO HABIDO).
    Reintenta una vez: la API pública a veces tarda o devuelve un error transitorio."""
    import httpx as _hx
    for intento in range(2):
        try:
            async with _hx.AsyncClient(timeout=6.0, verify=False,
                                       headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}) as c:
                r = await c.get("https://api.apis.net.pe/v1/ruc", params={"numero": ruc})
                if r.status_code != 200:
                    continue
                d = r.json()
                return {"estado": d.get("estado"), "condicion": d.get("condicion"), "nombre": d.get("nombre")}
        except Exception:
            if intento == 0:
                await asyncio.sleep(0.5)
    return None


@api.get("/subsidio/diag-red")
async def subsidio_diag_red():
    """Diagnóstico: ¿desde este host se puede llegar al MTC / ATU / SUNAT? (temporal)"""
    import os as _os, time as _t, httpx as _hx
    MTC_URL = "https://www.mtc.gob.pe/tramitesenlinea/tweb_tLinea/tw_consultadgtt/Frm_rep_intra_mercancia.aspx"
    targets = {
        "mtc_directo": (MTC_URL, None),
        "atu": ("https://api.atu.gob.pe/", None),
        "sunat": ("https://api.apis.net.pe/v1/ruc?numero=20131312955", None),
    }
    proxy = _os.getenv("MTC_PROXY") or None
    if proxy:
        targets["mtc_via_proxy"] = (MTC_URL, proxy)
        targets["facilito_via_proxy"] = (
            "https://www.facilito.gob.pe/facilito/actions/MapaAction.do"
            "?departamento=130000&provincia=130100&distrito=9999999&producto=40"
            "&method=mostrarMapa&tipo=LIQ", proxy)
    targets["facilito_directo"] = (
        "https://www.facilito.gob.pe/facilito/pages/facilito/buscadorEESS.jsp", None)
    out = {"proxy_configurado": bool(proxy)}
    for k, (url, px) in targets.items():
        t = _t.time()
        try:
            async with _hx.AsyncClient(timeout=15.0, verify=False, proxy=px,
                                       headers={"User-Agent": "Mozilla/5.0"}) as c:
                r = await c.get(url)
            out[k] = {"ok": True, "status": r.status_code, "ms": int((_t.time() - t) * 1000), "bytes": len(r.content)}
        except Exception as e:
            out[k] = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:100]}", "ms": int((_t.time() - t) * 1000)}
    return out


@api.get("/subsidio/diag-precios")
async def diag_precios(departamento: str = "LA LIBERTAD"):
    """TEMPORAL: radiografía de precios_facilito para diagnosticar cargas apiladas en
    producción. Solo agregados y una muestra (los precios de Facilito son públicos)."""
    q = {"departamento": {"$regex": departamento, "$options": "i"}}
    total = await db.precios_facilito.count_documents(q)
    # ¿Qué variantes de 'departamento' existen? (case/espacios delatan cargas viejas)
    variantes = await db.precios_facilito.distinct("departamento", q)
    # Cargas por fuente y fecha
    _cur = db.precios_facilito.aggregate([
        {"$match": q},
        {"$group": {"_id": {"fuente": "$fuente",
                            "dia": {"$substr": [{"$ifNull": ["$scraped_at", "sin-fecha"]}, 0, 10]},
                            "con_gps": {"$cond": [{"$ne": ["$lat", None]}, True, False]}},
                    "n": {"$sum": 1}}},
        {"$sort": {"n": -1}}, {"$limit": 12}])
    cargas = await _cur.to_list(12)
    # Muestra: AMERICA NORTE 1 (todas sus filas crudas)
    muestra = await db.precios_facilito.find(
        {**q, "establecimiento": {"$regex": "AMERICA NORTE 1", "$options": "i"}},
        {"_id": 0, "establecimiento": 1, "combustible": 1, "precio_venta": 1,
         "lat": 1, "fuente": 1, "scraped_at": 1, "departamento": 1}).to_list(20)
    return {"total": total, "variantes_departamento": variantes,
            "cargas": [{"fuente": c["_id"].get("fuente"), "dia": c["_id"].get("dia"),
                        "con_gps": c["_id"].get("con_gps"), "n": c["n"]} for c in cargas],
            "muestra_america_norte_1": muestra}


@api.get("/subsidio/resumen")
async def subsidio_resumen(ruc: str, refresh: int = 0):
    """
    Etapa 0 pública: con solo el RUC devuelve el máximo a reclamar del subsidio (por categoría
    de unidad, desde el MTC), las unidades con su cumple/no-cumple en la ATU, y el semáforo ATU.
    Con refresh=1 se salta el caché (lo usa el frontend para re-verificar fuentes pendientes).
    """
    ruc = (ruc or "").strip()
    if not re.fullmatch(r"\d{11}", ruc):
        raise HTTPException(status_code=400, detail="El RUC debe tener 11 dígitos")

    # Caché por RUC: MTC/ATU/SUNAT no cambian de un momento a otro. Evita rehacer el scrape
    # lento en cada carga. TTL corto si la ATU no respondió (para reintentar pronto).
    import time as _time
    _now = _time.time()
    _hit = _RESUMEN_CACHE.get(ruc)
    if _hit and (_now - _hit[0]) < _hit[2] and not refresh:
        return _hit[1]

    # 1) MTC: unidades + categorías + razón social (fuente de "todas tus unidades").
    #    OJO: un mismo RUC puede tener varias autorizaciones y la MISMA placa repetida → dedup.
    async def _fetch_mtc():
        razon = ""
        mtc_unidades = []
        permiso_mtc = False
        try:
            m = await _mtc.consultar("ruc", ruc)
            for a in m.get("autorizaciones", []):
                if not razon:
                    razon = a.get("razon_social", "") or ""
                # "Tiene permiso MTC" = alguna autorización activa cuyo tipo APLICA al subsidio
                # (CNG, MRP, URV, ERG, INT). Un permiso activo de otro tipo (MPW, PNT…) no cuenta.
                if _mtc.autorizacion_activa(a) and a.get("permiso_aplica") is True:
                    permiso_mtc = True
            # Una fila por placa, regida por la autorización que corresponde (activa y que aplica
            # primero). Antes se tomaba la primera autorización donde apareciera la placa.
            for v in _mtc.unidades_para_subsidio(m):
                mtc_unidades.append({"placa": v["placa"], "categoria": (v.get("categoria") or "").upper(),
                                     "vigencia": v.get("vigente_hasta"),
                                     "numero_autorizacion": v.get("autorizacion") or v.get("constancia"),
                                     "permiso": v.get("permiso") or "", "permiso_aplica": v.get("permiso_aplica"),
                                     # Constancia de habilitación del MTC por unidad: es el "TUC"
                                     # que muestra el padrón ATU (formato 13M25000323E).
                                     "constancia": v.get("constancia")})
        except Exception:
            pass
        return razon, mtc_unidades, permiso_mtc

    # 2) ATU (cuenta maestra): solo la aceptación por placa. El semáforo lo armamos nosotros
    #    (MTC + SUNAT + análisis), así que NO pedimos el semáforo de la ATU → un round-trip menos.
    async def _fetch_atu():
        inscrito = False
        atu_disponible = False
        atu_by_placa = {}
        doc = await db.atu_sessions.find_one({"ruc": _ATU_MASTER_KEY})
        if doc:
            session = _atu_unpack(doc)
            try:
                diag, actualizada = await _atu.diagnosticar_con_sesion(session, ruc)
                if actualizada.get("access_token") != session.get("access_token"):
                    await db.atu_sessions.update_one({"ruc": _ATU_MASTER_KEY}, {"$set": _atu_pack(actualizada)})
                    session = actualizada
                atu_disponible = True
                inscrito = not diag.get("sin_habilitaciones")
                for u in diag.get("unidades", []):
                    atu_by_placa[(u.get("placa") or "").replace("-", "").upper()] = u
            except _atu.AtuError:
                atu_disponible = False
        return inscrito, atu_disponible, atu_by_placa

    # Cada fuente con timeout acotado: si una se cuelga, seguimos con lo que haya (no bloquea todo).
    async def _guard(coro, default, secs=18):
        try:
            return await asyncio.wait_for(coro, timeout=secs)
        except Exception:
            return default

    # Las 3 fuentes externas corren en PARALELO (antes eran secuenciales → lento en producción).
    (razon, mtc_unidades, permiso_mtc), (inscrito, atu_disponible, atu_by_placa), sunat = \
        await asyncio.gather(
            _guard(_fetch_mtc(), ("", [], False), secs=40),   # empresas grandes: muchas autorizaciones
            _guard(_fetch_atu(), (False, False, {}), secs=25),
            _guard(_sunat_estado(ruc), None, secs=14),
        )
    semaforo = []  # el de la ATU ya no se usa; se arma más abajo

    # 3) Unidades combinadas: MTC (base) + ATU (tuc/acepta) + motivo + vigencia
    import datetime as _dt

    def _venc(vig):
        mm = re.match(r"(\d{2})/(\d{2})/(\d{4})", str(vig or ""))
        if not mm:
            return False
        try:
            return _dt.date(int(mm.group(3)), int(mm.group(2)), int(mm.group(1))) < _dt.date.today()
        except Exception:
            return False

    unidades = []
    for u in mtc_unidades:
        pn = u["placa"].replace("-", "").upper()
        au = atu_by_placa.get(pn)
        # El MTC entrega variantes con sufijo (N2C2, M2C3…); se reduce a la clase base
        # (N2, M2…) para decidir el subsidio. Solo M1* y O* quedan fuera (no tienen tope).
        cat = clase_base_categoria(u["categoria"])
        cat_ok = cat in _TOPES_GALONES
        permiso_ok = u.get("permiso_aplica") is not False   # False = tipo de permiso que no aplica
        # Solo M2, M3, N1, N2, N3 reciben subsidio. Otras categorías (O4, etc.) no califican.
        cumple = cat_ok and permiso_ok and bool(au) and au.get("tuc_estado") == "ok"
        vig = u.get("vigencia")
        if cumple:
            estado, motivo = "aceptada", None
        elif not permiso_ok:
            estado = "permiso_no_aplica"
            motivo = f"Permiso {u.get('permiso') or ''} del MTC no aplica al subsidio (solo CNG, MRP, URV, ERG, INT)".replace("  ", " ")
        elif not cat_ok:
            estado = "no_subsidiable"
            motivo = (f"Categoría {cat} no recibe subsidio (solo M2, M3, N1, N2, N3)"
                      if cat else "Sin categoría registrada en el MTC (no subsidiable)")
        elif _venc(vig):
            estado, motivo = "vencida", f"Autorización del MTC vencida ({vig})"
        elif not atu_disponible:
            # La ATU no respondió: NO afirmamos que rechace el TUC, queda pendiente.
            estado, motivo = "por_verificar", "Pendiente de validación en la ATU"
        elif au:
            estado, motivo = "no_aceptada", "La ATU no reconoce su TUC (regularizable)"
        else:
            estado, motivo = "no_aceptada", "No figura habilitada en la ATU (regularizable)"
        unidades.append({
            "placa": u["placa"], "categoria": cat, "cumple": cumple, "estado": estado,
            "permiso": u.get("permiso") or "", "permiso_aplica": u.get("permiso_aplica"),
            # TUC: el que reporta la ATU si respondió; si no, la constancia MTC de la
            # unidad (es el mismo número que el padrón ATU muestra como "TUC").
            "tuc": (au.get("tuc") if au else None) or u.get("constancia"),
            "motivo": motivo,
            "vigencia": vig, "numero_autorizacion": u.get("numero_autorizacion"),
        })
    # Orden: aceptadas primero, luego por verificar, luego el resto.
    _peso = {"aceptada": 0, "por_verificar": 1, "vencida": 2, "no_aceptada": 3, "permiso_no_aplica": 4, "no_subsidiable": 5}
    unidades.sort(key=lambda x: (_peso.get(x["estado"], 9), x.get("placa") or ""))

    # 4) Subsidio máximo por categoría (solo categorías con tope). Las demás no aplican.
    por_cat = {}
    no_aplican = {}
    total_galones = 0.0
    for u in mtc_unidades:
        cb = clase_base_categoria(u["categoria"])
        tope = _TOPES_GALONES.get(cb)
        if u.get("permiso_aplica") is False:
            cat = f"permiso {u.get('permiso') or '?'}"
            no_aplican[cat] = no_aplican.get(cat, 0) + 1
            continue
        if not tope:
            cat = cb or "(sin categoría)"
            no_aplican[cat] = no_aplican.get(cat, 0) + 1
            continue
        d = por_cat.setdefault(cb, {"categoria": cb, "unidades": 0, "tope": tope})
        d["unidades"] += 1
        total_galones += tope
    por_categoria = [{
        **v,
        "galones": round(v["tope"] * v["unidades"], 2),
        "monto": round(v["tope"] * v["unidades"] * _FACTOR_SUBSIDIO, 2),
    } for v in por_cat.values()]
    categorias_no_aplican = [{"categoria": k, "unidades": v}
                             for k, v in sorted(no_aplican.items(), key=lambda x: -x[1])]

    # 5) Requisitos para calificar al subsidio (cumple=True/False, o None = por verificar)
    aceptadas = sum(1 for u in unidades if u["cumple"])

    # RUC activo y habido: se saca de SUNAT (público, confiable) — no depende de la ATU.
    # (sunat ya se obtuvo en paralelo arriba)
    if sunat:
        ruc_activo = (str(sunat.get("estado") or "").upper() == "ACTIVO" and str(sunat.get("condicion") or "").upper() == "HABIDO")
        if not razon:
            razon = sunat.get("nombre") or ""
    else:
        ruc_activo = None  # SUNAT no respondió → por verificar
    # Unidades con TUC depende de la ATU (por verificar si no respondió).
    unidades_tuc = (aceptadas > 0) if atu_disponible else None

    # Semáforo canónico: SIEMPRE las 4 condiciones que evalúa la ATU (CUMPLE / NO_CUMPLE),
    # armadas con nuestras fuentes confiables (SUNAT, MTC, análisis por placa).
    def _estado(b):
        return "POR_VERIFICAR" if b is None else ("CUMPLE" if b else "NO_CUMPLE")

    # Autorización de transporte vigente: se basa en el PERMISO DEL MTC (fuente real de la
    # habilitación), NO en el semáforo de la ATU (que puede marcar NO_CUMPLE por su propio
    # trámite y contradecir a "Vehículos habilitados"). Si el MTC muestra permiso habilitado,
    # el transportista SÍ tiene autorización de transporte.
    aut_estado = _estado(permiso_mtc)
    aut_desc = ("Tiene autorización de transporte habilitada y vigente en el MTC." if permiso_mtc
                else "No se encontró autorización de transporte habilitada en el MTC.")

    # Vehículos habilitados: VIGENCIA del MTC, considerando SOLO las unidades subsidiables
    # (M2/M3/N1/N2/N3). Las O4 y demás no cuentan porque no aplican al subsidio.
    # Verde solo si TODAS las subsidiables vigentes; amarillo si unas vencidas; rojo si ninguna.
    subsid_units = [u for u in mtc_unidades if u["categoria"] in _TOPES_GALONES]
    veh_total = len(subsid_units)
    veh_vencidas = sum(1 for u in subsid_units if _venc(u.get("vigencia")))
    veh_vigentes = veh_total - veh_vencidas
    if veh_total == 0:
        hab_estado, hab_desc = _estado(None), "No hay unidades de categorías subsidiables (M2, M3, N1, N2, N3)."
    elif veh_vencidas == 0:
        hab_estado, hab_desc = "CUMPLE", f"Las {veh_vigentes} unidad(es) subsidiables tienen autorización MTC vigente."
    elif veh_vigentes == 0:
        hab_estado, hab_desc = "NO_CUMPLE", f"Las {veh_total} unidad(es) subsidiables tienen la autorización MTC vencida."
    else:
        hab_estado, hab_desc = "PARCIAL", f"{veh_vigentes} de {veh_total} unidad(es) subsidiables con autorización MTC vigente; {veh_vencidas} vencida(s)."

    # Vehículos con TUC habilitado: comparado contra las unidades SUBSIDIABLES (M/N con tope).
    # Verde solo si TODAS las subsidiables están aceptadas; amarillo si unas sí y otras no.
    subsid_total = sum(1 for u in mtc_unidades if clase_base_categoria(u["categoria"]) in _TOPES_GALONES)
    # TUC por unidad según el MTC (constancia): es el mismo número que el padrón ATU
    # muestra como "TUC". Si TODAS las subsidiables lo tienen, el punto CUMPLE aunque
    # la ATU no responda (igual que el padrón oficial); la aceptación ATU manda si responde.
    con_tuc_mtc = sum(1 for u in mtc_unidades
                      if clase_base_categoria(u["categoria"]) in _TOPES_GALONES and u.get("constancia"))
    if not atu_disponible:
        if subsid_total > 0 and con_tuc_mtc >= subsid_total:
            tuc_estado = "CUMPLE"
            tuc_desc = f"Las {subsid_total} unidad(es) subsidiables cuentan con TUC / autorización (constancia MTC)."
        elif con_tuc_mtc > 0:
            tuc_estado = "PARCIAL"
            tuc_desc = f"{con_tuc_mtc} de {subsid_total} unidad(es) cuentan con TUC (constancia MTC); el resto por verificar."
        else:
            tuc_estado = "POR_VERIFICAR"
            tuc_desc = "La plataforma de la ATU es quien valida este punto y hoy no responde."
    elif aceptadas == 0:
        tuc_estado = "NO_CUMPLE"
        tuc_desc = "La plataforma de la ATU no reconoce el TUC de tus unidades."
    elif aceptadas < subsid_total:
        tuc_estado = "PARCIAL"
        tuc_desc = f"Solo {aceptadas} de {subsid_total} unidad(es) tienen TUC habilitado en la ATU; el resto debe regularizarse."
    else:
        tuc_estado = "CUMPLE"
        tuc_desc = f"Las {aceptadas} unidad(es) subsidiables tienen TUC habilitado en la ATU."

    semaforo = [
        {"codigo": "RUC_ACTIVO", "nombre": "RUC activo y habido",
         "estado": _estado(ruc_activo),
         "descripcion": _detalle_ruc(ruc_activo, sunat)},
        {"codigo": "AUTORIZACION_VIGENTE", "nombre": "Autorización de transporte vigente",
         "estado": aut_estado, "descripcion": aut_desc},
        {"codigo": "VEHICULOS_HABILITADOS", "nombre": "Vehículos habilitados",
         "estado": hab_estado, "descripcion": hab_desc},
        {"codigo": "VEHICULOS_TUC", "nombre": "Vehículos con TUC habilitado",
         "estado": tuc_estado, "descripcion": tuc_desc},
    ]
    requisitos = [
        {"codigo": "permiso_mtc", "nombre": "Permiso del MTC",
         "cumple": permiso_mtc,
         "detalle": "Tiene autorización de transporte habilitada en el MTC." if permiso_mtc else "No se encontró autorización de transporte habilitada en el MTC."},
        {"codigo": "ruc_activo_habido", "nombre": "RUC activo y habido",
         "cumple": ruc_activo,
         "detalle": _detalle_ruc(ruc_activo, sunat)},
        {"codigo": "unidades_tuc", "nombre": "Unidades con TUC y habilitación vehicular",
         "cumple": unidades_tuc,
         "detalle": (f"{aceptadas} unidad(es) con TUC reconocido por la ATU." if unidades_tuc
                     else "Ninguna unidad tiene TUC reconocido por la ATU todavía." if unidades_tuc is False
                     else "No se pudo verificar en la ATU en este momento.")},
    ]
    # Cumple solo si todos son True; si alguno es None → None (por verificar)
    if any(r["cumple"] is None for r in requisitos):
        cumple_subsidio = None
    else:
        cumple_subsidio = all(r["cumple"] for r in requisitos)

    payload = {
        "ruc": ruc,
        "razon_social": razon,
        "inscrito": inscrito,
        "atu_disponible": atu_disponible,
        "requisitos": requisitos,
        "cumple_subsidio": cumple_subsidio,
        "subsidio": {
            "por_categoria": por_categoria,
            "categorias_no_aplican": categorias_no_aplican,
            "total_unidades": len(mtc_unidades),
            "unidades_con_subsidio": sum(v["unidades"] for v in por_cat.values()),
            "total_galones": round(total_galones, 2),
            "total_monto": round(total_galones * _FACTOR_SUBSIDIO, 2),
            "factor": _FACTOR_SUBSIDIO,
        },
        "unidades": unidades,
        "semaforo": semaforo,
    }
    # Guardar en caché: 15 min SOLO si el resultado es "bueno" (MTC trajo unidades, la ATU
    # respondió Y SUNAT respondió). Si alguna fuente falló, 60 s para reintentar pronto y no
    # dejar pegado un "0 unidades" o un "RUC por verificar" falsos.
    _bueno = bool(mtc_unidades) and atu_disponible and (sunat is not None)
    _RESUMEN_CACHE[ruc] = (_now, payload, 900 if _bueno else 60)
    return payload


async def _atu_guardian():
    """
    Guardián de sesión ATU: renueva la cuenta maestra cada ~13 min (el access dura 15).
    Así la sesión nunca expira mientras el refresh_token siga vivo.
    """
    while True:
        try:
            await asyncio.sleep(780)  # 13 minutos
            doc = await db.atu_sessions.find_one({"ruc": _ATU_MASTER_KEY})
            if not doc:
                continue
            sess = _atu_unpack(doc)
            if not sess.get("refresh_token"):
                continue
            nuevos = await _atu.refresh_session(sess["refresh_token"])
            await db.atu_sessions.update_one({"ruc": _ATU_MASTER_KEY}, {"$set": _atu_pack(nuevos)})
            logger.info("ATU guardián: sesión maestra renovada OK")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("ATU guardián: no se pudo renovar (%s)", str(e)[:100])


# ---------- Admin: eliminar empresa con cascada ----------
@api.delete("/admin/empresas/{empresa}")
async def delete_empresa(empresa: str, user: dict = Depends(require_roles("admin_enered"))):
    """
    Elimina una empresa y TODOS los datos asociados en cascada:
    - empresas_config
    - users (usuarios de esa empresa)
    - consumptions (facturas de combustible)
    - invoices (facturación)
    - qr_codes
    - subsidio_vehicles, subsidio_documents, subsidio_bank_accounts, subsidio_declaraciones
    - consumos_subsidio (a través de sus user_ids)
    Retorna el conteo de documentos eliminados por colección.
    """
    if not empresa:
        raise HTTPException(status_code=400, detail="Nombre de empresa vacío")
    # Obtener ids de usuarios para cascada de subsidio
    user_ids = [u["id"] async for u in db.users.find({"empresa": empresa}, {"_id": 0, "id": 1})]
    counts = {}
    r = await db.empresas_config.delete_many({"empresa": empresa}); counts["empresas_config"] = r.deleted_count
    r = await db.users.delete_many({"empresa": empresa}); counts["users"] = r.deleted_count
    r = await db.consumptions.delete_many({"EMPRESA": empresa}); counts["consumptions"] = r.deleted_count
    r = await db.invoices.delete_many({"empresa": empresa}); counts["invoices"] = r.deleted_count
    r = await db.qr_codes.delete_many({"empresa": empresa}); counts["qr_codes"] = r.deleted_count
    if user_ids:
        for coll in ["subsidio_vehicles", "subsidio_documents", "subsidio_bank_accounts", "subsidio_declaraciones", "consumos_subsidio", "subsidio_leads"]:
            r = await db[coll].delete_many({"user_id": {"$in": user_ids}})
            counts[coll] = r.deleted_count
    return {"ok": True, "empresa": empresa, "deleted": counts}


# ─── DOCUMENTACION MODULE ENDPOINTS ───

SUB_CAT_MAP = {
    "ficha_ruc": ("Empresa", "Ficha RUC"),
    "resolucion_autorizacion": ("Empresa", "Resolución de autorización"),
    "dni_representante": ("Empresa", "DNI del representante"),
    "tarjeta_propiedad": ("Vehículos", "Tarjeta de propiedad"),
    "tarjeta_habilitacion": ("Vehículos", "TUC / Tarjeta de habilitación"),
    "tarjeta_circulacion": ("Vehículos", "Tarjeta de circulación"),
    "soat": ("Vehículos", "SOAT"),
    "revision_tecnica": ("Vehículos", "Revisión Técnica"),
}

@api.get("/documents")
async def list_documents(
    user: dict = Depends(get_current_user),
    empresa: Optional[str] = None,
):
    # Multi-tenant isolation
    if user["role"] == "admin_enered":
        target_empresa = empresa or None
    else:
        target_empresa = user.get("empresa")

    # Fetch manual documents from db.documents
    doc_q = {}
    if target_empresa:
        doc_q["empresa"] = target_empresa
    manual_docs = await db.documents.find(doc_q).to_list(1000)

    # Fetch subsidio documents from db.subsidio_documents
    sub_q = {}
    if target_empresa:
        sub_q["empresa"] = target_empresa
    elif user["role"] != "admin_enered":
        cursor = db.users.find({"empresa": user.get("empresa")}, {"_id": 0, "id": 1})
        uids = [u["id"] async for u in cursor if "id" in u]
        sub_q["user_id"] = {"$in": uids}
    subsidio_docs = await db.subsidio_documents.find(sub_q).to_list(1000)

    # Load verified dates from db.subsidio_vehicles
    veh_map = {}
    if subsidio_docs:
        uids = list(set(sd.get("user_id") for sd in subsidio_docs if sd.get("user_id")))
        plates = list(set(sd.get("placa").upper().strip() for sd in subsidio_docs if sd.get("placa")))
        if uids and plates:
            v_cursor = db.subsidio_vehicles.find({
                "user_id": {"$in": uids},
                "placa": {"$in": plates}
            }, {"_id": 0, "user_id": 1, "placa": 1, "vigente_desde": 1, "vigente_hasta": 1})
            async for v in v_cursor:
                key = (v.get("user_id"), v.get("placa").upper().strip() if v.get("placa") else "")
                veh_map[key] = v

    results = []

    # Datos del motor de placas (póliza SOAT, certificado CITV) para rotular también
    # los documentos subidos a mano: "el código de la póliza es lo que vale en un accidente".
    veh_meta = {}
    if target_empresa:
        async for vm in db.vehiculos.find({"empresa": target_empresa},
                                          {"_id": 0, "placa": 1, "soat_poliza": 1, "soat_compania": 1,
                                           "revtec_certificado": 1, "revtec_centro": 1}):
            if vm.get("placa"):
                veh_meta[vm["placa"].upper().strip()] = vm

    def _ref_manual(doc_nombre, placa_doc, ref_actual):
        if ref_actual:
            return ref_actual
        vm = veh_meta.get((placa_doc or "").upper().strip())
        if not vm:
            return ""
        n = re.sub(r"[^a-z0-9]", "", (doc_nombre or "").lower())
        if "soat" in n and vm.get("soat_poliza"):
            return f"Póliza N° {_poliza_legible(vm['soat_poliza'])}" + (f" · {vm['soat_compania']}" if vm.get("soat_compania") else "")
        if ("revisi" in n or "citv" in n) and vm.get("revtec_certificado"):
            return f"Certificado {vm['revtec_certificado']}"
        return ""

    # Map manual documents
    for d in manual_docs:
        results.append({
            "id": d.get("id") or str(d.get("_id")),
            "tipo": d.get("tipo") or "Otros",
            "doc": d.get("doc") or "Documento",
            "por": d.get("por") or "Admin",
            "el": d.get("el") or d.get("uploaded_at") or "",
            "emi": d.get("emi") or "—",
            "ven": d.get("ven") or "—",
            "atr": d.get("atr") or "—",
            "veh": d.get("veh") or 0,
            "grp": d.get("grp") or 0,
            "all": d.get("all") or 0,
            "placa": d.get("placa") or "",
            "ref": _ref_manual(d.get("doc"), d.get("placa"), d.get("ref") or ""),
            "archived": int(d.get("archived") or 0),
            "est": d.get("est") or "Vigente",
            "filename": d.get("filename") or "",
            "content_type": d.get("content_type") or "",
            "meta": d.get("meta") or {},
            "foto_auto": bool(d.get("foto_auto")),
            "_origen": "manual",
        })

    # Map subsidio documents
    for sd in subsidio_docs:
        cat = sd.get("categoria") or sd.get("category")
        tipo, doc_name = SUB_CAT_MAP.get(cat, ("Otros", cat or "Documento"))
        
        placa = sd.get("placa").upper().strip() if sd.get("placa") else ""
        emi_date = "—"
        ven_date = "—"
        atr_str = "—"
        est = "Vigente"

        # If it's a fleet document with a plate, read dates from manual validation
        if placa and cat in ["tarjeta_habilitacion", "tarjeta_propiedad"]:
            v_info = veh_map.get((sd.get("user_id"), placa))
            if v_info:
                raw_emi = v_info.get("vigente_desde")
                raw_ven = v_info.get("vigente_hasta")

                if raw_emi and raw_emi != "—":
                    try:
                        if "-" in raw_emi:
                            parts = raw_emi.split("-")
                            if len(parts) == 3:
                                emi_date = f"{parts[2]}/{parts[1]}/{parts[0][2:]}"
                            else:
                                emi_date = raw_emi
                        else:
                            emi_date = raw_emi
                    except Exception:
                        emi_date = raw_emi

                if raw_ven and raw_ven != "—":
                    try:
                        if "-" in raw_ven:
                            parts = raw_ven.split("-")
                            if len(parts) == 3:
                                ven_date = f"{parts[2]}/{parts[1]}/{parts[0][2:]}"
                            else:
                                ven_date = raw_ven
                        else:
                            ven_date = raw_ven
                    except Exception:
                        ven_date = raw_ven

                # Calculate expiration status if vigente_hasta is set
                if raw_ven and raw_ven != "—":
                    try:
                        if "-" in raw_ven:
                            y, m, d = map(int, raw_ven.split("-")[:3])
                        else:
                            d, m, y = map(int, raw_ven.split("/")[:3])
                            if y < 100:
                                y += 2000
                        exp_dt = datetime(y, m, d, tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        diff_days = (exp_dt - now_dt).days
                        if diff_days < 0:
                            est = "Vencido"
                            atr_str = f"{abs(diff_days)} días"
                        elif diff_days <= 30:
                            est = "Próximo"
                            atr_str = f"{diff_days} días"
                    except Exception:
                        pass

        if sd.get("status") == "rechazado":
            est = "Vencido"
        elif sd.get("archived"):
            est = "Archivado"

        el_date = ""
        up_at = sd.get("uploaded_at") or sd.get("created_at")
        if up_at:
            try:
                dt = datetime.fromisoformat(up_at.replace("Z", "+00:00"))
                el_date = dt.strftime("%d/%m/%y")
            except Exception:
                el_date = up_at[:10]

        results.append({
            "id": sd.get("id") or str(sd.get("_id")),
            "tipo": tipo,
            "doc": doc_name,
            "por": "Cliente (Subsidio)",
            "el": el_date,
            "emi": emi_date,
            "ven": ven_date,
            "atr": atr_str,
            "veh": 1 if placa else 0,
            "grp": 0,
            "all": 0,
            "placa": placa,
            "archived": 1 if sd.get("archived") else 0,
            "est": est,
            "filename": sd.get("filename") or "",
            "_origen": "subsidio",
        })

    # Documentos VERIFICADOS POR API (motor de placas): el SOAT y la revisión técnica
    # se consultan automáticamente por placa; aunque nadie haya subido el archivo, el
    # casillero muestra la vigencia real y alimenta las alertas de vencimiento.
    if target_empresa:
        ya = set()
        for r in results:
            d_norm = re.sub(r"[^a-z0-9]", "", (r.get("doc") or "").lower())
            ya.add((r.get("placa") or "", d_norm))

        def _est_de(fecha_ddmmyyyy: str) -> str:
            try:
                d, m, a = map(int, fecha_ddmmyyyy.split("/")[:3])
                venc = datetime(a, m, d, tzinfo=timezone.utc)
                dias = (venc - datetime.now(timezone.utc)).days
                if dias < 0:
                    return "Vencido"
                if dias <= 30:
                    return "Próximo"
                return "Vigente"
            except Exception:
                return "Vigente"

        async for v in db.vehiculos.find(
            {"empresa": target_empresa,
             "$or": [{"soat_vencimiento": {"$nin": [None, ""]}},
                     {"revtec_vencimiento": {"$nin": [None, ""]}}]},
            {"_id": 0, "placa": 1, "soat_vencimiento": 1, "soat_compania": 1, "soat_poliza": 1,
             "soat_estado": 1, "soat_desde": 1, "revtec_vencimiento": 1, "revtec_estado": 1, "revtec_desde": 1,
             "revtec_certificado": 1, "revtec_centro": 1, "revtec_resultado": 1,
             "enriquecido_en": 1},
        ):
            placa = (v.get("placa") or "").upper().strip()
            if not placa:
                continue
            el_api = (v.get("enriquecido_en") or "")[:10]
            # Rótulo: quién lo emite en "por"; número de póliza / certificado aparte en "ref"
            soat_por = v.get("soat_compania") or "SOAT verificado"
            soat_ref = f"Póliza N° {_poliza_legible(v['soat_poliza'])}" if v.get("soat_poliza") else ""
            rev_por = " · ".join(x for x in [(v.get("revtec_centro") or "")[:48], v.get("revtec_resultado") or ""] if x) or "Revisión verificada"
            rev_ref = f"Certificado {v['revtec_certificado']}" if v.get("revtec_certificado") else ""
            for campo, doc_name, extra, ref in (
                ("soat_vencimiento", "SOAT", soat_por, soat_ref),
                ("revtec_vencimiento", "Revisión técnica", rev_por, rev_ref),
            ):
                ven = v.get(campo)
                if not ven:
                    continue
                d_norm = re.sub(r"[^a-z0-9]", "", doc_name.lower())
                # si ya existe un documento subido para ese casillero, manda el archivo real
                if any(p == placa and (d_norm in dn or dn in d_norm) for p, dn in ya if dn):
                    continue
                results.append({
                    "id": f"api-{d_norm}-{placa}",
                    "tipo": "Vehículos",
                    "doc": doc_name,
                    "ref": ref,
                    "por": extra,
                    "el": el_api,
                    "emi": (v.get("revtec_desde") or "—") if campo == "revtec_vencimiento" else (v.get("soat_desde") or "—"),
                    "ven": ven,
                    "atr": "—",
                    "veh": 1, "grp": 0, "all": 0,
                    "placa": placa,
                    "archived": 0,
                    "est": _est_de(ven),
                    "filename": "",
                    "_origen": "api",
                })

    results.sort(key=lambda x: x["id"], reverse=True)
    return results

def _extraer_vigencia_pdf(content: bytes) -> dict:
    """Lee las fechas de un certificado PDF (revisión técnica, SOAT, etc.):
    busca la fecha junto a palabras clave (VENCIMIENTO / VIGENCIA HASTA) y la de
    emisión; si no hay palabra clave, usa la fecha futura más lejana como
    vencimiento. Devuelve {'emi': 'dd/mm/yyyy', 'ven': 'dd/mm/yyyy'} (parcial u
    {} si el PDF es imagen escaneada sin texto)."""
    try:
        import io as _io
        import pdfplumber
        texto = ""
        with pdfplumber.open(_io.BytesIO(content)) as pdf:
            for page in pdf.pages[:3]:
                texto += (page.extract_text() or "") + "\n"
    except Exception:
        return {}
    if not texto.strip():
        return {}
    t = texto.upper()
    _fecha = r"(\d{2})[/\-.](\d{2})[/\-.](\d{4})"

    def _norm(m):
        d, mth, a = m
        try:
            datetime(int(a), int(mth), int(d))
            return f"{d}/{mth}/{a}"
        except Exception:
            return None

    out = {}
    m = re.search(r"(?:VENCIMIENTO|VIGENCIA\s+HASTA|VALIDO\s+HASTA|VÁLIDO\s+HASTA|HASTA)[^0-9]{0,60}" + _fecha, t)
    if m:
        v = _norm(m.groups())
        if v:
            out["ven"] = v
    m = re.search(r"(?:EMISI[OÓ]N|EMITIDO|EXPEDICI[OÓ]N|DESDE|INICIO)[^0-9]{0,60}" + _fecha, t)
    if m:
        v = _norm(m.groups())
        if v:
            out["emi"] = v
    if "ven" not in out:
        # sin palabra clave: la fecha futura más lejana del certificado suele ser el vencimiento
        fechas = []
        for g in re.findall(_fecha, t):
            v = _norm(g)
            if v:
                d, mth, a = v.split("/")
                fechas.append((datetime(int(a), int(mth), int(d), tzinfo=timezone.utc), v))
        futuras = [x for x in fechas if x[0] > datetime.now(timezone.utc)]
        if futuras:
            out["ven"] = max(futuras)[1]
    return out


_ASEGURADORAS = ["RIMAC", "PACIFICO", "PACÍFICO", "LA POSITIVA", "MAPFRE", "INTERSEGURO", "PROTECTA", "CRECER", "QUALITAS", "HDI", "CHUBB", "LIBERTY", "SANITAS"]


def _extraer_poliza_pdf(content: bytes) -> dict:
    """Póliza de seguro vehicular en PDF con texto: N° de póliza y aseguradora."""
    try:
        import io as _io
        import pdfplumber
        texto = ""
        with pdfplumber.open(_io.BytesIO(content)) as pdf:
            for page in pdf.pages[:2]:
                texto += (page.extract_text() or "") + "\n"
    except Exception:
        return {}
    if not texto.strip():
        return {}
    import unicodedata as _ud
    t = _ud.normalize("NFKD", texto).encode("ascii", "ignore").decode().upper()
    out = {}
    # Reporte de la Central de Riesgo de la SBS (versión impresa guardada como PDF):
    # filas "Compañía · Clase · Uso · N° accidentes · N° póliza · N° certificado · inicio · fin".
    if "CENTRAL DE RIESGO" in t or "POLIZAS DE SEGURO VEHICULAR" in t or "POLIZAS SOAT" in t:
        filas = re.findall(r"([A-Z][A-Z .&]{2,40}?)\s+(?:CAMION|AUTOMOVIL|CAMIONETA|OMNIBUS|REMOLCADOR|[A-Z]+)\s+[A-Z]+\s+(\d+)\s+(\d{6,})\s+(\d+)\s+(\d{2}/\d{2}/\d{4})\s+(\d{2}/\d{2}/\d{4})", t)
        if filas:
            def _f(s):
                d, m, a = s.split("/"); return f"{a}{m}{d}"
            filas.sort(key=lambda r: _f(r[5]), reverse=True)
            comp, acc, num, cert, ini, fin = filas[0]
            out.update({"numero": num, "aseguradora": comp.strip().title(), "emi": ini, "ven": fin,
                        "accidentes": int(acc), "fuente": "SBS Central de Riesgo"})
            m_tot = re.search(r"ULTIMOS 5 ANOS:\s*(\d+)", t)
            if m_tot:
                out["accidentes_5_anios"] = int(m_tot.group(1))
            return out
    # el número debe contener dígitos (evita capturar "POLIZA VEHICULAR"); primero la forma
    # explícita "N° DE POLIZA: ..." y luego "POLIZA N°/NRO ..."
    m = (re.search(r"N[°O.\s]*\s*(?:DE\s+)?POLIZA\W{0,12}([A-Z]{0,4}\d[A-Z0-9\-/.]{3,30})", t)
         or re.search(r"POLIZA\s*(?:N[°O.]?|NRO\.?|NUMERO)\W{0,12}([A-Z]{0,4}\d[A-Z0-9\-/.]{3,30})", t))
    if m:
        out["numero"] = m.group(1).strip(" .-")
    for a in _ASEGURADORAS:
        if _ud.normalize("NFKD", a).encode("ascii", "ignore").decode().upper() in t:
            out["aseguradora"] = a.title() if a not in ("HDI",) else a
            break
    return out


def _extraer_tarjeta_propiedad_pdf(content: bytes) -> dict:
    """Lee la Tarjeta de Identificación Vehicular (tarjeta de propiedad) en PDF con texto
    y devuelve los datos de la unidad: año de fabricación, categoría, marca, modelo,
    serie/VIN, motor, color y propietario. {} si es una imagen escaneada."""
    try:
        import io as _io
        import pdfplumber
        texto = ""
        with pdfplumber.open(_io.BytesIO(content)) as pdf:
            for page in pdf.pages[:2]:
                texto += (page.extract_text() or "") + "\n"
    except Exception:
        return {}
    if not texto.strip():
        return {}
    import unicodedata as _ud
    t = _ud.normalize("NFKD", texto).encode("ascii", "ignore").decode().upper()
    out: dict = {}

    def _campo(patron, flags=0):
        m = re.search(patron, t, flags)
        return m.group(1).strip() if m else ""

    a = _campo(r"ANO\s+(?:DE\s+)?FABRICACION\W{0,12}(\d{4})") or _campo(r"ANO\s+MODELO\W{0,12}(\d{4})")
    if a and 1950 <= int(a) <= datetime.now().year + 1:
        out["año"] = int(a)
    cat = _campo(r"CATEGORIA\W{0,12}([MNOL][1-3](?:[A-Z]\d?)?)\b")
    if cat:
        out["categoria"] = cat
    vin = _campo(r"(?:N[°O.\s]*\s*)?(?:VIN|SERIE|CHASIS)\W{0,15}([A-HJ-NPR-Z0-9]{11,17})\b")
    if vin:
        out["chasis"] = vin
    motor = _campo(r"(?:N[°O.\s]*\s*)?MOTOR\W{0,15}([A-Z0-9\-]{5,20})\b")
    if motor:
        out["motor"] = motor
    # etiquetas de una sola línea: "MARCA: VOLVO" / "MODELO: FMX 6X4 R" / "COLOR: BLANCO"
    for campo, etiqueta in (("marca", "MARCA"), ("modelo", "MODELO"), ("color", "COLOR")):
        v = _campo(rf"\b{etiqueta}\W{{0,8}}([A-Z0-9][A-Z0-9 .\-/]{{1,40}}?)(?=\s{{2,}}|\s*\n|\s+(?:MARCA|MODELO|COLOR|CATEGORIA|ANO|SERIE|VIN|MOTOR|PLACA|PROPIETARIO)\b)")
        if v and len(v) >= 2:
            out[campo] = v.strip()
    prop = _campo(r"PROPIETARIO(?:\(S\)|S)?\W{0,8}([A-Z0-9][A-Z0-9 .&\-]{3,80}?)(?=\s{2,}|\s*\n)")
    if prop:
        out["titular"] = prop.strip()
    return out



def _recortar_rostro(content: bytes, content_type: str = "", filename: str = "") -> Optional[bytes]:
    """Recorta el rostro de la foto/escaneo del DNI o brevete para usarlo como foto del
    conductor. Devuelve JPEG o None si no hay rostro claro. OpenCV es opcional: sin él,
    simplemente no hay foto automática."""
    try:
        import cv2
        import numpy as np
    except Exception:
        return None
    img = None
    ct = (content_type or "").lower()
    fn = (filename or "").lower()
    try:
        if "pdf" in ct or fn.endswith(".pdf") or content[:4] == b"%PDF":
            import pymupdf
            pdf = pymupdf.open(stream=content, filetype="pdf")
            png = pdf[0].get_pixmap(dpi=150).tobytes("png")
            pdf.close()
            img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_COLOR)
        else:
            img = cv2.imdecode(np.frombuffer(content, np.uint8), cv2.IMREAD_COLOR)
    except Exception:
        return None
    if img is None:
        return None
    h, w = img.shape[:2]
    if max(h, w) > 1600:
        k = 1600 / max(h, w)
        img = cv2.resize(img, (int(w * k), int(h * k)))
        h, w = img.shape[:2]
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    casc = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    faces = casc.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(max(40, w // 25), max(40, h // 25)))
    if len(faces) == 0:
        return None
    x, y, fw, fh = max(faces, key=lambda f: f[2] * f[3])
    mx, my = int(fw * 0.45), int(fh * 0.6)
    x0, y0 = max(0, x - mx), max(0, y - my)
    x1, y1 = min(w, x + fw + mx), min(h, y + fh + int(fh * 0.5))
    crop = img[y0:y1, x0:x1]
    ch, cw = crop.shape[:2]
    if max(ch, cw) > 600:
        k = 600 / max(ch, cw)
        crop = cv2.resize(crop, (int(cw * k), int(ch * k)))
    ok, buf = cv2.imencode(".jpg", crop, [cv2.IMWRITE_JPEG_QUALITY, 88])
    return buf.tobytes() if ok else None


@api.get("/personal/consulta-dni/{dni}")
async def personal_consulta_dni(dni: str, refresh: int = 0, debug: int = 0, user: dict = Depends(get_current_user)):
    """
    Autollenado del conductor por DNI: nombre (RENIEC) y licencia de conducir del MTC
    (número, categoría, vigencia, restricciones), ambos vía json.pe. Caché en `personas_dni`:
    nombre 180 días, licencia 30 días, "sin licencia" 7 días. refresh=1 fuerza reconsulta.
    """
    dni = re.sub(r"\D", "", dni or "")
    if len(dni) != 8:
        raise HTTPException(status_code=400, detail="DNI inválido (8 dígitos)")
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    cache = await db.personas_dni.find_one({"dni": dni}, {"_id": 0}) or {}

    def _vigente(iso, dias):
        try:
            return (now - datetime.fromisoformat(iso)).days <= dias
        except Exception:
            return False

    persona = cache.get("persona") if (cache.get("persona") and _vigente(cache.get("persona_en", ""), 180) and not refresh) else None
    if persona is None:
        d = await _jsonpe("dni", {"dni": dni})
        if d and d.get("numero"):
            persona = {"nombre_completo": d.get("nombre_completo") or "", "nombres": d.get("nombres") or "",
                       "apellido_paterno": d.get("apellido_paterno") or "", "apellido_materno": d.get("apellido_materno") or ""}
            cache.update({"persona": persona, "persona_en": now_iso})
        elif d.get("_sin_registro"):
            persona = {"no_existe": True}
            cache.update({"persona": persona, "persona_en": now_iso})
        elif cache.get("persona"):
            persona = cache["persona"]  # sin respuesta ahora: se usa lo último conocido

    lic_fresca = cache.get("licencia_en") and _vigente(cache["licencia_en"], 7 if cache.get("sin_licencia") else 30) and not refresh
    if not lic_fresca:
        l = await _jsonpe("licencia", {"dni": dni})
        # json.pe anida los datos: {"numero_documento", "nombre_completo", "licencia": {...}}
        if isinstance(l, dict) and isinstance(l.get("licencia"), dict):
            l = l["licencia"]
        if l and (l.get("numero") or l.get("categoria")):
            cache.update({"licencia": {k: (l.get(k) or "") for k in ("numero", "categoria", "fecha_expedicion", "fecha_vencimiento", "estado", "restricciones")},
                          "sin_licencia": False, "licencia_en": now_iso})
        elif l.get("_sin_registro"):
            cache.update({"licencia": None, "sin_licencia": True, "licencia_en": now_iso})

    cache["dni"] = dni
    cache["actualizado_en"] = now_iso
    await db.personas_dni.update_one({"dni": dni}, {"$set": cache}, upsert=True)

    lic = cache.get("licencia")
    if lic:
        m = re.match(r"(\d{2})/(\d{2})/(\d{4})", lic.get("fecha_vencimiento") or "")
        if m:
            venc = datetime(int(m.group(3)), int(m.group(2)), int(m.group(1)), tzinfo=timezone.utc)
            lic = {**lic, "dias_para_vencer": (venc - now).days, "vencida": venc < now}
    p = persona if (persona and not persona.get("no_existe")) else None
    nombre_sugerido = " ".join(x for x in [(p or {}).get("nombres"), (p or {}).get("apellido_paterno"), (p or {}).get("apellido_materno")] if x).strip()
    return {
        "dni": dni,
        "persona": p,
        "no_existe": bool(persona and persona.get("no_existe")),
        "nombre_sugerido": nombre_sugerido,
        "licencia": lic,
        "sin_licencia": bool(cache.get("sin_licencia")) and not lic,
        "verificado": {"reniec": p is not None, "mtc": bool(lic) or bool(cache.get("sin_licencia"))},
        "consultado_en": cache.get("licencia_en") or cache.get("persona_en") or now_iso,
        "fuente": "RENIEC y MTC (vía json.pe)",
        **({"_debug": {"jsonpe_token": bool(os.getenv("JSONPE_TOKEN", "").strip()), "ultimo_error": _JSONPE_ULTIMO_ERROR}}
           if (debug and user.get("role") == "admin_enered") else {}),
    }


@api.post("/documents")
async def upload_manual_document(
    file: UploadFile = File(...),
    tipo: str = Form(...),
    doc: str = Form(...),
    emi: Optional[str] = Form(None),
    ven: Optional[str] = Form(None),
    placa: Optional[str] = Form(None),
    conductor_id: Optional[str] = Form(None),
    viaje_id: Optional[str] = Form(None),
    ref: Optional[str] = Form(None),
    desc: Optional[str] = Form(None),
    extra: Optional[str] = Form(None),
    user: dict = Depends(get_current_user),
):
    content = await file.read()
    content_type = file.content_type or "application/octet-stream"
    meta = {}
    if extra:
        try:
            import json as _json_meta
            meta = _json_meta.loads(extra) if isinstance(extra, str) else {}
            if not isinstance(meta, dict):
                meta = {}
        except Exception:
            meta = {}
    # Perfil del conductor: si ya existe uno con FOTO para esa persona, no se crea otro
    # (el modal manda un "perfil.txt" de relleno cuando no adjuntan foto); solo se
    # actualizan sus datos (DNI, licencia verificada).
    if (tipo or "").lower().startswith("personal") and doc == "Perfil" and placa and not content_type.startswith("image/"):
        existente = await db.documents.find_one({"tipo": tipo, "doc": "Perfil", "placa": placa.upper().strip(),
                                                 "archived": {"$ne": 1}, "content_type": {"$regex": "^image/"}})
        if existente:
            upd = {}
            if desc: upd["desc"] = desc
            if ref: upd["ref"] = ref
            if meta: upd["meta"] = meta
            if upd:
                await db.documents.update_one({"id": existente["id"]}, {"$set": upd})
            existente.pop("_id", None)
            return existente
    key = f"documents/{user.get('empresa') or 'general'}/{str(uuid.uuid4())}_{file.filename}"
    storage.save_object(key, content, content_type)

    # Lectura automática de vigencias: si el certificado es un PDF con texto
    # (revisión técnica, SOAT, tarjeta...), las fechas se extraen solas y el
    # usuario no tiene que digitarlas. Solo llenamos lo que venga vacío.
    fechas_pdf = {}
    if "pdf" in (content_type or "").lower() or (file.filename or "").lower().endswith(".pdf"):
        try:
            fechas_pdf = await asyncio.to_thread(_extraer_vigencia_pdf, content)
        except Exception:
            fechas_pdf = {}
        if not emi and fechas_pdf.get("emi"):
            emi = fechas_pdf["emi"]
        if not ven and fechas_pdf.get("ven"):
            ven = fechas_pdf["ven"]

    # Póliza de seguro vehicular: leer N° de póliza y aseguradora del PDF → referencia
    if (not ref) and ("poliza" in re.sub(r"[^a-z0-9]", "", __import__("unicodedata").normalize("NFKD", doc or "").encode("ascii", "ignore").decode().lower())) and (
            "pdf" in (content_type or "").lower() or (file.filename or "").lower().endswith(".pdf")):
        try:
            pol = await asyncio.to_thread(_extraer_poliza_pdf, content)
            if pol.get("numero"):
                ref = f"Póliza N° {pol['numero']}" + (f" · {pol['aseguradora']}" if pol.get("aseguradora") else "")
                if not emi and pol.get("emi"):
                    emi = pol["emi"]
                if not ven and pol.get("ven"):
                    ven = pol["ven"]
                if pol.get("fuente") == "SBS Central de Riesgo":
                    desc = (desc or "") + f" [SBS: {pol.get('accidentes_5_anios', pol.get('accidentes', 0))} accidente(s) cubiertos en 5 años]"
        except Exception:
            pass

    # Tarjeta de propiedad: completa la ficha del vehículo (año, categoría, VIN, motor,
    # color, marca/modelo, propietario) con lo que dice el documento, solo en campos vacíos.
    datos_tarjeta = {}
    try:
        import unicodedata as _ud
        _dn = re.sub(r"[^a-z0-9]", "", _ud.normalize("NFKD", doc or "").encode("ascii", "ignore").decode().lower())
        es_tarjeta = ("propiedad" in _dn or "identificacionvehicular" in _dn or "tiv" == _dn)
        if es_tarjeta and placa and fechas_pdf is not None and (
            "pdf" in (content_type or "").lower() or (file.filename or "").lower().endswith(".pdf")):
            datos_tarjeta = await asyncio.to_thread(_extraer_tarjeta_propiedad_pdf, content)
            if datos_tarjeta:
                placa_t = placa.replace("-", "").replace(" ", "").upper()
                filt_t = {"placa": placa_t}
                if user.get("empresa"):
                    filt_t["empresa"] = user["empresa"]
                veh = await db.vehiculos.find_one(filt_t)
                if veh:
                    nuevos_t = {k: x for k, x in datos_tarjeta.items() if x and not veh.get(k)}
                    if nuevos_t:
                        nuevos_t["tarjeta_fuente"] = "pdf"
                        await db.vehiculos.update_one({"_id": veh["_id"]}, {"$set": nuevos_t})
                    datos_tarjeta = {"leidos": datos_tarjeta, "aplicados": [k for k in nuevos_t if k != "tarjeta_fuente"]}
    except Exception:
        datos_tarjeta = {}

    doc_id = str(uuid.uuid4())
    doc_record = {
        "id": doc_id,
        "empresa": user.get("empresa"),
        "tipo": tipo,
        "doc": doc,
        "por": user.get("name", "Usuario"),
        "el": datetime.now(timezone.utc).strftime("%d/%m/%y"),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "emi": emi or "—",
        "ven": ven or "—",
        "atr": "—",
        "veh": 1 if placa else 0,
        "grp": 0,
        "all": 0 if placa else 1,
        "placa": placa.upper().strip() if placa else "",
        "conductor_id": conductor_id or "",
        "viaje_id": viaje_id or "",
        "ref": ref or "",
        "desc": desc or "",
        "archived": 0,
        "est": "Vigente",
        "filename": file.filename,
        "storage_key": key,
        "content_type": content_type,
        "size": len(content),
        "meta": meta,
    }

    await db.documents.insert_one(doc_record)

    # Foto del conductor automática: al subir el DNI o el brevete, si la persona aún no tiene
    # foto, se recorta el rostro del documento y se usa como foto de perfil.
    try:
        d_key = re.sub(r"[^a-z]", "", (doc or "").lower())
        if (tipo or "").lower().startswith("personal") and d_key in ("dni", "brevete", "licencia") and placa:
            placa_p = placa.upper().strip()
            perfil = await db.documents.find_one({"tipo": tipo, "doc": "Perfil", "placa": placa_p, "archived": {"$ne": 1}})
            tiene_foto = bool(perfil and str(perfil.get("content_type") or "").startswith("image/"))
            if not tiene_foto:
                foto = await asyncio.to_thread(_recortar_rostro, content, content_type, file.filename or "")
                if foto:
                    fkey = f"documents/{user.get('empresa') or 'general'}/{uuid.uuid4()}_foto_conductor.jpg"
                    storage.save_object(fkey, foto, "image/jpeg")
                    campos = {"storage_key": fkey, "content_type": "image/jpeg", "filename": "foto_conductor.jpg",
                              "size": len(foto), "foto_auto": True, "foto_origen": doc}
                    if perfil:
                        await db.documents.update_one({"id": perfil["id"]}, {"$set": campos})
                    else:
                        base = {k: v for k, v in doc_record.items() if k != "_id"}
                        await db.documents.insert_one({**base, **campos, "id": str(uuid.uuid4()), "doc": "Perfil",
                                                       "emi": "—", "ven": "—", "meta": {}})
                    doc_record["foto_auto"] = True
    except Exception as _e:
        logger.warning(f"Recorte de rostro del conductor falló: {_e}")

    # Si es la revisión técnica o el SOAT de una placa y tenemos vencimiento,
    # se refleja también en la ficha del vehículo (columna + alertas).
    try:
        import unicodedata as _ud
        d_ascii = _ud.normalize("NFKD", doc or "").encode("ascii", "ignore").decode()
        d_norm = re.sub(r"[^a-z0-9]", "", d_ascii.lower())
        placa_n = (placa or "").replace("-", "").replace(" ", "").upper()
        ven_ok = ven and re.fullmatch(r"\d{2}/\d{2}/\d{4}", ven or "")
        pref = None
        if "revision" in d_norm or "revtec" in d_norm or "citv" in d_norm:
            pref = "revtec"
        elif "soat" in d_norm:
            pref = "soat"
        if pref and placa_n and ven_ok:
            filt_v = {"placa": placa_n}
            if user.get("empresa"):
                filt_v["empresa"] = user["empresa"]
            await db.vehiculos.update_one(filt_v, {"$set": {
                f"{pref}_vencimiento": ven,
                f"{pref}_estado": "VIGENTE",
                f"{pref}_fuente": "pdf",
            }})
    except Exception:
        pass

    doc_record.pop("_id", None)
    doc_record.pop("storage_key", None)
    doc_record.pop("content_type", None)
    doc_record["_origen"] = "manual"
    if fechas_pdf:
        doc_record["_fechas_leidas_del_pdf"] = fechas_pdf
    if datos_tarjeta:
        doc_record["_datos_tarjeta"] = datos_tarjeta
    return doc_record

class DocumentMetaUpdate(BaseModel):
    doc: Optional[str] = None
    emi: Optional[str] = None
    ven: Optional[str] = None
    ref: Optional[str] = None
    desc: Optional[str] = None


@api.patch("/documents/{doc_id}")
async def update_document_meta(
    doc_id: str,
    payload: DocumentMetaUpdate,
    user: dict = Depends(get_current_user),
):
    """Edita SOLO los metadatos de un documento (fechas, referencia, nombre, nota)
    sin exigir volver a subir el archivo — el adjunto existente se conserva."""
    doc = await db.documents.find_one({"id": doc_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    if user["role"] != "admin_enered" and doc.get("empresa") != user.get("empresa"):
        raise HTTPException(status_code=403, detail="No autorizado")
    cambios = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None}
    if not cambios:
        return {"status": "sin_cambios"}
    cambios["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db.documents.update_one({"id": doc_id}, {"$set": cambios})
    return {"status": "updated", "cambios": list(cambios.keys())}


@api.delete("/documents/{doc_id}")
async def delete_document(
    doc_id: str,
    user: dict = Depends(get_current_user),
):
    doc = await db.documents.find_one({"id": doc_id})
    if doc:
        if user["role"] != "admin_enered" and doc.get("empresa") != user.get("empresa"):
            raise HTTPException(status_code=403, detail="No autorizado")
        try:
            storage.delete_object(doc["storage_key"])
        except Exception:
            pass
        await db.documents.delete_one({"id": doc_id})
        return {"status": "deleted"}

    sub_doc = await db.subsidio_documents.find_one({"id": doc_id})
    if sub_doc:
        if user["role"] != "admin_enered" and sub_doc.get("empresa") != user.get("empresa"):
            raise HTTPException(status_code=403, detail="No autorizado")
        try:
            storage.delete_object(sub_doc["storage_key"])
        except Exception:
            pass
        await db.subsidio_documents.delete_one({"id": doc_id})
        return {"status": "deleted"}

    raise HTTPException(status_code=404, detail="Documento no encontrado")

@api.put("/documents/{doc_id}/archive")
async def archive_document(
    doc_id: str,
    archived: int,
    user: dict = Depends(get_current_user),
):
    doc = await db.documents.find_one({"id": doc_id})
    if doc:
        if user["role"] != "admin_enered" and doc.get("empresa") != user.get("empresa"):
            raise HTTPException(status_code=403, detail="No autorizado")
        est = "Archivado" if archived else "Vigente"
        await db.documents.update_one({"id": doc_id}, {"$set": {"archived": archived, "est": est}})
        return {"status": "updated"}

    sub_doc = await db.subsidio_documents.find_one({"id": doc_id})
    if sub_doc:
        if user["role"] != "admin_enered" and sub_doc.get("empresa") != user.get("empresa"):
            raise HTTPException(status_code=403, detail="No autorizado")
        await db.subsidio_documents.update_one({"id": doc_id}, {"$set": {"archived": bool(archived)}})
        return {"status": "updated"}

    raise HTTPException(status_code=404, detail="Documento no encontrado")

from fastapi.responses import StreamingResponse
import io

@api.get("/documents/{doc_id}/download")
async def download_document(
    doc_id: str,
    user: dict = Depends(get_current_user),
):
    doc = await db.documents.find_one({"id": doc_id})
    if doc:
        if user["role"] != "admin_enered" and doc.get("empresa") != user.get("empresa"):
            raise HTTPException(status_code=403, detail="No autorizado")
        try:
            file_bytes = storage.get_object_bytes(doc["storage_key"])
        except FileNotFoundError:
            file_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n5 0 obj\n<< /Length 58 >>\nstream\nBT\n/F1 16 Tf\n100 700 Td\n(Documento de prueba - Archivo no encontrado) Tj\nET\nendstream\nendobj\nxref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000223 00000 n \n0000000311 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n419\n%%EOF"
            doc["content_type"] = "application/pdf"
            doc["filename"] = "documento_prueba.pdf"
        
        content_type = doc.get("content_type") or "application/octet-stream"
        filename = doc.get("filename") or "documento"
        return StreamingResponse(
            io.BytesIO(file_bytes),
            media_type=content_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    sub_doc = await db.subsidio_documents.find_one({"id": doc_id})
    if sub_doc:
        if user["role"] != "admin_enered" and sub_doc.get("empresa") != user.get("empresa"):
            raise HTTPException(status_code=403, detail="No autorizado")
        try:
            file_bytes = storage.get_object_bytes(sub_doc["storage_key"])
        except FileNotFoundError:
            file_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n5 0 obj\n<< /Length 58 >>\nstream\nBT\n/F1 16 Tf\n100 700 Td\n(Documento de prueba - Archivo no encontrado) Tj\nET\nendstream\nendobj\nxref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000223 00000 n \n0000000311 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n419\n%%EOF"
            sub_doc["content_type"] = "application/pdf"
            sub_doc["filename"] = "documento_prueba.pdf"
            
        content_type = sub_doc.get("content_type") or "application/octet-stream"
        filename = sub_doc.get("filename") or "documento"
        return StreamingResponse(
            io.BytesIO(file_bytes),
            media_type=content_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
@app.get("/api/files/{file_id:path}")
async def get_legacy_file(file_id: str, user: dict = Depends(get_current_user)):
    if file_id.startswith("tmp_admin/"):
        if user["role"] not in ["admin_enered", "administrador"]:
            raise HTTPException(status_code=403, detail="No autorizado")
        import storage
        file_bytes = storage.get_object_bytes(file_id)
        if not file_bytes:
            raise HTTPException(status_code=404, detail="Temporal no encontrado")
        return Response(content=file_bytes, media_type="application/pdf")

    if user["role"] not in ["admin_enered", "administrador", "contabilidad"]:
        f = await db.files.find_one({"id": file_id})
        if not f or f.get("created_by") != user["id"]:
            raise HTTPException(status_code=404, detail="Archivo no encontrado")
    else:
        f = await db.files.find_one({"id": file_id})
        if not f:
            raise HTTPException(status_code=404, detail="Archivo no encontrado")
            
    return Response(content=f["data"], media_type=f["content_type"])

# ============================================================================
# SUBSIDIO MODULE (DU 004-2026) — añadido sin tocar lo anterior
# ============================================================================
from subsidio import subsidio_router, _set_db as _set_subsidio_db
_set_subsidio_db(db)
app.include_router(subsidio_router)


from abonos import abonos_router
app.include_router(abonos_router)


# CORS — supports comma-separated CORS_ORIGINS, plus FRONTEND_URL for backwards-compat
_origins_env = os.environ.get("CORS_ORIGINS", "")
_frontend = os.environ.get("FRONTEND_URL", "http://localhost:3000")
_allow_origins: list[str] = []
# El preflight OPTIONS lo maneja CORSMiddleware (abajo) contra la allow-list real.
# El handler manual anterior reflejaba CUALQUIER origen con credenciales → se eliminó.

if _origins_env:
    _allow_origins.extend([o.strip() for o in _origins_env.split(",") if o.strip()])
if _frontend and _frontend not in _allow_origins:
    _allow_origins.append(_frontend)
for lo in ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://127.0.0.1:3001"]:
    if lo not in _allow_origins:
        _allow_origins.append(lo)

# Optionally allow regex match for Netlify preview deploys, e.g.
# CORS_ORIGIN_REGEX="https://.*--enered\.netlify\.app"
_cors_regex = os.environ.get("CORS_ORIGIN_REGEX")

_cors_kwargs = {
    "allow_origins": _allow_origins,
    "allow_credentials": True,
    "allow_methods": ["*"],
    "allow_headers": ["*"],
}
if _cors_regex:
    _cors_kwargs["allow_origin_regex"] = _cors_regex

app.add_middleware(CORSMiddleware, **_cors_kwargs)
logger.info(f"CORS allow_origins={_allow_origins} regex={_cors_regex!r}")


# ─── Bitácora de acciones (audit log) ────────────────────────────────────────
_AUDIT_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
_AUDIT_SKIP = ("/api/auth/login", "/api/auth/logout", "/api/auth/refresh")
_AUDIT_ACTION = {"POST": "crear", "PUT": "editar", "PATCH": "editar", "DELETE": "borrar"}


def _audit_modulo(path: str) -> str:
    p = (path or "").lower()
    if "/subsidio" in p: return "Subsidio"
    if "/users" in p: return "Usuarios"
    if "/empresas" in p or "/servicios" in p or "/wialon" in p: return "Empresas"
    if "/invoices" in p or "/facturaci" in p or "/account-state" in p: return "Facturación"
    if "/documents" in p or "/documento" in p: return "Documentación"
    if "/vehiculos" in p or "/conductores" in p: return "Vehículos"
    if "/consumptions" in p or "/consumos" in p: return "Combustible"
    if "/abonos" in p or "/tesoreria" in p: return "Tesorería"
    if "/precios" in p: return "Precios"
    if "/qr" in p: return "QR"
    if "/infracciones" in p: return "Infracciones"
    return "Otro"


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    response = await call_next(request)
    try:
        path = request.url.path
        if (request.method in _AUDIT_METHODS and response.status_code < 400
                and not any(path.startswith(s) for s in _AUDIT_SKIP)):
            token = request.cookies.get("access_token")
            if not token:
                auth = request.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    token = auth[7:]
            uid = None
            if token:
                try:
                    uid = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM]).get("sub")
                except Exception:
                    uid = None
            if uid:
                u = await db.users.find_one({"id": uid}, {"_id": 0, "email": 1, "name": 1, "role": 1, "empresa": 1})
                if u:
                    imp_emp = request.headers.get("X-Impersonate-Empresa")
                    await db.audit_log.insert_one({
                        "id": str(uuid.uuid4()),
                        "at": datetime.now(timezone.utc).isoformat(),
                        "user_id": uid,
                        "user_email": u.get("email"),
                        "user_name": u.get("name"),
                        "user_role": u.get("role"),
                        "empresa": imp_emp or u.get("empresa"),
                        "impersonando": bool(imp_emp),
                        "action": _AUDIT_ACTION.get(request.method, request.method),
                        "modulo": _audit_modulo(path),
                        "method": request.method,
                        "path": path,
                        "status": response.status_code,
                        "ip": request.client.host if request.client else None,
                    })
    except Exception:
        pass
    return response


# ---------- Seed ----------
SAMPLE_COMPANIES = ["TRANSPORTES LIMA SAC", "LOGISTICA ANDINA SA", "CARGO PERU EIRL"]
SAMPLE_CITIES = ["LIMA", "AREQUIPA", "TRUJILLO", "CUSCO", "CHICLAYO"]
SAMPLE_STATIONS = ["PRIMAX SAN ISIDRO", "PRIMAX MIRAFLORES", "PRIMAX AREQUIPA", "PRIMAX TRUJILLO", "PRIMAX NORTE", "PRIMAX SUR"]
SAMPLE_PRODUCTS = ["DIESEL B5", "DIESEL DB5 S-50", "GASOLINA 90", "GASOLINA 95"]


async def seed_demo_data():
    # Users
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@enered.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")

    # El admin principal siempre existe; su contraseña viene de ADMIN_PASSWORD (Render).
    admins = [(admin_email, admin_password, "Admin ENERED")]

    # Cuentas secundarias y demo con contraseña FIJA: solo en entornos de desarrollo.
    # En producción NO se siembran (SEED_DEMO_USERS sin setear).
    seed_demo = os.environ.get("SEED_DEMO_USERS", "").strip().lower() in ("1", "true", "yes")
    if seed_demo:
        admins += [
            ("soporte@ecreea.com", "admin123", "Soporte ECREEA"),
            ("admin@enered.pe", "admin123", "Admin ENERED PE"),
        ]

    for email_add, pass_add, name_add in admins:
        if not await db.users.find_one({"email": email_add}):
            await db.users.insert_one({
                "id": str(uuid.uuid4()),
                "email": email_add,
                "name": name_add,
                "role": "admin_enered",
                "empresa": "ENERED S.A.C.",
                "password_hash": hash_password(pass_add),
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

    if not seed_demo:
        return   # producción: no sembrar usuarios demo con contraseña fija

    demo_users = [
        ("administrador@lima.com", "demo123", "Administrador Lima", "administrador", "TRANSPORTES LIMA SAC"),
        ("logistica@lima.com", "demo123", "Logística Lima", "logistica", "TRANSPORTES LIMA SAC"),
        ("contabilidad@lima.com", "demo123", "Contabilidad Lima", "contabilidad", "TRANSPORTES LIMA SAC"),
        ("administrador@andina.com", "demo123", "Administrador Andina", "administrador", "LOGISTICA ANDINA SA"),
        ("administrador@cargo.com", "demo123", "Administrador Cargo", "administrador", "CARGO PERU EIRL"),
    ]
    for email, pwd, name, role, empresa in demo_users:
        if not await db.users.find_one({"email": email}):
            await db.users.insert_one({
                "id": str(uuid.uuid4()),
                "email": email,
                "name": name,
                "role": role,
                "empresa": empresa,
                "password_hash": hash_password(pwd),
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

    # Consumptions - only if empty
    existing_count = await db.consumptions.count_documents({})
    if existing_count == 0:
        random.seed(42)
        rows = []
        today = datetime.now(timezone.utc).date()
        for empresa in SAMPLE_COMPANIES:
            placas = [f"{random.choice(['A','B','T','P','V'])}{random.randint(1,9)}{random.choice(['A','B','C'])}-{random.randint(100,999)}"
                      for _ in range(random.randint(6, 10))]
            for days_back in range(60):
                date = today - timedelta(days=days_back)
                week_num = date.isocalendar().week
                for _ in range(random.randint(1, 4)):
                    placa = random.choice(placas)
                    ciudad = random.choice(SAMPLE_CITIES)
                    estacion = random.choice(SAMPLE_STATIONS)
                    producto = random.choice(SAMPLE_PRODUCTS)
                    cantidad = round(random.uniform(8, 35), 2)
                    precio_pizarra = round(random.uniform(14.5, 17.2), 2)
                    descuento = round(random.uniform(0.4, 1.2), 2)
                    precio_unit = round(precio_pizarra - descuento, 2)
                    importe = round(cantidad * precio_unit, 2)
                    ahorro = round(cantidad * descuento, 2)
                    rows.append({
                        "id": str(uuid.uuid4()),
                        "FECHA": date.isoformat(),
                        "HORA": f"{random.randint(6,20):02d}:{random.randint(0,59):02d}",
                        "CIUDAD": ciudad,
                        "ESTACION": estacion,
                        "NRO_DE_TARJETA": f"TAR{random.randint(10000,99999)}",
                        "PLACA": placa,
                        "PRODUCTO": producto,
                        "UNIDAD": "GALON",
                        "CANTIDAD_GL": cantidad,
                        "PRECIO_UNITARIO": precio_unit,
                        "IMPORTE_TOTAL": importe,
                        "PRECIO_PIZARRA": precio_pizarra,
                        "AHORRO": ahorro,
                        "NOTA_DE_DESPACHO": f"ND{random.randint(100000,999999)}",
                        "EMPRESA": empresa,
                        "KILOMETRAJE": random.randint(1000, 250000),
                        "MEDIO_DE_IDENTIFICACION": random.choice(["TARJETA", "APP", "QR"]),
                        "SEMANA": f"2026-W{week_num:02d}",
                    })
        if rows:
            await db.consumptions.insert_many(rows)
            logger.info(f"Seeded {len(rows)} consumption rows")

    # Invoices — usar campos correctos del schema real de facturas
    if await db.invoices.count_documents({}) == 0:
        invoices = []
        for empresa in SAMPLE_COMPANIES:
            for i in range(3):
                f_emision = (datetime.now(timezone.utc).date() - timedelta(days=30 * i)).isoformat()
                f_venc = (datetime.now(timezone.utc).date() - timedelta(days=30 * i - 15)).isoformat()
                monto = round(random.uniform(5000, 35000), 2)
                estado = random.choice(["pendiente", "pagada", "vencida"])
                atraso = 0
                if estado == "vencida":
                    try:
                        from datetime import date as _d
                        atraso = max(0, (_d.today() - _d.fromisoformat(f_venc)).days)
                    except Exception:
                        pass
                invoices.append({
                    "id": str(uuid.uuid4()),
                    "empresa": empresa,
                    "n_doc": f"F001-{random.randint(1000,9999):08d}",
                    "tipo_doc": "Factura Ventas",
                    "producto": "DIESEL B5 S-50",
                    "f_emision": f_emision,
                    "f_vencimiento": f_venc,
                    "moneda": "PEN",
                    "monto_total": monto,
                    "saldo": monto if estado != "pagada" else 0.0,
                    "estado": estado,
                    "atraso_dias": atraso,
                    "pdf_filename": None,
                    "xml_filename": None,
                    "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    "uploaded_by": "seed",
                })
        if invoices:
            await db.invoices.insert_many(invoices)

    # Courses
    if await db.courses.count_documents({}) == 0:
        await db.courses.insert_one({
            "id": str(uuid.uuid4()),
            "titulo": "Conducción Eficiente y Ahorro de Combustible",
            "descripcion": "Aprende las mejores prácticas para reducir el consumo de combustible y mejorar la eficiencia de tu flota.",
            "video_url": "https://www.youtube.com/embed/dQw4w9WgXcQ",
            "pdf_url": None,
            "puntaje_minimo": 70,
            "preguntas": [
                {"pregunta": "¿Cuál es la velocidad óptima para ahorrar combustible?", "opciones": ["60-80 km/h", "100-120 km/h", "Mayor a 120 km/h"], "correcta": 0},
                {"pregunta": "¿Qué hábito reduce más el consumo?", "opciones": ["Aceleraciones bruscas", "Conducción suave", "Frenados fuertes"], "correcta": 1},
                {"pregunta": "¿Es recomendable mantener presión correcta en neumáticos?", "opciones": ["Sí", "No", "Solo en invierno"], "correcta": 0},
            ],
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    # Empresa configs (plan, RUC, línea de crédito, unidades)
    empresa_defaults = []
    for empresa, ruc, plan, linea, unidades in empresa_defaults:
        if not await db.empresas_config.find_one({"empresa": empresa}):
            await db.empresas_config.insert_one({
                "id": str(uuid.uuid4()),
                "empresa": empresa,
                "ruc": ruc,
                "plan": plan,
                "linea_credito": linea,
                "unidades_contratadas": unidades,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })





@app.get("/api/temp-backfill-invoices-881")
async def temp_backfill_invoices(_: dict = Depends(require_roles("admin_enered"))):
    """Temporary: sync existing confirmed subsidio records to db.invoices. Solo admin."""
    from datetime import timedelta as _td
    confirmed = await db.consumos_subsidio.find({"status": "confirmed"}).to_list(10000)
    created = 0
    for d in confirmed:
        n_doc = (d.get("numero_documento") or "").upper().strip()
        empresa = d.get("empresa") or ""
        if not n_doc or not empresa:
            continue
        existing = await db.invoices.find_one({"empresa": empresa, "n_doc": n_doc})
        if existing:
            continue
        fecha_str = (d.get("fecha") or "")[:10]
        f_venc = fecha_str
        try:
            f_dt = datetime.strptime(fecha_str, "%Y-%m-%d")
            f_venc = (f_dt + _td(days=30)).date().isoformat()
        except Exception:
            try:
                f_dt = datetime.strptime(fecha_str, "%d/%m/%Y")
                fecha_str = f_dt.date().isoformat()
                f_venc = (f_dt + _td(days=30)).date().isoformat()
            except Exception:
                pass
        inv_doc = {
            "id": d.get("id") or str(uuid.uuid4()),
            "empresa": empresa,
            "n_doc": n_doc,
            "tipo_doc": "factura",
            "producto": normalizar_producto(d.get("producto")) or "DIESEL B5",
            "f_emision": fecha_str,
            "f_vencimiento": f_venc,
            "moneda": "PEN",
            "monto_total": float(d.get("importe_total") or 0),
            "saldo": float(d.get("importe_total") or 0),
            "estado": "pendiente",
            "atraso_dias": 0,
            "pdf_filename": d.get("factura_filename"),
            "xml_filename": None,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "uploaded_by": "backfill",
            "created_via": "subsidio_backfill",
        }
        await db.invoices.insert_one(inv_doc)
        created += 1
    return {"ok": True, "backfilled": created}


async def _vigencias_nocturnas():
    """Tarea programada: recorre todas las empresas a ritmo lento (goteo) y actualiza
    lo que falte o esté por vencer (SOAT, revisión técnica, ficha). Se activa SOLO con
    VIGENCIAS_AUTO=1; hora local Perú configurable con VIGENCIAS_HORA (default 03)."""
    hora = int(os.getenv("VIGENCIAS_HORA", "3"))
    while True:
        try:
            # esperar hasta la próxima ejecución (hora Perú = UTC-5)
            ahora = datetime.now(timezone.utc) - timedelta(hours=5)
            objetivo = ahora.replace(hour=hora, minute=0, second=0, microsecond=0)
            if objetivo <= ahora:
                objetivo += timedelta(days=1)
            await asyncio.sleep(max(60, (objetivo - ahora).total_seconds()))
            empresas = [e for e in await db.vehiculos.distinct("empresa") if e]
            logger.info(f"[vigencias] inicio ciclo nocturno · {len(empresas)} empresas")
            total = 0
            for emp in empresas:
                try:
                    r = await _enriquecer_flota({"empresa": emp})
                    total += r.get("campos_completados", 0)
                    if r.get("mtc_bloqueado"):
                        logger.warning(f"[vigencias] MTC bloqueado durante {emp}; se sigue con SOAT/otros")
                except Exception as e:
                    logger.warning(f"[vigencias] {emp}: {e}")
                await asyncio.sleep(20)  # pausa entre empresas: nunca en ráfaga
            logger.info(f"[vigencias] ciclo terminado · {total} campos actualizados")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"[vigencias] error de ciclo: {e}")
            await asyncio.sleep(600)


@app.on_event("startup")
async def startup():
    try:
        res1 = await db.consumptions.delete_many({
            "EMPRESA": "DISTRIBUIDORA ESTARKOS SOCIEDAD ANONIMA CERRADA",
            "_origen": "manual"
        })
        res2 = await db.consumptions.delete_many({
            "EMPRESA": "DISTRIBUIDORA ESTARKOS SOCIEDAD ANONIMA CERRADA",
            "ESTACION": {"$regex": "Energix", "$options": "i"}
        })
        print(f"DELETED MANUAL RECORDS! {res1.deleted_count} + {res2.deleted_count}")
    except Exception as e:
        print("DELETE ERR", e)

    # Facturas de terceros guardadas como deuda (backfill/sync antiguos) → TERCERO, saldo 0.
    try:
        _mig = await db.invoices.update_many(
            {"created_via": {"$in": list(_TERCERO_VIAS)},
             "estado": {"$not": {"$regex": "^tercero$", "$options": "i"}},
             "$or": [{"ruc_emisor": {"$exists": False}}, {"ruc_emisor": {"$in": [None, ""]}},
                     {"ruc_emisor": {"$ne": ENERGIX_RUC}}]},
            {"$set": {"estado": "TERCERO", "saldo": 0.0, "atraso_dias": 0}})
        if _mig.modified_count:
            logger.info(f"[invoices] {_mig.modified_count} facturas de terceros pasadas a TERCERO/saldo 0")
    except Exception as e:
        logger.warning(f"[invoices] migración terceros falló: {e}")

    # Guardián de sesión ATU (auto-renueva la cuenta maestra cada ~13 min)
    try:
        asyncio.create_task(_atu_guardian())
        logger.info("ATU guardián iniciado")
    except Exception as e:
        print("ATU guardián no arrancó:", e)

    # Vigencias automáticas (SOAT / revisión técnica / ficha) a ritmo lento, de noche.
    # Apagado por defecto: gasta créditos de json.pe; se enciende con VIGENCIAS_AUTO=1.
    if os.getenv("VIGENCIAS_AUTO", "").strip() == "1":
        asyncio.create_task(_vigencias_nocturnas())
        logger.info(f"[vigencias] tarea nocturna activada (hora Perú {os.getenv('VIGENCIAS_HORA', '3')}:00)")

    try:
        await db.users.create_index("email", unique=True)
        await db.consumptions.create_index("EMPRESA")
        await db.consumptions.create_index("FECHA")
        await db.consumptions.create_index([("EMPRESA", 1), ("FECHA", -1)])
        await db.consumptions.create_index([("EMPRESA", 1), ("PLACA", 1)])
        await db.consumptions.create_index("PLACA")
        await db.consumptions.create_index("SEMANA")
        await db.invoices.create_index([("empresa", 1), ("estado", 1)])
        await db.qr_codes.create_index([("empresa", 1), ("placa", 1)])
        await db.consumos_subsidio.create_index([("user_id", 1), ("status", 1)])
        await db.consumos_subsidio.create_index([("user_id", 1), ("fecha", -1)])
        await db.empresas_config.create_index("empresa", unique=True)
        await db.subsidio_documents.create_index("user_id")
        await db.subsidio_vehicles.create_index("user_id")
        await db.subsidio_declaraciones.create_index("user_id")
        await db.subsidio_bank_accounts.create_index("user_id")
        await db.subsidio_leads.create_index("calc_id")
        await db.subsidio_leads.create_index("email")
        await db.subsidio_leads.create_index("ruc")
        await db.users.create_index([("role", 1), ("created_at", -1)])
        await db.calculations.create_index("id")
    except Exception as e:
        logger.warning(f"Index creation warning: {e}")

    try:
        await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=3600)
    except Exception as e:
        logger.warning(f"Token index warning: {e}")

    try:
        await seed_demo_data()
    except Exception as e:
        logger.warning(f"Seed demo data warning: {e}")

    try:
        result = await _svc.backfill_servicios(db)
        logger.info(f"Servicios backfill: {result}")
    except Exception as e:
        logger.warning(f"Servicios backfill failed: {e}")

    try:
        invs_to_heal = await db.invoices.find({"factura_storage_key": {"$exists": False}}).to_list(100)
        for inv in invs_to_heal:
            emp = inv.get("empresa") or ""
            ndoc = inv.get("n_doc") or inv.get("numero_documento")
            pdf_fname = inv.get("pdf_filename") or (f"{ndoc}.pdf" if ndoc else None)
            if emp and pdf_fname:
                s_key = _inv_key(emp, pdf_fname)
                await db.invoices.update_many({"_id": inv["_id"]}, {"$set": {"factura_storage_key": s_key, "pdf_key": s_key, "storage_key": s_key}})
                if inv.get("id"):
                    await db.empresas_invoices.update_many({"id": inv.get("id")}, {"$set": {"factura_storage_key": s_key, "pdf_key": s_key, "storage_key": s_key}})
                if ndoc:
                    await db.consumos_subsidio.update_many({"numero_documento": ndoc}, {"$set": {"factura_storage_key": s_key, "pdf_key": s_key, "storage_key": s_key}})
    except Exception as e:
        logger.warning(f"Auto-heal invoices warning: {e}")
        
    # Auto-apply pending saldo_a_favor to invoices
    async for config in db.empresas_config.find({"saldo_a_favor": {"$gt": 0}}):
        empresa = config["empresa"]
        saldo = float(config["saldo_a_favor"])
        cursor = db.invoices.find({
            "empresa": empresa,
            "estado": {"$in": ["PENDIENTE", "pendiente", "vencida", "VENCIDA", "por_vencer"]}
        }).sort("fecha_emision", 1)
        invoices = await cursor.to_list(1000)
        
        for fac in invoices:
            if saldo <= 0: break
            deuda = float(fac.get("saldo", fac.get("monto_total", 0)))
            if deuda <= 0: continue
            if saldo >= deuda:
                await db.invoices.update_one({"id": fac["id"]}, {"$set": {"estado": "pagada", "saldo": 0.0}})
                saldo -= deuda
            else:
                await db.invoices.update_one({"id": fac["id"]}, {"$set": {"saldo": round(deuda - saldo, 2)}})
                saldo = 0.0
        await db.empresas_config.update_one({"id": config["id"]}, {"$set": {"saldo_a_favor": round(saldo, 2)}})

    try:
        import sys
        sys.path.append(os.path.dirname(__file__) + "/..")
        from clean_estarkos import clean_estarkos
        await clean_estarkos()
    except Exception as e:
        print("clean_estarkos err:", e)

# ---------- Precios de Combustible (Facilito OSINERGMIN) ----------

@api.get("/precios")
async def get_precios(
    user: dict = Depends(get_current_user),
    empresa: Optional[str] = None,
    combustible: Optional[str] = None,
    departamento: Optional[str] = None,
    provincia: Optional[str] = None,
    distrito: Optional[str] = None,
    solo_enered: bool = False,
    limite: int = 500,
):
    """Devuelve precios de estaciones de servicio con soporte para 4 filtros:
    departamento, provincia, distrito y combustible.
    `limite`: tope de registros. La tabla usa 500 (los más baratos); el mapa pide
    muchos más para pintar TODO el país, no solo la franja más barata.
    """
    # Eliminar cualquier registro antiguo de prueba ("ES NUEVO CHIMBOTE", "ES CASMA", etc.)
    await db.precios_facilito.delete_many({"establecimiento": {"$regex": "^ES ", "$options": "i"}})
    await db.precios.delete_many({})

    facilito_count = await db.precios_facilito.count_documents({})
    if facilito_count < 1:
        try:
            from seed_facilito_precios import seed
            await seed()
        except Exception as se:
            logger.warning(f"Auto-seed Facilito exception: {se}")

    query: dict = {}
    if combustible:
        c_upper = combustible.strip().upper()
        if "DB5" in c_upper or "DIESEL" in c_upper:
            query["combustible"] = {"$regex": "DB5|DIESEL|S-50|UV", "$options": "i"}
        elif "REGULAR" in c_upper:
            query["combustible"] = {"$regex": "REGULAR|84|90", "$options": "i"}
        elif "PREMIUM" in c_upper:
            query["combustible"] = {"$regex": "PREMIUM|95|97|98", "$options": "i"}
        else:
            query["combustible"] = {"$regex": combustible, "$options": "i"}

    if departamento:
        dpto_norm = departamento.strip().upper().replace("Á", "A").replace("É", "E").replace("Í", "I").replace("Ó", "O").replace("Ú", "U")
        query["departamento"] = {"$regex": dpto_norm, "$options": "i"}
    if provincia:
        prov_norm = provincia.strip().upper().replace("PACASMALLO", "PACASMA").replace("PACASMAYO", "PACASMA")
        query["provincia"] = {"$regex": prov_norm, "$options": "i"}
    if distrito:
        dist_norm = distrito.strip().upper()
        query["$or"] = [
            {"distrito": {"$regex": dist_norm, "$options": "i"}},
            {"ciudad": {"$regex": dist_norm, "$options": "i"}},
            {"direccion": {"$regex": dist_norm, "$options": "i"}}
        ]
    if solo_enered:
        # El flag es_enered de precios_facilito se pierde en cada scrape (reemplaza la colección).
        # Filtramos por los nombres registrados en estaciones_enered (fuente de verdad).
        _enered_names = await db.estaciones_enered.distinct("nombre_facilito")
        query["establecimiento"] = {"$in": _enered_names or ["__NINGUNA__"]}

    # 1. Consulta estricta
    cursor = db.precios_facilito.find(query, {"_id": 0}).sort("precio_venta", 1).limit(limite)
    precios = await cursor.to_list(limite)

    # 2. Si no hay resultados para provincia/distrito específico, relajar a Departamento
    if not precios and departamento:
        dpto_norm = departamento.strip().upper().replace("Á", "A").replace("É", "E").replace("Í", "I").replace("Ó", "O").replace("Ú", "U")
        fallback_query = {"departamento": {"$regex": dpto_norm, "$options": "i"}}
        if combustible:
            fallback_query["combustible"] = {"$regex": combustible, "$options": "i"}
        if solo_enered:
            _en = await db.estaciones_enered.distinct("nombre_facilito")
            fallback_query["establecimiento"] = {"$in": _en or ["__NINGUNA__"]}
        cursor = db.precios_facilito.find(fallback_query, {"_id": 0}).sort("precio_venta", 1).limit(limite)
        precios = await cursor.to_list(limite)

    # 3. Si aún no hay resultados, auto-seed y re-consultar de inmediato
    if not precios:
        try:
            from seed_facilito_precios import seed
            await seed(db)
            cursor = db.precios_facilito.find(query, {"_id": 0}).sort("precio_venta", 1).limit(limite)
            precios = await cursor.to_list(limite)
            if not precios:
                cursor = db.precios_facilito.find({}, {"_id": 0}).sort("precio_venta", 1).limit(limite)
                precios = await cursor.to_list(limite)
        except Exception as se:
            logger.warning(f"Fallback seed exception: {se}")


    # Cruzar con precios ENERED de db.estaciones_enered
    enered_map = {}
    enered_docs = await db.estaciones_enered.find({}, {"_id": 0}).to_list(500)
    for e in enered_docs:
        enered_map[e.get("nombre_facilito", "").strip().upper()] = e


    for p in precios:
        nombre_est = p.get("establecimiento", "").strip().upper()
        enered_info = enered_map.get(nombre_est)
        if not enered_info:
            for key, val in enered_map.items():
                if key in nombre_est or nombre_est in key:
                    enered_info = val
                    break

        precio_pizarra = float(p.get("precio_venta") or 0)
        p["precio_pizarra"] = precio_pizarra

        if enered_info and enered_info.get("precio_enered"):
            p["es_enered"] = True
            p["precio_enered"] = float(enered_info.get("precio_enered"))
            ahorro = round(precio_pizarra - p["precio_enered"], 2)
            p["ahorro"] = max(ahorro, 0)
            p["porcentaje_ahorro"] = round((p["ahorro"] / precio_pizarra) * 100, 1) if precio_pizarra > 0 else 0
            p["acepta_factura"] = enered_info.get("acepta_factura", True)
            p["acepta_tarjeta"] = enered_info.get("acepta_tarjeta", True)
        else:
            p["precio_enered"] = None
            p["ahorro"] = 0.0
            p["porcentaje_ahorro"] = 0.0
            p["acepta_factura"] = False
            p["acepta_tarjeta"] = False

        p["calidad"] = 5 if p.get("es_enered") else 4

    # Deduplicar por (establecimiento, dirección, combustible) para eliminar filas repetidas
    seen = set()
    dedup_precios = []
    for p in precios:
        est = (p.get("establecimiento") or p.get("estacion") or "").strip().upper()
        dir_sub = (p.get("direccion") or "").strip().upper()[:20]
        comb = (p.get("combustible") or "").strip().upper()
        key = (est, dir_sub, comb)
        if key not in seen:
            seen.add(key)
            dedup_precios.append(p)
    precios = dedup_precios

    mejor_precio = min(
        [p.get("precio_enered") or p.get("precio_pizarra", 9999) for p in precios if (p.get("precio_pizarra") or 0) > 0] or [0]
    )
    last_sync = await db.precios_facilito.find_one({}, {"scraped_at": 1, "_id": 0}, sort=[("scraped_at", -1)])
    return {
        "precios": precios,
        "mejor_precio": mejor_precio if mejor_precio != 9999 else 0,
        "fuente": "facilito",
        "last_sync": last_sync.get("scraped_at") if last_sync else None,
        "total": len(precios),
    }



@api.get("/precios/ubicaciones")
async def get_ubicaciones(user: dict = Depends(get_current_user)):
    """Retorna la lista de departamentos, provincias y distritos disponibles."""
    from services.facilito_scraper import DEPARTAMENTOS
    dptos_facilito = [d["name"] for d in DEPARTAMENTOS]
    
    dptos_db = await db.precios_facilito.distinct("departamento")
    all_dptos = sorted(list(set(dptos_facilito + [d for d in dptos_db if d])))
    
    provincias_db = await db.precios_facilito.distinct("provincia")
    distritos_db = await db.precios_facilito.distinct("distrito")
    
    return {
        "departamentos": all_dptos,
        "provincias": [p for p in provincias_db if p],
        "distritos": [dist for dist in distritos_db if dist]
    }


@api.get("/precios/combustibles")
async def get_combustibles_disponibles(user: dict = Depends(get_current_user)):
    """Retorna los tipos de combustible disponibles en la BD."""
    from services.facilito_scraper import COMBUSTIBLES
    disponibles = await db.precios_facilito.distinct("combustible")
    if not disponibles:
        disponibles = COMBUSTIBLES
    return {"combustibles": sorted([c for c in disponibles if c])}


@api.post("/admin/precios/sync")
async def sync_precios(user: dict = Depends(require_roles("admin_enered"))):
    """Dispara el scraping de precios desde Facilito OSINERGMIN."""
    from services.facilito_scraper import scrape_all_precios_async, COMBUSTIBLES
    from seed_facilito_precios import seed

    enered_docs = await db.estaciones_enered.find({}, {"nombre_facilito": 1}).to_list(500)
    enered_stations = {e.get("nombre_facilito", "") for e in enered_docs if e.get("nombre_facilito")}

    results = []
    try:
        results = await scrape_all_precios_async(enered_stations)
    except Exception as e:
        logger.error(f"Facilito scrape error: {e}")

    # 1. Ejecutar semilla siempre como respaldo base para estaciones críticas (ej. Trujillo)
    await seed(db)

    if results:
        # 2. Agrupar por departamento para NO borrar zonas que hayan fallado/colgado en Facilito
        dptos_scraped = set(r.get("departamento") for r in results if r.get("departamento"))
        
        for dpto in dptos_scraped:
            await db.precios_facilito.delete_many({"departamento": dpto})
            
        await db.precios_facilito.insert_many(results)

    await db.precios_facilito.create_index("combustible")
    await db.precios_facilito.create_index("departamento")
    await db.precios_facilito.create_index("es_enered")
    
    count = await db.precios_facilito.count_documents({})

    return {
        "ok": True,
        "total_synced": len(results),
        "combustibles": COMBUSTIBLES,
        "message": f"{len(results)} precios actualizados desde Facilito OSINERGMIN",
    }



@api.get("/admin/precios/estaciones-enered")
async def list_estaciones_enered(user: dict = Depends(require_roles("admin_enered"))):
    """Lista las estaciones ENERED registradas con precio especial."""
    docs = await db.estaciones_enered.find({}, {"_id": 0}).to_list(500)
    return {"estaciones": docs}


@api.post("/admin/precios/estaciones-enered")
async def upsert_estacion_enered(
    data: dict,
    user: dict = Depends(require_roles("admin_enered"))
):
    """Agrega o actualiza una estacion ENERED con su precio especial."""
    nombre = data.get("nombre_facilito", "").strip()
    if not nombre:
        raise HTTPException(status_code=400, detail="nombre_facilito es requerido")

    precio = data.get("precio_enered")
    if precio is not None:
        precio = float(precio)

    doc = {
        "nombre_facilito": nombre,
        "precio_enered": precio,
        "departamento": data.get("departamento", ""),
        "provincia": data.get("provincia", ""),
        "distrito": data.get("distrito", ""),
        "acepta_factura": data.get("acepta_factura", True),
        "acepta_tarjeta": data.get("acepta_tarjeta", True),
        "activa": data.get("activa", True),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    await db.estaciones_enered.update_one(
        {"nombre_facilito": nombre},
        {"$set": doc},
        upsert=True,
    )
    await db.precios_facilito.update_many(
        {"establecimiento": {"$regex": nombre, "$options": "i"}},
        {"$set": {"es_enered": True}}
    )
    return {"ok": True, "nombre_facilito": nombre, "precio_enered": precio}


@api.delete("/admin/precios/estaciones-enered")
async def remove_estacion_enered(nombre_facilito: str, user: dict = Depends(require_roles("admin_enered"))):
    """Quita una estación de la Red ENERED: borra su precio especial y revierte es_enered."""
    nombre = (nombre_facilito or "").strip()
    if not nombre:
        raise HTTPException(status_code=400, detail="nombre_facilito es requerido")
    res = await db.estaciones_enered.delete_one({"nombre_facilito": nombre})
    await db.precios_facilito.update_many(
        {"establecimiento": {"$regex": re.escape(nombre), "$options": "i"}},
        {"$set": {"es_enered": False}, "$unset": {"precio_enered": ""}},
    )
    return {"ok": True, "removed": res.deleted_count}


def _build_invoice_query(inv_id: str) -> dict:
    from urllib.parse import unquote
    from bson import ObjectId
    clean_id = unquote(str(inv_id)).strip()
    esc = re.escape(clean_id)
    or_list = [
        {"id": clean_id},
        {"_id": clean_id},
        {"n_doc": clean_id},
        {"numero_documento": clean_id},
        {"n_doc": {"$regex": f"^{esc}$", "$options": "i"}},
        {"numero_documento": {"$regex": f"^{esc}$", "$options": "i"}},
        {"factura_filename": {"$regex": f"^{esc}$", "$options": "i"}},
        {"pdf_filename": {"$regex": f"^{esc}$", "$options": "i"}},
    ]
    if len(clean_id) == 24:
        try:
            or_list.append({"_id": ObjectId(clean_id)})
        except Exception:
            pass
    return {"$or": or_list}


def _safe_doc(name: str) -> str:
    if not name:
        return "GENERAL"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(name).strip())


def _inv_key(empresa: str, filename: str) -> str:
    emp = _safe_doc(empresa or "GENERAL")
    fn = _safe_doc(filename or "document.pdf")
    return f"invoices/{emp}/{fn}"


@api.get("/invoices/{inv_id}/download/{kind}")
async def invoice_download(inv_id: str, kind: str, request: Request):
    user = await get_current_user_optional(request)
    if kind not in ("pdf", "xml", "factura"):
        kind = "pdf"
    
    q = _build_invoice_query(inv_id)

    # 1. Buscar factura
    inv = await db.invoices.find_one(q, {"_id": 0})
    if not inv:
        inv = await db.empresas_invoices.find_one(q, {"_id": 0})
    if not inv:
        sub_doc = await db.consumos_subsidio.find_one(q) or await db.consumos_subsidio.find_one(q, {"_id": 0})
        if sub_doc:
            inv = {
                "id": sub_doc.get("id") or str(sub_doc.get("_id", "")) or inv_id,
                "n_doc": sub_doc.get("numero_documento") or sub_doc.get("n_doc") or inv_id,
                "empresa": sub_doc.get("empresa"),
                "pdf_filename": sub_doc.get("factura_filename") or sub_doc.get("pdf_filename"),
                "factura_storage_key": sub_doc.get("factura_storage_key"),
                "factura_filename": sub_doc.get("factura_filename"),
                "factura_content_type": sub_doc.get("factura_content_type") or "application/pdf",
                "monto_total": sub_doc.get("monto_total") or sub_doc.get("monto") or sub_doc.get("importe_total") or 0,
                "f_emision": sub_doc.get("fecha") or sub_doc.get("f_emision")
            }

    if not inv:
        from urllib.parse import unquote
        clean_doc = unquote(str(inv_id)).strip()
        esc_cdoc = re.escape(clean_doc)
        reg_q = {"$or": [{"n_doc": {"$regex": f"^{esc_cdoc}$", "$options": "i"}}, {"numero_documento": {"$regex": f"^{esc_cdoc}$", "$options": "i"}}]}
        inv = await db.invoices.find_one(reg_q, {"_id": 0}) or await db.empresas_invoices.find_one(reg_q, {"_id": 0})
        if not inv:
            sub_doc2 = await db.consumos_subsidio.find_one(reg_q)
            if sub_doc2:
                inv = {
                    "id": sub_doc2.get("id") or str(sub_doc2.get("_id", "")) or inv_id,
                    "n_doc": sub_doc2.get("numero_documento") or sub_doc2.get("n_doc") or inv_id,
                    "empresa": sub_doc2.get("empresa"),
                    "pdf_filename": sub_doc2.get("factura_filename") or sub_doc2.get("pdf_filename"),
                    "factura_storage_key": sub_doc2.get("factura_storage_key"),
                    "factura_filename": sub_doc2.get("factura_filename"),
                    "factura_content_type": sub_doc2.get("factura_content_type") or "application/pdf",
                    "monto_total": sub_doc2.get("monto_total") or sub_doc2.get("monto") or sub_doc2.get("importe_total") or 0,
                    "f_emision": sub_doc2.get("fecha") or sub_doc2.get("f_emision")
                }

    if not inv:
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    # 2. Chequeo de Subsidio (Storage Key) - Prioridad Absoluta
    if inv.get("factura_storage_key"):
        if kind == "xml":
            raise HTTPException(status_code=404, detail="No existe archivo XML para facturas de subsidio")
        
        key = inv["factura_storage_key"]
        fname = inv.get("factura_filename") or inv.get("pdf_filename") or "factura_original.pdf"
        media = inv.get("factura_content_type") or "application/pdf"

        data = None
        # 1) Intentar la key guardada.
        if key and storage.object_exists(key):
            try:
                data = storage.get_object_bytes(key)
            except Exception:
                data = None
        # 2) Fallback robusto: el archivo real del cliente vive en
        #    subsidio/{user_id}/factura_subsidio/{hash}-{factura_filename}. Buscamos por el
        #    nombre de archivo real aunque factura_storage_key apunte a una key inexistente.
        if data is None:
            # Probar varias pistas: nombre real, nombre sin espacios (el archivo se saneó al
            # subir) y, lo más estable, el número de documento (va embebido en el nombre).
            n_doc = inv.get("n_doc") or inv.get("numero_documento") or ""
            alt_fname = inv.get("factura_filename") or inv.get("pdf_filename") or ""
            candidates = [c for c in [
                alt_fname,
                alt_fname.replace(" ", ""),
                f"{n_doc}.pdf" if n_doc else "",
            ] if c]
            for cand in candidates:
                alt_key = storage.find_by_suffix(cand, prefix="subsidio/")
                if alt_key:
                    try:
                        data = storage.get_object_bytes(alt_key)
                    except Exception:
                        data = None
                    if data is not None:
                        break
        if data is None:
            raise HTTPException(status_code=404, detail="El documento original no está disponible")

        from fastapi.responses import Response
        import urllib.parse
        encoded_name = urllib.parse.quote(fname)
        return Response(
            content=data,
            media_type=media,
            headers={
                "Content-Disposition": f"inline; filename*=UTF-8''{encoded_name}"
            }
        )

    # 3. Fallback para facturas regulares de facturación (legacy o no-subsidio)
    fname = inv.get(f"{kind}_filename") or inv.get("pdf_filename") or inv.get("factura_filename")
    emp = inv.get("empresa") or ""
    n_doc = inv.get("n_doc") or inv.get("numero_documento") or inv_id

    candidate_keys = []
    if fname:
        candidate_keys.append(_inv_key(emp, fname))
        candidate_keys.append(f"invoices/{emp}/{fname}")
        candidate_keys.append(fname)
    if n_doc:
        candidate_keys.append(_inv_key(emp, f"{n_doc}.{kind}"))
        candidate_keys.append(f"invoices/{emp}/{n_doc}.{kind}")

    valid_key = None
    seen = set()
    for k in candidate_keys:
        if k:
            k_clean = str(k).lstrip("/")
            for alt_k in (k_clean, f"uploads/{k_clean}" if not k_clean.startswith("uploads/") else k_clean):
                if alt_k not in seen:
                    seen.add(alt_k)
                    if storage.object_exists(alt_k):
                        valid_key = alt_k
                        break
            if valid_key:
                break

    download_name = fname or f"{n_doc}.{kind}"
    media = "application/pdf" if kind == "pdf" else "application/xml"

    if valid_key:
        try:
            return storage.download_response(valid_key, download_name, media)
        except Exception:
            pass

    # Si llegamos hasta aquí y no hay factura_storage_key ni se halló en fallback, tirar 404 en lugar de generar
    raise HTTPException(status_code=404, detail="El documento no está disponible")


@api.get("/admin/subsidio/documents/{doc_id}/download")
async def subsidio_admin_document_download(doc_id: str, request: Request):
    user = await get_current_user(request)   # 401 si no hay token válido
    if user.get("role") != "admin_enered":
        raise HTTPException(status_code=403, detail="Solo admin ENERED")

    try:
        from urllib.parse import unquote
        clean_id = unquote(str(doc_id)).strip()
        doc = await db.subsidio_documentos.find_one({"$or": [{"id": clean_id}, {"_id": clean_id}]}) or await db.subsidio_documentos.find_one({"filename": clean_id})
        
        storage_key = None
        filename = "documento.pdf"
        if doc:
            storage_key = doc.get("storage_key") or doc.get("factura_storage_key") or doc.get("file_key")
            filename = doc.get("filename") or doc.get("nombre_archivo") or "documento.pdf"
        
        if not storage_key:
            storage_key = f"subsidio/documentos/{clean_id}"
            
        if storage.object_exists(storage_key):
            return storage.download_response(storage_key, filename, "application/pdf")
            
        pdf_bytes = _generate_minimal_pdf_bytes(
            f"Documento Subsidio {clean_id}",
            [
                f"Documento ID: {clean_id}",
                f"Tipo: {doc.get('categoria', 'Documento Subsidio') if doc else 'Documento Subsidio'}",
                "Documento oficialmente registrado en la plataforma Enered"
            ]
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="{filename}"'}
        )
    except Exception as err:
        logger.error(f"Error in subsidio_admin_document_download: {err}", exc_info=True)
        pdf_bytes = _generate_minimal_pdf_bytes(
            f"Documento {doc_id}",
            [
                f"ID: {doc_id}",
                "Documento registrado en la plataforma Enered"
            ]
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="{doc_id}.pdf"'}
        )


@api.get("/admin/subsidio/invoices/{inv_id}/download")
async def subsidio_admin_invoice_download(inv_id: str, request: Request):
    user = await get_current_user(request)   # 401 si no hay token válido
    if user.get("role") != "admin_enered":
        raise HTTPException(status_code=403, detail="Solo admin ENERED")

    try:
        return await invoice_download(inv_id=inv_id, kind="pdf", user=user)
    except (HTTPException, Exception) as err:
        logger.error(f"Error in subsidio_admin_invoice_download: {err}", exc_info=True)
        pdf_bytes = _generate_minimal_pdf_bytes(
            f"Factura {inv_id}",
            [
                f"Documento N: {inv_id}",
                "Estado: COMPROBANTE REGISTRADO EN ENERED",
                "Documento oficial de comprobante generado por Enered"
            ]
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="{inv_id}.pdf"'}
        )


@api.post("/admin/invoices/{inv_id}/upload-file")
async def upload_invoice_file(
    inv_id: str,
    file: UploadFile = File(...),
    kind: str = Form("pdf"),
    user: dict = Depends(require_roles("admin_enered"))
):
    from urllib.parse import unquote
    clean_id = unquote(str(inv_id)).strip()
    q = _build_invoice_query(clean_id)
    
    inv = await db.invoices.find_one(q) or await db.empresas_invoices.find_one(q) or await db.consumos_subsidio.find_one(q)
    if not inv:
        esc = re.escape(clean_id)
        alt_q = {"$or": [{"n_doc": {"$regex": f"^{esc}$", "$options": "i"}}, {"numero_documento": {"$regex": f"^{esc}$", "$options": "i"}}]}
        inv = await db.invoices.find_one(alt_q) or await db.empresas_invoices.find_one(alt_q) or await db.consumos_subsidio.find_one(alt_q)
    
    empresa = (inv.get("empresa") if inv else "GENERAL") or "GENERAL"
    n_doc = (inv.get("n_doc") or inv.get("numero_documento") if inv else clean_id) or clean_id
    
    content = await file.read()
    ext = "pdf" if file.filename.lower().endswith(".pdf") else "pdf"
    storage_key = f"invoices/{empresa}/{_safe_doc(n_doc)}.{ext}"
    storage.save_object(storage_key, content, file.content_type or "application/pdf")
    
    update_fields = {
        "factura_storage_key": storage_key,
        "storage_key": storage_key,
        "pdf_filename": file.filename,
        "factura_filename": file.filename
    }
    
    await db.invoices.update_many(q, {"$set": update_fields})
    await db.empresas_invoices.update_many(q, {"$set": update_fields})
    await db.consumos_subsidio.update_many(q, {"$set": update_fields})
    
    return {"ok": True, "storage_key": storage_key}


# ======================================================================================
# MANTENIMIENTO (Fleetrun ENERED): plan de intervalos, km real desde Wialon, servicios,
# costos. Colecciones: mtto_intervalos, mtto_servicios.
# ======================================================================================
_MTTO_PLAN_ESTANDAR = [
    {"nombre": "Cambio de aceite y filtro de aceite", "categoria": "Motor", "cada_km": 10000, "cada_dias": 180, "aviso_km": 1000, "aviso_dias": 15},
    {"nombre": "Filtro de aire", "categoria": "Motor", "cada_km": 20000, "cada_dias": 365, "aviso_km": 1500, "aviso_dias": 15},
    {"nombre": "Filtro de combustible", "categoria": "Motor", "cada_km": 20000, "cada_dias": 365, "aviso_km": 1500, "aviso_dias": 15},
    {"nombre": "Revisión de frenos (pastillas / zapatas)", "categoria": "Frenos", "cada_km": 20000, "cada_dias": 0, "aviso_km": 2000, "aviso_dias": 0},
    {"nombre": "Rotación y presión de neumáticos", "categoria": "Neumáticos", "cada_km": 10000, "cada_dias": 0, "aviso_km": 1000, "aviso_dias": 0},
    {"nombre": "Cambio de neumáticos", "categoria": "Neumáticos", "cada_km": 60000, "cada_dias": 0, "aviso_km": 5000, "aviso_dias": 0},
    {"nombre": "Refrigerante y sistema de enfriamiento", "categoria": "Motor", "cada_km": 40000, "cada_dias": 730, "aviso_km": 3000, "aviso_dias": 30},
    {"nombre": "Batería", "categoria": "Eléctrico", "cada_km": 0, "cada_dias": 730, "aviso_km": 0, "aviso_dias": 30},
    {"nombre": "Alineamiento y balanceo", "categoria": "Suspensión", "cada_km": 20000, "cada_dias": 0, "aviso_km": 2000, "aviso_dias": 0},
    {"nombre": "Caja y transmisión (aceite)", "categoria": "Transmisión", "cada_km": 60000, "cada_dias": 0, "aviso_km": 5000, "aviso_dias": 0},
]


def _mtto_empresa(u: dict) -> str:
    emp = (u.get("_empresa_activa") or u.get("empresa") or "").strip()
    if not emp:
        raise HTTPException(status_code=400, detail="Elige una empresa para ver su mantenimiento")
    return emp


def _mtto_placa(p: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (p or "").upper())


def _mtto_placa_de_unidad(nombre: str) -> str:
    """'CCQ-845 (V-413)' → 'CCQ845'."""
    m = re.search(r"\b([A-Z0-9]{3})-?([0-9]{3})\b", (nombre or "").upper())
    return (m.group(1) + m.group(2)) if m else _mtto_placa(nombre)[:6]


class MttoIntervaloIn(BaseModel):
    nombre: str
    categoria: Optional[str] = "General"
    cada_km: Optional[float] = 0
    cada_dias: Optional[int] = 0
    aviso_km: Optional[float] = 0
    aviso_dias: Optional[int] = 0
    placas: Optional[List[str]] = None   # vacío/None = aplica a toda la flota
    activo: Optional[bool] = True


class MttoRepuestoIn(BaseModel):
    descripcion: str
    cantidad: Optional[float] = 1
    costo: Optional[float] = 0


class MttoServicioIn(BaseModel):
    placa: str
    intervalo_id: Optional[str] = None
    nombre: str
    estado: Optional[str] = "hecho"          # planificado | en_taller | hecho
    fecha: Optional[str] = None              # YYYY-MM-DD
    km: Optional[float] = None
    taller: Optional[str] = ""
    costo_mano_obra: Optional[float] = 0
    costo_repuestos: Optional[float] = None  # si None se suma de repuestos
    repuestos: Optional[List[MttoRepuestoIn]] = None
    notas: Optional[str] = ""
    documento_id: Optional[str] = None


async def _mtto_km_actual(empresa: str, user: dict) -> dict:
    """Km actual por placa: Wialon (odómetro en vivo) si la empresa tiene GPS; si no, el
    kilometraje del módulo Vehículos. Devuelve {PLACA: {km, fuente, en, encendido}}."""
    out = {}
    try:
        info = await _svc.get_empresa_servicios(db, empresa)
        if info["servicios"].get("gps"):
            w = await get_wialon_units(empresa=empresa if user.get("role") == "admin_enered" else None, user=user)
            for un in (w or {}).get("units") or []:
                pn = _mtto_placa_de_unidad(un.get("name"))
                if not pn:
                    continue
                km = un.get("odometer") or 0
                try:
                    km = float(km)
                except Exception:
                    km = 0.0
                if km > 5_000_000:  # metros → km
                    km = km / 1000.0
                ts = un.get("timestamp")
                out[pn] = {"km": round(km, 1), "fuente": "Wialon", "en": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None,
                           "encendido": bool(un.get("ignition")), "unidad": un.get("name")}
    except HTTPException:
        pass
    except Exception as e:
        logger.warning(f"Mantenimiento: km desde Wialon falló para {empresa}: {e}")
    # Persistir el último km leído (para historial y para cuando Wialon no responda)
    if out:
        ahora = datetime.now(timezone.utc).isoformat()
        for pn, d in out.items():
            try:
                await db.vehiculos.update_many({"empresa": empresa, "placa": {"$regex": f"^{pn[:3]}-?{pn[3:]}$", "$options": "i"}},
                                               {"$set": {"km_wialon": d["km"], "km_wialon_en": ahora}})
            except Exception:
                pass
    async for v in db.vehiculos.find({"empresa": empresa}, {"_id": 0, "placa": 1, "kilometraje": 1, "km_wialon": 1, "km_wialon_en": 1}):
        pn = _mtto_placa(v.get("placa"))
        if pn and pn not in out:
            if v.get("km_wialon"):
                out[pn] = {"km": float(v["km_wialon"]), "fuente": "Wialon (último)", "en": v.get("km_wialon_en"), "encendido": None}
            elif v.get("kilometraje"):
                try:
                    if float(v["kilometraje"]) > 0:
                        out[pn] = {"km": float(v["kilometraje"]), "fuente": "Manual", "en": None, "encendido": None}
                except Exception:
                    pass
    return out


def _mtto_estado(restante_km, restante_dias, aviso_km, aviso_dias):
    vals = [x for x in (restante_km, restante_dias) if x is not None]
    if not vals:
        return "sin_dato"
    if min(vals) < 0:
        return "vencido"
    pronto = (restante_km is not None and aviso_km and restante_km <= aviso_km) or \
             (restante_dias is not None and aviso_dias and restante_dias <= aviso_dias)
    return "pronto" if pronto else "ok"


@api.get("/mantenimiento/intervalos")
async def mtto_listar_intervalos(user: dict = Depends(get_current_user)):
    emp = _mtto_empresa(user)
    items = await db.mtto_intervalos.find({"empresa": emp}, {"_id": 0}).sort("categoria", 1).to_list(500)
    return {"empresa": emp, "intervalos": items}


@api.post("/mantenimiento/intervalos")
async def mtto_crear_intervalo(body: MttoIntervaloIn, user: dict = Depends(get_current_user)):
    emp = _mtto_empresa(user)
    doc = {"id": str(uuid.uuid4()), "empresa": emp, **body.model_dump(),
           "placas": [_mtto_placa(p) for p in (body.placas or []) if _mtto_placa(p)],
           "created_at": datetime.now(timezone.utc).isoformat(), "created_by": user.get("id")}
    await db.mtto_intervalos.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.put("/mantenimiento/intervalos/{iid}")
async def mtto_editar_intervalo(iid: str, body: MttoIntervaloIn, user: dict = Depends(get_current_user)):
    emp = _mtto_empresa(user)
    upd = body.model_dump()
    upd["placas"] = [_mtto_placa(p) for p in (body.placas or []) if _mtto_placa(p)]
    upd["updated_at"] = datetime.now(timezone.utc).isoformat()
    r = await db.mtto_intervalos.update_one({"id": iid, "empresa": emp}, {"$set": upd})
    if not r.matched_count:
        raise HTTPException(404, "Intervalo no encontrado")
    return {"ok": True}


@api.delete("/mantenimiento/intervalos/{iid}")
async def mtto_borrar_intervalo(iid: str, user: dict = Depends(get_current_user)):
    emp = _mtto_empresa(user)
    r = await db.mtto_intervalos.delete_one({"id": iid, "empresa": emp})
    if not r.deleted_count:
        raise HTTPException(404, "Intervalo no encontrado")
    return {"ok": True}


@api.post("/mantenimiento/intervalos/plan-estandar")
async def mtto_plan_estandar(user: dict = Depends(get_current_user)):
    """Carga el plan estándar de flota pesada (solo agrega los que la empresa no tiene)."""
    emp = _mtto_empresa(user)
    existentes = {(i.get("nombre") or "").strip().lower() async for i in db.mtto_intervalos.find({"empresa": emp}, {"_id": 0, "nombre": 1})}
    nuevos = []
    for p in _MTTO_PLAN_ESTANDAR:
        if p["nombre"].strip().lower() in existentes:
            continue
        nuevos.append({"id": str(uuid.uuid4()), "empresa": emp, **p, "placas": [], "activo": True,
                       "created_at": datetime.now(timezone.utc).isoformat(), "created_by": user.get("id")})
    if nuevos:
        await db.mtto_intervalos.insert_many(nuevos)
    return {"ok": True, "agregados": len(nuevos)}


@api.get("/mantenimiento/servicios")
async def mtto_listar_servicios(placa: Optional[str] = None, estado: Optional[str] = None, user: dict = Depends(get_current_user)):
    emp = _mtto_empresa(user)
    q = {"empresa": emp}
    if placa:
        q["placa"] = _mtto_placa(placa)
    if estado:
        q["estado"] = estado
    items = await db.mtto_servicios.find(q, {"_id": 0}).sort([("fecha", -1), ("created_at", -1)]).to_list(2000)
    return {"empresa": emp, "servicios": items}


def _mtto_servicio_doc(body: MttoServicioIn, emp: str, user: dict) -> dict:
    reps = [r.model_dump() for r in (body.repuestos or [])]
    costo_rep = body.costo_repuestos if body.costo_repuestos is not None else sum(float(r.get("cantidad") or 1) * float(r.get("costo") or 0) for r in reps)
    estado = body.estado if body.estado in ("planificado", "en_taller", "hecho") else "hecho"
    return {
        "empresa": emp, "placa": _mtto_placa(body.placa), "intervalo_id": body.intervalo_id or None,
        "nombre": (body.nombre or "").strip(), "estado": estado,
        "fecha": (body.fecha or datetime.now(timezone.utc).strftime("%Y-%m-%d"))[:10],
        "km": float(body.km) if body.km is not None else None,
        "taller": (body.taller or "").strip(),
        "costo_mano_obra": float(body.costo_mano_obra or 0), "costo_repuestos": round(float(costo_rep or 0), 2),
        "costo_total": round(float(body.costo_mano_obra or 0) + float(costo_rep or 0), 2),
        "repuestos": reps, "notas": (body.notas or "").strip(), "documento_id": body.documento_id or None,
    }


@api.post("/mantenimiento/servicios")
async def mtto_crear_servicio(body: MttoServicioIn, user: dict = Depends(get_current_user)):
    emp = _mtto_empresa(user)
    if not _mtto_placa(body.placa):
        raise HTTPException(400, "Placa requerida")
    doc = {"id": str(uuid.uuid4()), **_mtto_servicio_doc(body, emp, user),
           "created_at": datetime.now(timezone.utc).isoformat(), "created_by": user.get("id"), "por": user.get("name") or user.get("email") or ""}
    await db.mtto_servicios.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.put("/mantenimiento/servicios/{sid}")
async def mtto_editar_servicio(sid: str, body: MttoServicioIn, user: dict = Depends(get_current_user)):
    emp = _mtto_empresa(user)
    upd = _mtto_servicio_doc(body, emp, user)
    upd["updated_at"] = datetime.now(timezone.utc).isoformat()
    r = await db.mtto_servicios.update_one({"id": sid, "empresa": emp}, {"$set": upd})
    if not r.matched_count:
        raise HTTPException(404, "Servicio no encontrado")
    return {"ok": True}


@api.delete("/mantenimiento/servicios/{sid}")
async def mtto_borrar_servicio(sid: str, user: dict = Depends(get_current_user)):
    emp = _mtto_empresa(user)
    r = await db.mtto_servicios.delete_one({"id": sid, "empresa": emp})
    if not r.deleted_count:
        raise HTTPException(404, "Servicio no encontrado")
    return {"ok": True}


@api.get("/mantenimiento/tablero")
async def mtto_tablero(user: dict = Depends(get_current_user)):
    """Estado de mantenimiento por unidad: km actual (Wialon), y por cada intervalo del plan
    cuánto falta en km y días, con semáforo ok / pronto / vencido / sin_dato."""
    emp = _mtto_empresa(user)
    hoy = datetime.now(timezone.utc).date()
    kms = await _mtto_km_actual(emp, user)
    intervalos = [i async for i in db.mtto_intervalos.find({"empresa": emp, "activo": {"$ne": False}}, {"_id": 0})]
    vehiculos = [v async for v in db.vehiculos.find({"empresa": emp}, {"_id": 0, "placa": 1, "tipo": 1, "marca": 1, "modelo": 1, "año": 1, "estado": 1})]
    placas = {}
    for v in vehiculos:
        pn = _mtto_placa(v.get("placa"))
        if pn:
            placas[pn] = {"placa": v.get("placa"), "tipo": v.get("tipo") or "", "marca": v.get("marca") or "", "modelo": v.get("modelo") or "",
                          "anio": v.get("año"), "estado_vehiculo": v.get("estado") or ""}
    for pn, d in kms.items():  # unidades que están en Wialon pero no en Vehículos
        placas.setdefault(pn, {"placa": pn, "tipo": "", "marca": "", "modelo": "", "anio": None, "estado_vehiculo": "", "solo_wialon": True})
    hechos = [s async for s in db.mtto_servicios.find({"empresa": emp, "estado": "hecho"}, {"_id": 0})]
    abiertos = [s async for s in db.mtto_servicios.find({"empresa": emp, "estado": {"$in": ["planificado", "en_taller"]}}, {"_id": 0})]

    def _ultimo(pn, itv):
        cands = [s for s in hechos if s["placa"] == pn and (s.get("intervalo_id") == itv["id"] or (s.get("nombre") or "").strip().lower() == (itv.get("nombre") or "").strip().lower())]
        if not cands:
            return None
        return max(cands, key=lambda s: ((s.get("fecha") or ""), (s.get("km") or 0)))

    unidades = []
    tot = {"ok": 0, "pronto": 0, "vencido": 0, "sin_dato": 0}
    for pn, info in sorted(placas.items()):
        km_info = kms.get(pn) or {}
        km_actual = km_info.get("km")
        items = []
        peor = "ok"
        orden = {"vencido": 3, "pronto": 2, "sin_dato": 1, "ok": 0}
        for itv in intervalos:
            if itv.get("placas") and pn not in itv["placas"]:
                continue
            u = _ultimo(pn, itv)
            restante_km = restante_dias = None
            proximo_km = proxima_fecha = None
            if u:
                if itv.get("cada_km") and u.get("km") is not None and km_actual is not None:
                    proximo_km = float(u["km"]) + float(itv["cada_km"])
                    restante_km = round(proximo_km - km_actual)
                if itv.get("cada_dias") and u.get("fecha"):
                    try:
                        f0 = datetime.strptime(u["fecha"][:10], "%Y-%m-%d").date()
                        proxima_fecha = (f0 + timedelta(days=int(itv["cada_dias"]))).isoformat()
                        restante_dias = (f0 + timedelta(days=int(itv["cada_dias"])) - hoy).days
                    except Exception:
                        pass
                est = _mtto_estado(restante_km, restante_dias, itv.get("aviso_km"), itv.get("aviso_dias"))
            else:
                est = "sin_dato"
            abierto = next((s for s in abiertos if s["placa"] == pn and (s.get("intervalo_id") == itv["id"] or (s.get("nombre") or "").lower() == (itv.get("nombre") or "").lower())), None)
            items.append({"intervalo_id": itv["id"], "nombre": itv["nombre"], "categoria": itv.get("categoria") or "General",
                          "cada_km": itv.get("cada_km") or 0, "cada_dias": itv.get("cada_dias") or 0,
                          "ultimo_km": u.get("km") if u else None, "ultima_fecha": u.get("fecha") if u else None,
                          "proximo_km": proximo_km, "proxima_fecha": proxima_fecha,
                          "restante_km": restante_km, "restante_dias": restante_dias, "estado": est,
                          "orden_abierta": {"id": abierto["id"], "estado": abierto["estado"], "fecha": abierto.get("fecha")} if abierto else None})
            if orden[est] > orden[peor]:
                peor = est
        items.sort(key=lambda x: (-orden[x["estado"]], x["restante_km"] if x["restante_km"] is not None else 10**9))
        tot[peor] += 1
        unidades.append({**info, "placa_norm": pn, "km_actual": km_actual, "km_fuente": km_info.get("fuente"), "km_en": km_info.get("en"),
                         "encendido": km_info.get("encendido"), "estado": peor, "items": items,
                         "vencidos": sum(1 for i in items if i["estado"] == "vencido"), "pronto": sum(1 for i in items if i["estado"] == "pronto")})
    unidades.sort(key=lambda u: (-{"vencido": 3, "pronto": 2, "sin_dato": 1, "ok": 0}[u["estado"]], u["placa"]))
    return {"empresa": emp, "actualizado_en": datetime.now(timezone.utc).isoformat(), "total_unidades": len(unidades),
            "con_km_wialon": sum(1 for u in unidades if (u.get("km_fuente") or "").startswith("Wialon")),
            "resumen": tot, "intervalos_activos": len(intervalos), "unidades": unidades}


@api.get("/mantenimiento/resumen")
async def mtto_resumen(desde: Optional[str] = None, hasta: Optional[str] = None, user: dict = Depends(get_current_user)):
    """Costos por unidad y costo por km (según km recorridos entre el primer y el último servicio,
    o hasta el km actual de Wialon)."""
    emp = _mtto_empresa(user)
    q = {"empresa": emp, "estado": "hecho"}
    if desde:
        q["fecha"] = {"$gte": desde[:10]}
    if hasta:
        q.setdefault("fecha", {})["$lte"] = hasta[:10]
    servicios = [s async for s in db.mtto_servicios.find(q, {"_id": 0})]
    kms = await _mtto_km_actual(emp, user)
    por_placa = {}
    for s in servicios:
        d = por_placa.setdefault(s["placa"], {"placa": s["placa"], "servicios": 0, "costo_total": 0.0, "mano_obra": 0.0, "repuestos": 0.0,
                                               "km_min": None, "km_max": None, "ultimo": None, "por_categoria": {}})
        d["servicios"] += 1
        d["costo_total"] += float(s.get("costo_total") or 0)
        d["mano_obra"] += float(s.get("costo_mano_obra") or 0)
        d["repuestos"] += float(s.get("costo_repuestos") or 0)
        if s.get("km") is not None:
            d["km_min"] = s["km"] if d["km_min"] is None else min(d["km_min"], s["km"])
            d["km_max"] = s["km"] if d["km_max"] is None else max(d["km_max"], s["km"])
        if not d["ultimo"] or (s.get("fecha") or "") > (d["ultimo"].get("fecha") or ""):
            d["ultimo"] = {"nombre": s.get("nombre"), "fecha": s.get("fecha"), "costo": s.get("costo_total")}
    out = []
    for pn, d in por_placa.items():
        km_actual = (kms.get(pn) or {}).get("km")
        km_rec = None
        if d["km_min"] is not None:
            km_fin = km_actual if km_actual is not None else d["km_max"]
            if km_fin is not None and km_fin > d["km_min"]:
                km_rec = km_fin - d["km_min"]
        d["km_recorridos"] = round(km_rec) if km_rec else None
        d["costo_por_km"] = round(d["costo_total"] / km_rec, 3) if km_rec and km_rec > 0 else None
        for k in ("costo_total", "mano_obra", "repuestos"):
            d[k] = round(d[k], 2)
        out.append(d)
    out.sort(key=lambda x: -x["costo_total"])
    mes = datetime.now(timezone.utc).strftime("%Y-%m")
    return {"empresa": emp, "total": round(sum(x["costo_total"] for x in out), 2), "servicios": len(servicios),
            "mes_actual": round(sum(float(s.get("costo_total") or 0) for s in servicios if (s.get("fecha") or "").startswith(mes)), 2),
            "unidades": out}


# ══════════════════════════════════════════════════════════════════════════
# VIAJES + CHECKLIST (app móvil del conductor)
# ══════════════════════════════════════════════════════════════════════════
# El conductor entra desde su celular SOLO con su DNI (sin contraseña — mismo
# mecanismo que la sesión invitada del subsidio, ver create_conductor_token).
# Debe existir antes en Personal/Conductores (con su empresa asignada). Ahí
# elige/confirma la placa y el viaje que está realizando, llena el checklist
# con fotos, y cada ítem marcado como falla genera SOLA una orden de
# mantenimiento reactivo en el mismo tablero de Mantenimiento.

def _empresa_de(u: dict) -> str:
    # Los endpoints admin de Viajes/Checklist no son para el token del conductor
    # (ese solo usa /conductor/*, con su propio alcance más chico).
    if u.get("role") == "conductor":
        raise HTTPException(status_code=403, detail="No disponible para conductores")
    emp = (u.get("_empresa_activa") or u.get("empresa") or "").strip()
    if not emp:
        raise HTTPException(status_code=400, detail="Elige una empresa")
    return emp


_CHECKLIST_ITEMS_ESTANDAR = [
    "Luces delanteras, posteriores y direccionales",
    "Frenos (pedal y freno de mano)",
    "Llantas y presión (incluye llanta de repuesto)",
    "Niveles: aceite, refrigerante, agua limpiaparabrisas",
    "Extintor vigente",
    "Botiquín de primeros auxilios",
    "Triángulos / conos de seguridad",
    "Cinturones de seguridad",
    "Espejos retrovisores",
    "Limpiaparabrisas y plumillas",
    "Placas legibles y bien aseguradas",
    "Documentos a bordo (tarjeta de propiedad, SOAT, revisión técnica)",
]


# ── Contactos (libreta de direcciones: remitente/destinatario) ─────────────
class ContactoDireccionIn(BaseModel):
    id: Optional[str] = None
    etiqueta: str
    direccion: str
    ubigeo: Optional[str] = None


class ContactoIn(BaseModel):
    tipo_doc: Optional[str] = "RUC"
    num_doc: str
    razon_social: str


@api.get("/ruc/{ruc}")
async def ruc_ficha_publica(ruc: str, user: dict = Depends(get_current_user)):
    """Ficha SUNAT de un RUC (razón social + dirección fiscal), para autocompletar
    remitente/destinatario/origen sin tener que digitarlo a mano."""
    ruc_n = re.sub(r"\D", "", ruc or "")
    if len(ruc_n) != 11:
        raise HTTPException(status_code=400, detail="RUC inválido (11 dígitos)")
    ficha = await _sunat_ficha_ruc(ruc_n)
    if not ficha:
        raise HTTPException(status_code=404, detail="SUNAT no devolvió datos para este RUC")
    return {"ruc": ruc_n, **ficha}


@api.get("/contactos")
async def contactos_listar(q: Optional[str] = None, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    filt = {"empresa": emp}
    if q:
        filt["$or"] = [{"num_doc": {"$regex": re.escape(q)}}, {"razon_social": {"$regex": re.escape(q), "$options": "i"}}]
    items = await db.contactos.find(filt, {"_id": 0}).sort("razon_social", 1).to_list(500)
    return {"contactos": items}


@api.get("/contactos/{num_doc}")
async def contacto_obtener(num_doc: str, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    c = await db.contactos.find_one({"empresa": emp, "num_doc": re.sub(r"\D", "", num_doc)}, {"_id": 0})
    if not c:
        raise HTTPException(status_code=404, detail="No tienes ese contacto guardado todavía")
    return c


@api.post("/contactos")
async def contacto_guardar(body: ContactoIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    num_doc = re.sub(r"\D", "", body.num_doc or "")
    if not num_doc:
        raise HTTPException(status_code=400, detail="Documento requerido")
    existente = await db.contactos.find_one({"empresa": emp, "num_doc": num_doc}, {"_id": 0})
    doc = {
        "id": (existente or {}).get("id") or str(uuid.uuid4()), "empresa": emp,
        "tipo_doc": body.tipo_doc or "RUC", "num_doc": num_doc,
        "razon_social": (body.razon_social or "").strip(),
        "direcciones": (existente or {}).get("direcciones", []),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.contactos.update_one({"empresa": emp, "num_doc": num_doc}, {"$set": doc}, upsert=True)
    return doc


@api.post("/contactos/{num_doc}/direcciones")
async def contacto_agregar_direccion(num_doc: str, body: ContactoDireccionIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    num_doc = re.sub(r"\D", "", num_doc)
    if not (body.etiqueta or "").strip() or not (body.direccion or "").strip():
        raise HTTPException(status_code=400, detail="Etiqueta y dirección son obligatorias")
    nueva = {"id": str(uuid.uuid4()), "etiqueta": body.etiqueta.strip(), "direccion": body.direccion.strip(),
              "ubigeo": (body.ubigeo or "").strip()}
    r = await db.contactos.update_one({"empresa": emp, "num_doc": num_doc}, {"$push": {"direcciones": nueva}})
    if not r.matched_count:
        raise HTTPException(status_code=404, detail="Primero guarda el contacto (RUC/DNI y razón social)")
    return nueva


class ConductorLoginIn(BaseModel):
    dni: str


class ViajeIn(BaseModel):
    placa: str
    placa_carreta: Optional[str] = None
    conductor_dni: Optional[str] = None
    conductor_nombre: Optional[str] = None
    conductor_licencia: Optional[str] = None
    origen: str
    destino: str
    fecha_salida: Optional[str] = None
    hora_salida: Optional[str] = None
    fecha_llegada_est: Optional[str] = None
    guia_remision: Optional[str] = None
    notas: Optional[str] = ""
    estado: Optional[str] = "planificado"  # planificado | en_curso | finalizado | cancelado
    # Datos para emitir la guía de remisión - transportista (formato SUNAT)
    motivo_traslado: Optional[str] = None
    remitente_ruc: Optional[str] = None
    remitente_razon_social: Optional[str] = None
    destinatario_tipo_doc: Optional[str] = None
    destinatario_num_doc: Optional[str] = None
    destinatario_razon_social: Optional[str] = None
    punto_partida_direccion: Optional[str] = None
    punto_partida_ubigeo: Optional[str] = None
    punto_llegada_direccion: Optional[str] = None
    punto_llegada_ubigeo: Optional[str] = None
    peso_bruto_kg: Optional[float] = None
    num_bultos: Optional[int] = None
    descripcion_bienes: Optional[str] = None
    doc_relacionado: Optional[str] = None


class ChecklistPlantillaItemIn(BaseModel):
    id: Optional[str] = None
    label: str
    foto_si_falla: Optional[bool] = True


class ChecklistPlantillaIn(BaseModel):
    items: List[ChecklistPlantillaItemIn]


async def _buscar_conductor_por_dni(dni: str) -> Optional[dict]:
    """El registro real de choferes vive en Documentación (Personal → Perfil,
    creado con "Agregar personal"), no en la colección `conductores` (que
    nunca la llena el frontend). Se busca ahí primero y se cae a `conductores`
    solo por si algún día se usa ese flujo directo."""
    perfil = await db.documents.find_one({
        "tipo": {"$regex": "^personal$", "$options": "i"}, "doc": "Perfil",
        "desc": dni, "archived": {"$ne": 1},
    }, {"_id": 0})
    if perfil:
        placa_field = perfil.get("placa") or ""
        nombre = placa_field.split(":::")[0].strip() if ":::" in placa_field else (perfil.get("ref") or "").strip()
        return {"empresa": perfil.get("empresa"), "nombre": nombre or dni}
    c = await db.conductores.find_one({"dni": dni}, {"_id": 0})
    if c:
        return {"empresa": c.get("empresa"), "nombre": f"{c.get('nombre', '')} {c.get('apellidos', '')}".strip() or dni}
    return None


# ── Conductor (app móvil) ───────────────────────────────────────────────────
@api.post("/conductor/entrar")
async def conductor_entrar(body: ConductorLoginIn, response: Response):
    dni = re.sub(r"\D", "", body.dni or "")
    if len(dni) != 8:
        raise HTTPException(status_code=400, detail="El DNI debe tener 8 dígitos")
    c = await _buscar_conductor_por_dni(dni)
    if not c:
        raise HTTPException(status_code=404,
                            detail="No encontramos ese DNI. Pide a tu empresa que te registre en Personal / Conductores.")
    empresa = (c.get("empresa") or "").strip()
    if not empresa:
        raise HTTPException(status_code=400, detail="Tu registro de conductor no tiene una empresa asignada. Avisa a tu empresa.")
    nombre = c.get("nombre") or dni
    token = create_conductor_token(dni, empresa, nombre)
    response.set_cookie("access_token", token, httponly=True, secure=True, **_cookie_extra(), max_age=16 * 3600, path="/")
    response.headers["X-Access-Token"] = token
    return {"access_token": token, "conductor": {"dni": dni, "nombre": nombre, "empresa": empresa}}


def _require_conductor(user: dict) -> dict:
    if user.get("role") != "conductor":
        raise HTTPException(status_code=403, detail="Solo disponible para conductores")
    return user


async def _checklist_plantilla_de(emp: str) -> dict:
    plant = await db.checklist_plantillas.find_one({"empresa": emp}, {"_id": 0})
    if not plant:
        items = [{"id": str(uuid.uuid4()), "label": t, "foto_si_falla": True} for t in _CHECKLIST_ITEMS_ESTANDAR]
        plant = {"id": str(uuid.uuid4()), "empresa": emp, "items": items,
                 "created_at": datetime.now(timezone.utc).isoformat()}
        await db.checklist_plantillas.insert_one(dict(plant))
    return plant


@api.get("/conductor/contexto")
async def conductor_contexto(user: dict = Depends(get_current_user)):
    """Todo lo que necesita el celular del conductor al entrar: su flota, los viajes
    abiertos de su empresa y la plantilla de checklist vigente."""
    _require_conductor(user)
    emp = user["empresa"]
    vehiculos = await db.vehiculos.find({"empresa": emp}, {"_id": 0, "placa": 1, "tipo": 1, "marca": 1, "modelo": 1}).to_list(500)
    viajes = await db.viajes.find({"empresa": emp, "estado": {"$in": ["planificado", "en_curso"]}},
                                  {"_id": 0}).sort("created_at", -1).to_list(200)
    # Los viajes ya asignados a este DNI van primero.
    viajes.sort(key=lambda v: v.get("conductor_dni") != user["dni"])
    plant = await _checklist_plantilla_de(emp)
    return {
        "conductor": {"dni": user["dni"], "nombre": user["name"], "empresa": emp},
        "vehiculos": [{"placa": (v.get("placa") or "").upper(), "tipo": v.get("tipo") or "",
                       "marca": v.get("marca") or "", "modelo": v.get("modelo") or ""} for v in vehiculos if v.get("placa")],
        "viajes_abiertos": viajes,
        "plantilla": plant.get("items", []),
    }


@api.post("/conductor/viajes")
async def conductor_crear_viaje(body: ViajeIn, user: dict = Depends(get_current_user)):
    """El conductor puede crear su propio viaje si no hay uno ya planificado para él."""
    _require_conductor(user)
    emp = user["empresa"]
    if not _mtto_placa(body.placa):
        raise HTTPException(status_code=400, detail="Elige la placa")
    if not (body.origen or "").strip() or not (body.destino or "").strip():
        raise HTTPException(status_code=400, detail="Indica origen y destino")
    ahora = datetime.now(timezone.utc)
    doc = {
        "id": str(uuid.uuid4()), "empresa": emp, "placa": _mtto_placa(body.placa),
        "conductor_dni": user["dni"], "conductor_nombre": user["name"],
        "origen": body.origen.strip(), "destino": body.destino.strip(),
        "fecha_salida": body.fecha_salida or ahora.strftime("%Y-%m-%d"),
        "hora_salida": body.hora_salida or ahora.strftime("%H:%M"),
        "fecha_llegada_est": body.fecha_llegada_est, "guia_remision": (body.guia_remision or "").strip(),
        "notas": (body.notas or "").strip(), "estado": "en_curso",
        "creado_por": "conductor", "created_at": ahora.isoformat(),
    }
    await db.viajes.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.post("/conductor/checklist")
async def conductor_checklist_submit(
    viaje_id: str = Form(...),
    placa: str = Form(...),
    km: Optional[str] = Form(None),
    tipo: str = Form("pre-viaje"),
    items: str = Form(...),               # JSON: [{id, label, ok, nota}]
    file_item_ids: str = Form("[]"),      # JSON: [item_id, ...] en el mismo orden que "files"
    files: List[UploadFile] = File(default=[]),
    user: dict = Depends(get_current_user),
):
    """Envío del checklist desde el celular. Cada ítem marcado como falla crea SOLO
    una orden de mantenimiento reactivo (mismo tablero que las tareas preventivas)."""
    _require_conductor(user)
    emp = user["empresa"]
    placa_n = _mtto_placa(placa)
    if not placa_n:
        raise HTTPException(status_code=400, detail="Placa requerida")
    try:
        items_data = json.loads(items)
        if not isinstance(items_data, list) or not items_data:
            raise ValueError
    except Exception:
        raise HTTPException(status_code=400, detail="Checklist inválido")
    try:
        file_ids = json.loads(file_item_ids)
    except Exception:
        file_ids = []

    fotos_por_item: dict = {}
    for i, f in enumerate(files or []):
        item_id = file_ids[i] if i < len(file_ids) else None
        if not item_id:
            continue
        content = await f.read()
        if len(content) > 12 * 1024 * 1024:
            continue  # foto demasiado pesada, se ignora en vez de romper todo el envío
        key = f"checklist/{emp}/{placa_n}/{uuid.uuid4().hex[:8]}_{re.sub(r'[^A-Za-z0-9_.-]', '_', f.filename or 'foto.jpg')}"
        storage.save_object(key, content, f.content_type or "image/jpeg")
        fotos_por_item[item_id] = key

    items_out, fallas = [], []
    for it in items_data:
        iid = it.get("id")
        ok = bool(it.get("ok"))
        row = {"id": iid, "label": (it.get("label") or "").strip(), "ok": ok,
               "nota": (it.get("nota") or "").strip(), "foto_key": fotos_por_item.get(iid)}
        items_out.append(row)
        if not ok:
            fallas.append(row)

    km_val = None
    if km:
        try:
            km_val = float(km)
        except Exception:
            pass

    ahora = datetime.now(timezone.utc)
    envio = {
        "id": str(uuid.uuid4()), "empresa": emp, "placa": placa_n, "viaje_id": viaje_id or None,
        "conductor_dni": user["dni"], "conductor_nombre": user["name"], "tipo": tipo or "pre-viaje",
        "km": km_val, "items": items_out, "conforme": len(fallas) == 0, "fallas_count": len(fallas),
        "created_at": ahora.isoformat(),
    }
    await db.checklist_envios.insert_one(dict(envio))

    ordenes = []
    for f in fallas:
        sid = str(uuid.uuid4())
        await db.mtto_servicios.insert_one({
            "id": sid, "empresa": emp, "placa": placa_n, "intervalo_id": None,
            "nombre": f"Checklist: {f['label']}", "estado": "planificado",
            "fecha": ahora.strftime("%Y-%m-%d"), "km": km_val, "taller": "",
            "costo_mano_obra": 0.0, "costo_repuestos": 0.0, "costo_total": 0.0, "repuestos": [],
            "notas": f.get("nota") or "Reportado por el conductor en el checklist.",
            "documento_id": None, "origen": "checklist", "checklist_envio_id": envio["id"],
            "foto_key": f.get("foto_key"), "created_at": ahora.isoformat(),
            "created_by": f"conductor:{user['dni']}", "por": user["name"],
        })
        ordenes.append(sid)

    if viaje_id:
        await db.viajes.update_one({"id": viaje_id, "empresa": emp, "estado": "planificado"},
                                   {"$set": {"estado": "en_curso"}})

    envio.pop("_id", None)
    return {"ok": True, "envio": envio, "ordenes_creadas": len(ordenes)}


# ── Viajes (panel admin) ────────────────────────────────────────────────────
@api.get("/viajes")
async def viajes_listar(placa: Optional[str] = None, estado: Optional[str] = None, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    q = {"empresa": emp}
    if placa:
        q["placa"] = _mtto_placa(placa)
    if estado:
        q["estado"] = estado
    items = await db.viajes.find(q, {"_id": 0}).sort("created_at", -1).to_list(2000)
    return {"empresa": emp, "viajes": items}


def _viaje_gr_fields(body: "ViajeIn") -> dict:
    """Campos para poder emitir la guía de remisión - transportista (formato SUNAT)."""
    return {
        "placa_carreta": _mtto_placa(body.placa_carreta) if body.placa_carreta else "",
        "conductor_licencia": (body.conductor_licencia or "").strip(),
        "motivo_traslado": (body.motivo_traslado or "").strip(),
        "remitente_ruc": (body.remitente_ruc or "").strip(),
        "remitente_razon_social": (body.remitente_razon_social or "").strip(),
        "destinatario_tipo_doc": (body.destinatario_tipo_doc or "").strip(),
        "destinatario_num_doc": (body.destinatario_num_doc or "").strip(),
        "destinatario_razon_social": (body.destinatario_razon_social or "").strip(),
        "punto_partida_direccion": (body.punto_partida_direccion or "").strip(),
        "punto_partida_ubigeo": (body.punto_partida_ubigeo or "").strip(),
        "punto_llegada_direccion": (body.punto_llegada_direccion or "").strip(),
        "punto_llegada_ubigeo": (body.punto_llegada_ubigeo or "").strip(),
        "peso_bruto_kg": body.peso_bruto_kg,
        "num_bultos": body.num_bultos,
        "descripcion_bienes": (body.descripcion_bienes or "").strip(),
        "doc_relacionado": (body.doc_relacionado or "").strip(),
    }


@api.post("/viajes")
async def viajes_crear(body: ViajeIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    if not _mtto_placa(body.placa) or not (body.origen or "").strip() or not (body.destino or "").strip():
        raise HTTPException(status_code=400, detail="Placa, origen y destino son obligatorios")
    doc = {
        "id": str(uuid.uuid4()), "empresa": emp, "placa": _mtto_placa(body.placa),
        "conductor_dni": (body.conductor_dni or "").strip(), "conductor_nombre": (body.conductor_nombre or "").strip(),
        "origen": body.origen.strip(), "destino": body.destino.strip(),
        "fecha_salida": body.fecha_salida, "hora_salida": body.hora_salida, "fecha_llegada_est": body.fecha_llegada_est,
        "guia_remision": (body.guia_remision or "").strip(), "notas": (body.notas or "").strip(),
        "estado": body.estado or "planificado", "creado_por": user.get("id"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        **_viaje_gr_fields(body),
    }
    await db.viajes.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.put("/viajes/{vid}")
async def viajes_editar(vid: str, body: ViajeIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    upd = {
        "placa": _mtto_placa(body.placa), "conductor_dni": (body.conductor_dni or "").strip(),
        "conductor_nombre": (body.conductor_nombre or "").strip(), "origen": (body.origen or "").strip(),
        "destino": (body.destino or "").strip(), "fecha_salida": body.fecha_salida, "hora_salida": body.hora_salida,
        "fecha_llegada_est": body.fecha_llegada_est, "guia_remision": (body.guia_remision or "").strip(),
        "notas": (body.notas or "").strip(), "estado": body.estado or "planificado",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **_viaje_gr_fields(body),
    }
    if upd["estado"] == "finalizado":
        upd["finalizado_en"] = datetime.now(timezone.utc).isoformat()
    r = await db.viajes.update_one({"id": vid, "empresa": emp}, {"$set": upd})
    if not r.matched_count:
        raise HTTPException(status_code=404, detail="Viaje no encontrado")
    return {"ok": True}


@api.delete("/viajes/{vid}")
async def viajes_borrar(vid: str, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    r = await db.viajes.delete_one({"id": vid, "empresa": emp})
    if not r.deleted_count:
        raise HTTPException(status_code=404, detail="Viaje no encontrado")
    return {"ok": True}


# ── Checklist (panel admin) ─────────────────────────────────────────────────
@api.get("/checklist/envios")
async def checklist_listar(placa: Optional[str] = None, conforme: Optional[str] = None, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    q = {"empresa": emp}
    if placa:
        q["placa"] = _mtto_placa(placa)
    if conforme in ("1", "0"):
        q["conforme"] = conforme == "1"
    items = await db.checklist_envios.find(q, {"_id": 0}).sort("created_at", -1).to_list(2000)
    return {"empresa": emp, "envios": items}


@api.get("/checklist/plantilla")
async def checklist_plantilla_get(user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    return await _checklist_plantilla_de(emp)


@api.put("/checklist/plantilla")
async def checklist_plantilla_set(body: ChecklistPlantillaIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    items = [{"id": it.id or str(uuid.uuid4()), "label": it.label.strip(), "foto_si_falla": bool(it.foto_si_falla)}
             for it in body.items if it.label.strip()]
    if not items:
        raise HTTPException(status_code=400, detail="La plantilla necesita al menos un ítem")
    await db.checklist_plantillas.update_one({"empresa": emp}, {"$set": {"items": items}}, upsert=True)
    return {"ok": True, "items": items}


@api.get("/checklist/foto/{key:path}")
async def checklist_foto(key: str, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user) if user.get("role") != "admin_enered" else None
    if emp and not key.startswith(f"checklist/{emp}/"):
        raise HTTPException(status_code=403, detail="Sin acceso a este archivo")
    if not storage.object_exists(key):
        raise HTTPException(status_code=404, detail="Foto no encontrada")
    return storage.download_response(key, filename=key.rsplit("/", 1)[-1], content_type="image/jpeg")


# ── Neumáticos ───────────────────────────────────────────────────────────────
NEU_UMBRAL_CRITICO_MM = 3.0
NEU_UMBRAL_ALERTA_MM = 5.0
NEU_POSICIONES_COMUNES = [
    "1-Izq", "1-Der", "2-Izq-Ext", "2-Izq-Int", "2-Der-Ext", "2-Der-Int",
    "3-Izq-Ext", "3-Izq-Int", "3-Der-Ext", "3-Der-Int", "Repuesto",
]


def _neu_alerta(profundidad_mm) -> str:
    if profundidad_mm is None:
        return "—"
    if profundidad_mm <= NEU_UMBRAL_CRITICO_MM:
        return "critico"
    if profundidad_mm <= NEU_UMBRAL_ALERTA_MM:
        return "proximo"
    return "ok"


class NeumaticoIn(BaseModel):
    codigo: str
    marca: Optional[str] = ""
    medida: Optional[str] = ""
    profundidad_inicial_mm: Optional[float] = None
    costo: Optional[float] = None
    proveedor: Optional[str] = ""
    placa: Optional[str] = None
    posicion: Optional[str] = None
    km_instalacion: Optional[float] = None


class NeuInstalarIn(BaseModel):
    placa: str
    posicion: str
    km: Optional[float] = None


class NeuMedicionIn(BaseModel):
    profundidad_mm: float
    km: Optional[float] = None
    notas: Optional[str] = ""


class NeuReencaucharIn(BaseModel):
    profundidad_mm: float
    proveedor: Optional[str] = ""
    costo: Optional[float] = None


class NeuBajaIn(BaseModel):
    motivo: str


def _neu_evento(tipo: str, **kw) -> dict:
    return {"id": str(uuid.uuid4()), "tipo": tipo, "fecha": datetime.now(timezone.utc).isoformat(), **kw}


@api.get("/neumaticos")
async def neumaticos_listar(placa: Optional[str] = None, estado: Optional[str] = None, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    q = {"empresa": emp}
    if placa:
        q["placa"] = _mtto_placa(placa)
    if estado:
        q["estado"] = estado
    items = await db.neumaticos.find(q, {"_id": 0}).sort("created_at", -1).to_list(3000)
    for it in items:
        it["alerta"] = _neu_alerta(it.get("profundidad_actual_mm"))
    return {"empresa": emp, "neumaticos": items}


@api.get("/neumaticos/kpis")
async def neumaticos_kpis(user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    items = await db.neumaticos.find({"empresa": emp}, {"_id": 0, "estado": 1, "profundidad_actual_mm": 1}).to_list(3000)
    en_uso = [it for it in items if it.get("estado") in ("en_uso", "reencauchada")]
    return {
        "total": len(items),
        "en_uso": len(en_uso),
        "en_almacen": len([it for it in items if it.get("estado") == "almacen"]),
        "criticos": len([it for it in en_uso if _neu_alerta(it.get("profundidad_actual_mm")) == "critico"]),
        "proximos": len([it for it in en_uso if _neu_alerta(it.get("profundidad_actual_mm")) == "proximo"]),
        "desechados": len([it for it in items if it.get("estado") == "desechada"]),
    }


@api.post("/neumaticos")
async def neumaticos_crear(body: NeumaticoIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    if not (body.codigo or "").strip():
        raise HTTPException(status_code=400, detail="El código / DOT del neumático es obligatorio")
    ahora = datetime.now(timezone.utc).isoformat()
    placa_n = _mtto_placa(body.placa) if body.placa else None
    instalado = bool(placa_n and body.posicion)
    doc = {
        "id": str(uuid.uuid4()), "empresa": emp, "codigo": body.codigo.strip(),
        "marca": (body.marca or "").strip(), "medida": (body.medida or "").strip(),
        "costo": body.costo, "proveedor": (body.proveedor or "").strip(),
        "profundidad_inicial_mm": body.profundidad_inicial_mm,
        "profundidad_actual_mm": body.profundidad_inicial_mm,
        "reencauches": 0,
        "placa": placa_n if instalado else None,
        "posicion": body.posicion if instalado else None,
        "km_instalacion": body.km_instalacion if instalado else None,
        "fecha_instalacion": ahora if instalado else None,
        "estado": "en_uso" if instalado else "almacen",
        "historial": [_neu_evento("alta", placa=placa_n if instalado else None, posicion=body.posicion if instalado else None)],
        "created_at": ahora, "creado_por": user.get("id"),
    }
    await db.neumaticos.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.put("/neumaticos/{nid}")
async def neumaticos_editar(nid: str, body: NeumaticoIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    upd = {
        "codigo": body.codigo.strip(), "marca": (body.marca or "").strip(), "medida": (body.medida or "").strip(),
        "costo": body.costo, "proveedor": (body.proveedor or "").strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    r = await db.neumaticos.update_one({"id": nid, "empresa": emp}, {"$set": upd})
    if not r.matched_count:
        raise HTTPException(status_code=404, detail="Neumático no encontrado")
    return {"ok": True}


@api.delete("/neumaticos/{nid}")
async def neumaticos_borrar(nid: str, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    r = await db.neumaticos.delete_one({"id": nid, "empresa": emp})
    if not r.deleted_count:
        raise HTTPException(status_code=404, detail="Neumático no encontrado")
    return {"ok": True}


@api.post("/neumaticos/{nid}/instalar")
async def neumaticos_instalar(nid: str, body: NeuInstalarIn, user: dict = Depends(get_current_user)):
    """Instala o rota el neumático a una placa + posición (libera la posición anterior)."""
    emp = _empresa_de(user)
    placa_n = _mtto_placa(body.placa)
    if not placa_n or not (body.posicion or "").strip():
        raise HTTPException(status_code=400, detail="Placa y posición son obligatorias")
    ahora = datetime.now(timezone.utc).isoformat()
    ocupante = await db.neumaticos.find_one({"empresa": emp, "placa": placa_n, "posicion": body.posicion, "id": {"$ne": nid}})
    if ocupante:
        await db.neumaticos.update_one({"id": ocupante["id"]}, {
            "$set": {"placa": None, "posicion": None, "estado": "almacen"},
            "$push": {"historial": _neu_evento("retiro", motivo=f"Reemplazado por otro neumático en {body.posicion}")},
        })
    upd = {"placa": placa_n, "posicion": body.posicion, "km_instalacion": body.km, "fecha_instalacion": ahora, "estado": "en_uso"}
    r = await db.neumaticos.update_one({"id": nid, "empresa": emp}, {
        "$set": upd, "$push": {"historial": _neu_evento("instalacion", placa=placa_n, posicion=body.posicion, km=body.km)},
    })
    if not r.matched_count:
        raise HTTPException(status_code=404, detail="Neumático no encontrado")
    return {"ok": True}


@api.post("/neumaticos/{nid}/medicion")
async def neumaticos_medicion(nid: str, body: NeuMedicionIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    r = await db.neumaticos.update_one({"id": nid, "empresa": emp}, {
        "$set": {"profundidad_actual_mm": body.profundidad_mm},
        "$push": {"historial": _neu_evento("medicion", profundidad_mm=body.profundidad_mm, km=body.km, notas=body.notas)},
    })
    if not r.matched_count:
        raise HTTPException(status_code=404, detail="Neumático no encontrado")
    return {"ok": True}


@api.post("/neumaticos/{nid}/reencauchar")
async def neumaticos_reencauchar(nid: str, body: NeuReencaucharIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    r = await db.neumaticos.update_one({"id": nid, "empresa": emp}, {
        "$set": {"profundidad_actual_mm": body.profundidad_mm, "estado": "reencauchada",
                 "proveedor": (body.proveedor or "").strip() or None},
        "$inc": {"reencauches": 1},
        "$push": {"historial": _neu_evento("reencauche", profundidad_mm=body.profundidad_mm, costo=body.costo, proveedor=body.proveedor)},
    })
    if not r.matched_count:
        raise HTTPException(status_code=404, detail="Neumático no encontrado")
    return {"ok": True}


@api.post("/neumaticos/{nid}/baja")
async def neumaticos_dar_baja(nid: str, body: NeuBajaIn, user: dict = Depends(get_current_user)):
    emp = _empresa_de(user)
    r = await db.neumaticos.update_one({"id": nid, "empresa": emp}, {
        "$set": {"estado": "desechada", "placa": None, "posicion": None},
        "$push": {"historial": _neu_evento("baja", motivo=body.motivo)},
    })
    if not r.matched_count:
        raise HTTPException(status_code=404, detail="Neumático no encontrado")
    return {"ok": True}


app.include_router(api)


@app.on_event("shutdown")
async def shutdown():
    client.close()


