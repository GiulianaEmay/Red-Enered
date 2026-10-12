"""ENERED — Subsidio module (DU 004-2026)
Endpoints públicos (calculadora) + privados (cliente_subsidio).
Aislado del resto del backend: solo añade endpoints, no modifica los existentes.
"""
from __future__ import annotations

import os
import asyncio
import io
import uuid
import logging
import httpx
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Literal

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr, Field

import storage  # tu storage.py existente (R2 + fallback local)
import re as _re

logger = logging.getLogger("enered.subsidio")

# Conectores que van en minúscula dentro de nombres de ciudad
_CITY_MINOR_WORDS = {"de", "del", "la", "las", "los", "y", "el", "en", "a"}


def normalize_city(value: Optional[str]) -> str:
    """Unifica escritura de ciudad: 'TRUJILLO'/'trujillo'/'tRujilLo' -> 'Trujillo'."""
    if not value:
        return ""
    s = _re.sub(r"\s+", " ", str(value).strip())
    if not s:
        return ""
    tokens = _re.split(r"([ \-])", s)
    out, word_idx = [], 0
    for tok in tokens:
        if tok in (" ", "-"):
            out.append(tok)
            continue
        low = tok.lower()
        if word_idx > 0 and low in _CITY_MINOR_WORDS:
            out.append(low)
        elif low:
            out.append(low[0].upper() + low[1:])
        word_idx += 1
    return "".join(out)

subsidio_router = APIRouter(prefix="/api")

# Will be wired up in server.py
db = None
JWT_ALGORITHM = "HS256"


def _jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def _set_db(database):
    """Inject Mongo db from server.py at startup."""
    global db
    db = database


def _hash_pw(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def _verify_pw(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except Exception:
        return False


def _create_access_token(user_id: str, email: str, role: str, empresa: Optional[str]) -> str:
    from datetime import timedelta
    payload = {
        "sub": user_id, "email": email, "role": role, "empresa": empresa,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=60 * 8),
        "type": "access",
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALGORITHM)


def _create_refresh_token(user_id: str) -> str:
    from datetime import timedelta
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "refresh",
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALGORITHM)


def _create_guest_token(ruc: str, empresa: str) -> str:
    """Token de sesión INVITADA para el diagnóstico (/subsidio): lleva el RUC, NO persiste usuario."""
    payload = {
        "type": "guest_subsidio", "ruc": ruc, "empresa": empresa,
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALGORITHM)


def _guest_user_from_payload(payload: dict) -> dict:
    """Usuario sintético (no existe en BD) para una sesión invitada del subsidio."""
    ruc = payload.get("ruc", "")
    empresa = payload.get("empresa") or f"RUC {ruc}"
    return {
        "id": f"guest:{ruc}", "email": f"{ruc}@invitado.subsidio", "name": empresa,
        "role": "cliente_subsidio", "empresa": empresa, "ruc": ruc,
        "acceso_etapa0": True, "registrado_etapa0": False, "es_guest": True,
        "documentos_completos": False, "permisos": None, "tipo_cliente": "subsidio",
    }


def _guest_public(u: dict) -> dict:
    return {
        "id": u["id"], "email": u["email"], "name": u.get("name"), "role": "cliente_subsidio",
        "empresa": u.get("empresa"), "ruc": u.get("ruc"),
        "acceso_etapa0": True, "registrado_etapa0": False, "es_guest": True,
        "servicios": {"plataforma": False, "combustible": False, "gps": False, "subsidio": True},
        "tipo_cliente": "subsidio", "empresas_asignadas": [], "empresa_activa": u.get("empresa"),
    }


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


def _set_auth_cookies(response: Response, access: str, refresh: str):
    response.set_cookie("access_token", access, httponly=True, secure=True, **_cookie_extra(),
                        max_age=60 * 60 * 8, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=True, **_cookie_extra(),
                        max_age=7 * 86400, path="/")


async def _heredar_ruc(u: dict) -> dict:
    """Si el usuario no tiene RUC propio, toma el de su empresa (empresas_config) o el de
    un usuario hermano de la misma empresa — igual que /auth/me — y lo persiste en su ficha.
    Sin esto, acciones como 'Traer unidades de mi diagnóstico' fallaban en cuentas nuevas."""
    try:
        ruc = (u.get("ruc") or "").strip()
        if _re.fullmatch(r"\d{11}", ruc) or not u.get("empresa"):
            return u
        cfg = await db.empresas_config.find_one({"empresa": u["empresa"]}, {"_id": 0, "ruc": 1})
        ruc_emp = ((cfg or {}).get("ruc") or "").strip()
        if not _re.fullmatch(r"\d{11}", ruc_emp):
            hermano = await db.users.find_one({"empresa": u["empresa"], "ruc": {"$regex": r"^\d{11}$"}}, {"_id": 0, "ruc": 1})
            ruc_emp = ((hermano or {}).get("ruc") or "").strip()
        if _re.fullmatch(r"\d{11}", ruc_emp):
            u["ruc"] = ruc_emp
            if u.get("id") and not u.get("_impersonando") and not u.get("_empresa_activa"):
                await db.users.update_one({"id": u["id"], "$or": [{"ruc": {"$in": [None, ""]}}, {"ruc": {"$exists": False}}]},
                                          {"$set": {"ruc": ruc_emp}})
    except Exception:
        pass
    return u


async def _get_current_user(request: Request) -> dict:
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
        payload = jwt.decode(token, _jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") == "guest_subsidio":
            return _guest_user_from_payload(payload)   # sesión invitada: no existe en BD
        if payload.get("type") not in ("access", "download"):
            raise HTTPException(status_code=401, detail="Token inválido")
        # Token de descarga: SOLO lecturas (GET), nunca escrituras.
        if payload.get("type") == "download" and request.method != "GET":
            raise HTTPException(status_code=401, detail="Token de descarga no válido para esta operación")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
        # Cambio de empresa (X-Impersonate-Empresa), mismo contrato que server.py.
        # Sin esto, un cliente con varias empresas operaba SIEMPRE sobre su empresa base
        # y el expediente de una empresa mostraba los vehículos/consumos de las otras.
        imp = (request.headers.get("X-Impersonate-Empresa") or "").strip()
        if imp:
            if user.get("role") == "admin_enered":
                rep = (await db.users.find_one({"empresa": imp, "role": "cliente_subsidio"}, {"_id": 0, "password_hash": 0})
                       or await db.users.find_one({"empresa": imp, "role": {"$ne": "admin_enered"}}, {"_id": 0, "password_hash": 0}))
                if rep:
                    eff = dict(rep)
                    eff["_admin_id"] = user.get("id")
                    eff["_admin_role"] = user.get("role")
                    eff["_impersonando"] = True
                    return await _heredar_ruc(eff)
            else:
                asignadas = user.get("empresas_asignadas") or []
                match = next((e for e in asignadas if (e or {}).get("empresa") == imp), None)
                if match:
                    eff = dict(user)
                    eff["empresa"] = match.get("empresa")
                    eff["ruc"] = match.get("ruc", "")
                    eff["_empresa_activa"] = match.get("empresa")
                    return await _heredar_ruc(eff)
        return await _heredar_ruc(user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sesión expirada")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


async def _get_company_uids(user) -> list[str]:
    """uids de la empresa EFECTIVA del usuario (respeta el cambio de empresa del
    header). Acepta el dict del usuario efectivo; por compatibilidad también un id
    (en ese caso resuelve al usuario base desde la BD). Incluye a los usuarios
    multi-empresa que tienen esa empresa en empresas_asignadas."""
    if isinstance(user, str):
        user = await db.users.find_one({"id": user}) or {"id": user}
    uids = [user["id"]] if user.get("id") else []
    emp = user.get("empresa")
    if emp:
        async for x in db.users.find(
            {"$or": [{"empresa": emp}, {"empresas_asignadas.empresa": emp}]},
            {"_id": 0, "id": 1},
        ):
            if x.get("id") and x["id"] not in uids:
                uids.append(x["id"])
    return uids or [user.get("id")]


def _usuario_en_empresa(u: dict, empresa: Optional[str]) -> dict:
    """Vista del usuario `u` como una de SUS empresas (base o asignada). El admin
    la usa para abrir el expediente de cada empresa de un cliente multi-empresa
    (?empresa=...). Si no se pide empresa o coincide con la base, devuelve `u`."""
    emp = (empresa or "").strip()
    if not emp or emp == u.get("empresa"):
        return u
    for a in (u.get("empresas_asignadas") or []):
        if (a or {}).get("empresa") == emp:
            eff = dict(u)
            eff["empresa"] = emp
            eff["ruc"] = a.get("ruc") or u.get("ruc")
            eff["_empresa_activa"] = emp
            eff["empresa_base"] = u.get("empresa")
            return eff
    raise HTTPException(status_code=400, detail=f"La empresa '{emp}' no pertenece a este usuario")


def _own_q(user, uids) -> dict:
    """Filtro de propiedad del expediente con soporte multi-empresa: el mismo
    usuario puede pertenecer a varias empresas, así que manda el campo `empresa`
    del documento (la empresa activa). Los documentos antiguos sin empresa caen
    al filtro por user_id. `user` puede ser el dict efectivo o un nombre de empresa."""
    emp = user.get("empresa") if isinstance(user, dict) else user
    base = {"user_id": {"$in": uids}}
    if not emp:
        return base
    base["$and"] = [{"$or": [{"empresa": emp}, {"empresa": {"$in": [None, ""]}}]}]
    return base


async def _flota_categorias(user, uids: list[str]) -> tuple[set[str], dict[str, str]]:
    """Placas (normalizadas) y su categoría, para el validador automático de facturas.
    Junta la flota PRINCIPAL (db.vehiculos, por empresa) con subsidio_vehicles (que manda
    si hay choque de placa) — el mismo criterio que ya usan el expediente admin y el
    dashboard del cliente. Antes el validador solo miraba subsidio_vehicles: una placa
    dada de alta únicamente en el módulo Vehículos (sin duplicarla en Subsidio) no se
    reconocía, y la factura quedaba "no se pudo verificar la flota" → OBSERVADA aunque
    la placa sí estuviera registrada."""
    np = lambda p: _re.sub(r"[^A-Z0-9]", "", (p or "").upper())
    cats: dict[str, str] = {}
    emp = user.get("empresa") if isinstance(user, dict) else None
    if emp:
        async for mv in db.vehiculos.find({"empresa": emp}, {"_id": 0, "placa": 1, "categoria": 1}):
            pn = np(mv.get("placa") or mv.get("veh"))
            if pn:
                cats[pn] = (mv.get("categoria") or "").upper()
    async for sv in db.subsidio_vehicles.find(_own_q(user, uids), {"_id": 0, "placa": 1, "categoria": 1}):
        pn = np(sv.get("placa"))
        if pn:
            cats[pn] = (sv.get("categoria") or "").upper()
    return set(cats.keys()), cats


async def _require_subsidio(request: Request) -> dict:
    user = await _get_current_user(request)
    allowed = ["admin_enered", "cliente_subsidio", "administrador", "logistica", "contabilidad"]
    if user["role"] not in allowed:
        raise HTTPException(status_code=403, detail="No tienes acceso al módulo de subsidio")
    return user


def _programa_de_fecha(fecha_str) -> tuple:
    """A qué decreto pertenece una factura según su fecha de emisión: DU 004 o el periodo
    del DU 007 que le toque (1, 2 o 3). Se usa para clasificar las facturas de db.invoices
    (el espejo de Facturación, ajeno al subsidio, que nunca trae el campo `programa`) igual
    que cualquier otra factura — no fijas siempre a un solo decreto."""
    from services.validador_facturas import periodo_du007
    from datetime import date as _date
    try:
        f = _date.fromisoformat(str(fecha_str)[:10])
    except (ValueError, TypeError):
        return "du004", None
    n = periodo_du007(f)
    if n is not None:
        return "du007", n
    return "du004", None


def _normalize_doc(d: dict) -> dict:
    if not d:
        return d
    if "categoria" in d and "category" not in d:
        d["category"] = d["categoria"]
    elif "category" in d and "categoria" not in d:
        d["categoria"] = d["category"]
    
    if "uploaded_at" in d and "created_at" not in d:
        d["created_at"] = d["uploaded_at"]
    elif "created_at" in d and "uploaded_at" not in d:
        d["uploaded_at"] = d["created_at"]
    return d



# ============================================================================
# MODELS
# ============================================================================
class CategoriaVehicular(BaseModel):
    code: Literal["M2", "M3", "N1", "N2", "N3"]
    cantidad: int = Field(ge=0)
    galones_mensuales: float = Field(ge=0)


class CalculationCreate(BaseModel):
    califica: bool
    categorias: List[CategoriaVehicular] = []
    total_galones_mensuales: Optional[float] = None
    subsidio_estimado: float = 0.0
    detalle: Optional[dict] = None
    canal_origen: str = "calculadora"


class RegisterFromCalculator(BaseModel):
    calc_id: str
    ruc: str = Field(min_length=11, max_length=11)
    razon_social: str
    contacto: str
    telefono: str
    email: EmailStr
    password: str = Field(min_length=8)


class RegisterPublicoIn(BaseModel):
    ruc: str = Field(min_length=11, max_length=11)
    razon_social: str
    contacto: str
    telefono: str
    email: EmailStr
    password: str = Field(min_length=8)


class RegistroEtapa0In(BaseModel):
    """El cliente que entró por RUC crea su usuario ENERED (correo + contraseña)."""
    email: EmailStr
    password: str = Field(min_length=8)


class EntrarRucIn(BaseModel):
    ruc: str = Field(min_length=11, max_length=11)


class BankAccountIn(BaseModel):
    es_banco_nacion: bool
    banco: str
    tipo_cuenta: Literal["ahorros", "corriente"]
    numero_cuenta: str
    # El subsidio se abona SOLO en soles: no se aceptan cuentas en dólares.
    moneda: Literal["PEN"] = "PEN"
    cci: Optional[str] = None


class VehicleIn(BaseModel):
    placa: str
    categoria: Literal["M2", "M3", "N1", "N2", "N3"]


class VehicleAdminIn(BaseModel):
    placa: str
    categoria: Literal["M2", "M3", "N1", "N2", "N3"]
    anio_fabricacion: Optional[int] = None
    vigente_desde: Optional[str] = None
    vigente_hasta: Optional[str] = None


class InvoiceAdminCreateIn(BaseModel):
    numero_documento: str
    fecha: str
    estacion: str
    ruc_emisor: str
    ciudad: str
    placa: str
    galones: float
    precio_unitario: float
    importe_total: float
    producto: Optional[str] = "DIESEL B5"
    programa: Optional[str] = "du004"


class RepresentanteUpdateIn(BaseModel):
    representante: str


# Etapas del trámite (controladas por admin_enered)
SUBSIDIO_STAGES = ["solicitud_enviada", "evaluacion_atu", "aprobada", "abonado_en_cuenta"]


class StageUpdateIn(BaseModel):
    stage: Literal["solicitud_enviada", "evaluacion_atu", "aprobada", "abonado_en_cuenta"]


# ============================================================================
# PUBLIC: Calculator
# ============================================================================
@subsidio_router.post("/calculations")
async def create_calculation(payload: CalculationCreate):
    """Public endpoint — la calculadora externa guarda el resultado y obtiene calc_id."""
    calc_id = str(uuid.uuid4())
    doc = {
        "id": calc_id,
        "califica": payload.califica,
        "categorias": [c.model_dump() for c in payload.categorias],
        "total_galones_mensuales": payload.total_galones_mensuales,
        "subsidio_estimado": payload.subsidio_estimado,
        "detalle": payload.detalle or {},
        "canal_origen": payload.canal_origen,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "linked_user_id": None,
    }
    await db.calculations.insert_one(doc)
    # Save also as lead
    await db.subsidio_leads.insert_one({
        "id": str(uuid.uuid4()),
        "calc_id": calc_id,
        "califica": payload.califica,
        "subsidio_estimado": payload.subsidio_estimado,
        "registered": False,
        "created_at": doc["created_at"],
    })
    return {
        "calc_id": calc_id,
        "subsidio_estimado": payload.subsidio_estimado,
        "califica": payload.califica,
        "created_at": doc["created_at"],
    }


@subsidio_router.get("/calculations/{calc_id}")
async def get_calculation(calc_id: str):
    calc = await db.calculations.find_one({"id": calc_id}, {"_id": 0})
    if not calc:
        raise HTTPException(status_code=404, detail="Cálculo no encontrado")
    return calc


# ============================================================================
# PUBLIC: Self-register from calculator
# ============================================================================
@subsidio_router.get("/sunat/ruc/{ruc}")
async def lookup_ruc(ruc: str):
    """Consulta SUNAT vía api.apis.net.pe usando token desde variable de entorno.
    Si falla, permite escribir la razón social a mano (fallback manual)."""
    ruc = (ruc or "").strip()
    if not ruc.isdigit() or len(ruc) != 11:
        raise HTTPException(status_code=400, detail="RUC inválido: deben ser 11 dígitos numéricos")

    # Token solo desde variable de entorno (sin fallback hardcodeado).
    token = os.getenv("DECOLECTA_TOKEN", "").strip()
    if not token:
        raise HTTPException(status_code=503, detail="Servicio SUNAT no configurado (DECOLECTA_TOKEN)")

    url = f"https://api.decolecta.com/v1/sunat/ruc?numero={ruc}"
    headers = {
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers=headers)
        
        # Manejo de errores más tolerante
        if r.status_code == 401 or r.status_code == 403:
            logger.warning("apis.net.pe auth error %s: %s", r.status_code, r.text[:200])
            # Fallback: permitir entrada manual
            raise HTTPException(
                status_code=206,  # Partial Content — requiere entrada manual
                detail="SUNAT no disponible en este momento. Por favor, ingresa la razón social manualmente."
            )
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail="RUC no encontrado en SUNAT")
        if r.status_code == 429 or r.status_code == 422:
            raise HTTPException(status_code=429, detail="Límite de consultas SUNAT alcanzado. Intenta en unos segundos.")
        if r.status_code != 200:
            logger.warning("apis.net.pe respondió %s: %s", r.status_code, r.text[:200])
            raise HTTPException(status_code=502, detail=f"SUNAT respondió con {r.status_code}")
        
        data = r.json() or {}
    except HTTPException:
        raise
    except Exception as ex:
        logger.warning("RUC lookup failed: %s", ex)
        raise HTTPException(status_code=206, detail="No pudimos consultar SUNAT. Ingresa la razón social manualmente.")

    razon_social = (
        data.get("razonSocial")
        or data.get("nombre")
        or data.get("razon_social")
        or ""
    ).strip()
    if not razon_social:
        raise HTTPException(status_code=404, detail="RUC no encontrado en SUNAT")

    return {
        "ruc": ruc,
        "razon_social": razon_social,
        "estado": data.get("estado") or "",
        "condicion": data.get("condicion") or "",
        "direccion": data.get("direccion") or "",
        "departamento": data.get("departamento") or "",
        "provincia": data.get("provincia") or "",
        "distrito": data.get("distrito") or "",
    }


@subsidio_router.post("/auth/register-from-calculator")
async def register_from_calculator(payload: RegisterFromCalculator, response: Response):
    calc = await db.calculations.find_one({"id": payload.calc_id})
    if not calc:
        raise HTTPException(status_code=400, detail="calc_id inválido")

    email = payload.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Ya existe una cuenta con este correo")

    # Find or create empresa (en empresas_config si no existe)
    empresa_name = payload.razon_social.strip()
    existing_emp = await db.empresas_config.find_one({"empresa": empresa_name})
    if not existing_emp:
        await db.empresas_config.insert_one({
            "id": str(uuid.uuid4()),
            "empresa": empresa_name,
            "ruc": payload.ruc,
            "plan": "subsidio",
            "tipo_cliente": "subsidio",
            "servicios": {
                "plataforma": False,
                "combustible": False,
                "gps": False,
                "subsidio": True,
            },
            "linea_credito": 0,
            "unidades_contratadas": 0,
            "dias_credito": 0,
            "canal_origen": "calculadora",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "email": email,
        "name": payload.contacto,
        "password_hash": _hash_pw(payload.password),
        "role": "cliente_subsidio",
        "empresa": empresa_name,
        "ruc": payload.ruc,
        "contacto": payload.contacto,
        "telefono": payload.telefono,
        "calc_id": payload.calc_id,
        "documentos_completos": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(user_doc)
    user_doc.pop("_id", None)

    # Link calc & lead
    await db.calculations.update_one(
        {"id": payload.calc_id},
        {"$set": {"linked_user_id": user_id, "linked_empresa": empresa_name}}
    )
    await db.subsidio_leads.update_one(
        {"calc_id": payload.calc_id},
        {"$set": {"registered": True, "user_id": user_id}}
    )

    access = _create_access_token(user_id, email, "cliente_subsidio", empresa_name)
    refresh = _create_refresh_token(user_id)
    _set_auth_cookies(response, access, refresh)
    response.headers["X-Access-Token"] = access

    pub = {k: v for k, v in user_doc.items() if k != "password_hash"}
    pub["servicios"] = {
        "plataforma": False,
        "combustible": False,
        "gps": False,
        "subsidio": True,
    }
    pub["tipo_cliente"] = "subsidio"
    return {"user": pub, "access_token": access}


@subsidio_router.post("/subsidio/registro-publico")
async def register_publico(payload: RegisterPublicoIn, response: Response):
    """
    Registro desde la landing pública /subsidio (después de ver la Etapa 0).
    El transportista crea su propia contraseña y queda logueado como cliente_subsidio.
    """
    email = payload.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Ya existe una cuenta con este correo")

    empresa_name = (payload.razon_social or "").strip() or f"RUC {payload.ruc}"
    existing_emp = await db.empresas_config.find_one({"empresa": empresa_name})
    if not existing_emp:
        await db.empresas_config.insert_one({
            "id": str(uuid.uuid4()),
            "empresa": empresa_name,
            "ruc": payload.ruc,
            "plan": "subsidio",
            "tipo_cliente": "subsidio",
            "servicios": {"plataforma": False, "combustible": False, "gps": False, "subsidio": True},
            "linea_credito": 0, "unidades_contratadas": 0, "dias_credito": 0,
            "canal_origen": "landing_subsidio",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id, "email": email, "name": payload.contacto,
        "password_hash": _hash_pw(payload.password),
        "role": "cliente_subsidio", "empresa": empresa_name, "ruc": payload.ruc,
        "contacto": payload.contacto, "telefono": payload.telefono,
        "documentos_completos": False,
        "canal_origen": "landing_subsidio",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(user_doc)
    user_doc.pop("_id", None)

    access = _create_access_token(user_id, email, "cliente_subsidio", empresa_name)
    refresh = _create_refresh_token(user_id)
    _set_auth_cookies(response, access, refresh)
    response.headers["X-Access-Token"] = access

    pub = {k: v for k, v in user_doc.items() if k != "password_hash"}
    pub["servicios"] = {"plataforma": False, "combustible": False, "gps": False, "subsidio": True}
    pub["tipo_cliente"] = "subsidio"
    return {"user": pub, "access_token": access}


async def _sunat_nombre(ruc: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False,
                                     headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}) as c:
            r = await c.get("https://api.apis.net.pe/v1/ruc", params={"numero": ruc})
            if r.status_code == 200:
                return (r.json().get("nombre") or "").strip()
    except Exception:
        pass
    return ""


_FICHA_CACHE = {}  # ruc -> (timestamp, ficha) — evita pegarle a SUNAT en cada carga del dashboard


async def _sunat_ficha(ruc: str) -> Optional[dict]:
    """
    Consulta pública de SUNAT para validar la Ficha RUC sin que el cliente suba nada.
    Devuelve {nombre, estado, condicion, direccion, activo_habido} o None si no responde.
    Con caché en memoria (10 min): el estado del RUC no cambia de un minuto a otro.
    """
    ruc = (ruc or "").strip()
    if not _re.fullmatch(r"\d{11}", ruc):
        return None
    import time as _t
    _hit = _FICHA_CACHE.get(ruc)
    if _hit and (_t.time() - _hit[0]) < 600:
        return _hit[1]
    try:
        async with httpx.AsyncClient(timeout=12.0, verify=False,
                                     headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}) as c:
            r = await c.get("https://api.apis.net.pe/v1/ruc", params={"numero": ruc})
            if r.status_code in (404, 422):
                # El RUC no existe en SUNAT (distinto de "el servicio no responde").
                ficha = {"ruc": ruc, "nombre": "", "estado": "NO EXISTE", "condicion": "",
                         "direccion": "", "activo_habido": False, "no_encontrado": True,
                         "verificado_en": datetime.now(timezone.utc).isoformat(),
                         "fuente": "SUNAT (consulta pública)"}
                _FICHA_CACHE[ruc] = (_t.time(), ficha)
                return ficha
            if r.status_code != 200:
                return None
            d = r.json()
    except Exception:
        return None
    estado = (d.get("estado") or "").strip().upper()
    condicion = (d.get("condicion") or "").strip().upper()
    # Ubicación: la fuente ya la desglosa (ubigeo, distrito, provincia, departamento).
    ubicacion = " / ".join([p for p in [(d.get("distrito") or "").strip(),
                                        (d.get("provincia") or "").strip(),
                                        (d.get("departamento") or "").strip()] if p])
    ficha = {
        "ruc": ruc,
        "nombre": (d.get("nombre") or "").strip(),
        "estado": estado,
        "condicion": condicion,
        "direccion": (d.get("direccion") or "").strip(),
        "ubicacion": ubicacion,
        "ubigeo": (d.get("ubigeo") or "").strip(),
        "distrito": (d.get("distrito") or "").strip(),
        "provincia": (d.get("provincia") or "").strip(),
        "departamento": (d.get("departamento") or "").strip(),
        "activo_habido": estado == "ACTIVO" and condicion == "HABIDO",
        "verificado_en": datetime.now(timezone.utc).isoformat(),
        "fuente": "SUNAT (consulta pública)",
    }
    _FICHA_CACHE[ruc] = (_t.time(), ficha)
    return ficha


@subsidio_router.post("/subsidio/entrar")
async def entrar_por_ruc(payload: EntrarRucIn, response: Response):
    """
    Entrada a la plataforma con SOLO el RUC (Etapa 0), como SESIÓN INVITADA:
    NO crea ningún usuario ni empresa en la BD (evita ensuciar la plataforma por cada
    búsqueda). Emite un token temporal que lleva el RUC; el cliente ve su Mi Flota con
    la Etapa 0 y los 5 módulos (bloqueados). La cuenta real se crea desde el admin.
    """
    ruc = (payload.ruc or "").strip()
    if not _re.fullmatch(r"\d{11}", ruc):
        raise HTTPException(status_code=400, detail="El RUC debe tener 11 dígitos")
    empresa_name = (await _sunat_nombre(ruc)) or f"RUC {ruc}"
    token = _create_guest_token(ruc, empresa_name)
    # Cookie de acceso (sin refresh: la sesión invitada dura 8h y no se renueva).
    response.set_cookie("access_token", token, httponly=True, secure=True, **_cookie_extra(),
                        max_age=8 * 3600, path="/")
    response.headers["X-Access-Token"] = token
    return {"user": _guest_public(_guest_user_from_payload({"ruc": ruc, "empresa": empresa_name})),
            "access_token": token}


@subsidio_router.post("/subsidio/registro-etapa0")
async def registro_etapa0(payload: RegistroEtapa0In, request: Request, response: Response):
    """
    El cliente que entró por RUC (Etapa 0) crea su usuario ENERED: correo + contraseña.
    Se guarda en su expediente, se quita el bloqueo de Etapa 0 y avanza a la Etapa 1;
    quedan visibles/accesibles los módulos regulares (los premium siguen bloqueados).
    """
    current = await _get_current_user(request)
    if current.get("role") != "cliente_subsidio":
        raise HTTPException(status_code=403, detail="Solo disponible para clientes del subsidio")
    email = (payload.email or "").strip().lower()
    # El correo no puede estar usado por otra cuenta
    dup = await db.users.find_one({"email": email, "id": {"$ne": current["id"]}})
    if dup:
        raise HTTPException(status_code=409, detail="Ese correo ya está registrado. Usa otro o inicia sesión.")

    if current.get("es_guest"):
        # Sesión invitada (entró solo con su RUC): el usuario NO existe todavía → se crea aquí.
        # Si ese RUC ya tiene una cuenta creada, no se pisa: que inicie sesión con su correo.
        ruc = current.get("ruc") or ""
        ya = await db.users.find_one({"ruc": ruc, "role": "cliente_subsidio", "es_guest": {"$ne": True}})
        if ya:
            raise HTTPException(status_code=409,
                                detail=f"Este RUC ya tiene una cuenta ENERED ({ya.get('email')}). Inicia sesión con ese correo.")
        nuevo = {
            "id": str(uuid.uuid4()),
            "email": email,
            "password_hash": _hash_pw(payload.password),
            "name": current.get("empresa") or f"RUC {ruc}",
            "role": "cliente_subsidio",
            "empresa": current.get("empresa") or f"RUC {ruc}",
            "ruc": ruc,
            "tipo_cliente": "subsidio",
            "servicios": {"plataforma": False, "combustible": False, "gps": False, "subsidio": True},
            "acceso_etapa0": False,          # ya registrado → puede avanzar a Etapa 1
            "registrado_etapa0": True,
            "registro_etapa0_at": datetime.now(timezone.utc).isoformat(),
            "documentos_completos": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "origen": "registro_etapa0_invitado",
        }
        await db.users.insert_one(nuevo)
        current = {"id": nuevo["id"]}
    else:
        await db.users.update_one({"id": current["id"]}, {"$set": {
            "email": email,
            "password_hash": _hash_pw(payload.password),
            "acceso_etapa0": False,          # ya registrado → puede avanzar a Etapa 1
            "registrado_etapa0": True,
            "registro_etapa0_at": datetime.now(timezone.utc).isoformat(),
        }})
    u = await db.users.find_one({"id": current["id"]}, {"_id": 0, "password_hash": 0})
    # Reemitir tokens con el correo nuevo
    access = _create_access_token(u["id"], email, "cliente_subsidio", u.get("empresa"))
    refresh = _create_refresh_token(u["id"])
    _set_auth_cookies(response, access, refresh)
    response.headers["X-Access-Token"] = access
    return {
        "user": {"id": u["id"], "email": email, "name": u.get("name"), "role": "cliente_subsidio",
                 "empresa": u.get("empresa"), "ruc": u.get("ruc"), "acceso_etapa0": False,
                 "registrado_etapa0": True,
                 "servicios": {"plataforma": False, "combustible": False, "gps": False, "subsidio": True},
                 "tipo_cliente": "subsidio"},
        "access_token": access,
    }


# ============================================================================
# PRIVATE: cliente_subsidio
# ============================================================================
DOCUMENT_LABELS = {
    "ficha_ruc": "Ficha RUC (activo y habido)",
    "resolucion_autorizacion": "Autorización del transportista",
    "dni_representante": "DNI del representante legal",
    "tarjeta_habilitacion": "Tarjeta de habilitación",
    "tarjeta_propiedad": "Tarjeta de propiedad",
    "comprobante_jun_2026": "Comprobantes — Mes 1 (junio 2026)",
    "comprobante_jul_2026": "Comprobantes — Mes 2 (julio 2026)",
    "evidencia_cci": "Evidencia de la cuenta (CCI)",
}

EMPRESA_CATEGORIES = ["ficha_ruc", "resolucion_autorizacion", "dni_representante"]
# Documentos de empresa que NO bloquean la declaración jurada (Flor, 09/09/2026): la resolución /
# permiso de transportista se verifica en línea contra el MTC y muchas empresas no tienen el PDF.
EMPRESA_OPCIONALES = {"resolucion_autorizacion"}
FLOTA_CATEGORIES = ["tarjeta_habilitacion", "tarjeta_propiedad"]
COMBUSTIBLE_CATEGORIES = ["comprobante_jun_2026", "comprobante_jul_2026"]
# La evidencia del CCI acompaña a la cuenta bancaria (no es un doc de empresa/flota/combustible).
BANCO_CATEGORIES = ["evidencia_cci"]
ALL_CATEGORIES = EMPRESA_CATEGORIES + FLOTA_CATEGORIES + COMBUSTIBLE_CATEGORIES + BANCO_CATEGORIES

# MIME allowed per category (Art. user-defined: empresa solo PDF, flota PDF+imágenes)
EMPRESA_MIME = {"application/pdf"}
FLOTA_MIME = {"application/pdf", "image/jpeg", "image/jpg", "image/png", "image/webp"}
# Las facturas de combustible SOLO se aceptan en PDF (permite leer el QR y validar en SUNAT).
COMBUSTIBLE_MIME = {"application/pdf"}
# La evidencia del CCI sí admite captura de pantalla.
BANCO_MIME = {"application/pdf", "image/jpeg", "image/jpg", "image/png", "image/webp"}


def _allowed_mimes_for(categoria: str) -> set:
    if categoria in EMPRESA_CATEGORIES:
        return EMPRESA_MIME
    if categoria in FLOTA_CATEGORIES:
        return FLOTA_MIME
    if categoria in BANCO_CATEGORIES:
        return BANCO_MIME
    return COMBUSTIBLE_MIME


@subsidio_router.get("/subsidio/status")
async def subsidio_status(user: dict = Depends(_require_subsidio)):
    """Devuelve si el usuario ya completó documentos (para redirect post-login)."""
    return {
        "documentos_completos": bool(user.get("documentos_completos")),
        "ruc": user.get("ruc"),
        "empresa": user.get("empresa"),
    }


_MTC_CACHE: dict = {}   # ruc -> (timestamp, data). El scrape del MTC es lento: se reusa.


async def _mtc_consulta(ruc: str) -> Optional[dict]:
    """Consulta al MTC por RUC con caché en memoria (10 min) para no repetir el scrape."""
    import time as _t
    ruc = (ruc or "").strip()
    if not _re.fullmatch(r"\d{11}", ruc):
        return None
    hit = _MTC_CACHE.get(ruc)
    if hit and (_t.time() - hit[0]) < 600:
        return hit[1]
    try:
        import mtc as _mtc
        data = await _mtc.consultar("ruc", ruc)
    except Exception:
        return None
    _MTC_CACHE[ruc] = (_t.time(), data)
    return data


def _mtc_vencida(vig) -> bool:
    import datetime as _dt
    m = _re.match(r"(\d{2})/(\d{2})/(\d{4})", str(vig or ""))
    if not m:
        return False
    try:
        return _dt.date(int(m.group(3)), int(m.group(2)), int(m.group(1))) < _dt.date.today()
    except Exception:
        return False


async def _mtc_autorizacion(ruc: str) -> Optional[dict]:
    """
    Autorización (resolución) de transporte del MTC — evita subir la resolución en PDF.
    Devuelve los datos de la autorización habilitada y vigente, o la primera encontrada.
    """
    data = await _mtc_consulta(ruc)
    if data is None:
        return None
    auts = data.get("autorizaciones", []) or []
    if not auts:
        return {"encontrada": False, "habilitado": False,
                "verificado_en": datetime.now(timezone.utc).isoformat(),
                "fuente": "MTC · DGTT (consulta pública)"}
    import mtc as _mtc
    # Rige la autorización ACTIVA cuyo tipo de permiso APLICA al subsidio; si no hay, la
    # activa que haya; si no, la primera.
    activas = [a for a in auts if _mtc.autorizacion_activa(a)]
    mejor = (next((a for a in activas if a.get("permiso_aplica") is True), None)
             or next((a for a in activas if a.get("permiso_aplica") is None), None)
             or (activas[0] if activas else auts[0]))
    vig = mejor.get("vigente_hasta")
    return {
        "encontrada": True,
        "codigo": mejor.get("codigo") or "",
        "tipo_permiso": mejor.get("tipo_permiso") or _mtc.tipo_permiso(mejor.get("codigo")),
        "permiso_aplica": mejor.get("permiso_aplica", _mtc.permiso_aplica(mejor.get("codigo"))),
        "permisos": [{"codigo": a.get("codigo"), "tipo": a.get("tipo_permiso"), "aplica": a.get("permiso_aplica"),
                      "activo": _mtc.autorizacion_activa(a), "unidades": a.get("total_unidades", 0)} for a in auts],
        "razon_social": mejor.get("razon_social") or "",
        "modalidad": mejor.get("modalidad") or "",
        "estado": mejor.get("estado") or "",
        "vigencia": vig,
        "vencida": _mtc_vencida(vig),
        "habilitado": bool(mejor.get("habilitado")) and not _mtc_vencida(vig),
        "total_autorizaciones": len(auts),
        "total_unidades": sum(a.get("total_unidades", 0) for a in auts),
        "verificado_en": datetime.now(timezone.utc).isoformat(),
        "fuente": "MTC · DGTT (consulta pública)",
    }


async def _mtc_habilitaciones(ruc: str) -> Optional[dict]:
    """
    Habilitación vehicular oficial del MTC por RUC — evita que el cliente suba la
    tarjeta de habilitación de CADA unidad. Devuelve {PLACA_NORMALIZADA: {...}} o None.
    """
    data = await _mtc_consulta(ruc)
    if data is None:
        return None

    import datetime as _dt

    def _vencida(vig):
        m = _re.match(r"(\d{2})/(\d{2})/(\d{4})", str(vig or ""))
        if not m:
            return False
        try:
            return _dt.date(int(m.group(3)), int(m.group(2)), int(m.group(1))) < _dt.date.today()
        except Exception:
            return False

    import mtc as _mtc
    out = {}
    # Una fila por placa, regida por la autorización activa que APLICA al subsidio (si la
    # misma placa está en un permiso que aplica y en otro que no, manda el que aplica).
    for v in _mtc.unidades_para_subsidio(data):
        pn = (v.get("placa") or "").replace("-", "").replace(" ", "").upper()
        if not pn or pn in out:
            continue
        vig = v.get("vigente_hasta")
        if True:
            out[pn] = {
                "placa": v.get("placa"),
                "categoria": (v.get("categoria") or "").upper(),
                "constancia": v.get("constancia") or v.get("autorizacion") or "",
                "anio": v.get("anio") or "",
                "chasis": v.get("chasis") or "",
                "ejes": v.get("ejes") or "",
                "vigencia": vig,
                "vencida": _vencida(vig),
                "habilitado": bool(v.get("autorizacion_activa")),
                "autorizacion": v.get("autorizacion") or "",
                "permiso": v.get("permiso") or "",
                "permiso_aplica": v.get("permiso_aplica"),
                "razon_social": v.get("razon_social") or "",
                "verificado_en": datetime.now(timezone.utc).isoformat(),
                "fuente": "MTC · DGTT (consulta pública)",
            }
    return out


@subsidio_router.get("/subsidio/ficha-ruc")
async def subsidio_ficha_ruc(user: dict = Depends(_require_subsidio), ruc: Optional[str] = None):
    """
    Validación en línea de la Ficha RUC contra SUNAT — evita que el cliente suba el PDF.
    Devuelve razón social, estado, condición y si está ACTIVO y HABIDO.
    """
    objetivo = (ruc or user.get("ruc") or "").strip()
    if not _re.fullmatch(r"\d{11}", objetivo):
        raise HTTPException(status_code=400, detail="RUC inválido (11 dígitos)")
    ficha = await _sunat_ficha(objetivo)
    if not ficha:
        raise HTTPException(status_code=503, detail="SUNAT no responde en este momento. Intenta de nuevo.")
    return ficha


async def _grifo_por_ruc(ruc: str, razon: Optional[str] = None) -> Optional[dict]:
    """
    Grifo por RUC con TODAS las fuentes gratuitas:
      1) padrón CSV de OSINERGMIN (Datos Abiertos, incompleto),
      2) Facilito por razón social (toda estación que declara precios está inscrita),
      3) si nadie dio la razón social, se toma de SUNAT (consulta pública) y se reintenta.
    Así un RUC como 20515401076 (SERVIKYA / Primax Huaura), que no está en el CSV,
    sale inscrito sin que el cliente escriba nada.
    """
    from services.padron_grifos import buscar_por_ruc
    g = await buscar_por_ruc(db, ruc, razon_social=razon or None)
    if g is None or g.get("inscrito"):
        return g
    ficha = await _sunat_ficha(ruc)
    nombre = ((ficha or {}).get("nombre") or "").strip()
    if not nombre:
        return g
    # SUNAT suele traer "NOMBRE LARGO-NOMBRE CORTO": se prueban las partes y el completo.
    candidatos = []
    for parte in nombre.split("-"):
        parte = parte.strip()
        if parte and parte not in candidatos and parte != (razon or ""):
            candidatos.append(parte)
    if nombre not in candidatos:
        candidatos.append(nombre)
    for c in candidatos:
        g2 = await buscar_por_ruc(db, ruc, razon_social=c)
        if g2 and g2.get("inscrito"):
            g2["razon_social_sunat"] = nombre
            g2["fuente"] = (g2.get("fuente") or "OSINERGMIN") + " · razón social de SUNAT"
            return g2
    g["razon_social_sunat"] = nombre
    return g


@subsidio_router.get("/subsidio/grifo/{ruc}")
async def subsidio_grifo(ruc: str, razon: str = "", user: dict = Depends(_require_subsidio)):
    """
    Autocompleta los datos del grifo (razón social, ubicación, dirección) desde el padrón
    de OSINERGMIN, e indica si está inscrito. Alimenta la sección 'GRIFO' del formulario ATU.
    Si el RUC no figura en el CSV de Datos Abiertos (incompleto), busca la razón social en
    las estaciones de Facilito antes de marcarlo en rojo.
    """
    g = await _grifo_por_ruc(ruc, razon)
    if g is None:
        raise HTTPException(status_code=400, detail="RUC inválido (11 dígitos)")
    return g


@subsidio_router.post("/subsidio/comprobante/extraer")
async def subsidio_extraer_comprobante(file: UploadFile = File(...), user: dict = Depends(_require_subsidio)):
    """
    Lee un comprobante (PDF con QR, o XML) y devuelve los campos que exige la ATU,
    ya autocompletados. El usuario puede editar todo antes de guardar.
    """
    contenido = await file.read()
    if len(contenido) > 20 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Archivo mayor a 20MB")

    from services.extractor_comprobante import extraer
    from services.padron_grifos import buscar_por_ruc
    datos = extraer(contenido, file.filename or "")

    # Completar los datos del grifo desde OSINERGMIN con el RUC del emisor
    # (con respaldo Facilito por razón social si el CSV no lo tiene).
    if datos.get("ruc_emisor"):
        g = await _grifo_por_ruc(datos["ruc_emisor"], datos.get("razon_social_emisor"))
        if g:
            datos["grifo"] = g
            if g.get("inscrito"):
                datos.setdefault("razon_social_emisor", g.get("razon_social"))
                for k_dest, k_src in (("departamento", "departamento"), ("provincia", "provincia"),
                                      ("distrito", "distrito"), ("direccion_grifo", "direccion")):
                    if not datos.get(k_dest) and g.get(k_src):
                        datos[k_dest] = g[k_src]
                        datos.setdefault("fuentes", {})[k_dest] = "OSINERGMIN"

    # Avisar si el comprobante no está a nombre del transportista.
    if datos.get("ruc_adquirente") and user.get("ruc"):
        datos["adquirente_coincide"] = datos["ruc_adquirente"] == user["ruc"]
    return datos


@subsidio_router.get("/subsidio/carga-masiva/plantilla")
async def subsidio_plantilla_masiva(programa: str = "du004", user: dict = Depends(_require_subsidio)):
    """Descarga la plantilla ENERED de carga masiva, ya con la flota del transportista."""
    from services.carga_masiva import generar_plantilla
    programa = programa if programa in ("du004", "du007") else "du004"
    uids = await _get_company_uids(user)
    _, _cats_plantilla = await _flota_categorias(user, uids)
    vehiculos = [{"placa": p, "categoria": c} for p, c in sorted(_cats_plantilla.items())]
    xlsx = generar_plantilla(empresa=user.get("empresa") or "", ruc=user.get("ruc") or "",
                             vehiculos=vehiculos, programa=programa)
    nombre = f"ENERED_carga_masiva_{programa}_{(user.get('ruc') or 'comprobantes')}.xlsx"
    return StreamingResponse(
        io.BytesIO(xlsx),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{nombre}"'},
    )


@subsidio_router.post("/subsidio/carga-masiva/previsualizar")
async def subsidio_previsualizar_masiva(file: UploadFile = File(...), programa: str = Form("du004"),
                                        user: dict = Depends(_require_subsidio)):
    """
    Lee la plantilla llena y devuelve cada fila validada (sin guardar todavía),
    completando los datos del grifo desde OSINERGMIN.
    """
    from services.carga_masiva import leer_plantilla
    from services.validador_facturas import validar_factura
    from services.padron_grifos import buscar_por_ruc

    programa = programa if programa in ("du004", "du007") else "du004"
    contenido = await file.read()
    if len(contenido) > 20 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Archivo mayor a 20MB")
    try:
        filas = leer_plantilla(contenido)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"No se pudo leer la plantilla: {e}")
    if not filas:
        raise HTTPException(status_code=400, detail="La plantilla no tiene filas con datos")

    uids = await _get_company_uids(user)
    _np = lambda p: _re.sub(r"[^A-Z0-9]", "", (p or "").upper())
    placas, cats = await _flota_categorias(user, uids)

    previas = await db.consumos_subsidio.find(
        _own_q(user, uids), {"_id": 0, "ruc_emisor": 1, "numero_documento": 1}
    ).to_list(3000)
    vistos = {(str(p.get("ruc_emisor") or "").strip(), str(p.get("numero_documento") or "").strip().upper(),
               _np(p.get("placa"))) for p in previas if p.get("numero_documento")}

    grifos: dict[str, dict] = {}
    resultado, resumen = [], {"CONFORME": 0, "OBSERVADA": 0, "RECHAZADA": 0}
    for f in filas:
        # Completar datos del grifo desde OSINERGMIN si faltan en la plantilla.
        ruc_g = f.get("ruc_emisor")
        if ruc_g:
            if ruc_g not in grifos:
                grifos[ruc_g] = await _grifo_por_ruc(ruc_g) or {}
            g = grifos[ruc_g]
            if g.get("inscrito"):
                f.setdefault("estacion", g.get("razon_social"))
                for k in ("departamento", "provincia", "distrito"):
                    if not f.get(k):
                        f[k] = g.get(k)
                if not f.get("direccion_grifo"):
                    f["direccion_grifo"] = g.get("direccion")
            f["grifo_inscrito"] = bool(g.get("inscrito"))

        # La categoría real la manda la flota registrada (como hace la ATU).
        pn = _np(f.get("placa"))
        if pn in cats and cats[pn]:
            f["categoria"] = cats[pn]

        val = validar_factura(f, placas_flota=placas, categoria_por_placa=cats, numeros_existentes=vistos,
                              programa=programa)
        if f.get("numero_documento"):
            vistos.add((str(ruc_g or "").strip(), f["numero_documento"].strip().upper(), _np(f.get("placa"))))
        resumen[val["estado"]] = resumen.get(val["estado"], 0) + 1
        resultado.append({**f, "validacion": val, "validacion_estado": val["estado"], "programa": programa})

    return {"filas": resultado, "total": len(resultado), "resumen": resumen,
            "listas_para_guardar": resumen.get("CONFORME", 0) + resumen.get("OBSERVADA", 0)}


@subsidio_router.post("/subsidio/carga-masiva/confirmar")
async def subsidio_confirmar_masiva(payload: dict, user: dict = Depends(_require_subsidio)):
    """Guarda como borrador las filas de la carga masiva (se omiten las RECHAZADAS)."""
    filas = payload.get("filas") or []
    if not filas:
        raise HTTPException(status_code=400, detail="No hay filas para guardar")
    ahora = datetime.now(timezone.utc).isoformat()
    docs = []
    for f in filas:
        if (f.get("validacion_estado") or "").upper() == "RECHAZADA":
            continue
        programa_fila = f.get("programa") if f.get("programa") in ("du004", "du007") else "du004"
        docs.append({
            "id": str(uuid.uuid4()),
            "user_id": user["id"], "empresa": user.get("empresa"), "empresa_id": user.get("empresa"),
            "origin": "carga_masiva",
            "numero_documento": f.get("numero_documento"), "serie": f.get("serie"), "numero": f.get("numero"),
            "fecha": f.get("fecha"), "ruc_emisor": f.get("ruc_emisor"),
            "estacion": f.get("estacion"), "ciudad": normalize_city(f.get("distrito")),
            "departamento": f.get("departamento"), "provincia": f.get("provincia"), "distrito": f.get("distrito"),
            "direccion_grifo": f.get("direccion_grifo"),
            "placa": f.get("placa"), "placa_match": f.get("placa"), "categoria": f.get("categoria"),
            "producto": f.get("producto"), "galones": f.get("galones"),
            "tiene_nc": f.get("tiene_nc"), "serie_nc": f.get("serie_nc"),
            "numero_nc": f.get("numero_nc"), "alcance_nc": f.get("alcance_nc"),
            "validacion": f.get("validacion"), "validacion_estado": f.get("validacion_estado"),
            "requiere_revision": (f.get("validacion") or {}).get("requiere_revision", True),
            "status": "draft", "created_at": ahora, "confirmed_at": None,
            "programa": programa_fila,
            "periodo_du007": (f.get("validacion") or {}).get("periodo_du007") if programa_fila == "du007" else None,
        })
    if not docs:
        raise HTTPException(status_code=400, detail="Todas las filas fueron rechazadas; corrige la plantilla")
    await db.consumos_subsidio.insert_many(docs)
    return {"guardadas": len(docs), "omitidas": len(filas) - len(docs)}



def _sn_comprobante(x) -> Optional[tuple]:
    """(SERIE, número sin ceros) para comparar 'F001-2660', 'F001-0002660' y 'F0010002660'."""
    t = _re.sub(r"[^A-Z0-9-]", "", str(x or "").upper())
    m = _re.match(r"^([A-Z]{1,2}\d{2,3})-?0*(\d+)$", t)
    return (m.group(1), int(m.group(2))) if m else None


def _partir_pdf_por_factura(content: bytes) -> list:
    """Divide un PDF con varias facturas (una por página, o la misma repetida en páginas
    seguidas) en trozos [{numero_documento, ruc_emisor, importe_total, fecha, paginas, pdf}].
    Las páginas sin QR legible salen con numero_documento=None para reportarlas."""
    import pymupdf
    from services.extractor_comprobante import extraer_de_qr as _qr
    doc = pymupdf.open(stream=content, filetype="pdf")
    n = len(doc)
    if n <= 1:
        q = _qr(content) or {}
        doc.close()
        return [{"numero_documento": q.get("numero_documento"), "ruc_emisor": q.get("ruc_emisor"),
                 "importe_total": q.get("importe_total"), "fecha": q.get("fecha"), "paginas": [1], "pdf": content}]
    trozos = []
    for i in range(n):
        sub = pymupdf.open()
        sub.insert_pdf(doc, from_page=i, to_page=i)
        b = sub.tobytes()
        sub.close()
        q = _qr(b) or {}
        num = q.get("numero_documento")
        # misma factura en páginas seguidas (original + copia) → un solo trozo
        if trozos and num and trozos[-1]["numero_documento"] == num:
            trozos[-1]["paginas"].append(i + 1)
            continue
        trozos.append({"numero_documento": num, "ruc_emisor": q.get("ruc_emisor"), "importe_total": q.get("importe_total"),
                       "fecha": q.get("fecha"), "paginas": [i + 1], "pdf": b})
    doc.close()
    return trozos


async def _enganchar_pdf(user: dict, uids: list, content: bytes, filename: str, solo_ids: Optional[list] = None) -> dict:
    """Engancha las facturas contenidas en `content` (1 o varias páginas) a los comprobantes
    de la empresa que aún no tienen archivo, identificándolas por el QR (serie-número y RUC).
    `solo_ids` restringe a comprobantes concretos (p.ej. desde 'Editar comprobante')."""
    q = {**_own_q(user, uids), "$or": [{"factura_storage_key": {"$in": [None, ""]}}, {"factura_storage_key": {"$exists": False}}]}
    if solo_ids:
        q["id"] = {"$in": solo_ids}
    pendientes = await db.consumos_subsidio.find(q, {"_id": 0, "id": 1, "numero_documento": 1, "ruc_emisor": 1, "placa": 1, "origin": 1}).to_list(4000)
    por_num: dict = {}
    for p in pendientes:
        k = _sn_comprobante(p.get("numero_documento"))
        if k:
            por_num.setdefault(k, []).append(p)
    ahora = datetime.now(timezone.utc).isoformat()
    try:
        trozos = await asyncio.to_thread(_partir_pdf_por_factura, content)
    except Exception as e:
        logger.warning(f"No se pudo partir el PDF {filename}: {e}")
        trozos = [{"numero_documento": None, "paginas": [1], "pdf": content}]
    adjuntadas, detalle = 0, []
    for t in trozos:
        num = t.get("numero_documento")
        pags = ",".join(str(x) for x in t["paginas"])
        if not num:
            # Sin QR: si se pidió un comprobante concreto y el PDF es de 1 página, se adjunta igual.
            if solo_ids and len(solo_ids) == 1 and len(trozos) == 1:
                objetivos = [p for p in pendientes if p["id"] in solo_ids]
            else:
                detalle.append({"paginas": pags, "ok": False, "error": "Sin QR legible; adjúntala desde 'Editar comprobante'"})
                continue
        else:
            cands = por_num.get(_sn_comprobante(num)) or []
            if t.get("ruc_emisor"):
                con_ruc = [c for c in cands if _re.sub(r"\D", "", str(c.get("ruc_emisor") or "")) == t["ruc_emisor"]]
                cands = con_ruc or cands
            objetivos = cands
        if not objetivos:
            detalle.append({"paginas": pags, "numero_documento": num, "ok": False,
                            "error": "No hay un comprobante con ese número sin archivo (¿ya tiene PDF o no está en la carga?)"})
            continue
        base = _re.sub(r"[^A-Za-z0-9_.-]", "_", (filename or "factura").rsplit(".", 1)[0])[:40]
        nombre = f"{base}_{(num or 'pag' + pags).replace('/', '-')}.pdf"
        key = _subsidio_key(user["id"], "factura_subsidio", None, nombre)
        storage.save_object(key, t["pdf"], "application/pdf")
        ids = [o["id"] for o in objetivos]
        upd = {"factura_filename": nombre, "factura_storage_key": key, "factura_content_type": "application/pdf",
               "factura_size": len(t["pdf"]), "factura_adjunta_at": ahora, "factura_paginas_origen": pags}
        # Datos del QR: solo llenan lo que esté vacío (importe, fecha, RUC) — no pisan lo escrito.
        for camp, val in (("importe_total", t.get("importe_total")), ("ruc_emisor", t.get("ruc_emisor"))):
            if val:
                await db.consumos_subsidio.update_many({"id": {"$in": ids}, "$or": [{camp: {"$in": [None, "", 0]}}, {camp: {"$exists": False}}]}, {"$set": {camp: val}})
        await db.consumos_subsidio.update_many({"id": {"$in": ids}}, {"$set": upd})
        for _i in ids:
            await _revalidar_tras_cambio(_i)
        ids_set = set(ids)
        if num:
            por_num[_sn_comprobante(num)] = [c for c in (por_num.get(_sn_comprobante(num)) or []) if c["id"] not in ids_set]
        adjuntadas += len(ids)
        detalle.append({"paginas": pags, "numero_documento": num, "ok": True, "consumos": len(ids),
                        "placas": [o.get("placa") for o in objetivos if o.get("placa")]})
    return {"adjuntadas": adjuntadas, "trozos": len(trozos), "detalle": detalle}

@subsidio_router.post("/subsidio/carga-masiva/confirmar-con-pdf")
async def subsidio_confirmar_masiva_con_pdf(
    filas: str = Form(...),
    files: List[UploadFile] = File(...),
    user: dict = Depends(_require_subsidio),
):
    """Flujo de carga masiva: Excel validado + el PDF con las facturas (obligatorio) → recién
    se guardan los borradores, cada uno con su factura enganchada por QR (serie-número y RUC).
    Acepta un PDF por factura o un solo PDF con todas (una por página). Las filas cuya factura
    no aparece en el PDF se guardan igual, pero quedan OBSERVADAS con el motivo 'falta el PDF'."""
    import json as _json
    try:
        lista = _json.loads(filas) if isinstance(filas, str) else (filas or [])
    except Exception:
        raise HTTPException(status_code=400, detail="Filas inválidas")
    if not lista:
        raise HTTPException(status_code=400, detail="No hay filas para guardar")
    if not files:
        raise HTTPException(status_code=400, detail="Adjunta el PDF con las facturas para continuar")
    ahora = datetime.now(timezone.utc).isoformat()
    docs = []
    for f in lista:
        if (f.get("validacion_estado") or "").upper() == "RECHAZADA":
            continue
        programa_fila = f.get("programa") if f.get("programa") in ("du004", "du007") else "du004"
        docs.append({
            "id": str(uuid.uuid4()),
            "user_id": user["id"], "empresa": user.get("empresa"), "empresa_id": user.get("empresa"),
            "origin": "carga_masiva",
            "numero_documento": f.get("numero_documento"), "serie": f.get("serie"), "numero": f.get("numero"),
            "fecha": f.get("fecha"), "ruc_emisor": f.get("ruc_emisor"),
            "estacion": f.get("estacion"), "ciudad": normalize_city(f.get("distrito")),
            "departamento": f.get("departamento"), "provincia": f.get("provincia"), "distrito": f.get("distrito"),
            "direccion_grifo": f.get("direccion_grifo"),
            "placa": f.get("placa"), "placa_match": f.get("placa"), "categoria": f.get("categoria"),
            "producto": f.get("producto"), "galones": f.get("galones"),
            "tiene_nc": f.get("tiene_nc"), "serie_nc": f.get("serie_nc"),
            "numero_nc": f.get("numero_nc"), "alcance_nc": f.get("alcance_nc"),
            "validacion": f.get("validacion"), "validacion_estado": f.get("validacion_estado"),
            "requiere_revision": (f.get("validacion") or {}).get("requiere_revision", True),
            "status": "draft", "created_at": ahora, "confirmed_at": None,
            "programa": programa_fila,
            "periodo_du007": (f.get("validacion") or {}).get("periodo_du007") if programa_fila == "du007" else None,
        })
    if not docs:
        raise HTTPException(status_code=400, detail="Todas las filas fueron rechazadas; corrige la plantilla")
    await db.consumos_subsidio.insert_many(docs)
    nuevos_ids = [d["id"] for d in docs]

    uids = await _get_company_uids(user)
    adjuntadas, resultados = 0, []
    for f in files:
        content = await f.read()
        if content[:4] != b"%PDF":
            resultados.append({"filename": f.filename, "ok": False, "error": "Solo se aceptan facturas en PDF"})
            continue
        if len(content) > 40 * 1024 * 1024:
            resultados.append({"filename": f.filename, "ok": False, "error": "Archivo > 40MB"})
            continue
        r = await _enganchar_pdf(user, uids, content, f.filename or "facturas.pdf", solo_ids=nuevos_ids)
        adjuntadas += r["adjuntadas"]
        for d in r["detalle"]:
            resultados.append({"filename": f.filename, **d})

    # Filas cuya factura no se ubicó por QR: se les adjunta el PDF completo tal cual lo subió el
    # cliente (sin observar la fila). Admin ENERED lo revisa y, si hace falta, lo reemplaza
    # desde el expediente o "Editar comprobante".
    lote_keys = []
    for f in files:
        try:
            await f.seek(0)
            content = await f.read()
        except Exception:
            content = b""
        if content[:4] != b"%PDF":
            continue
        nombre = _re.sub(r"[^A-Za-z0-9_.-]", "_", (f.filename or "facturas.pdf"))[:60]
        key = _subsidio_key(user["id"], "factura_subsidio", None, f"lote_{nombre}")
        storage.save_object(key, content, "application/pdf")
        lote_keys.append({"key": key, "filename": f.filename or "facturas.pdf", "size": len(content)})
    sin_qr = [d async for d in db.consumos_subsidio.find(
        {"id": {"$in": nuevos_ids}, "$or": [{"factura_storage_key": {"$in": [None, ""]}}, {"factura_storage_key": {"$exists": False}}]},
        {"_id": 0, "id": 1, "numero_documento": 1, "placa": 1})]
    if sin_qr and lote_keys:
        principal = lote_keys[0]
        await db.consumos_subsidio.update_many(
            {"id": {"$in": [d["id"] for d in sin_qr]}},
            {"$set": {"factura_filename": principal["filename"], "factura_storage_key": principal["key"],
                      "factura_content_type": "application/pdf", "factura_size": principal["size"],
                      "factura_adjunta_at": ahora, "factura_lote": True,
                      "factura_lote_archivos": lote_keys,
                      "nota_enered": "PDF del lote adjunto sin coincidencia de QR: ubicar la factura dentro del PDF."}})
    con_pdf = len(nuevos_ids) - len(sin_qr)
    return {"guardadas": len(docs), "omitidas": len(lista) - len(docs), "con_pdf": con_pdf,
            "con_lote": len(sin_qr) if lote_keys else 0, "sin_pdf": 0 if lote_keys else len(sin_qr),
            "sin_pdf_detalle": [] if lote_keys else sin_qr[:100], "adjuntadas": adjuntadas, "resultados": resultados}


@subsidio_router.get("/subsidio/carga-masiva/pendientes-factura")
async def subsidio_masiva_pendientes(user: dict = Depends(_require_subsidio)):
    """Comprobantes cargados por plantilla (Excel) que aún no tienen su PDF adjunto."""
    uids = await _get_company_uids(user)
    pend = await db.consumos_subsidio.find(
        {**_own_q(user, uids),
         "$or": [{"factura_storage_key": {"$in": [None, ""]}}, {"factura_storage_key": {"$exists": False}}]},
        {"_id": 0, "id": 1, "numero_documento": 1, "placa": 1, "ruc_emisor": 1, "fecha": 1, "galones": 1, "origin": 1},
    ).sort("fecha", 1).to_list(2000)
    return {"pendientes": pend, "total": len(pend)}


@subsidio_router.post("/subsidio/carga-masiva/adjuntar-facturas")
async def subsidio_masiva_adjuntar(
    files: List[UploadFile] = File(...),
    user: dict = Depends(_require_subsidio),
):
    """Adjunta los PDF a los comprobantes ya cargados (Excel o a mano) que no tienen archivo.

    Acepta un PDF por factura O un solo PDF con varias facturas (una por página, o la
    misma repetida en páginas seguidas): se parte por página, se lee el QR de cada una
    (serie-número y RUC, norma SUNAT) y cada trozo se guarda como el PDF de su comprobante.
    Si una factura cubre varias placas, se engancha a todas.
    """
    if not files:
        raise HTTPException(status_code=400, detail="Sin archivos")
    if len(files) > 60:
        raise HTTPException(status_code=400, detail="Máximo 60 archivos por carga")
    uids = await _get_company_uids(user)
    adjuntadas, resultados = 0, []
    for f in files:
        content = await f.read()
        if len(content) > 40 * 1024 * 1024:
            resultados.append({"filename": f.filename, "ok": False, "error": "Archivo > 40MB"})
            continue
        if content[:4] != b"%PDF":
            resultados.append({"filename": f.filename, "ok": False, "error": "Solo se aceptan facturas en PDF"})
            continue
        r = await _enganchar_pdf(user, uids, content, f.filename or "factura.pdf")
        adjuntadas += r["adjuntadas"]
        for d in r["detalle"]:
            resultados.append({"filename": f.filename, **d})
    return {"adjuntadas": adjuntadas, "total": len(files), "resultados": resultados}


@subsidio_router.post("/subsidio/invoices/{invoice_id}/adjuntar-pdf")
async def subsidio_invoice_adjuntar_pdf(invoice_id: str, file: UploadFile = File(...), user: dict = Depends(_require_subsidio)):
    """Adjunta (o reemplaza) el PDF de UN comprobante desde 'Editar comprobante'. Si el PDF trae
    varias facturas, se usa solo la página cuyo QR coincide con este comprobante."""
    uids = await _get_company_uids(user)
    inv = await db.consumos_subsidio.find_one({"id": invoice_id, **_own_q(user, uids)}, {"_id": 0, "id": 1, "numero_documento": 1, "ruc_emisor": 1, "factura_storage_key": 1})
    if not inv:
        raise HTTPException(status_code=404, detail="Comprobante no encontrado")
    content = await file.read()
    if content[:4] != b"%PDF":
        raise HTTPException(status_code=400, detail="Solo se acepta PDF")
    if inv.get("factura_storage_key"):  # reemplazo: se libera el enganche actual
        await db.consumos_subsidio.update_one({"id": invoice_id}, {"$set": {"factura_storage_key": None, "factura_reemplazada_at": datetime.now(timezone.utc).isoformat()}})
    r = await _enganchar_pdf(user, uids, content, file.filename or "factura.pdf", solo_ids=[invoice_id])
    if not r["adjuntadas"]:
        raise HTTPException(status_code=422, detail={"message": "No se encontró en el PDF una página cuyo QR coincida con este comprobante", "detalle": r["detalle"]})
    return {"ok": True, **r}


@subsidio_router.post("/subsidio/padron-grifos/sync")
async def subsidio_sync_padron(user: dict = Depends(_require_subsidio)):
    """Descarga el padrón de grifos de OSINERGMIN (Datos Abiertos) y lo carga en la base."""
    from services.padron_grifos import sincronizar
    try:
        return await sincronizar(db)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"No se pudo sincronizar el padrón: {e}")


@subsidio_router.get("/subsidio/validation-state")
async def subsidio_validation_state(user: dict = Depends(_require_subsidio)):
    """
    Estado de validación de las facturas subidas por el cliente. Se usa para mostrar el
    aviso 'estamos validando tu información' en Combustible, Gestión de Gastos y Mi Flota
    mientras el equipo ENERED no haya validado (los KPIs salen en 0 hasta entonces).
    - uploaded: total de facturas que el cliente subió (cualquier estado)
    - confirmed: facturas ya validadas (status=confirmed → alimentan los KPIs)
    - pending_validation: subió facturas pero aún ninguna fue validada
    """
    uids = await _get_company_uids(user)
    # Total de facturas que el cliente subió (cualquier estado, incluido draft)
    uploaded = await db.consumos_subsidio.count_documents(_own_q(user, uids))
    # "visible" = facturas con datos REALES reconocidos que ya alimentan los KPIs.
    # Clave: una factura puede estar 'confirmed' pero con galones/importe en 0/null porque
    # el OCR no extrajo o ENERED aún no la validó — en ese caso los KPIs salen en 0 y el
    # aviso DEBE mostrarse. Por eso exigimos galones > 0 (dato real), no solo status.
    visible = await db.consumos_subsidio.count_documents({
        **_own_q(user, uids),
        "status": "confirmed",
        "origin": {"$ne": "admin_ocr"},
        "estacion": {"$ne": "ENERED"},
        "galones": {"$gt": 0},
    })
    fleet = 0
    empresa = user.get("empresa")
    if empresa:
        fleet = await db.consumptions.count_documents({"EMPRESA": empresa})
    # ¿el cliente ya empezó a cargar su expediente? (facturas, documentos o vehículos)
    docs = await db.subsidio_documents.count_documents(_own_q(user, uids))
    vehicles = await db.subsidio_vehicles.count_documents(_own_q(user, uids))
    started = uploaded > 0 or docs > 0 or vehicles > 0
    validated = visible > 0 or fleet > 0
    return {
        "uploaded": uploaded,        # facturas subidas (para el conteo del texto)
        "visible": visible,          # facturas ya visibles en Combustible/Gestión
        "docs": docs,
        "vehicles": vehicles,
        "has_uploads": started,
        "validated": validated,
        # Mostrar el aviso: el cliente ya cargó algo de su expediente pero nada está validado aún.
        "pending_validation": started and not validated,
    }


def _subsidio_key(user_id: str, category: str, placa: Optional[str], filename: str) -> str:
    safe = "".join(c for c in filename if c.isalnum() or c in ("-", "_", "."))[-80:]
    pid = f"{placa}-" if placa else ""
    return f"subsidio/{user_id}/{category}/{pid}{uuid.uuid4().hex[:8]}-{safe}"


@subsidio_router.get("/subsidio/dashboard")
async def subsidio_dashboard(user: dict = Depends(_require_subsidio)):
    """Devuelve toda la info para la pantalla de carga de documentos."""
    # Cálculo
    calc = await db.calculations.find_one({"id": user.get("calc_id")}, {"_id": 0}) or {}

    uids = await _get_company_uids(user)
    
    # Vehículos
    vehicles_dict = {}
    
    # Placas que el cliente quitó del expediente (la flota principal no se toca).
    _excl = await db.subsidio_vehicles_excluidos.find(
        _own_q(user, uids), {"_id": 0, "placa": 1}).to_list(500)
    excluidas = {e.get("placa") for e in _excl}

    # Traer primero los de la flota principal si hay empresa
    if user.get("empresa"):
        main_veh = await db.vehiculos.find({"empresa": user.get("empresa")}, {"_id": 0}).to_list(1000)
        for mv in main_veh:
            placa = (mv.get("placa") or mv.get("veh") or "").strip().upper()
            if not placa or placa in excluidas: continue
            vehicles_dict[placa] = {
                "id": mv.get("id", str(uuid.uuid4())),
                "placa": placa,
                "categoria": mv.get("categoria") or "N1",
                "user_id": mv.get("created_by") or user["id"],
                "from_main_fleet": True
            }
            
    # Traer los del modulo subsidio (sobreescriben si hay duplicados por placa)
    sub_veh = await db.subsidio_vehicles.find(_own_q(user, uids), {"_id": 0}).to_list(500)
    for sv in sub_veh:
        placa = (sv.get("placa") or "").strip().upper()
        if not placa: continue
        vehicles_dict[placa] = sv
        
    vehicles = list(vehicles_dict.values())

    # Documentos
    docs = await db.subsidio_documents.find(
        _own_q(user, uids), {"_id": 0}
    ).to_list(1000)
    docs = [_normalize_doc(d) for d in docs]

    # Cuenta bancaria + evidencia del CCI (voucher/captura que respalda la cuenta)
    bank = await db.subsidio_bank_accounts.find_one(
        _own_q(user, uids), {"_id": 0}, sort=[("updated_at", -1)]
    )
    evidencia_cci = [d for d in docs if d["categoria"] == "evidencia_cci"]

    # Construir checklist
    def files_for(cat, placa=None):
        return [d for d in docs if d["categoria"] == cat and d.get("placa") == placa]

    # Documentos que ENERED verifica en línea COMO APOYO. El cliente igual debe adjuntarlos.
    #   ficha_ruc               → SUNAT (activo y habido)
    #   resolucion_autorizacion → MTC (autorización de transporte vigente)
    ficha_ruc_sunat = await _sunat_ficha(user.get("ruc") or "")
    aut_mtc = await _mtc_autorizacion(user.get("ruc") or "")

    checklist = {"empresa": [], "flota": [], "combustible": []}
    for cat in EMPRESA_CATEGORIES:
        f = files_for(cat)
        if cat == "resolucion_autorizacion":
            ok = bool(aut_mtc and aut_mtc.get("habilitado"))
            checklist["empresa"].append({
                "categoria": cat, "label": DOCUMENT_LABELS[cat],
                "uploaded": bool(f), "files": f,
                "requiere_archivo": False,          # opcional: no bloquea la declaración jurada
                "opcional": True,
                "auto_validado": True,
                "validado": ok,
                "autorizacion": aut_mtc,
                "detalle": (
                    f"Autorización {aut_mtc.get('codigo') or ''} habilitada en el MTC · Vigente hasta {aut_mtc.get('vigencia')}."
                    if ok else
                    f"La autorización del MTC está vencida ({aut_mtc.get('vigencia')})."
                    if (aut_mtc and aut_mtc.get("vencida")) else
                    "No se encontró autorización de transporte en el MTC."
                    if (aut_mtc and not aut_mtc.get("encontrada")) else
                    "No se pudo verificar en el MTC en este momento."
                ),
            })
            continue
        if cat == "ficha_ruc":
            ok = bool(ficha_ruc_sunat and ficha_ruc_sunat["activo_habido"])
            checklist["empresa"].append({
                "categoria": cat, "label": DOCUMENT_LABELS[cat],
                "uploaded": bool(f), "files": f,   # el adjunto es obligatorio
                "requiere_archivo": True,
                "auto_validado": True,
                "validado": ok,
                "sunat": ficha_ruc_sunat,
                "detalle": (
                    "Este RUC no figura en SUNAT."
                    if (ficha_ruc_sunat or {}).get("no_encontrado") else
                    f"Verificado en SUNAT: {ficha_ruc_sunat['estado']} y {ficha_ruc_sunat['condicion']}."
                    if ficha_ruc_sunat else
                    "No se pudo verificar en SUNAT en este momento."
                ),
            })
            continue
        checklist["empresa"].append({
            "categoria": cat, "label": DOCUMENT_LABELS[cat],
            "uploaded": bool(f), "files": f,
        })
    # Tarjeta de habilitación: se verifica contra el MTC (constancia + vigencia) y además se adjunta.
    mtc_hab = await _mtc_habilitaciones(user.get("ruc") or "") if vehicles else None

    for v in vehicles:
        for cat in FLOTA_CATEGORIES:
            f = files_for(cat, v["placa"])
            if cat == "tarjeta_habilitacion":
                pn = (v["placa"] or "").replace("-", "").replace(" ", "").upper()
                h = (mtc_hab or {}).get(pn)
                ok = bool(h and h["habilitado"])
                checklist["flota"].append({
                    "categoria": cat, "placa": v["placa"],
                    "label": f"{DOCUMENT_LABELS[cat]} — Placa {v['placa']}",
                    "uploaded": bool(f), "files": f,   # el adjunto es obligatorio
                "requiere_archivo": True,
                    "auto_validado": True,
                    "validado": ok,
                    "mtc": h,
                    "detalle": (
                        f"Habilitada en el MTC · Constancia {h['constancia']} · Vigente hasta {h['vigencia']}."
                        if ok else
                        f"Autorización del MTC vencida ({h['vigencia']})." if (h and h.get("vencida")) else
                        "Esta placa no figura habilitada en el MTC." if mtc_hab is not None else
                        "No se pudo verificar en el MTC en este momento."
                    ),
                })
                continue
            checklist["flota"].append({
                "categoria": cat, "placa": v["placa"],
                "label": f"{DOCUMENT_LABELS[cat]} — Placa {v['placa']}",
                "uploaded": bool(f), "files": f,
            })
    for cat in COMBUSTIBLE_CATEGORIES:
        f = files_for(cat)
        checklist["combustible"].append({
            "categoria": cat, "label": DOCUMENT_LABELS[cat],
            "uploaded": bool(f), "files": f,
        })

    total_required = 3 + 2 * len(vehicles) + 2
    total_done = sum(1 for items in checklist.values() for it in items if it["uploaded"])
    pct = round((total_done / total_required) * 100) if total_required else 0

    # Faltan placas para subir flota
    can_finalize = (
        all(it["uploaded"] for it in checklist["empresa"])
        and len(vehicles) > 0
        and all(it["uploaded"] for it in checklist["flota"])
        and all(it["uploaded"] for it in checklist["combustible"])
        and bank is not None
    )

    # Conteos de facturas (drafts y confirmadas)
    invoices_draft = await db.consumos_subsidio.count_documents({**_own_q(user, uids), "status": "draft"})
    invoices_confirmed = await db.consumos_subsidio.count_documents({**_own_q(user, uids), "status": "confirmed"})
    
    # Calcular ahorro_reconocido real (galones confirmados * 4)
    ahorro_reconocido_real = 0
    if invoices_confirmed > 0:
        agg = await db.consumos_subsidio.aggregate([
            {"$match": {**_own_q(user, uids), "status": "confirmed"}},
            {"$group": {"_id": None, "total_gal": {"$sum": "$galones"}}}
        ]).to_list(1)
        if agg and agg[0].get("total_gal"):
            ahorro_reconocido_real = round(float(agg[0]["total_gal"]) * 4.0, 2)

    user_out = {k: v for k, v in user.items() if k not in ("password_hash", "_id")}
    # Representante legal registrado en SUNAT (ficha de la empresa) → declaración jurada
    try:
        cfg_rep = await db.empresas_config.find_one({"empresa": user.get("empresa")}, {"_id": 0, "representante_legal": 1, "ruc": 1})
        rep = (cfg_rep or {}).get("representante_legal")
        if not rep:
            ruc_e = ((cfg_rep or {}).get("ruc") or user.get("ruc") or "").strip()
            if ruc_e:
                cache = await db.representantes_ruc.find_one({"ruc": ruc_e}, {"_id": 0, "representantes": 1})
                reps = (cache or {}).get("representantes") or []
                rep = next((r for r in reps if "GERENTE" in r.get("cargo", "").upper() or "TITULAR" in r.get("cargo", "").upper()), reps[0] if reps else None)
        if rep:
            user_out["representante_legal"] = rep
    except Exception:
        pass
    return {
        "user": user_out,
        "calculation": calc,
        "ahorro_estimado": calc.get("subsidio_estimado", 0),
        "ahorro_reconocido": ahorro_reconocido_real,
        "vehicles": vehicles,
        "bank_account": bank,
        "evidencia_cci": evidencia_cci,
        "checklist": checklist,
        "progress": {"total_required": total_required, "total_done": total_done, "pct": pct},
        "can_finalize": can_finalize,
        "documentos_completos": bool(user.get("documentos_completos")),
        "invoices": {"draft": invoices_draft, "confirmed": invoices_confirmed},
        "declaracion": await db.subsidio_declaraciones.find_one(
            {"user_id": user["id"]}, {"_id": 0}
        ),
    }


# ============================================================================
# DECLARACIÓN JURADA
# ============================================================================
class DeclaracionPayload(BaseModel):
    accepted: bool
    representante: Optional[str] = None
    representante_dni: Optional[str] = None


@subsidio_router.post("/subsidio/declaracion")
async def aceptar_declaracion(
    payload: DeclaracionPayload,
    request: Request,
    user: dict = Depends(_require_subsidio),
):
    if not payload.accepted:
        raise HTTPException(status_code=400, detail="Debes marcar la casilla de aceptación")

    uids = await _get_company_uids(user)
    
    # Idempotente: si ya aceptó alguien de la empresa, devolver el registro existente
    existing = await db.subsidio_declaraciones.find_one(_own_q(user, uids), {"_id": 0})
    if existing:
        return {"ok": True, "declaracion": existing, "already": True}

    # Validar etapas 1, 2 y 3. Orden nuevo (Giuliana, 25/09/2026): la constancia y la DJ se
    # firman ANTES de "Enviar reporte" — el envío exige ambas firmas — así que aquí basta con
    # tener facturas cargadas (borrador o confirmadas). Antes exigía confirmadas y sin borradores,
    # lo que haría imposible firmar antes de enviar.
    cargadas = await db.consumos_subsidio.count_documents(
        {**_own_q(user, uids), "status": {"$in": ["draft", "confirmed"]}, "invalida": {"$ne": True}}
    )
    if cargadas == 0:
        raise HTTPException(status_code=400, detail="Debes cargar al menos una factura de combustible antes de firmar la declaración.")

    # Verificar docs empresa + flota subidos
    docs = await db.subsidio_documents.find(_own_q(user, uids), {"_id": 0}).to_list(1000)
    docs = [_normalize_doc(d) for d in docs]
    vehicles = await db.subsidio_vehicles.find(_own_q(user, uids), {"_id": 0}).to_list(200)
    docs_set = {(d["categoria"], d.get("placa")) for d in docs}
    # Todos los documentos deben estar adjuntos: la verificación en línea (SUNAT/MTC) es
    # un apoyo para el cliente, pero no reemplaza el archivo en el expediente.
    missing = []
    for cat in EMPRESA_CATEGORIES:
        if cat in EMPRESA_OPCIONALES:
            continue  # la autorización del MTC se verifica en línea; el archivo no es obligatorio
        if (cat, None) not in docs_set:
            missing.append(DOCUMENT_LABELS[cat])
    if len(vehicles) == 0:
        missing.append("Al menos una placa registrada")
    for v in vehicles:
        for cat in FLOTA_CATEGORIES:
            if (cat, v["placa"]) not in docs_set:
                missing.append(f"{DOCUMENT_LABELS[cat]} — {v['placa']}")
    if missing:
        raise HTTPException(status_code=400, detail={
            "message": "Faltan documentos antes de firmar la declaración",
            "missing": missing[:10],
        })

    record = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "empresa": user.get("empresa"),
        "ruc": user.get("ruc"),
        "representante": payload.representante or user.get("contacto") or user.get("name"),
        "representante_dni": (payload.representante_dni or "").strip() or None,
        "accepted_at": datetime.now(timezone.utc).isoformat(),
        "ip": (request.client.host if request.client else None),
        "user_agent": request.headers.get("user-agent", ""),
        "texto": (
            "Declaro bajo juramento que la información, documentos y comprobantes presentados "
            "para acceder al subsidio económico del Decreto de Urgencia N.° 004-2026 son verdaderos, "
            "exactos y corresponden a unidades con habilitación vigente. Reconozco que la presentación "
            "de información falsa, adulterada o inexacta genera la pérdida automática del subsidio, "
            "sin perjuicio de las responsabilidades administrativas, civiles y penales que correspondan."
        ),
    }
    await db.subsidio_declaraciones.insert_one(record)
    # Marcar expediente como enviado a la ATU para toda la empresa
    await db.users.update_many(
        {"id": {"$in": uids}},
        {"$set": {"expediente_status": "submitted", "documentos_completos": True,
                  "expediente_submitted_at": record["accepted_at"],
                  "expediente_stage": "solicitud_enviada",
                  "expediente_stage_updated_at": record["accepted_at"]}},
    )
    rec_out = {k: v for k, v in record.items() if k != "_id"}
    return {"ok": True, "declaracion": rec_out, "expediente_status": "submitted"}


async def _firmas_pendientes_por_decreto(user: dict, uids: list) -> dict:
    """Son DOS declaraciones juradas distintas: la del DU 004 (una sola) y la del DU 007 (una por
    periodo). Pendiente = tiene facturas cargadas (no nulas, no rechazadas) y no firmó."""
    q = _own_q(user, uids)
    du004_fact = await db.consumos_subsidio.count_documents(
        {**q, "programa": {"$ne": "du007"}, "status": {"$in": ["draft", "confirmed"]}, "invalida": {"$ne": True}})
    du004_firmada = bool(await db.subsidio_declaraciones.find_one(q, {"_id": 1}))
    rows = await db.consumos_subsidio.find(
        {**q, "programa": "du007", "invalida": {"$ne": True}, "validacion_estado": {"$ne": "RECHAZADA"}},
        {"_id": 0, "periodo_du007": 1}).to_list(5000)
    con_fact = sorted({r.get("periodo_du007") for r in rows if r.get("periodo_du007") in (1, 2, 3)})
    firmados = sorted({d.get("periodo") async for d in db.declaraciones_du007.find(q, {"_id": 0, "periodo": 1})})
    return {
        "du004": {"facturas": du004_fact, "firmada": du004_firmada, "pendiente": du004_fact > 0 and not du004_firmada},
        "du007": {"periodos_con_facturas": con_fact, "periodos_firmados": firmados,
                  "periodos_pendientes": [p for p in con_fact if p not in firmados]},
    }


@subsidio_router.get("/subsidio/firmas")
async def get_firmas(user: dict = Depends(_require_subsidio)):
    """Firmas del cliente: constancia + DJ DU 004 (candado de 'Enviar reporte') y, además, qué
    tiene pendiente en cada decreto (la DJ del DU 007 es OTRA, por periodo)."""
    uids = await _get_company_uids(user)
    f = await _firmas_para_enviar(user, uids)
    por_decreto = await _firmas_pendientes_por_decreto(user, uids)
    # `listo` y `pendientes` solo miran la constancia (obligatoria). Las DJ (du004/du007) se
    # informan para mostrarlas como recomendadas, pero no bloquean nada.
    tiene_facturas = por_decreto["du004"]["facturas"] > 0 or bool(por_decreto["du007"]["periodos_con_facturas"])
    return {**f, "listo": f["constancia"], **por_decreto, "tiene_facturas": tiene_facturas,
            "pendientes": (["constancia"] if not f["constancia"] else []),
            "dj_pendientes": (["du004"] if por_decreto["du004"]["pendiente"] else [])
                             + [f"du007_p{p}" for p in por_decreto["du007"]["periodos_pendientes"]]}


@subsidio_router.get("/subsidio/declaracion")
async def get_declaracion(user: dict = Depends(_require_subsidio)):
    uids = await _get_company_uids(user)
    rec = await db.subsidio_declaraciones.find_one(_own_q(user, uids), {"_id": 0}, sort=[("accepted_at", -1)])
    return {"declaracion": rec}


@subsidio_router.post("/subsidio/documents")
async def upload_document(
    file: UploadFile = File(...),
    categoria: str = Form(...),
    placa: Optional[str] = Form(None),
    user: dict = Depends(_require_subsidio),
):
    if categoria not in ALL_CATEGORIES:
        raise HTTPException(status_code=400, detail="Categoría inválida")
    if categoria in FLOTA_CATEGORIES and not placa:
        raise HTTPException(status_code=400, detail="Placa requerida para documentos de flota")

    placa_norm = placa.upper().strip() if placa else None
    if placa_norm:
        own = await db.subsidio_vehicles.find_one({"user_id": user["id"], "placa": placa_norm})
        if not own:
            raise HTTPException(status_code=400, detail="La placa no está registrada en tu flota")

    # Validate MIME per category
    content_type = (file.content_type or "application/octet-stream").lower()
    allowed = _allowed_mimes_for(categoria)
    if content_type not in allowed:
        nice = {
            frozenset(EMPRESA_MIME): "PDF",
            frozenset(FLOTA_MIME): "PDF, JPG o PNG",
        }.get(frozenset(allowed), "PDF, JPG o PNG")
        raise HTTPException(status_code=400, detail=f"Formato no permitido. Esta etapa solo acepta: {nice}")

    content = await file.read()
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Archivo demasiado grande (max 20MB)")

    key = _subsidio_key(user["id"], categoria, placa_norm, file.filename or "doc")
    storage.save_object(key, content, content_type)

    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "empresa": user.get("empresa"),
        "categoria": categoria,
        "category": categoria,
        "placa": placa_norm,
        "filename": file.filename,
        "storage_key": key,
        "content_type": content_type,
        "size": len(content),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "pendiente_validacion",
    }
    await db.subsidio_documents.insert_one(doc)
    return {"ok": True, "document": {k: v for k, v in doc.items() if k != "_id"}}


@subsidio_router.delete("/subsidio/documents/{doc_id}")
async def delete_document(doc_id: str, user: dict = Depends(_require_subsidio)):
    uids = await _get_company_uids(user)
    d = await db.subsidio_documents.find_one({"id": doc_id, **_own_q(user, uids)})
    if not d:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    try:
        storage.delete_object(d["storage_key"])
    except Exception as e:
        logger.warning(f"No se pudo borrar storage: {e}")
    await db.subsidio_documents.delete_one({"id": doc_id})
    return {"ok": True}


@subsidio_router.get("/subsidio/documents/{doc_id}/download")
async def download_document(doc_id: str, user: dict = Depends(_require_subsidio)):
    uids = await _get_company_uids(user)
    d = await db.subsidio_documents.find_one({"id": doc_id, **_own_q(user, uids)}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    return storage.download_response(d["storage_key"], d["filename"], d.get("content_type", "application/octet-stream"))


@subsidio_router.get("/subsidio/my-docs-summary")
async def my_docs_summary(user: dict = Depends(_require_subsidio)):
    """Resumen de documentos subidos en Mi Flota, listos para consumirse
    desde los módulos Vehículos y Documentación una vez desbloqueados.
    Retorna:
      - empresa: [{id, categoria, label, filename, uploaded_at, download_url}]
      - por_placa: { "ABC-123": [{...docs de esa placa...}], ... }
      - combustible: [{...docs comprobantes...}]
    """
    uids = await _get_company_uids(user)
    docs = await db.subsidio_documents.find(
        _own_q(user, uids), {"_id": 0, "storage_key": 0}
    ).sort("uploaded_at", -1).to_list(2000)

    empresa = []
    por_placa = {}
    combustible = []
    for d in docs:
        d = _normalize_doc(d)
        cat = d.get("categoria")
        item = {
            "id": d.get("id"),
            "categoria": cat,
            "label": DOCUMENT_LABELS.get(cat, cat),
            "filename": d.get("filename"),
            "content_type": d.get("content_type"),
            "size": d.get("size"),
            "placa": d.get("placa"),
            "uploaded_at": d.get("uploaded_at"),
            "download_url": f"/api/subsidio/documents/{d.get('id')}/download",
        }
        if cat in EMPRESA_CATEGORIES:
            empresa.append(item)
        elif cat in FLOTA_CATEGORIES:
            placa = (d.get("placa") or "").upper().strip()
            por_placa.setdefault(placa, []).append(item)
        elif cat in COMBUSTIBLE_CATEGORIES:
            combustible.append(item)

    return {
        "empresa": empresa,
        "por_placa": por_placa,
        "combustible": combustible,
        "total": len(docs),
    }



@subsidio_router.put("/subsidio/bank-account")
async def update_bank_account(payload: BankAccountIn, user: dict = Depends(_require_subsidio)):
    if not payload.es_banco_nacion and not payload.cci:
        raise HTTPException(status_code=400, detail="CCI obligatorio si no es Banco de la Nación")
    doc = payload.model_dump()
    uids = await _get_company_uids(user)
    doc["user_id"] = user["id"]
    doc["empresa"] = user.get("empresa")
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()
    # Find existing bank account for company or insert new
    existing = await db.subsidio_bank_accounts.find_one(_own_q(user, uids))
    if existing:
        await db.subsidio_bank_accounts.update_one({"user_id": existing["user_id"]}, {"$set": doc})
    else:
        await db.subsidio_bank_accounts.insert_one(doc)
    return {"ok": True, "bank_account": doc}


@subsidio_router.post("/subsidio/vehicles")
async def add_vehicle(payload: VehicleIn, user: dict = Depends(_require_subsidio)):
    placa = payload.placa.upper().strip()
    uids = await _get_company_uids(user)
    if await db.subsidio_vehicles.find_one({**_own_q(user, uids), "placa": placa}):
        raise HTTPException(status_code=409, detail="La placa ya está registrada en la empresa")
    # Si estaba excluida del expediente (se borró antes), re-agregarla la reactiva.
    await db.subsidio_vehicles_excluidos.delete_many({**_own_q(user, uids), "placa": placa})
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "empresa": user.get("empresa"),
        "placa": placa,
        "categoria": payload.categoria,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.subsidio_vehicles.insert_one(doc)
    
    # --- AUTO SYNC CON MODULO VEHICULOS ---
    existing_vehiculo = await db.vehiculos.find_one({"placa": placa})
    token = os.getenv("CONSULTADATOS_TOKEN", "").strip()
    if not existing_vehiculo and token:
        import urllib.request
        import json
        import ssl
        import asyncio

        placa_clean = placa.replace("-", "").upper()
        url = f"https://api2.consultadatos.com/api/placa/leyenda/{placa_clean}"
        
        marca = ""
        modelo = ""
        chasis = ""
        año = None
        titular = ""
        tipo = ""
        
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
                    
                    if props:
                        titular = props[0].get("propietario", "")
                    
                    try:
                        año_str = v.get("ano_fab") or v.get("an_mode")
                        if año_str:
                            año = int(año_str)
                    except:
                        pass
                        
                    marca = v.get("marca", "")
                    modelo = v.get("modelo", "")
                    chasis = v.get("no_vin") or v.get("num_serie", "")
                    tipo = v.get("desc_tipo_carr", "")
        except Exception:
            pass # Si falla SUNARP, registramos el vehiculo con datos en blanco
            
        vehiculo_doc = {
            "id": str(uuid.uuid4()),
            "placa": placa,
            "marca": marca,
            "modelo": modelo,
            "año": año,
            "chasis": chasis,
            "estado": "OPERATIVO",
            "unidad": "",
            "tipo": tipo,
            "base": "",
            "titular": titular,
            "cc": "",
            "conductor_principal_id": None,
            "empresa": user.get("empresa"),
            "kilometraje": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": user["id"],
        }
        await db.vehiculos.insert_one(vehiculo_doc)
    # --------------------------------------
    return {"ok": True, "vehicle": {k: v for k, v in doc.items() if k != "_id"}}


@subsidio_router.post("/subsidio/vehicles/importar-diagnostico")
async def importar_unidades_diagnostico(user: dict = Depends(_require_subsidio)):
    """Trae a la Etapa 2 las unidades que el diagnóstico (Etapa 0) encontró en el MTC
    para el RUC de la empresa, para que el cliente no las vuelva a escribir a mano.
    Es idempotente: las placas ya registradas se respetan (no se duplican ni se pisan)."""
    ruc = (user.get("ruc") or "").strip()
    if not _re.fullmatch(r"\d{11}", ruc):
        raise HTTPException(status_code=400, detail="La empresa no tiene un RUC válido registrado")

    try:
        import asyncio as _asyncio
        import mtc as _mtc
        m = await _asyncio.wait_for(_mtc.consultar("ruc", ruc), timeout=45)
    except Exception as e:
        logger.warning(f"Importar unidades del diagnóstico falló para RUC {ruc}: {e}")
        raise HTTPException(status_code=502,
                            detail="No pudimos consultar el MTC en este momento. Intenta de nuevo en un minuto.")

    # Un RUC puede tener varias autorizaciones con la MISMA placa repetida → dedup.
    # Solo entran las categorías que califican al subsidio (M2, M3, N1, N2, N3 y sus
    # variantes N2C2, M2C3…); remolques (O1…O4) y M1 se omiten para no confundir al cliente.
    from services.validador_facturas import clase_base_categoria as _clase_base
    encontradas, vistas, omitidas = [], set(), []
    for v in _mtc.unidades_para_subsidio(m):
        placa = (v.get("placa") or "").upper().strip()
        pn = placa.replace("-", "").replace(" ", "")
        if not pn or pn in vistas:
            continue
        vistas.add(pn)
        cat_raw = (v.get("categoria") or "").upper()
        cat = _clase_base(cat_raw)
        # Placas de un permiso que NO aplica al subsidio (MPW, PNT, PNW, CON, TRA, ESC) se omiten.
        if v.get("permiso_aplica") is False:
            omitidas.append({"placa": placa, "categoria": cat_raw or "—", "motivo": f"permiso {v.get('permiso')} no aplica"})
            continue
        if cat not in ("M2", "M3", "N1", "N2", "N3"):
            omitidas.append({"placa": placa, "categoria": cat_raw or "—"})
            continue
        encontradas.append({"placa": placa, "categoria": cat, "permiso": v.get("permiso") or ""})

    uids = await _get_company_uids(user)
    existentes = {
        (v.get("placa") or "").upper().replace("-", "").replace(" ", "")
        for v in await db.subsidio_vehicles.find(_own_q(user, uids), {"_id": 0, "placa": 1}).to_list(500)
    }

    nuevos = []
    for u in encontradas:
        if u["placa"].replace("-", "").replace(" ", "") in existentes:
            continue
        nuevos.append({
            "id": str(uuid.uuid4()),
            "user_id": user["id"],
            "empresa": user.get("empresa"),
            "placa": u["placa"],
            "categoria": u["categoria"],
            "origen": "diagnostico_mtc",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    if nuevos:
        await db.subsidio_vehicles.insert_many(nuevos)

    return {
        "ok": True,
        "encontradas": len(encontradas),
        "importadas": len(nuevos),
        "ya_registradas": len(encontradas) - len(nuevos),
        "placas": [n["placa"] for n in nuevos],
        "omitidas": len(omitidas),
        "omitidas_detalle": omitidas[:50],
        "nota": (f"{len(omitidas)} unidad(es) no aplican al subsidio (remolques o M1) y no se importaron: "
                 + ", ".join(f"{o['placa']} ({o['categoria']})" for o in omitidas[:8]) + ("…" if len(omitidas) > 8 else "")
                 if omitidas else ""),
    }


@subsidio_router.delete("/subsidio/vehicles/{placa}")
async def remove_vehicle(placa: str, user: dict = Depends(_require_subsidio)):
    placa_norm = placa.upper().strip()
    uids = await _get_company_uids(user)
    await db.subsidio_vehicles.delete_one({**_own_q(user, uids), "placa": placa_norm})
    # La placa puede venir "prestada" de la flota principal (db.vehiculos), que NO se
    # toca desde aquí (la usa el monitoreo). Se marca como excluida del expediente para
    # que el dashboard no la vuelva a mostrar; re-agregarla quita la exclusión.
    await db.subsidio_vehicles_excluidos.update_one(
        {"placa": placa_norm, **_own_q(user, uids)},
        {"$set": {"placa": placa_norm, "user_id": user["id"], "empresa": user.get("empresa"),
                  "excluded_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    # Borra docs de esa placa
    docs = await db.subsidio_documents.find(
        {**_own_q(user, uids), "placa": placa_norm}, {"_id": 0}
    ).to_list(100)
    for d in docs:
        try:
            storage.delete_object(d["storage_key"])
        except Exception:
            pass
    await db.subsidio_documents.delete_many({**_own_q(user, uids), "placa": placa_norm})
    return {"ok": True}


@subsidio_router.post("/subsidio/finalize")
async def finalize(user: dict = Depends(_require_subsidio)):
    """Marca el expediente como completado. Valida que todo esté presente."""
    # Re-construir el dashboard para verificar can_finalize
    uids = await _get_company_uids(user)
    vehicles = await db.subsidio_vehicles.find(_own_q(user, uids), {"_id": 0}).to_list(200)
    docs = await db.subsidio_documents.find(_own_q(user, uids), {"_id": 0}).to_list(1000)
    docs = [_normalize_doc(d) for d in docs]
    bank = await db.subsidio_bank_accounts.find_one(_own_q(user, uids), {"_id": 0})

    missing = []
    docs_set = {(d["categoria"], d.get("placa")) for d in docs}
    # Todos los documentos deben adjuntarse (la verificación en línea es solo apoyo).
    for cat in EMPRESA_CATEGORIES:
        if cat in EMPRESA_OPCIONALES:
            continue  # la autorización del MTC se verifica en línea; el archivo no es obligatorio
        if (cat, None) not in docs_set:
            missing.append(DOCUMENT_LABELS[cat])
    if not vehicles:
        missing.append("Al menos 1 vehículo registrado")
    for v in vehicles:
        for cat in FLOTA_CATEGORIES:
            if (cat, v["placa"]) not in docs_set:
                missing.append(f"{DOCUMENT_LABELS[cat]} — {v['placa']}")
    for cat in COMBUSTIBLE_CATEGORIES:
        if (cat, None) not in docs_set:
            missing.append(DOCUMENT_LABELS[cat])
    if not bank:
        missing.append("Cuenta bancaria para depósito")

    if missing:
        raise HTTPException(status_code=400, detail={"message": "Faltan documentos", "missing": missing})

    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {
            "documentos_completos": True,
            "expediente_status": "verifying",
            "documentos_completados_at": datetime.now(timezone.utc).isoformat(),
        }}
    )
    # Al terminar Mi Flota, desbloqueamos los módulos operativos:
    # Combustible, Cuenta, Vehículos y Documentación pasan a estar disponibles.
    # El resto (Analytics BI, Monitoreo, Calendario, etc.) siguen mostrando la vista Demo.
    empresa_name = user.get("empresa")
    if empresa_name:
        await db.empresas_config.update_one(
            {"empresa": empresa_name},
            {"$set": {
                "servicios.plataforma": True,
                "servicios.combustible": True,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }}
        )
    return {"ok": True}


# ============================================================================
# OCR de facturas — DU 004-2026
# ============================================================================
class InvoiceUpdateIn(BaseModel):
    fecha: Optional[str] = None
    hora: Optional[str] = None
    estacion: Optional[str] = None
    ciudad: Optional[str] = None
    placa: Optional[str] = None
    producto: Optional[str] = None
    galones: Optional[float] = None
    precio_unitario: Optional[float] = None
    importe_total: Optional[float] = None
    numero_documento: Optional[str] = None
    ruc_emisor: Optional[str] = None
    programa: Optional[str] = None
    # Campos del formulario de la ATU (editables por el cliente)
    serie: Optional[str] = None
    numero: Optional[str] = None
    categoria: Optional[str] = None
    departamento: Optional[str] = None
    provincia: Optional[str] = None
    distrito: Optional[str] = None
    direccion_grifo: Optional[str] = None
    tiene_nc: Optional[bool] = None
    serie_nc: Optional[str] = None
    numero_nc: Optional[str] = None
    alcance_nc: Optional[str] = None
    # Declarar factura como inválida (NO se borra, solo se marca con su motivo).
    invalida: Optional[bool] = None
    motivos_invalidez: Optional[List[str]] = None  # ej: ["tipo_combustible", "sin_placa"]
    motivo_invalidez_otros: Optional[str] = None


@subsidio_router.post("/subsidio/invoices/upload")
async def invoices_upload(
    files: List[UploadFile] = File(...),
    programa: str = Form("du004"),
    user: dict = Depends(_require_subsidio),
):
    """Recibe N facturas (imágenes o PDFs), las pasa por OCR Gemini Vision,
    guarda el archivo en storage y un draft en consumos_subsidio (status=draft).
    Devuelve la lista con los datos extraídos para verificación."""
    from services.pdf_invoice_reader import extract_invoice_data as _extract_pdf_text
    from services.invoice_ocr import extract_invoice_data as _extract_vision

    if not files:
        raise HTTPException(status_code=400, detail="Sin archivos")
    if len(files) > 60:
        raise HTTPException(status_code=400, detail="Máximo 60 facturas por carga")
    programa = programa if programa in ("du004", "du007") else "du004"

    # Cargar placas para auto-match — flota PRINCIPAL + subsidio_vehicles, de TODA la
    # empresa (no solo el user_id exacto de la sesión). Antes solo miraba subsidio_vehicles
    # del usuario que subía el archivo: una placa registrada en el módulo Vehículos (sin
    # duplicarla en Subsidio) o dada de alta por OTRO usuario de la misma empresa no se
    # encontraba, y la factura quedaba "no se pudo verificar la flota" → OBSERVADA aunque
    # la placa sí estuviera registrada.
    uids = await _get_company_uids(user)
    from services.validador_facturas import validar_factura as _validar
    _np = lambda p: _re.sub(r"[^A-Z0-9]", "", (p or "").upper())
    placas_norm, categoria_por_placa = await _flota_categorias(user, uids)
    # Facturas ya cargadas → detectar duplicados
    _previas = await db.consumos_subsidio.find(
        _own_q(user, uids), {"_id": 0, "ruc_emisor": 1, "numero_documento": 1}
    ).to_list(2000)
    _npl = lambda x: _re.sub(r"[^A-Z0-9]", "", (x or "").upper())
    numeros_existentes = {
        (str(p.get("ruc_emisor") or "").strip(), str(p.get("numero_documento") or "").strip().upper(),
         _npl(p.get("placa")))
        for p in _previas if p.get("numero_documento")
    }

    results = []
    for f in files:
        content = await f.read()
        if len(content) > 20 * 1024 * 1024:
            results.append({"filename": f.filename, "ok": False, "error": "Archivo > 20MB"})
            continue
        content_type = f.content_type or "application/octet-stream"
        # Las facturas de combustible SOLO se aceptan en PDF (el QR/XML del PDF es la fuente exacta).
        # Las fotos del celular llegan ya convertidas a PDF por la captura móvil (ver captura_fotos).
        if not (content_type in COMBUSTIBLE_MIME or content[:4] == b"%PDF"):
            results.append({"filename": f.filename, "ok": False,
                            "error": "Solo se aceptan facturas en PDF"})
            continue
        content_type = "application/pdf"

        # Save raw file
        key = _subsidio_key(user["id"], "factura_subsidio", None, f.filename or "factura")
        storage.save_object(key, content, content_type)

        # OCR — motor según formato: PDF con texto usa el parser; imágenes/escaneos usan Gemini Vision
        ct = (content_type or "").lower()
        is_pdf = "pdf" in ct or content[:4] == b"%PDF"
        _sid = f"ocr-{user['id']}-{uuid.uuid4().hex[:6]}"
        # 1) QR / XML: fuente EXACTA (norma SUNAT). Da serie, número, fecha, RUC del grifo,
        #    IGV y total sin depender del OCR; el XML además da los galones.
        from services.extractor_comprobante import extraer as _extraer_comprobante
        try:
            base = _extraer_comprobante(content, f.filename or "")
        except Exception as _e:
            logger.warning(f"Extracción QR/XML falló en {f.filename}: {_e}")
            base = {}

        ocr_error_code, ocr_retry_after = None, None
        try:
            if is_pdf:
                ocr = await _extract_pdf_text(content, content_type, session_id=_sid)
                _ex = ocr.get("extracted") or {}
                # PDF escaneado (sin texto extraíble) → reintenta con visión
                if not any(_ex.get(k) for k in ("placa", "importe_total", "galones", "numero_documento")):
                    try:
                        ocr = await _extract_vision(content, content_type, session_id=_sid)
                    except Exception:
                        pass
            else:
                # Imágenes (JPG/PNG/WEBP/HEIC…) → Gemini Vision
                ocr = await _extract_vision(content, content_type, session_id=_sid)
            extracted = ocr["extracted"]
            raw_resp = ocr["raw_response"]
            ocr_error_code = ocr.get("error_code")
            ocr_retry_after = ocr.get("retry_after")
            ocr_ok = True
            ocr_error = None
            # El motor de visión no lanza: si devolvió vacío y reporta el fallo en raw_response,
            # lo registramos como error para que el admin vea POR QUÉ no se leyó nada.
            _prov_err = str(raw_resp or "").strip()
            if not any(extracted.get(k) for k in ("numero_documento", "galones", "importe_total", "placa")) \
                    and _prov_err[:8].lower() in ("claude: ", "gemini: ", "legacy: "):
                ocr_ok, ocr_error = False, ocr.get("error_message") or _prov_err[:200]
        except Exception as e:
            logger.warning(f"OCR error en {f.filename}: {e}")
            extracted, raw_resp, ocr_ok, ocr_error = {}, "", False, str(e)[:200]

        # El dato del QR/XML manda sobre el del OCR (es exacto, no inferido).
        if base:
            for _k_ocr, _k_base in (("numero_documento", "numero_documento"), ("fecha", "fecha"),
                                    ("ruc_emisor", "ruc_emisor"), ("importe_total", "importe_total"),
                                    ("galones", "galones"), ("producto", "producto"),
                                    ("placa", "placa"), ("precio_unitario", "precio_unitario")):
                if base.get(_k_base) not in (None, ""):
                    extracted[_k_ocr] = base[_k_base]
            if base.get("razon_social_emisor") and not extracted.get("estacion"):
                extracted["estacion"] = base["razon_social_emisor"]
            ocr_ok = ocr_ok or bool(base.get("extraccion_ok"))

        # 2) Datos del grifo desde OSINERGMIN con el RUC del emisor (lo que exige la ATU).
        _grifo = None
        if extracted.get("ruc_emisor"):
            try:
                _grifo = await _grifo_por_ruc(extracted["ruc_emisor"],
                                              extracted.get("estacion") or base.get("razon_social_emisor"))
                if _grifo and _grifo.get("inscrito"):
                    # La razón social del padrón OSINERGMIN/SUNAT es exacta; lo que el OCR pone en
                    # "estacion" muchas veces es la DIRECCIÓN impresa del grifo ("CARRETERA
                    # PANAMERICANA NORTE…"). Se guarda lo del OCR aparte y manda el padrón.
                    _rs = (_grifo.get("razon_social_sunat") or _grifo.get("razon_social") or "").strip()
                    if _rs:
                        if extracted.get("estacion") and extracted["estacion"] != _rs:
                            extracted["estacion_ocr"] = extracted["estacion"]
                        extracted["estacion"] = _rs
                    if not extracted.get("ciudad"):
                        extracted["ciudad"] = _grifo.get("distrito")
            except Exception:
                pass

        # Una factura con VARIAS placas de diésel se registra como una fila por placa, cada una
        # con sus galones/importe (la serie se repite; el duplicado se controla por número+placa).
        _extracted_base = dict(extracted)
        for _var in _variantes_por_placa(_extracted_base):
          extracted = {**_extracted_base, **_var}
          if not _var and extracted.get("importe_diesel") and extracted.get("items") \
                  and any(not it.get("es_diesel") for it in extracted["items"] if it.get("producto")):
              # Gasohol + diésel en la misma factura: el importe del consumo es el de la línea de diésel.
              extracted["importe_total"] = extracted["importe_diesel"]

          # Auto-match con flota del usuario
          placa_match = None
          if extracted.get("placa") and _np(extracted["placa"]) in placas_norm:
              placa_match = extracted["placa"]

          doc = {
              "id": str(uuid.uuid4()),
              "user_id": user["id"],
              "empresa": user.get("empresa"),
              "empresa_id": user.get("empresa"),
              "calc_id": user.get("calc_id"),
              "factura_filename": f.filename,
              "factura_storage_key": key,
              "factura_content_type": content_type,
              "factura_size": len(content),
              "raw_ocr_response": raw_resp,
              "ocr_ok": ocr_ok,
              "ocr_error": ocr_error,
              "ocr_error_code": ocr_error_code if not ocr_ok else None,
              "ocr_retry_after": ocr_retry_after if not ocr_ok else None,
              "placa_match": placa_match,  # placa que coincide con flota, si la hubo
              "status": "draft",  # draft → confirmed
              "created_at": datetime.now(timezone.utc).isoformat(),
              "confirmed_at": None,
              # Campos OCR
              "fecha": extracted.get("fecha"),
              "hora": extracted.get("hora"),
              "estacion": extracted.get("estacion"),
              "ciudad": normalize_city(extracted.get("ciudad")),
              "ruc_emisor": extracted.get("ruc_emisor"),
              "placa": extracted.get("placa"),
              "producto": extracted.get("producto"),
              "galones": extracted.get("galones"),
              "precio_unitario": extracted.get("precio_unitario"),
              "importe_total": extracted.get("importe_total"),
              "numero_documento": extracted.get("numero_documento"),
              "confianza": extracted.get("confianza", 0.0),
              # Datos del grifo (OSINERGMIN) y trazabilidad de la extracción — los pide la ATU.
              "serie": base.get("serie"), "numero": base.get("numero"),
              "departamento": (_grifo or {}).get("departamento"),
              "provincia": (_grifo or {}).get("provincia"),
              "distrito": (_grifo or {}).get("distrito"),
              "direccion_grifo": (_grifo or {}).get("direccion"),
              "grifo_inscrito": bool((_grifo or {}).get("inscrito")),
              "fuentes": base.get("fuentes") or {},
              "origin": "individual",
              "programa": programa,   # du004 | du007 — cada subsidio lleva su propio bucket
              "items_ocr": extracted.get("items") or [],
          }
          _completar_precio(doc)

          # ── Validación automática contra las reglas del decreto correspondiente
          try:
              _val = _validar(doc, placas_flota=placas_norm,
                              categoria_por_placa=categoria_por_placa,
                              numeros_existentes=numeros_existentes,
                              programa=programa)
              doc["validacion"] = _val
              doc["validacion_estado"] = _val["estado"]          # CONFORME | OBSERVADA | RECHAZADA
              doc["requiere_revision"] = _val["requiere_revision"]
              if programa == "du007":
                  doc["periodo_du007"] = _val.get("periodo_du007")
              # Evita que dos archivos de la MISMA carga se dupliquen entre sí.
              if doc.get("numero_documento"):
                  numeros_existentes.add((str(doc.get("ruc_emisor") or "").strip(),
                                          str(doc["numero_documento"]).strip().upper(),
                                          _npl(doc.get("placa"))))
          except Exception as _e:
              logger.warning(f"Validación automática falló en {f.filename}: {_e}")
              doc["validacion_estado"] = "OBSERVADA"
              doc["requiere_revision"] = True
          await db.consumos_subsidio.insert_one(doc)
          results.append({
              "id": doc["id"],
              "filename": f.filename,
              "ok": ocr_ok,
              "error": ocr_error,
              "data": {k: v for k, v in doc.items() if k != "_id" and k != "raw_ocr_response"},
          })

    # Mark expediente as verifying — en el campo del programa correspondiente, para no
    # pisar el estado del otro decreto (antes subir una factura del DU 007 marcaba
    # "verifying" el expediente del DU 004 del mismo cliente, y viceversa).
    campo_status_up = "expediente_status_du007" if programa == "du007" else "expediente_status"
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {campo_status_up: "verifying"}},
    )
    return {"uploaded": len(results), "items": results}


@subsidio_router.get("/subsidio/invoices/preview")
async def invoices_preview(programa: str = "du004", user: dict = Depends(_require_subsidio)):
    """Devuelve facturas en draft (pendientes de confirmar) del usuario, por programa."""
    uids = await _get_company_uids(user)
    # Las filas antiguas no tienen campo "programa": cuentan como du004.
    filtro_prog = {"programa": "du007"} if programa == "du007" else {"programa": {"$ne": "du007"}}
    rows = await db.consumos_subsidio.find(
        {**_own_q(user, uids), "status": "draft", **filtro_prog},
        {"_id": 0, "raw_ocr_response": 0, "factura_storage_key": 0},
    ).sort("created_at", -1).to_list(500)
    # Placas registradas para mostrar dropdown de corrección
    vehicles = await db.subsidio_vehicles.find(
        _own_q(user, uids), {"_id": 0, "placa": 1, "categoria": 1}
    ).to_list(200)
    for _r in rows:
        _completar_precio(_r)
    return {"items": rows, "vehicles": vehicles}


@subsidio_router.get("/subsidio/invoices/{invoice_id}/file")
async def invoice_file(invoice_id: str, user: dict = Depends(_require_subsidio)):
    """Sirve el PDF/imagen original de una factura del propio cliente, inline,
    para previsualizarla al costado del formulario de edición."""
    uids = await _get_company_uids(user)
    d = await db.consumos_subsidio.find_one(
        {"id": invoice_id, **_own_q(user, uids)},
        {"_id": 0, "factura_storage_key": 1, "factura_filename": 1, "factura_content_type": 1},
    )
    if not d:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    key = d.get("factura_storage_key")
    if not key:
        raise HTTPException(status_code=404, detail="Este comprobante no tiene archivo adjunto")
    return storage.download_response(
        key, d.get("factura_filename") or "factura.pdf",
        d.get("factura_content_type") or "application/pdf",
    )


@subsidio_router.put("/subsidio/invoices/{invoice_id}")
async def invoices_update(
    invoice_id: str,
    payload: InvoiceUpdateIn,
    user: dict = Depends(_require_subsidio),
):
    uids = await _get_company_uids(user)
    inv = await db.consumos_subsidio.find_one(
        {"id": invoice_id, **_own_q(user, uids)}, {"_id": 0}
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    patch = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None}
    if "placa" in patch and patch["placa"]:
        patch["placa"] = patch["placa"].upper().strip()
    if patch.get("serie") and patch.get("numero"):
        patch["numero_documento"] = f"{patch['serie'].upper()}-{patch['numero']}"
    patch["updated_at"] = datetime.now(timezone.utc).isoformat()

    # Si cambió el RUC del grifo (o la factura no tiene estación), completar grifo desde OSINERGMIN.
    ruc_nuevo = str(patch.get("ruc_emisor") or inv.get("ruc_emisor") or "").strip()
    cambio_ruc = bool(patch.get("ruc_emisor")) and patch["ruc_emisor"] != inv.get("ruc_emisor")
    if _re.fullmatch(r"\d{11}", ruc_nuevo) and (cambio_ruc or not (patch.get("estacion") or inv.get("estacion"))):
        try:
            g = await _grifo_por_ruc(ruc_nuevo, patch.get("estacion") or inv.get("estacion"))
            if g and g.get("inscrito"):
                if cambio_ruc or not (patch.get("estacion") or inv.get("estacion")):
                    patch["estacion"] = g.get("razon_social") or patch.get("estacion") or inv.get("estacion")
                for k_dest, k_src in (("departamento", "departamento"), ("provincia", "provincia"),
                                      ("distrito", "distrito"), ("direccion_grifo", "direccion")):
                    if g.get(k_src) and (cambio_ruc or not inv.get(k_dest)):
                        patch[k_dest] = g[k_src]
                if cambio_ruc and not patch.get("ciudad") and g.get("distrito"):
                    patch["ciudad"] = g["distrito"]
                patch["grifo_inscrito"] = True
            elif cambio_ruc:
                patch["grifo_inscrito"] = False
        except Exception as _e:
            logger.warning(f"Padrón de grifos al editar factura falló: {_e}")

    # Revalidar con los datos corregidos, para que el estado se actualice al instante.
    try:
        from services.validador_facturas import validar_factura as _validar_upd
        futuro = {**inv, **patch}
        placas, cats = await _flota_categorias(user, uids)
        _npu = lambda x: _re.sub(r"[^A-Z0-9]", "", (x or "").upper())
        otras = await db.consumos_subsidio.find(
            {**_own_q(user, uids), "id": {"$ne": invoice_id}},
            {"_id": 0, "ruc_emisor": 1, "numero_documento": 1, "placa": 1}).to_list(3000)
        vistos = {(str(o.get("ruc_emisor") or "").strip(),
                   str(o.get("numero_documento") or "").strip().upper(), _npu(o.get("placa")))
                  for o in otras if o.get("numero_documento")}
        _v = _validar_upd(futuro, placas_flota=placas, categoria_por_placa=cats, numeros_existentes=vistos,
                          programa=inv.get("programa") or "du004")
        patch["validacion"] = _v
        patch["validacion_estado"] = _v["estado"]
        patch["requiere_revision"] = _v["requiere_revision"]
        if (inv.get("programa") or "du004") == "du007":
            patch["periodo_du007"] = _v.get("periodo_du007")
    except Exception as _e:
        logger.warning(f"Revalidación tras editar falló: {_e}")

    await db.consumos_subsidio.update_one({"id": invoice_id}, {"$set": patch})
    updated = await db.consumos_subsidio.find_one(
        {"id": invoice_id},
        {"_id": 0, "raw_ocr_response": 0, "factura_storage_key": 0},
    )
    return {"ok": True, "item": updated}


@subsidio_router.delete("/subsidio/invoices/{invoice_id}")
async def invoices_delete(invoice_id: str, user: dict = Depends(_require_subsidio)):
    uids = await _get_company_uids(user)
    inv = await db.consumos_subsidio.find_one({"id": invoice_id, **_own_q(user, uids)})
    if not inv:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    try:
        storage.delete_object(inv["factura_storage_key"])
    except Exception:
        pass
    
    # Delete from db.invoices if it was confirmed
    n_doc = (inv.get("numero_documento") or "").upper().strip()
    empresa = inv.get("empresa") or user.get("empresa") or ""
    if n_doc:
        await db.invoices.delete_one({"empresa": empresa, "n_doc": n_doc})

    await db.consumos_subsidio.delete_one({"id": invoice_id})
    return {"ok": True}


async def _firmas_para_enviar(user: dict, uids: list) -> dict:
    """Estado de las dos firmas que exige 'Enviar reporte': la Constancia de términos del servicio
    (por usuario, versión vigente) y la Declaración jurada de veracidad (por empresa)."""
    from server import CONSTANCIA_VERSION as _CV
    constancia = (user.get("constancia_aceptada") or {}).get("version") == _CV
    if not constancia and user.get("id"):
        # el objeto `user` puede venir del contexto de impersonación/empresa: releer al usuario real
        _u = await db.users.find_one({"id": user["id"]}, {"_id": 0, "constancia_aceptada": 1})
        constancia = ((_u or {}).get("constancia_aceptada") or {}).get("version") == _CV
    declaracion = bool(await db.subsidio_declaraciones.find_one(_own_q(user, uids), {"_id": 1}))
    return {"constancia": constancia, "declaracion": declaracion}


@subsidio_router.post("/subsidio/invoices/confirm")
async def invoices_confirm(user: dict = Depends(_require_subsidio)):
    """Confirma TODAS las facturas en draft del usuario → status=confirmed.
    Crea las facturas correspondientes en db.invoices y marca expediente_status=confirmed.
    Candado (Giuliana, 25/09/2026): NO se envía el reporte sin la Constancia de términos del
    servicio aceptada y la Declaración jurada de veracidad firmada — si algo sale mal ante la
    ATU, la responsabilidad quedó declarada por el cliente. El admin que impersona no está
    sujeto (actúa a sabiendas)."""
    now = datetime.now(timezone.utc).isoformat()
    uids = await _get_company_uids(user)
    # Giuliana (25/09/2026): lo que protege a ENERED es la CONSTANCIA de términos del servicio
    # (ENERGIX); la declaración jurada de veracidad es opcional y no bloquea el envío.
    if not user.get("_admin_id"):
        firmas = await _firmas_para_enviar(user, uids)
        if not firmas["constancia"]:
            raise HTTPException(status_code=409, detail={
                "codigo": "firmas_pendientes", **firmas,
                "message": "Antes de enviar tu reporte debes aceptar la Constancia de términos del servicio.",
            })
    drafts = await db.consumos_subsidio.find({**_own_q(user, uids), "status": "draft"}).to_list(1000)

    for d in drafts:
        fecha_str = d.get("fecha") or datetime.now(timezone.utc).date().isoformat()
        if len(fecha_str) > 10:
            fecha_str = fecha_str[:10]
        f_venc = fecha_str
        try:
            f_dt = datetime.strptime(fecha_str, "%Y-%m-%d")
            f_venc = (f_dt + timedelta(days=30)).date().isoformat()
        except Exception:
            try:
                f_dt = datetime.strptime(fecha_str, "%d/%m/%Y")
                fecha_str = f_dt.date().isoformat()
                f_venc = (f_dt + timedelta(days=30)).date().isoformat()
            except Exception:
                pass

        n_doc = (d.get("numero_documento") or "").upper().strip()
        empresa = d.get("empresa") or user.get("empresa") or ""
        if n_doc:
            existing = await db.invoices.find_one({"empresa": empresa, "n_doc": n_doc})
            if not existing:
                inv_doc = {
                    "id": d.get("id") or str(uuid.uuid4()),
                    "empresa": empresa,
                    "n_doc": n_doc,
                    "tipo_doc": "factura",
                    "producto": d.get("producto") or "DIESEL B5 S-50",
                    "f_emision": fecha_str,
                    "f_vencimiento": f_venc,
                    "moneda": "PEN",
                    "monto_total": float(d.get("importe_total") or 0.0),
                    "saldo": float(d.get("importe_total") or 0.0),
                    "estado": "pendiente",
                    "atraso_dias": 0,
                    "pdf_filename": d.get("factura_filename") or d.get("pdf_filename"),
                    "factura_storage_key": d.get("factura_storage_key"),
                    "factura_filename": d.get("factura_filename"),
                    "factura_content_type": d.get("factura_content_type"),
                    "xml_filename": None,
                    "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    "uploaded_by": user["email"],
                    "created_via": "subsidio_confirm",
                }
                await db.invoices.insert_one(inv_doc)

    res = await db.consumos_subsidio.update_many(
        {"user_id": user["id"], "status": "draft"},
        {"$set": {"status": "confirmed", "confirmed_at": now}},
    )
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"expediente_status": "confirmed"}},
    )
    return {"ok": True, "confirmed": res.modified_count}


def _combustible_to_subsidio(r: dict) -> dict:
    try:
        gal = float(r.get("CANTIDAD_GL") or 0)
    except Exception:
        gal = 0.0
    try:
        imp = float(r.get("IMPORTE_TOTAL") or 0)
    except Exception:
        imp = 0.0

    return {
        "id": r.get("id") or str(uuid.uuid4()),
        "fecha": r.get("FECHA") or "",
        "hora": r.get("HORA") or "",
        "placa": r.get("PLACA") or "",
        "ciudad": r.get("CIUDAD") or "",
        "estacion": r.get("ESTACION") or "",
        "producto": r.get("PRODUCTO") or "",
        "galones": gal,
        "precio_unitario": r.get("PRECIO_UNITARIO") or 0,
        "importe_total": imp,
        "ruc_emisor": r.get("RUC_EMISOR") or "",
        "numero_documento": r.get("NUMERO_DOCUMENTO") or "",
        "estado": "Confirmado (Combustible)",
        "_origen": "combustible"
    }

# ============================================================
# Captura desde el celular (QR): el cliente escanea un QR en la PC, abre una página
# móvil SIN login (el enlace temporal lo autoriza), toma fotos de sus facturas y
# entran al MISMO pipeline de OCR/validación que la carga normal, como borradores.
# ============================================================
CAPTURA_TTL_MIN = 20


def _ahora_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _captura_valida(token: str) -> dict:
    c = await db.capturas_movil.find_one({"token": token}, {"_id": 0})
    if not c:
        raise HTTPException(status_code=404, detail="Enlace de captura no válido")
    if c.get("estado") != "abierta" or str(c.get("expires_at") or "") < _ahora_iso():
        raise HTTPException(status_code=410, detail="Este enlace ya venció. Genera un QR nuevo desde la computadora.")
    return c


@subsidio_router.post("/subsidio/captura/sesion")
async def captura_crear(payload: Optional[dict] = None, user: dict = Depends(_require_subsidio)):
    """Crea un enlace temporal de captura (para el QR) ligado a la empresa activa y al decreto."""
    import secrets as _sec
    from datetime import timedelta as _td
    programa = (payload or {}).get("programa") or "du004"
    programa = programa if programa in ("du004", "du007") else "du004"
    token = _sec.token_urlsafe(6)
    now = datetime.now(timezone.utc)
    doc = {"token": token, "user_id": user["id"], "empresa": user.get("empresa"), "programa": programa,
           "created_at": now.isoformat(), "expires_at": (now + _td(minutes=CAPTURA_TTL_MIN)).isoformat(),
           "estado": "abierta", "recibidas": 0, "items": []}
    await db.capturas_movil.insert_one(doc)
    return {"token": token, "programa": programa, "expires_at": doc["expires_at"], "ttl_min": CAPTURA_TTL_MIN}


@subsidio_router.get("/captura/{token}")
async def captura_info(token: str):
    """Público: datos mínimos para la página móvil (sin exponer nada sensible)."""
    c = await _captura_valida(token)
    return {"ok": True, "empresa": c.get("empresa"), "programa": c.get("programa"),
            "expires_at": c.get("expires_at"), "recibidas": c.get("recibidas", 0)}


def _variantes_por_placa(extracted: dict) -> list:
    """Si el OCR leyó varias líneas de diésel con placas distintas, devuelve una variante
    (placa, galones, precio, importe, producto) por placa; si no, una sola variante vacía."""
    items = [it for it in (extracted.get("items") or []) if isinstance(it, dict) and it.get("es_diesel") and it.get("galones")]
    por_placa = {}
    for it in items:
        pl = it.get("placa")
        if not pl:
            return [{}]          # alguna línea sin placa: no podemos repartir con certeza
        agg = por_placa.setdefault(pl, {"placa": pl, "galones": 0.0, "importe_total": 0.0, "precio_unitario": it.get("precio_unitario"), "producto": it.get("producto"), "_imp_ok": True})
        agg["galones"] += float(it["galones"])
        if it.get("importe") is None:
            agg["_imp_ok"] = False
        else:
            agg["importe_total"] += float(it["importe"])
    if len(por_placa) < 2:
        return [{}]
    out = []
    for agg in por_placa.values():
        v = {"placa": agg["placa"], "galones": round(agg["galones"], 3), "producto": agg["producto"], "precio_unitario": agg["precio_unitario"]}
        if agg["_imp_ok"]:
            v["importe_total"] = round(agg["importe_total"], 2)
        elif agg["precio_unitario"]:
            v["importe_total"] = round(agg["galones"] * agg["precio_unitario"], 2)
        out.append(v)
    return out


async def _foto_a_pdf(f: UploadFile) -> UploadFile:
    """Si el archivo es una imagen (JPG/PNG/WEBP/HEIC…), la envuelve en un PDF de una página con la
    imagen a tamaño completo. Si ya es PDF u otra cosa, lo devuelve tal cual."""
    import io as _io
    from starlette.datastructures import UploadFile as _UF, Headers as _H
    content = await f.read()
    if content[:4] == b"%PDF":
        return _UF(file=_io.BytesIO(content), filename=f.filename, headers=_H({"content-type": "application/pdf"}))
    try:
        from PIL import Image as _Img, ImageOps as _Ops
        img = _Img.open(_io.BytesIO(content))
        img = _Ops.exif_transpose(img).convert("RGB")   # respeta la orientación de la cámara
        buf = _io.BytesIO()
        img.save(buf, format="PDF", resolution=150.0)
        nombre = (f.filename or "foto").rsplit(".", 1)[0] + ".pdf"
        return _UF(file=_io.BytesIO(buf.getvalue()), filename=nombre, headers=_H({"content-type": "application/pdf"}))
    except Exception as _e:
        logger.warning(f"No se pudo convertir la foto a PDF ({f.filename}): {_e}")
        return _UF(file=_io.BytesIO(content), filename=f.filename, headers=_H({"content-type": f.content_type or "application/octet-stream"}))


@subsidio_router.post("/captura/{token}/fotos")
async def captura_fotos(token: str, files: List[UploadFile] = File(...)):
    """Público: recibe las fotos tomadas desde el celular y las procesa en nombre del
    cliente dueño del enlace, con el mismo OCR y validador de la carga normal."""
    c = await _captura_valida(token)
    if not files:
        raise HTTPException(status_code=400, detail="Sin fotos")
    if len(files) > 20:
        raise HTTPException(status_code=400, detail="Máximo 20 fotos por envío")
    u = await db.users.find_one({"id": c["user_id"]}, {"_id": 0, "password_hash": 0})
    if not u:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    u = await _heredar_ruc(u)
    if c.get("empresa"):
        u = {**u, "empresa": c["empresa"]}   # respeta la empresa activa al generar el QR
    # Cada FOTO se convierte a un PDF de una página (la plataforma trabaja solo con PDF: visor,
    # ZIP para la ATU, lector de QR). El pipeline luego lee el QR de SUNAT impreso y, si hace
    # falta, usa visión sobre la página.
    files = [await _foto_a_pdf(f) for f in files]
    res = await invoices_upload(files=files, programa=c.get("programa") or "du004", user=u)
    items = []
    for r in res.get("items", []):
        d = r.get("data") or {}
        items.append({"id": r.get("id"), "archivo": r.get("filename"), "ok": bool(r.get("ok")),
                      "guardada": bool(r.get("id")), "error": r.get("error"),
                      "error_code": d.get("ocr_error_code"),
                      "numero": d.get("numero_documento"), "placa": d.get("placa"),
                      "galones": d.get("galones"), "importe": d.get("importe_total"),
                      "estado": d.get("validacion_estado"), "fecha": d.get("fecha"),
                      "recibida_at": _ahora_iso()})
    await db.capturas_movil.update_one(
        {"token": token},
        {"$inc": {"recibidas": len(items)}, "$push": {"items": {"$each": items}}, "$set": {"ultima_at": _ahora_iso()}})
    return {"ok": True, "procesadas": len(items), "items": items}


@subsidio_router.get("/subsidio/captura/{token}/estado")
async def captura_estado(token: str, user: dict = Depends(_require_subsidio)):
    """La PC consulta cuántas fotos llegaron y qué se leyó (para refrescar su lista)."""
    c = await db.capturas_movil.find_one({"token": token}, {"_id": 0})
    if not c:
        raise HTTPException(status_code=404, detail="Enlace no válido")
    uids = await _get_company_uids(user)
    if c.get("user_id") not in uids:
        raise HTTPException(status_code=403, detail="Este enlace no es de tu empresa")
    vencido = str(c.get("expires_at") or "") < _ahora_iso()
    return {"recibidas": c.get("recibidas", 0), "items": c.get("items", []), "estado": c.get("estado"),
            "expires_at": c.get("expires_at"), "vencido": vencido}


@subsidio_router.post("/subsidio/captura/{token}/cerrar")
async def captura_cerrar(token: str, user: dict = Depends(_require_subsidio)):
    uids = await _get_company_uids(user)
    await db.capturas_movil.update_one({"token": token, "user_id": {"$in": uids}},
                                       {"$set": {"estado": "cerrada", "cerrada_at": _ahora_iso()}})
    return {"ok": True}


@subsidio_router.get("/subsidio/du007/estado")
async def du007_estado(user: dict = Depends(_require_subsidio)):
    """Estado del DU 007 del cliente: facturas por periodo (conteo, galones, monto) y
    declaraciones ya firmadas. Alimenta las 3 etapas del módulo DU-007."""
    uids = await _get_company_uids(user)
    rows = await db.consumos_subsidio.find(
        {**_own_q(user, uids), "programa": "du007"},
        {"_id": 0, "periodo_du007": 1, "galones": 1, "importe_total": 1, "validacion_estado": 1, "invalida": 1},
    ).to_list(2000)
    periodos = {1: {"facturas": 0, "galones": 0.0, "importe": 0.0, "conformes": 0},
                2: {"facturas": 0, "galones": 0.0, "importe": 0.0, "conformes": 0},
                3: {"facturas": 0, "galones": 0.0, "importe": 0.0, "conformes": 0}}
    fuera_periodo = rechazadas = nulas = 0
    for r in rows:
        if r.get("invalida"):
            # Marcada NULA por el admin: no cuenta ni suma.
            nulas += 1
            continue
        p = r.get("periodo_du007")
        if p not in periodos:
            # Fecha de emisión fuera de los 3 periodos: no se agrupa ni suma.
            fuera_periodo += 1
            continue
        if r.get("validacion_estado") == "RECHAZADA":
            # Dentro de un periodo pero rechazada por otra regla: tampoco suma.
            rechazadas += 1
            continue
        periodos[p]["facturas"] += 1
        periodos[p]["galones"] += float(r.get("galones") or 0)
        periodos[p]["importe"] += float(r.get("importe_total") or 0)
        if r.get("validacion_estado") == "CONFORME":
            periodos[p]["conformes"] += 1
    decls = await db.declaraciones_du007.find(
        _own_q(user, uids), {"_id": 0, "periodo": 1, "accepted_at": 1, "representante": 1},
    ).to_list(10)
    return {"periodos": [{"periodo": k, **{kk: round(vv, 2) if isinstance(vv, float) else vv
                                            for kk, vv in v.items()}} for k, v in periodos.items()],
            "fuera_periodo": fuera_periodo, "rechazadas": rechazadas, "nulas": nulas,
            "declaraciones": decls}


@subsidio_router.post("/subsidio/du007/declaracion")
async def du007_declaracion(payload: dict, request: Request, user: dict = Depends(_require_subsidio)):
    """Firma la declaración jurada del DU 007 para UN periodo (cada periodo se presenta
    por separado). Requiere al menos una factura válida de ese periodo."""
    try:
        periodo = int(payload.get("periodo"))
    except (TypeError, ValueError):
        periodo = 0
    if periodo not in (1, 2, 3):
        raise HTTPException(status_code=400, detail="Periodo inválido (1, 2 o 3)")
    uids = await _get_company_uids(user)
    if not user.get("_admin_id"):
        _f = await _firmas_para_enviar(user, uids)
        if not _f["constancia"]:
            raise HTTPException(status_code=409, detail={
                "codigo": "firmas_pendientes", "constancia": False, "declaracion": True,
                "message": "Antes de firmar la declaración del DU 007 debes aceptar la Constancia de términos del servicio."})
    n = await db.consumos_subsidio.count_documents(
        {**_own_q(user, uids), "programa": "du007", "periodo_du007": periodo,
         "validacion_estado": {"$ne": "RECHAZADA"}})
    if n == 0:
        raise HTTPException(status_code=400,
                            detail=f"Aún no tienes facturas válidas del periodo {periodo}. Carga tu combustible primero.")
    ya = await db.declaraciones_du007.find_one({**_own_q(user, uids), "periodo": periodo})
    if ya:
        raise HTTPException(status_code=409, detail=f"La declaración del periodo {periodo} ya fue firmada.")
    rec = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "empresa": user.get("empresa"),
        "ruc": user.get("ruc"),
        "periodo": periodo,
        "facturas_incluidas": n,
        "representante": payload.get("representante") or user.get("contacto") or user.get("name"),
        "accepted_at": datetime.now(timezone.utc).isoformat(),
        "ip": (request.client.host if request.client else None),
        "user_agent": request.headers.get("user-agent", ""),
        "texto": ("Declaro bajo juramento que los consumos de combustible presentados para el "
                  f"periodo {periodo} del DU 007-2026 son exactos y corresponden a unidades M2/M3/N1/N2/N3 "
                  "con habilitación vigente."),
    }
    await db.declaraciones_du007.insert_one(rec)
    return {"ok": True, "periodo": periodo, "facturas_incluidas": n}


@subsidio_router.get("/subsidio/invoices/confirmed")
async def invoices_confirmed(programa: str = "du004", user: dict = Depends(_require_subsidio)):
    """Lista facturas confirmadas (para módulos del cliente_subsidio), por programa."""
    uids = await _get_company_uids(user)
    filtro_prog = {"programa": "du007"} if programa == "du007" else {"programa": {"$ne": "du007"}}
    rows = await db.consumos_subsidio.find(
        {**_own_q(user, uids), "status": "confirmed", **filtro_prog},
        {"_id": 0, "raw_ocr_response": 0, "factura_storage_key": 0},
    ).to_list(2000)

    if user.get("empresa"):
        rows_comb = await db.consumptions.find(
            {"EMPRESA": user["empresa"]},
            {"_id": 0}
        ).to_list(2000)
        mapped = [_combustible_to_subsidio(r) for r in rows_comb]
        rows.extend(mapped)

    rows.sort(key=lambda x: x.get("fecha") or "", reverse=True)
    for _r in rows:
        if isinstance(_r, dict):
            _completar_precio(_r)
    return rows



def _fecha_any(s):
    """Fecha en ISO (YYYY-MM-DD), DD/MM/YYYY o DD-MM-YYYY → date | None."""
    s = str(s or "").strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(s[:10], fmt).date()
        except Exception:
            pass
    return None


def _estado_por_fecha(d, hoy):
    """Semáforo por fecha de vencimiento: vencido / ≤30 días por vencer / vigente."""
    if d is None:
        return None, None
    dias = (d - hoy).days
    return ("expired" if dias < 0 else "expiring" if dias <= 30 else "active"), dias


async def _dashboard_verificado(user: dict, uids: list, vehicles: list) -> dict:
    """
    KPIs VERIFICADOS del dashboard, sin gastar créditos de pago:
      · SUNAT (consulta pública)  → Ficha RUC activo y habido.
      · MTC · DGTT (consulta pública, 1 scrape por RUC, caché 10 min)
            → autorización de transporte (vigencia) y, por placa, habilitación TUC
              (constancia, vigencia, categoría, año de fabricación).
      · Motor de placas (módulo Vehículos, ya guardado en la BD) → SOAT y CITV.
      · Expediente → adjuntos (DNI del representante, tarjeta de propiedad).
    Lo que el MTC informa (año, constancia, vigencia, categoría vacía) se persiste en
    la unidad del expediente para que no vuelva a quedar en blanco.
    """
    import asyncio as _asyncio
    hoy = datetime.now(timezone.utc).date()
    ahora = datetime.now(timezone.utc).isoformat()
    ruc = (user.get("ruc") or "").strip()
    empresa = user.get("empresa")

    def _pn(p):
        return (p or "").replace("-", "").replace(" ", "").upper().strip()

    def _int(x):
        try:
            v = int(str(x).strip()[:4])
            return v if 1950 <= v <= hoy.year + 1 else None
        except Exception:
            return None

    async def _safe(coro, t=45):
        try:
            return await _asyncio.wait_for(coro, timeout=t)
        except Exception:
            return None

    sunat = aut = mtc_hab = None
    if _re.fullmatch(r"\d{11}", ruc):
        t_sunat = _asyncio.ensure_future(_safe(_sunat_ficha(ruc), 15))
        # Secuencial a propósito: la 2ª llamada reutiliza la caché del scrape del MTC.
        aut = await _safe(_mtc_autorizacion(ruc))
        mtc_hab = await _safe(_mtc_habilitaciones(ruc))
        sunat = await t_sunat

    # Motor de placas: SOAT / CITV / año ya consultados y guardados (0 créditos ahora).
    motor = {}
    if empresa:
        async for mv in db.vehiculos.find(
            {"empresa": empresa},
            {"_id": 0, "placa": 1, "año": 1, "anio": 1, "categoria": 1, "constancia_mtc": 1,
             "soat_vencimiento": 1, "soat_estado": 1, "soat_compania": 1,
             "revtec_vencimiento": 1, "revtec_estado": 1, "revtec_centro": 1},
        ):
            pn = _pn(mv.get("placa"))
            if pn:
                motor[pn] = mv

    docs = await db.subsidio_documents.find(_own_q(user, uids), {"_id": 0, "categoria": 1, "category": 1, "placa": 1}).to_list(3000)
    subidos = {((d.get("categoria") or d.get("category")), _pn(d.get("placa")) or None) for d in docs}

    items = []

    def _item(cat, label, placa, status, dias=None, fecha=None, fuente="", detalle="", verificado=False):
        items.append({
            "categoria": cat,
            "label": label,
            "placa": placa,
            "uploaded": (cat, _pn(placa) or None) in subidos,
            "expires_at": fecha.isoformat() if fecha else None,
            "days_remaining": dias,
            "status": status,           # active | expiring | expired | missing | unknown
            "fuente": fuente,
            "verificado": verificado,
            "detalle": detalle,
        })

    # ---- Empresa ----
    if sunat and sunat.get("no_encontrado"):
        _item("ficha_ruc", DOCUMENT_LABELS["ficha_ruc"], None, "expired", fuente="SUNAT", verificado=True,
              detalle="Este RUC no figura en SUNAT.")
    elif sunat:
        ok = bool(sunat.get("activo_habido"))
        _item("ficha_ruc", DOCUMENT_LABELS["ficha_ruc"], None, "active" if ok else "expired", fuente="SUNAT",
              verificado=True, detalle=f"SUNAT: {sunat.get('estado') or '—'} y {sunat.get('condicion') or '—'}.")
    else:
        up = ("ficha_ruc", None) in subidos
        _item("ficha_ruc", DOCUMENT_LABELS["ficha_ruc"], None, "unknown" if up else "missing", fuente="SUNAT",
              detalle="No se pudo verificar en SUNAT en este momento." if up else "documento pendiente de carga")

    if aut and aut.get("encontrada"):
        d = _fecha_any(aut.get("vigencia"))
        st, dias = _estado_por_fecha(d, hoy)
        if st is None:
            st = "active" if aut.get("habilitado") else "expired"
        elif not aut.get("habilitado") and st != "expired":
            st = "expired"
        _item("resolucion_autorizacion", DOCUMENT_LABELS["resolucion_autorizacion"], None, st, dias, d,
              fuente="MTC · DGTT", verificado=True,
              detalle=(f"Autorización {aut.get('codigo') or ''} · vence en {dias} días" if st == "expiring"
                       else f"Autorización {aut.get('codigo') or ''} vencida el {aut.get('vigencia')}" if st == "expired"
                       else f"Autorización {aut.get('codigo') or ''} vigente hasta {aut.get('vigencia')}"))
    elif aut is not None:
        _item("resolucion_autorizacion", DOCUMENT_LABELS["resolucion_autorizacion"], None, "missing",
              fuente="MTC · DGTT", verificado=True, detalle="No figura autorización de transporte en el MTC.")
    else:
        up = ("resolucion_autorizacion", None) in subidos
        _item("resolucion_autorizacion", DOCUMENT_LABELS["resolucion_autorizacion"], None, "unknown" if up else "missing",
              fuente="MTC · DGTT", detalle="No se pudo verificar en el MTC en este momento." if up else "documento pendiente de carga")

    up = ("dni_representante", None) in subidos
    _item("dni_representante", DOCUMENT_LABELS["dni_representante"], None, "active" if up else "missing",
          fuente="Expediente", detalle="adjunto en el expediente" if up else "documento pendiente de carga")

    # ---- Flota (por placa) ----
    unidades_meta, ages = {}, []
    older_than_10 = habilitadas = en_regla = 0
    for v in vehicles:
        placa = (v.get("placa") or "").upper().strip()
        pn = _pn(placa)
        h = (mtc_hab or {}).get(pn)
        m = motor.get(pn, {})
        anio = _int((h or {}).get("anio")) or _int(m.get("año") or m.get("anio")) or _int(v.get("anio_fabricacion"))
        cat = ((h or {}).get("categoria") or m.get("categoria") or v.get("categoria") or "").upper()
        tuc_ok, vencidos_unidad = False, 0

        # TUC / habilitación vehicular (MTC)
        if h:
            d = _fecha_any(h.get("vigencia"))
            st, dias = _estado_por_fecha(d, hoy)
            if st is None:
                st = "active" if h.get("habilitado") else "expired"
            tuc_ok = st in ("active", "expiring") and bool(h.get("habilitado"))
            if st == "expired":
                vencidos_unidad += 1
            _item("tarjeta_habilitacion", "Habilitación TUC", placa, st, dias, d, fuente="MTC · DGTT", verificado=True,
                  detalle=(f"vence en {dias} días · constancia {h.get('constancia') or '—'}" if st == "expiring"
                           else f"vencida el {h.get('vigencia')}" if st == "expired"
                           else f"vigente hasta {h.get('vigencia') or '—'} · constancia {h.get('constancia') or '—'}"))
        elif mtc_hab is not None:
            vencidos_unidad += 1
            _item("tarjeta_habilitacion", "Habilitación TUC", placa, "missing", fuente="MTC · DGTT", verificado=True,
                  detalle="no figura habilitada en el MTC")
        else:
            d = _fecha_any(v.get("vigente_hasta"))
            st, dias = _estado_por_fecha(d, hoy)
            _item("tarjeta_habilitacion", "Habilitación TUC", placa, st or "unknown", dias, d, fuente="MTC · DGTT",
                  detalle="MTC sin respuesta; dato guardado" if st else "MTC sin respuesta")

        # SOAT (ya guardado por el motor de placas)
        d = _fecha_any(m.get("soat_vencimiento"))
        st, dias = _estado_por_fecha(d, hoy)
        if st:
            if st == "expired":
                vencidos_unidad += 1
            _item("soat", "SOAT", placa, st, dias, d, fuente=m.get("soat_compania") or "Motor de placas", verificado=True,
                  detalle=(f"vence en {dias} días" if st == "expiring" else f"vencido el {d.strftime('%d/%m/%Y')}" if st == "expired"
                           else f"vigente hasta {d.strftime('%d/%m/%Y')}") + (f" · {m['soat_compania']}" if m.get("soat_compania") else ""))
        else:
            _item("soat", "SOAT", placa, "unknown", fuente="Motor de placas",
                  detalle="sin dato · actualiza vigencias en Documentación")

        # CITV / revisión técnica (ya guardada)
        d = _fecha_any(m.get("revtec_vencimiento"))
        st, dias = _estado_por_fecha(d, hoy)
        if st:
            if st == "expired":
                vencidos_unidad += 1
            _item("revision_tecnica", "Revisión técnica (CITV)", placa, st, dias, d, fuente="MTC · CITV", verificado=True,
                  detalle=(f"vence en {dias} días" if st == "expiring" else f"vencida el {d.strftime('%d/%m/%Y')}" if st == "expired"
                           else f"vigente hasta {d.strftime('%d/%m/%Y')}") + (f" · {m['revtec_centro']}" if m.get("revtec_centro") else ""))
        elif "SIN REGISTRO" in str(m.get("revtec_estado") or "").upper():
            vencidos_unidad += 1
            _item("revision_tecnica", "Revisión técnica (CITV)", placa, "missing", fuente="MTC · CITV", verificado=True,
                  detalle="sin registro de revisión técnica en el MTC")
        else:
            _item("revision_tecnica", "Revisión técnica (CITV)", placa, "unknown", fuente="MTC · CITV",
                  detalle="sin dato · actualiza vigencias en Documentación")

        # Tarjeta de propiedad (adjunto del expediente)
        up = ("tarjeta_propiedad", pn) in subidos
        _item("tarjeta_propiedad", "Tarjeta de propiedad", placa, "active" if up else "missing", fuente="Expediente",
              detalle="adjunta en el expediente" if up else "documento pendiente de carga")

        if anio:
            edad = hoy.year - anio
            ages.append(edad)
            if edad >= 10:
                older_than_10 += 1
        if tuc_ok:
            habilitadas += 1
            if vencidos_unidad == 0:
                en_regla += 1
        unidades_meta[placa] = {
            "categoria": cat or None, "anio": anio,
            "tuc": bool(tuc_ok) if (h or mtc_hab is not None) else None,
            "constancia": (h or {}).get("constancia") or m.get("constancia_mtc") or v.get("constancia") or None,
            "soat_vencimiento": m.get("soat_vencimiento") or None,
            "revtec_vencimiento": m.get("revtec_vencimiento") or None,
        }

        # Persistir lo verificado en la unidad del expediente (solo si cambia)
        try:
            upd = {}
            if anio and v.get("anio_fabricacion") != anio:
                upd["anio_fabricacion"] = anio
            if cat and not v.get("categoria"):
                upd["categoria"] = cat
            if h:
                if h.get("constancia") and v.get("constancia") != h["constancia"]:
                    upd["constancia"] = h["constancia"]
                dv = _fecha_any(h.get("vigencia"))
                if dv and v.get("vigente_hasta") != dv.isoformat():
                    upd["vigente_hasta"] = dv.isoformat()
            if upd and v.get("id"):
                upd["verificado_mtc_en"] = ahora
                await db.subsidio_vehicles.update_one({"id": v["id"]}, {"$set": upd})
                v.update(upd)
        except Exception:
            pass

    n_ok = sum(1 for i in items if i["status"] in ("active", "expiring"))
    n_bad = sum(1 for i in items if i["status"] in ("expired", "missing"))
    n_exp = sum(1 for i in items if i["status"] == "expiring")
    n_ven = sum(1 for i in items if i["status"] == "expired")
    n_mis = sum(1 for i in items if i["status"] == "missing")
    n_unk = sum(1 for i in items if i["status"] == "unknown")
    pct_docs = round(n_ok / (n_ok + n_bad) * 100) if (n_ok + n_bad) > 0 else 0
    if n_ven:
        docs_detalle = f"{n_ven} vencido{'s' if n_ven > 1 else ''}"
    elif n_exp:
        docs_detalle = f"{n_exp} por vencer pronto"
    elif n_mis:
        docs_detalle = f"{n_mis} pendiente{'s' if n_mis > 1 else ''}"
    elif n_ok:
        docs_detalle = "Todos al día"
    else:
        docs_detalle = "Sin datos"

    fuentes = []
    if sunat is not None:
        fuentes.append("SUNAT")
    if mtc_hab is not None or (aut and aut.get("encontrada")):
        fuentes.append("MTC")
    if motor:
        fuentes.append("Motor de placas")
    return {
        "items": items,
        "summary": {"active": n_ok - n_exp, "expiring": n_exp, "expired": n_ven, "missing": n_mis, "unknown": n_unk},
        "pct_docs": pct_docs,
        "docs_detalle": docs_detalle,
        "unidades_validas": habilitadas if mtc_hab is not None else sum(
            1 for v in vehicles if _estado_por_fecha(_fecha_any(v.get("vigente_hasta")), hoy)[0] in (None, "active", "expiring")),
        "unidades_mtc": len(mtc_hab) if mtc_hab is not None else None,
        "unidades_en_regla": en_regla,
        "avg_age": round(sum(ages) / len(ages), 1) if ages else 0.0,
        "older_than_10": older_than_10,
        "anios_conocidos": len(ages),
        "unidades_meta": unidades_meta,
        "verificacion": {
            "sunat": sunat is not None,
            "mtc": mtc_hab is not None,
            "mtc_autorizacion": bool(aut and aut.get("encontrada")),
            "fuentes": fuentes,
            "verificado_en": ahora,
        },
    }


@subsidio_router.get("/subsidio/dashboard-data")
async def subsidio_dashboard_data(user: dict = Depends(_require_subsidio)):
    """Datos del dashboard del cliente_subsidio (5 filas):
    Fila 1: Etapas del trámite
    Fila 2: 6 KPIs
    Fila 3: Evolución semanal (semanas de 7 días desde 01/06/2026)
    Fila 4: Top unidades, Top estaciones
    Fila 5: Semáforo de vencimientos de documentos
    """
    from datetime import date, timedelta
    
    uids = await _get_company_uids(user)

    rows = await db.consumos_subsidio.find(
        {**_own_q(user, uids), "status": "confirmed"},
        {"_id": 0, "raw_ocr_response": 0, "factura_storage_key": 0},
    ).to_list(5000)

    if user.get("empresa"):
        rows_comb = await db.consumptions.find(
            {"EMPRESA": user["empresa"]},
            {"_id": 0}
        ).to_list(5000)
        mapped = [_combustible_to_subsidio(r) for r in rows_comb]
        rows.extend(mapped)

    def _f(x):
        try:
            return float(x) if x not in (None, "") else 0.0
        except Exception:
            return 0.0

    def _parse_date(s):
        if not s:
            return None
        s = str(s).strip()
        # ISO YYYY-MM-DD
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").date()
        except Exception:
            pass
        # DD/MM/YYYY
        try:
            return datetime.strptime(s[:10], "%d/%m/%Y").date()
        except Exception:
            pass
        # DD-MM-YYYY
        try:
            return datetime.strptime(s[:10], "%d-%m-%Y").date()
        except Exception:
            return None

    # Estación: si la factura no la trae, se toma la razón social del padrón OSINERGMIN (por RUC).
    try:
        from services.padron_grifos import COLECCION as _COL_GRIFOS
        rucs_sin = {str(r.get("ruc_emisor") or "").strip() for r in rows
                    if not (r.get("estacion") or "").strip() and _re.fullmatch(r"\d{11}", str(r.get("ruc_emisor") or "").strip())}
        if rucs_sin:
            nombres = {}
            async for g in db[_COL_GRIFOS].find({"ruc": {"$in": list(rucs_sin)}}, {"_id": 0, "ruc": 1, "razon_social": 1}):
                nombres.setdefault(g["ruc"], g.get("razon_social"))
            for r in rows:
                if not (r.get("estacion") or "").strip():
                    r["estacion"] = nombres.get(str(r.get("ruc_emisor") or "").strip()) or r.get("estacion")
    except Exception:
        pass

    # === KPIs base (galones, importe) ===
    total_gal = sum(_f(r.get("galones")) for r in rows)
    total_importe = sum(_f(r.get("importe_total")) for r in rows)
    # Precio promedio solo con facturas que traen galones E importe (si no, se distorsiona).
    _con_imp = [r for r in rows if _f(r.get("importe_total")) > 0 and _f(r.get("galones")) > 0]
    gal_con_importe = sum(_f(r.get("galones")) for r in _con_imp)
    imp_con_importe = sum(_f(r.get("importe_total")) for r in _con_imp)
    facturas_sin_importe = sum(1 for r in rows if _f(r.get("importe_total")) <= 0)

    # === Unidades (vehículos) ===
    vehicles = await db.subsidio_vehicles.find(_own_q(user, uids), {"_id": 0}).to_list(200)
    unidades_incluidas = len(vehicles)
    placas_activas = {(r.get("placa") or "").upper().strip() for r in rows if (r.get("placa") or "").strip()}
    unidades_activas = len({v["placa"] for v in vehicles if v["placa"].upper() in placas_activas})

    cfg = await db.empresas_config.find_one({"empresa": user.get("empresa")})
    unidades_contratadas = cfg.get("unidades_contratadas", 0) if cfg else 0

    cat_counts = {}
    for v in vehicles:
        cat = v.get("categoria", "N2")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    detail_parts = [f"{count} {cat}" for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1])]
    unidades_detalle = " - ".join(detail_parts) if detail_parts else "0 unidades"

    # KPIs verificados (SUNAT + MTC + motor de placas), sin créditos de pago.
    ver = await _dashboard_verificado(user, uids, vehicles)
    valid_vehicles = ver["unidades_validas"]
    pct_docs = ver["pct_docs"]
    docs_detalle = ver["docs_detalle"]

    distinct_months = {r.get("fecha")[:7] for r in rows if r.get("fecha") and len(r.get("fecha")) >= 7}
    num_meses = len(distinct_months) if distinct_months else 1

    by_month_stats = {}
    for r in rows:
        f_date = _parse_date(r.get("fecha"))
        if not f_date:
            continue
        ym = f_date.strftime("%Y-%m")
        stats = by_month_stats.setdefault(ym, {"galones": 0.0, "importe": 0.0})
        stats["galones"] += _f(r.get("galones"))
        stats["importe"] += _f(r.get("importe_total"))

    sorted_months = sorted(by_month_stats.keys())
    precio_promedio_diff = 0.0
    if len(sorted_months) >= 2:
        m_curr = sorted_months[-1]
        m_prev = sorted_months[-2]
        s_curr = by_month_stats[m_curr]
        s_prev = by_month_stats[m_prev]
        avg_curr = s_curr["importe"] / s_curr["galones"] if s_curr["galones"] > 0 else 0.0
        avg_prev = s_prev["importe"] / s_prev["galones"] if s_prev["galones"] > 0 else 0.0
        precio_promedio_diff = avg_curr - avg_prev

    avg_age = ver["avg_age"]
    older_than_10 = ver["older_than_10"]

    precio_promedio_gl = (imp_con_importe / gal_con_importe) if gal_con_importe > 0 else 0
    # Costo promedio por unidad dividiendo entre unidades_incluidas para coincidir con la maqueta
    costo_promedio_unidad = (total_importe / unidades_incluidas) if unidades_incluidas > 0 else 0

    # === Etapas (Fila 1) ===
    current_stage = user.get("expediente_stage")
    stages_list = [
        {"key": "solicitud_enviada",  "label": "Solicitud enviada"},
        {"key": "evaluacion_atu",     "label": "Evaluación ATU"},
        {"key": "aprobada",           "label": "Aprobada"},
        {"key": "abonado_en_cuenta",  "label": "Abonado en cuenta"},
    ]
    if current_stage in SUBSIDIO_STAGES:
        cur_idx = SUBSIDIO_STAGES.index(current_stage)
    else:
        cur_idx = -1
    for i, s in enumerate(stages_list):
        s["status"] = "done" if i < cur_idx else ("current" if i == cur_idx else "pending")

    # === Serie semanal (Fila 3): semanas de 7 días empezando 01/06/2026 ===
    WEEK_START = date(2026, 6, 1)
    weeks_map = {}



    for r in rows:
        d = _parse_date(r.get("fecha"))
        if not d:
            continue
        delta_days = (d - WEEK_START).days
        if delta_days < 0:
            continue
        week_idx = delta_days // 7  # 0-based
        wk_start = WEEK_START + timedelta(days=week_idx * 7)
        wk_end = wk_start + timedelta(days=6)
        key = week_idx
        slot = weeks_map.setdefault(key, {
            "semana": f"Sem {week_idx + 1}",
            "rango": f"{wk_start.strftime('%d/%m')}–{wk_end.strftime('%d/%m')}",
            "galones": 0.0,
            "importe": 0.0,
            "cargas": 0,
        })
        slot["galones"] += _f(r.get("galones"))
        slot["importe"] += _f(r.get("importe_total"))
        slot["cargas"] += 1

    serie_semanal = []
    if weeks_map:
        max_week = max(weeks_map.keys())
        for i in range(max_week + 1):
            wk_start = WEEK_START + timedelta(days=i * 7)
            wk_end = wk_start + timedelta(days=6)
            slot = weeks_map.get(i, {
                "semana": f"Sem {i + 1}",
                "rango": f"{wk_start.strftime('%d/%m')}–{wk_end.strftime('%d/%m')}",
                "galones": 0.0,
                "importe": 0.0,
                "cargas": 0,
            })
            serie_semanal.append({
                "semana": slot["semana"],
                "rango": slot["rango"],
                "galones": round(slot["galones"], 2),
                "importe": round(slot["importe"], 2),
                "cargas": slot["cargas"],
            })

    # === Top unidades (Fila 4 izq) ===
    by_placa = {}
    for r in rows:
        p = (r.get("placa") or "Sin placa").upper().strip() or "Sin placa"
        d = by_placa.setdefault(p, {"galones": 0.0, "importe": 0.0, "cargas": 0})
        d["galones"] += _f(r.get("galones"))
        d["importe"] += _f(r.get("importe_total"))
        d["cargas"] += 1
    def _meta_placa(p):
        pn = p.replace("-", "").replace(" ", "").upper()
        for k, mm in ver["unidades_meta"].items():
            if k.replace("-", "").replace(" ", "").upper() == pn:
                return mm
        return {}
    top_unidades = sorted(
        [{"placa": p, "galones": round(v["galones"], 2), "importe": round(v["importe"], 2), "cargas": v["cargas"],
          "categoria": _meta_placa(p).get("categoria"), "anio": _meta_placa(p).get("anio")}
         for p, v in by_placa.items()],
        key=lambda x: -x["galones"],
    )[:5]

    # === Top estaciones (Fila 4 der) ===
    by_est = {}
    for r in rows:
        e = (r.get("estacion") or "Sin estación").strip() or "Sin estación"
        d = by_est.setdefault(e, {"galones": 0.0, "importe": 0.0, "cargas": 0})
        d["galones"] += _f(r.get("galones"))
        d["importe"] += _f(r.get("importe_total"))
        d["cargas"] += 1
    top_estaciones = sorted(
        [{"estacion": e, "galones": round(v["galones"], 2), "importe": round(v["importe"], 2), "cargas": v["cargas"]} for e, v in by_est.items()],
        key=lambda x: -x["galones"],
    )[:5]

    # === Semáforo de vencimientos (Fila 5) — VERIFICADO (SUNAT / MTC / motor de placas) ===
    docs_semaforo = ver["items"]
    summary_active = ver["summary"]["active"]
    summary_expiring = ver["summary"]["expiring"]
    summary_expired = ver["summary"]["expired"]
    summary_missing = ver["summary"]["missing"]

    # Calc para subsidio_estimado (legacy)
    calc = await db.calculations.find_one({"id": user.get("calc_id")}, {"_id": 0}) or {}
    subsidio_estimado = float(calc.get("subsidio_estimado", 0) or 0)

    # Contar drafts pendientes (facturas subidas pero no confirmadas)
    pending_drafts = await db.consumos_subsidio.count_documents(
        {"user_id": user["id"], "status": "draft"}
    )

    # Serie mensual (legacy compatibility para no romper otras vistas)
    by_month = {}
    for r in rows:
        f = r.get("fecha") or ""
        ym = f[:7] if len(f) >= 7 else "sin-fecha"
        d = by_month.setdefault(ym, {"galones": 0.0, "importe": 0.0, "facturas": 0})
        d["galones"] += _f(r.get("galones"))
        d["importe"] += _f(r.get("importe_total"))
        d["facturas"] += 1
    serie_mensual = [
        {"mes": k, "galones": round(v["galones"], 2), "importe": round(v["importe"], 2), "facturas": v["facturas"]}
        for k, v in sorted(by_month.items()) if k != "sin-fecha"
    ]

    return {
        # Fila 1
        "stages": stages_list,
        "current_stage": current_stage,
        # Pending drafts (banner)
        "pending_drafts": pending_drafts,
        # Fila 2 (6 KPIs)
        "kpis": {
            "unidades_incluidas": unidades_incluidas,
            "unidades_contratadas": unidades_contratadas,
            "unidades_detalle": unidades_detalle,
            "unidades_validas": valid_vehicles,
            "unidades_validas_pct": round((valid_vehicles / unidades_incluidas * 100) if unidades_incluidas > 0 else 0),
            "galones_reconocidos": round(total_gal, 2),
            "invoices_confirmed": len(rows),
            "invoices_total": len(rows) + pending_drafts,
            "gasto_total": round(total_importe, 2),
            "precio_promedio_galon": round(precio_promedio_gl, 2),
            "costo_promedio_unidad": round(costo_promedio_unidad, 2),
            "pct_docs": pct_docs,
            "docs_detalle": docs_detalle,
            "num_meses": num_meses,
            "precio_promedio_diff": round(precio_promedio_diff, 2),
            "avg_age": avg_age,
            "older_than_10": older_than_10,
            "facturas_sin_importe": facturas_sin_importe,
            "anios_conocidos": ver["anios_conocidos"],
            "unidades_mtc": ver["unidades_mtc"],
            "unidades_en_regla": ver["unidades_en_regla"],
            # Legacy (no romper UI antigua/admin)
            "unidades_activas": unidades_activas,
            "facturas_confirmadas": len(rows),
            "galones_confirmados": round(total_gal, 2),
            "importe_total": round(total_importe, 2),
            "subsidio_estimado": round(subsidio_estimado, 2),
            "subsidio_reconocido": round(total_gal * 4, 2),
            "precio_promedio": round(precio_promedio_gl, 2),
        },
        # Fila 3
        "serie_semanal": serie_semanal,
        # Fila 4
        "top_unidades": top_unidades,
        "top_estaciones": top_estaciones,
        # Fila 5
        "documentos_semaforo": {
            "items": docs_semaforo,
            "summary": {
                "active": summary_active,
                "expiring": summary_expiring,
                "expired": summary_expired,
                "missing": summary_missing,
                "unknown": ver["summary"]["unknown"],
            },
        },
        "unidades_meta": ver["unidades_meta"],
        "verificacion": ver["verificacion"],
        # Legacy
        "serie_mensual": serie_mensual,
        "top_placas": top_unidades,
        "ultimas_facturas": sorted(rows, key=lambda r: r.get("fecha") or "", reverse=True)[:10],
    }



# ============================================================================
# ADMIN — Vista de expedientes para admin_enered (read-only)
# ============================================================================
async def _require_admin_enered(request: Request) -> dict:
    user = await _get_current_user(request)
    if user.get("role") != "admin_enered":
        raise HTTPException(status_code=403, detail="Solo admin_enered")
    return user


@subsidio_router.get("/admin/subsidio/expedientes")
async def admin_list_expedientes(
    _: dict = Depends(_require_admin_enered),
    q: Optional[str] = None,
    estado: Optional[str] = None,
    limit: int = 200,
    programa: Optional[str] = None,
):
    """Lista todos los clientes de subsidio con resumen del expediente.
    `programa`: du004 (default, incluye facturas sin programa — registros previos al DU 007)
    o du007 (solo facturas de ese programa)."""
    # Include both cliente_subsidio users AND users whose empresa has servicios.subsidio enabled
    empresas_subsidio = []
    async for cfg in db.empresas_config.find({"servicios.subsidio": True}, {"_id": 0, "empresa": 1}):
        if cfg.get("empresa"):
            empresas_subsidio.append(cfg["empresa"])

    role_or = [{"role": "cliente_subsidio"}]
    if empresas_subsidio:
        role_or.append({"empresa": {"$in": empresas_subsidio}, "role": {"$ne": "admin_enered"}})
        role_or.append({"empresas_asignadas.empresa": {"$in": empresas_subsidio}, "role": {"$ne": "admin_enered"}})
    filt = {"$or": role_or} if len(role_or) > 1 else role_or[0]

    if q:
        # El RUC de la empresa puede vivir SOLO en empresas_config (lo carga "Empresas y
        # Servicios") si el usuario nunca inició sesión: _heredar_ruc recién lo copia a su
        # ficha en el primer login. Sin esto, buscar por RUC no encontraba expedientes de
        # empresas que ya tenían su RUC registrado, solo por no haber entrado nunca.
        empresas_por_ruc = [
            cfg["empresa"] async for cfg in db.empresas_config.find(
                {"ruc": {"$regex": q}}, {"_id": 0, "empresa": 1}) if cfg.get("empresa")
        ]
        or_q = [
            {"empresa": {"$regex": q, "$options": "i"}},
            {"ruc": {"$regex": q}},
            {"email": {"$regex": q, "$options": "i"}},
            {"empresas_asignadas.empresa": {"$regex": q, "$options": "i"}},
            {"empresas_asignadas.ruc": {"$regex": q}},
        ]
        if empresas_por_ruc:
            or_q.append({"empresa": {"$in": empresas_por_ruc}})
            or_q.append({"empresas_asignadas.empresa": {"$in": empresas_por_ruc}})
        filt = {"$and": [filt, {"$or": or_q}]}
    campo_status = "expediente_status_du007" if programa == "du007" else "expediente_status"
    if estado:
        filt[campo_status] = estado

    users = await db.users.find(filt, {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(limit)
    if not users:
        return {"items": [], "total": 0}

    uids = [u.get("id") for u in users if u.get("id")]
    calc_ids = [u.get("calc_id") for u in users if u.get("calc_id")]

    # Bulk queries
    calcs = await db.calculations.find({"id": {"$in": calc_ids}}, {"_id": 0}).to_list(10000)
    calcs_map = {c["id"]: c for c in calcs}

    # Un cliente multi-empresa (empresas_asignadas) genera UNA FILA POR EMPRESA: cada
    # expediente se cuenta y se abre por separado (antes se sumaba todo en la empresa
    # base y las otras empresas no aparecían en el panel).
    filas = []  # (user, empresa, ruc)
    for u in users:
        asignadas = [a for a in (u.get("empresas_asignadas") or []) if (a or {}).get("empresa")]
        if len(asignadas) >= 2:
            vistas = set()
            if u.get("empresa"):
                vistas.add(u["empresa"])
                filas.append((u, u["empresa"], u.get("ruc")))
            for a in asignadas:
                if a["empresa"] not in vistas:
                    vistas.add(a["empresa"])
                    filas.append((u, a["empresa"], a.get("ruc") or ""))
        else:
            filas.append((u, u.get("empresa"), u.get("ruc")))

    # RUC de respaldo desde empresas_config, para filas sin RUC propio en el usuario
    # (mismo caso: nunca inició sesión, así que _heredar_ruc no llegó a copiarlo).
    _empresas_filas = sorted({e for (_, e, _) in filas if e})
    _ruc_por_empresa = {}
    if _empresas_filas:
        async for cfg in db.empresas_config.find(
            {"empresa": {"$in": _empresas_filas}}, {"_id": 0, "empresa": 1, "ruc": 1}):
            if cfg.get("empresa") and cfg.get("ruc"):
                _ruc_por_empresa[cfg["empresa"]] = cfg["ruc"]
    filas = [(u, emp, ruc or _ruc_por_empresa.get(emp, "")) for (u, emp, ruc) in filas]

    # Conteos por (user_id, empresa). Los registros antiguos sin empresa se atribuyen a
    # la empresa base del usuario (mismo criterio que _own_q).
    def _emp_key(uid: str, emp, base_de: dict):
        return (uid, emp if emp else base_de.get(uid))
    base_de = {u.get("id"): u.get("empresa") for u in users}

    docs_agg = await db.subsidio_documents.aggregate([
        {"$match": {"user_id": {"$in": uids}}},
        {"$group": {"_id": {"u": "$user_id", "e": "$empresa"}, "count": {"$sum": 1}}}
    ]).to_list(10000)
    docs_map = {}
    for d in docs_agg:
        k = _emp_key(d["_id"]["u"], d["_id"].get("e"), base_de)
        docs_map[k] = docs_map.get(k, 0) + d["count"]

    veh_agg = await db.subsidio_vehicles.aggregate([
        {"$match": {"user_id": {"$in": uids}}},
        {"$group": {"_id": {"u": "$user_id", "e": "$empresa"}, "count": {"$sum": 1}}}
    ]).to_list(10000)
    veh_map = {}
    for d in veh_agg:
        k = _emp_key(d["_id"]["u"], d["_id"].get("e"), base_de)
        veh_map[k] = veh_map.get(k, 0) + d["count"]

    # du007: solo facturas marcadas con ese programa. du004 (default): todo lo que NO sea
    # du007 — incluye las facturas previas al DU 007, que no llevan el campo `programa`.
    prog_match = {"programa": "du007"} if programa == "du007" else {"programa": {"$ne": "du007"}}

    # Se leen las filas (no un $group en Mongo) para aplicar EXACTAMENTE la misma regla de
    # 'reconocida' y la misma corrección de importe por placa que el detalle del expediente:
    # antes el listado sumaba el importe guardado y no cuadraba con el detalle/tabla.
    inv_rows = await db.consumos_subsidio.find(
        {"user_id": {"$in": uids}, **prog_match},
        {"_id": 0, "id": 1, "user_id": 1, "empresa": 1, "status": 1, "validacion_estado": 1, "invalida": 1,
         "galones": 1, "precio_unitario": 1, "importe_total": 1, "numero_documento": 1, "ruc_emisor": 1},
    ).to_list(50000)

    _reparto = _repartir_importes_por_placa(inv_rows)
    inv_map = {}
    for r in inv_rows:
        if r.get("id") in _reparto:
            r = {**r, **_reparto[r["id"]]}
        k = _emp_key(r.get("user_id"), r.get("empresa"), base_de)
        if k not in inv_map:
            inv_map[k] = {"draft": 0, "conf": 0, "gal": 0, "imp": 0}
        nula = bool(r.get("invalida"))
        if r.get("status") == "draft":
            inv_map[k]["draft"] += 1
        elif r.get("status") == "confirmed" and not nula:
            inv_map[k]["conf"] += 1
        if _es_reconocida(r, programa):
            _imp = _importe_por_placa(r)
            inv_map[k]["gal"] += float(r.get("galones") or 0)
            inv_map[k]["imp"] += float(_imp if _imp is not None else (r.get("importe_total") or 0))

    # Facturas de Red-Enered (db.invoices) por empresa, SIN contar el espejo de las que
    # ya están en consumos_subsidio (mismo id): antes se sumaban dos veces y la lista
    # decía "40 facturas" donde había 20. Este espejo no trae `programa`, así que se
    # calcula por su fecha de emisión (igual que en el detalle del expediente) y solo se
    # suma al panel del decreto que le corresponde — antes el DU 007 no sumaba nada de
    # aquí, sin importar la fecha real de esas facturas.
    empresas_list = sorted({e for (_, e, _) in filas if e})
    if empresas_list:
        ids_consumos = [c.get("id") async for c in db.consumos_subsidio.find(
            {"user_id": {"$in": uids}}, {"_id": 0, "id": 1}) if c.get("id")]
        enered_invs = await db.invoices.find(
            {"empresa": {"$in": empresas_list}, "id": {"$nin": ids_consumos}},
            {"_id": 0, "empresa": 1, "monto_total": 1, "f_emision": 1},
        ).to_list(20000)
        enered_map = {}
        for ei in enered_invs:
            prog_ei, _periodo_ei = _programa_de_fecha(ei.get("f_emision"))
            if prog_ei != programa:
                continue
            emp = ei.get("empresa")
            if not emp:
                continue
            agg = enered_map.setdefault(emp, {"count": 0, "imp": 0.0})
            agg["count"] += 1
            agg["imp"] += float(ei.get("monto_total") or 0)
        for (u, emp, _r) in filas:
            uid = u.get("id")
            if emp and emp in enered_map:
                k = (uid, emp)
                if k not in inv_map:
                    inv_map[k] = {"draft": 0, "conf": 0, "gal": 0, "imp": 0}
                inv_map[k]["conf"] += enered_map[emp]["count"]
                inv_map[k]["imp"] += enered_map[emp]["imp"]

    # DU 007 firma por periodo en su propia colección (declaraciones_du007) — no en
    # subsidio_declaraciones, que es la declaración única del DU 004. Antes la columna
    # "DJ" del panel DU 007 mostraba la firma del DU 004 (o su ausencia) sin relación real.
    decl_col = db.declaraciones_du007 if programa == "du007" else db.subsidio_declaraciones
    decl_list = await decl_col.find({"user_id": {"$in": uids}}, {"_id": 0}).to_list(10000)
    decl_map = {}
    for d in decl_list:
        if not d.get("user_id"):
            continue
        k = _emp_key(d["user_id"], d.get("empresa"), base_de)
        # DU 007: puede haber una declaración por periodo — nos quedamos con la más reciente.
        if k not in decl_map or (d.get("accepted_at") or "") > (decl_map[k].get("accepted_at") or ""):
            decl_map[k] = d

    out = []
    for (u, emp, ruc) in filas:
        uid = u.get("id")
        k = (uid, emp)
        calc = calcs_map.get(u.get("calc_id"), {})
        docs_count = docs_map.get(k, 0)
        vehicles_count = veh_map.get(k, 0)

        inv = inv_map.get(k, {"draft": 0, "conf": 0, "gal": 0, "imp": 0})
        decl = decl_map.get(k)
        multi = len([a for a in (u.get("empresas_asignadas") or []) if (a or {}).get("empresa")]) >= 2

        out.append({
            "user_id": uid,
            "empresa": emp,
            "ruc": ruc,
            "multiempresa": multi,
            "empresa_base": u.get("empresa") if multi else None,
            "email": u.get("email"),
            "contacto": u.get("contacto"),
            "telefono": u.get("telefono"),
            "created_at": u.get("created_at"),
            "expediente_status": u.get(campo_status) or "uploading",
            "expediente_stage": u.get("expediente_stage_du007" if programa == "du007" else "expediente_stage"),
            "expediente_stage_updated_at": u.get(
                "expediente_stage_du007_updated_at" if programa == "du007" else "expediente_stage_updated_at"),
            "documentos_completos": bool(u.get("documentos_completos")),
            "expediente_submitted_at": u.get(
                "expediente_submitted_at_du007" if programa == "du007" else "expediente_submitted_at"),
            "ahorro_estimado": calc.get("subsidio_estimado", 0),
            "ahorro_reconocido": round(float(inv["gal"]) * SUBSIDIO_SOLES_POR_GALON, 2),  # = subsidio estimado
            "subsidio_estimado": round(float(inv["gal"]) * SUBSIDIO_SOLES_POR_GALON, 2),
            "galones_confirmados": round(float(inv["gal"]), 2),
            "importe_confirmado": round(float(inv["imp"]), 2),
            "docs_count": docs_count,
            "vehicles_count": vehicles_count,
            "invoices": {"draft": inv["draft"], "confirmed": inv["conf"]},
            "declaracion_firmada": bool(decl),
            "declaracion_at": (decl or {}).get("accepted_at"),
        })
    return {"items": out, "total": len(out)}





SUBSIDIO_SOLES_POR_GALON = 4.0   # S/ por galón reconocido (DU 004 y DU 007, mismo factor)


def _es_reconocida(i: dict, programa: Optional[str]) -> bool:
    """Criterio ÚNICO de 'reconocida' (lo usan listado, detalle, KPIs y la tabla del admin):
    las NULAS nunca; DU 007 = todo lo que el validador no rechazó (esa página no tiene paso
    de 'Confirmar'); DU 004 = status=confirmed."""
    if i.get("invalida"):
        return False
    if programa == "du007":
        return (i.get("validacion_estado") or "") != "RECHAZADA"
    return i.get("status") == "confirmed"


_CAMPOS_FALTA = (("fecha", "fecha"), ("numero_documento", "N° de comprobante"), ("galones", "galones"),
                 ("importe_total", "importe total"), ("ruc_emisor", "RUC del grifo"))


def _veredicto_desactualizado(i: dict) -> bool:
    """El veredicto guardado se calculó con datos que YA cambiaron: (a) dice que falta un dato
    que hoy sí está (la relectura del QR o una edición lo completó después), o (b) es DU 007 con
    fecha dentro de un periodo pero sin periodo asignado. Ese veredicto no vale: hay que revalidar."""
    if i.get("invalida") or not i.get("validacion_estado"):
        return False
    v = i.get("validacion") or {}
    m = " ".join(v.get("motivos") or [])
    if m.startswith("Falta:") or "Falta: " in m:
        for campo, clave in _CAMPOS_FALTA:
            if clave in m and i.get(campo):
                return True
    if i.get("programa") == "du007" and i.get("fecha") and not i.get("periodo_du007"):
        try:
            from services.validador_facturas import periodo_du007 as _p7
            from datetime import date as _d
            if _p7(_d.fromisoformat(str(i["fecha"])[:10])) is not None:
                return True
        except Exception:
            pass
    return False


def _expediente_stats(invoices: list[dict], programa: Optional[str]) -> dict:
    """KPIs de facturas del expediente. Todas las cifras salen del MISMO conjunto de filas y
    la MISMA regla (`_es_reconocida`) que la tabla de facturas del admin, para que lo de
    arriba cuadre con lo de abajo:
      · galones_confirmados / importe_confirmado: suma de las reconocidas (= pie de la tabla)
      · subsidio_estimado: galones reconocidos × S/ 4 (lo que antes se llamaba 'Ahorro
        recalculado' y se confundía con el importe facturado)
      · DU 007: desglose por periodo (1, 2, 3) y 'sin_periodo' (facturas que nunca pasaron
        por el validador nuevo o cuya fecha no cae en ningún periodo) + nulas / rechazadas."""
    rec = [i for i in invoices if _es_reconocida(i, programa)]
    gal = round(sum(float(i.get("galones") or 0) for i in rec), 2)
    imp = round(sum(float(i.get("importe_total") or 0) for i in rec), 2)
    out = {
        "invoices_draft": sum(1 for i in invoices if i.get("status") == "draft"),
        "invoices_confirmed": len(rec),
        "invoices_total": len(invoices),
        "galones_confirmados": gal,
        "importe_confirmado": imp,
        "subsidio_estimado": round(gal * SUBSIDIO_SOLES_POR_GALON, 2),
        "soles_por_galon": SUBSIDIO_SOLES_POR_GALON,
        "nulas": sum(1 for i in invoices if i.get("invalida")),
        "rechazadas": sum(1 for i in invoices if not i.get("invalida") and (i.get("validacion_estado") or "") == "RECHAZADA"),
        # Sin revalidar = nunca validadas + validadas con datos que después cambiaron (veredicto viejo).
        "sin_revalidar": sum(1 for i in invoices if not i.get("invalida")
                             and (not i.get("validacion_estado") or i.get("validacion_desactualizado"))),
        "veredicto_desactualizado": sum(1 for i in invoices if i.get("validacion_desactualizado")),
        "reconocidas_sin_galones": sum(1 for i in rec if not i.get("galones")),
    }
    if programa == "du007":
        per = {k: {"periodo": k, "facturas": 0, "galones": 0.0, "importe": 0.0, "conformes": 0, "observadas": 0}
               for k in (1, 2, 3)}
        sin = {"facturas": 0, "galones": 0.0, "importe": 0.0}
        for i in rec:
            p = i.get("periodo_du007")
            dest = per.get(p) if p in per else sin
            dest["facturas"] += 1
            dest["galones"] += float(i.get("galones") or 0)
            dest["importe"] += float(i.get("importe_total") or 0)
            if dest is not sin:
                if i.get("validacion_estado") == "CONFORME":
                    dest["conformes"] += 1
                elif i.get("validacion_estado") == "OBSERVADA":
                    dest["observadas"] += 1
        for d in list(per.values()) + [sin]:
            d["galones"] = round(d["galones"], 2)
            d["importe"] = round(d["importe"], 2)
            d["subsidio"] = round(d["galones"] * SUBSIDIO_SOLES_POR_GALON, 2)
        out["periodos"] = [per[1], per[2], per[3]]
        out["sin_periodo"] = sin
    return out


@subsidio_router.get("/admin/subsidio/expedientes/{user_id}")
async def admin_get_expediente(user_id: str, empresa: Optional[str] = None, programa: Optional[str] = None,
                               _: dict = Depends(_require_admin_enered)):
    """Detalle completo de un expediente: cálculo, banco, docs, flota, facturas, declaración.
    `empresa`: para clientes multi-empresa, cuál de sus empresas abrir (por defecto la base).
    `programa`: du004 (default, incluye facturas sin programa) o du007 (solo ese programa)."""
    u = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    if not u:
        raise HTTPException(status_code=404, detail="Expediente no encontrado")
    u = _usuario_en_empresa(u, empresa)
    # Si el usuario nunca inició sesión, su RUC pudo quedar sin copiar desde empresas_config
    # (eso lo hace _heredar_ruc recién en el primer login) — el expediente admin mostraba
    # "RUC" en blanco aunque la empresa ya lo tuviera registrado en Empresas y Servicios.
    u = await _heredar_ruc(u)

    uids = await _get_company_uids(u)

    calc = await db.calculations.find_one({"id": u.get("calc_id")}, {"_id": 0}) if u.get("calc_id") else None

    # Obtener el último banco y declaración (cualquiera de la empresa sirve). DU 007 firma
    # por periodo en su propia colección — no en subsidio_declaraciones, que es del DU 004.
    bank = await db.subsidio_bank_accounts.find_one(_own_q(u, uids), {"_id": 0}, sort=[("updated_at", -1)])
    decl_col = db.declaraciones_du007 if programa == "du007" else db.subsidio_declaraciones
    decl = await decl_col.find_one(_own_q(u, uids), {"_id": 0}, sort=[("accepted_at", -1)])

    # Estado/etapa del trámite: DU 007 tiene sus propios campos (no comparte con el DU 004
    # el "Confirmado" / "Enviado ATU" / etapa del trámite — antes heredaba lo del DU 004
    # aunque nada se hubiera presentado todavía para el DU 007).
    if programa == "du007":
        u["expediente_status"] = u.get("expediente_status_du007") or "uploading"
        u["expediente_stage"] = u.get("expediente_stage_du007")
        u["expediente_stage_updated_at"] = u.get("expediente_stage_du007_updated_at")
        u["expediente_submitted_at"] = u.get("expediente_submitted_at_du007")

    docs = await db.subsidio_documents.find(_own_q(u, uids), {"_id": 0, "storage_key": 0}).sort("uploaded_at", -1).to_list(500)
    
    # Merge vehicles from both main fleet and subsidio
    _excl = await db.subsidio_vehicles_excluidos.find(
        _own_q(u, uids), {"_id": 0, "placa": 1}).to_list(500)
    excluidas = {e.get("placa") for e in _excl}
    vehicles_dict = {}
    if u.get("empresa"):
        main_veh = await db.vehiculos.find({"empresa": u.get("empresa")}, {"_id": 0}).to_list(1000)
        for mv in main_veh:
            placa = (mv.get("placa") or mv.get("veh") or "").strip().upper()
            if not placa or placa in excluidas: continue
            vehicles_dict[placa] = {
                "id": mv.get("id", str(uuid.uuid4())),
                "placa": placa,
                "categoria": mv.get("categoria") or "N1",
                "user_id": mv.get("created_by") or user_id,
                "from_main_fleet": True
            }
    
    sub_veh = await db.subsidio_vehicles.find(_own_q(u, uids), {"_id": 0}).sort("created_at", 1).to_list(200)
    for sv in sub_veh:
        placa = (sv.get("placa") or "").strip().upper()
        if not placa: continue
        vehicles_dict[placa] = sv
        
    vehicles = list(vehicles_dict.values())
    # du007: solo facturas marcadas con ese programa. du004 (default): todo lo que NO sea
    # du007 — incluye las facturas previas al DU 007, que no llevan el campo `programa`.
    prog_match = {"programa": "du007"} if programa == "du007" else {"programa": {"$ne": "du007"}}
    sub_invs = await db.consumos_subsidio.find(
        {**_own_q(u, uids), **prog_match},
        {"_id": 0, "raw_ocr_response": 0, "factura_storage_key": 0},
    ).sort("fecha", -1).to_list(2000)

    invoices = list(sub_invs)

    # Evitar duplicados: una factura confirmada desde Subsidio existe tanto en
    # consumos_subsidio (registro rico y editable) como en db.invoices (espejo de
    # facturación, mismo id / mismo n_doc). Mostramos solo la de consumos_subsidio.
    seen_ids = {i.get("id") for i in invoices if i.get("id")}
    seen_ndocs = {
        (i.get("numero_documento") or i.get("n_doc") or "").strip().upper()
        for i in invoices
    }
    seen_ndocs.discard("")

    # El espejo db.invoices no trae `programa` (se creó por el panel Admin, ajeno al
    # subsidio), así que se calcula aquí según su fecha de emisión — igual que cualquier
    # otra factura — y solo se agrega al expediente que le corresponde según esa fecha.
    if u.get("empresa"):
        enered_invs = await db.invoices.find(
            {"empresa": u.get("empresa")},
            {"_id": 0}
        ).to_list(2000)
        for ei in enered_invs:
            ndoc = (ei.get("n_doc") or "").strip().upper()
            # Ya presente vía consumos_subsidio (mismo id o mismo número) → no duplicar
            if ei.get("id") in seen_ids:
                continue
            if ndoc and ndoc in seen_ndocs:
                continue
            prog_ei, periodo_ei = _programa_de_fecha(ei.get("f_emision"))
            if prog_ei != programa:
                continue  # esta factura le toca al otro decreto, no a este expediente
            seen_ids.add(ei.get("id"))
            if ndoc:
                seen_ndocs.add(ndoc)
            # Map db.invoices format to consumos_subsidio format for the admin table
            mapped_inv = {
                "id": ei.get("id"),
                "numero_documento": ei.get("n_doc"),
                "fecha": ei.get("f_emision"),
                "importe_total": ei.get("monto_total"),
                "status": "confirmed", # By default Red-Enered invoices are confirmed
                "empresa": ei.get("empresa"),
                "producto": ei.get("producto"),
                "factura_filename": ei.get("pdf_filename"),
                # Campos que antes se perdían al mapear → la tabla admin los mostraba vacíos
                # y parecía que "no se guardaba". Se incluyen para reflejar el registro real.
                "placa": ei.get("placa"),
                "galones": ei.get("galones"),
                "precio_unitario": ei.get("precio_unitario"),
                "ciudad": normalize_city(ei.get("ciudad")),
                "ruc_emisor": ei.get("ruc_emisor"),
                "estacion": ei.get("estacion"),
                "hora": ei.get("hora"),
                "created_via": ei.get("created_via"),
                "invalida": ei.get("invalida"),
                "motivos_invalidez": ei.get("motivos_invalidez"),
                "motivo_invalidez_otros": ei.get("motivo_invalidez_otros"),
                "origen": "RED_ENERED",
                "is_tercero": False,
                "programa": prog_ei,
                "periodo_du007": periodo_ei,
            }
            invoices.append(mapped_inv)
            
    # sort all by fecha descending
    invoices.sort(key=lambda x: x.get("fecha") or "", reverse=True)

    # Importe de cada fila = consumo de ESA placa (galones × precio). Una factura con varias
    # placas se guarda en varias filas con el total repetido: sumarlo tal cual multiplicaba el
    # importe del expediente (S/ 960 mil en 5.9 mil galones). Se corrige al leer, guardando el
    # total original en importe_factura, y la revalidación lo persiste.
    # Razón social del grifo por RUC (padrón OSINERGMIN local y, si no está, SUNAT con caché):
    # muchas filas guardaron como "estación" la DIRECCIÓN que leyó el OCR. Se corrige al mostrar
    # (sin tocar la BD); "Revalidar todas" lo deja persistido.
    _rs_por_ruc = await _razones_sociales_por_ruc(invoices)
    _reparto = _repartir_importes_por_placa(invoices)
    for i in invoices:
        _rs = _rs_por_ruc.get(str(i.get("ruc_emisor") or "").strip())
        if _rs and (i.get("estacion") or "").strip() != _rs:
            i["estacion_ocr"] = i.get("estacion")
            i["estacion"] = _rs
        if _veredicto_desactualizado(i):
            i["validacion_desactualizado"] = True
        _imp = _importe_por_placa(i)
        if _imp is not None:
            i["importe_factura"] = i.get("importe_total")
            i["importe_total"] = _imp
            i["importe_corregido"] = True
        elif i.get("id") in _reparto:
            i.update(_reparto[i["id"]])
            i["importe_corregido"] = True
        _completar_precio(i)

    # Etiquetas legibles
    for d in docs:
        d = _normalize_doc(d)
        d["label"] = DOCUMENT_LABELS.get(d.get("categoria"), d.get("categoria"))

    return {
        "user": u,
        "calculation": calc,
        "bank_account": bank,
        "documents": docs,
        "vehicles": vehicles,
        "invoices": invoices,
        "declaracion": decl,
        "stats": {
            "docs_count": len(docs),
            "vehicles_count": len(vehicles),
            **_expediente_stats(invoices, programa),
        },
    }


async def _buscar_key_archivo(inv: dict, keys_cache: Optional[list] = None) -> Optional[str]:
    """Localiza el archivo de una factura con la MISMA tolerancia que la descarga individual:
    primero la referencia directa; si está rota, busca por nombre de archivo (con y sin
    espacios) y por número de documento en el almacenamiento, y cruza las colecciones de
    facturación por si el archivo se subió por otra vía.
    keys_cache: listado completo de keys 'subsidio/' pre-cargado — obligatorio cuando se
    procesan muchas facturas (evita re-listar el bucket por cada una)."""
    cache_set = set(keys_cache) if keys_cache is not None else None

    def _existe(k: str) -> bool:
        if cache_set is not None and k in cache_set:
            return True
        return storage.object_exists(k)

    def _por_sufijo(suffix: str, prefix: str) -> Optional[str]:
        if keys_cache is not None:
            s = suffix.lower()
            for k in keys_cache:
                if k.startswith(prefix) and k.lower().endswith(s):
                    return k
            return None
        return storage.find_by_suffix(suffix, prefix=prefix)

    key = inv.get("factura_storage_key")
    if key and _existe(key):
        return key
    fname = inv.get("factura_filename") or inv.get("pdf_filename")
    n_doc = (inv.get("numero_documento") or inv.get("n_doc") or "").strip()
    uid = inv.get("user_id")
    candidatos = [c for c in [fname, (fname or "").replace(" ", ""),
                              f"{n_doc}.pdf" if n_doc else ""] if c]
    for cand in candidatos:
        try:
            k = _por_sufijo(cand, f"subsidio/{uid}/") if uid else None
            if not k:
                k = _por_sufijo(cand, "subsidio/")
            if k:
                return k
        except Exception:
            pass
    if n_doc:
        q = {"$or": [{"n_doc": n_doc}, {"numero_documento": n_doc}]}
        for col in (db.invoices, db.empresas_invoices):
            alt = await col.find_one(q)
            if alt:
                for kk in ("factura_storage_key", "storage_key", "pdf_key"):
                    k = alt.get(kk)
                    if k and _existe(k):
                        return k
    return None


@subsidio_router.post("/admin/subsidio/expedientes/{user_id}/invoices/revalidar")
async def admin_revalidar_invoices(user_id: str, empresa: Optional[str] = None, programa: Optional[str] = None,
                                   _: dict = Depends(_require_admin_enered)):
    """Vuelve a correr el validador automático sobre TODAS las facturas del expediente
    (sin tocar sus datos), con la flota y los duplicados actuales. Para corregir en bloque
    facturas que quedaron OBSERVADA por un bug ya arreglado (p. ej. la flota no se
    reconocía), sin que el cliente tenga que reabrir y reguardar cada una a mano."""
    u = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    if not u:
        raise HTTPException(status_code=404, detail="Expediente no encontrado")
    u = _usuario_en_empresa(u, empresa)
    uids = await _get_company_uids(u)

    prog_match = {"programa": "du007"} if programa == "du007" else (
        {"programa": {"$ne": "du007"}} if programa == "du004" else {})
    filas = await db.consumos_subsidio.find(
        {**_own_q(u, uids), **prog_match}, {"_id": 0}
    ).to_list(5000)
    if not filas:
        return {"revisadas": 0, "cambiaron": 0, "por_estado": {}}

    return await _revalidar_expediente(u, uids, filas, promover=True)


async def _revalidar_expediente(u: dict, uids: list, filas: list, promover: bool = True) -> dict:
    """Revalida en bloque las facturas de un expediente con las MISMAS reglas que crear/editar
    desde el admin: (1) reclasifica el decreto por fecha (julio → DU 004, setiembre → DU 007),
    (2) entre copias iguales la primera cargada vale y solo las posteriores son duplicadas,
    (3) si `promover`, los borradores completos, no nulos y no rechazados pasan a confirmados."""
    from services.validador_facturas import validar_factura as _validar_re
    placas, cats = await _flota_categorias(u, uids)
    _npr = lambda x: _re.sub(r"[^A-Z0-9]", "", (x or "").upper())
    _clave = lambda f: (str(f.get("ruc_emisor") or "").strip(), str(f.get("numero_documento") or "").strip().upper(),
                        _npr(f.get("placa")))
    vistos = {_clave(f) for f in filas if f.get("numero_documento")}
    # Copia válida de cada clave: la MÁS COMPLETA y, en empate, la más antigua; el resto duplicadas.
    primera: dict = {}
    for f in sorted(filas, key=lambda x: (-_completitud(x), str(x.get("created_at") or ""))):
        if f.get("numero_documento"):
            primera.setdefault(_clave(f), f["id"])

    cambiaron = promovidas = reclasificadas = 0
    por_estado = {"CONFORME": 0, "OBSERVADA": 0, "RECHAZADA": 0}
    _reparto = _repartir_importes_por_placa(filas)
    # Razón social del grifo por RUC (padrón local primero, SUNAT si no está): corrige filas
    # donde el OCR guardó la dirección impresa como "estación". Una consulta por RUC distinto.
    _rs_por_ruc = await _razones_sociales_por_ruc(filas)
    for f in filas:
        prog = f.get("programa") if f.get("programa") in ("du004", "du007") else "du004"
        patch: dict = {}
        _rs = _rs_por_ruc.get(str(f.get("ruc_emisor") or "").strip())
        if _rs and (f.get("estacion") or "").strip() != _rs:
            if f.get("estacion"):
                patch["estacion_ocr"] = f.get("estacion")
            patch["estacion"] = _rs
            f = {**f, "estacion": _rs}
        if f.get("id") in _reparto:
            patch.update(_reparto[f["id"]])
            f = {**f, **_reparto[f["id"]]}
        if f.get("fecha"):
            prog_fecha = _programa_estricto_por_fecha(f.get("fecha"))
            if prog_fecha in ("du004", "du007") and prog_fecha != prog:
                prog = prog_fecha
                patch["programa"] = prog
                reclasificadas += 1
        clave = _clave(f)
        numeros_sin_esta = vistos - {clave}
        if f.get("numero_documento") and primera.get(clave) != f["id"]:
            numeros_sin_esta = numeros_sin_esta | {clave}   # es una copia posterior → duplicada
        val = _validar_re({**f, "programa": prog}, placas_flota=placas, categoria_por_placa=cats,
                          numeros_existentes=numeros_sin_esta, programa=prog)
        por_estado[val["estado"]] = por_estado.get(val["estado"], 0) + 1
        if val["estado"] != f.get("validacion_estado"):
            cambiaron += 1
        _imp = _importe_por_placa(f)
        if _imp is not None:
            patch["importe_total"] = _imp
            f = {**f, "importe_total": _imp}
        _pd = _precio_derivado(f)
        if _pd is not None:
            patch["precio_unitario"] = _pd
            patch["precio_derivado"] = True
            f = {**f, "precio_unitario": _pd}
        patch.update({"validacion": val, "validacion_estado": val["estado"],
                      "requiere_revision": val["requiere_revision"],
                      "periodo_du007": val.get("periodo_du007") if prog == "du007" else None})
        if promover and f.get("status") == "draft" and not f.get("invalida") and val["estado"] != "RECHAZADA" \
                and all(f.get(k) for k in ("fecha", "numero_documento", "galones", "importe_total", "ruc_emisor", "placa")):
            patch.update({"status": "confirmed", "confirmed_at": datetime.now(timezone.utc).isoformat(),
                          "confirmado_por": "admin_revalidar"})
            promovidas += 1
        await db.consumos_subsidio.update_one({"id": f["id"]}, {"$set": patch})

    return {"revisadas": len(filas), "cambiaron": cambiaron, "promovidas": promovidas,
            "reclasificadas": reclasificadas, "por_estado": por_estado}


@subsidio_router.post("/admin/subsidio/revalidar-todos")
async def admin_revalidar_todos(programa: Optional[str] = None, promover: int = 1,
                                _: dict = Depends(_require_admin_enered)):
    """Corre la revalidación en bloque sobre TODAS las empresas con facturas de subsidio.
    Para limpiar producción de una vez: estados viejos, decreto por fecha, duplicadas y
    borradores completos (que pasan a confirmados si promover=1)."""
    prog_match = {"programa": "du007"} if programa == "du007" else (
        {"programa": {"$ne": "du007"}} if programa == "du004" else {})
    uids_con_facturas = await db.consumos_subsidio.distinct("user_id", prog_match)
    hechos: set = set()
    total = {"empresas": 0, "revisadas": 0, "cambiaron": 0, "promovidas": 0, "reclasificadas": 0,
             "por_estado": {"CONFORME": 0, "OBSERVADA": 0, "RECHAZADA": 0}, "errores": []}
    for uid in uids_con_facturas:
        if not uid or uid in hechos:
            continue
        u = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0})
        if not u:
            continue
        try:
            uids = await _get_company_uids(u)
            hechos.update(uids)
            filas = await db.consumos_subsidio.find({**_own_q(u, uids), **prog_match}, {"_id": 0}).to_list(5000)
            if not filas:
                continue
            r = await _revalidar_expediente(u, uids, filas, promover=bool(promover))
            total["empresas"] += 1
            for k in ("revisadas", "cambiaron", "promovidas", "reclasificadas"):
                total[k] += r[k]
            for k, v in r["por_estado"].items():
                total["por_estado"][k] = total["por_estado"].get(k, 0) + v
        except Exception as e:
            total["errores"].append({"user_id": uid, "error": str(e)[:120]})
    return total


@subsidio_router.get("/admin/subsidio/expedientes/{user_id}/invoices/zip")
async def admin_zip_invoices(
    user_id: str,
    placa: str = "", desde: str = "", hasta: str = "", q: str = "", empresa: str = "", programa: Optional[str] = None,
    _: dict = Depends(_require_admin_enered),
):
    """Descarga en UN ZIP los archivos de las facturas del expediente (respetando los
    filtros), cada uno nombrado PLACA_NroDoc.ext, más un resumen.xlsx con totales.
    Agiliza armar el paquete operativo para la ATU."""
    import zipfile
    from zipstream import ZipStream
    from fastapi.responses import StreamingResponse

    # Todas las cuentas de la MISMA empresa (las facturas pueden estar repartidas entre ellas).
    t_user = await db.users.find_one({"id": user_id}, {"_id": 0, "id": 1, "empresa": 1, "ruc": 1,
                                                       "empresas_asignadas": 1}) or {"id": user_id}
    t_user = _usuario_en_empresa(t_user, empresa)
    uids = await _get_company_uids(t_user)
    filtro = _own_q(t_user, uids)
    # Sin esto, el ZIP del panel DU 007 bajaba también las facturas del DU 004 (y viceversa):
    # no filtraba por programa como sí hace la lista y el detalle del expediente.
    if programa == "du007":
        filtro["programa"] = "du007"
    elif programa == "du004":
        filtro["programa"] = {"$ne": "du007"}
    if placa:
        filtro["placa"] = placa.upper().strip()
    if desde or hasta:
        rango = {}
        if desde:
            rango["$gte"] = desde
        if hasta:
            rango["$lte"] = hasta
        filtro["fecha"] = rango
    if q:
        rq = {"$regex": _re.escape(q.strip()), "$options": "i"}
        filtro["$or"] = [{"numero_documento": rq}, {"estacion": rq}, {"ruc_emisor": rq}]

    rows = await db.consumos_subsidio.find(filtro, {"_id": 0}).sort("fecha", 1).to_list(5000)
    if not rows:
        raise HTTPException(status_code=404, detail="No hay facturas con esos filtros")

    from openpyxl import Workbook
    ws_wb = Workbook()
    ws = ws_wb.active
    ws.title = "Facturas"
    ws.append(["Fecha", "Placa", "Producto", "Galones", "Importe (S/)", "RUC emisor",
               "Estación", "N° Doc", "Archivo en ZIP", "Estado"])
    tot_gal = tot_imp = 0.0
    con_archivo = sin_archivo = 0

    # Un solo listado del bucket para resolver los archivos de TODAS las facturas
    # (existencia por caché, sin descargar nada todavía).
    _keys = storage.list_keys("subsidio/")
    usados: set = set()
    archivos: list = []  # (nombre_en_zip, key) a transmitir bajo demanda
    for r in rows:
        nombre_zip = ""
        key = await _buscar_key_archivo(r, keys_cache=_keys)
        if key:
            fname = r.get("factura_filename") or "archivo"
            ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else "pdf"
            base = f"{r.get('placa') or 'SIN-PLACA'}_{(r.get('numero_documento') or r.get('id'))}".replace("/", "-")
            nombre_zip = f"{base}.{ext}"
            k2 = 2
            while nombre_zip in usados:
                nombre_zip = f"{base}_{k2}.{ext}"; k2 += 1
            usados.add(nombre_zip)
            archivos.append((nombre_zip, key))
            con_archivo += 1
        else:
            sin_archivo += 1
            # Distinguir el registro digitado a mano (nunca tuvo archivo) del archivo
            # que debía existir y no se encontró en el almacenamiento.
            if r.get("factura_storage_key") or (r.get("factura_filename") and not str(r.get("factura_filename")).startswith("manual_entry")):
                nombre_zip = "(archivo no encontrado en almacenamiento)"
            else:
                nombre_zip = "(sin archivo — registro manual)"
        g = float(r.get("galones") or 0)
        imp = float(r.get("importe_total") or 0)
        tot_gal += g
        tot_imp += imp
        ws.append([r.get("fecha"), r.get("placa"), r.get("producto"), g, imp,
                   r.get("ruc_emisor"), r.get("estacion"), r.get("numero_documento"),
                   nombre_zip, r.get("status")])
    ws.append([])
    ws.append(["TOTAL", "", "", round(tot_gal, 3), round(tot_imp, 2), "", "",
               f"{len(rows)} facturas", f"{con_archivo} con archivo / {sin_archivo} sin archivo", ""])
    xbuf = io.BytesIO()
    ws_wb.save(xbuf)
    resumen_bytes = xbuf.getvalue()

    # ZIP en STREAMING: el navegador empieza a bajar de inmediato y cada archivo se
    # lee de R2 bajo demanda (un archivo a la vez → memoria baja, sin temp gigante ni
    # bloqueo del event loop). Clave para expedientes con cientos de comprobantes.
    zs = ZipStream(compress_type=zipfile.ZIP_DEFLATED)
    zs.add(data=resumen_bytes, arcname="resumen.xlsx")

    def _leer(k):
        try:
            yield storage.get_object_bytes(k)
        except Exception as e:
            logger.warning(f"[zip_invoices] error leyendo {k}: {e}")

    for arcname, key in archivos:
        zs.add(data=_leer(key), arcname=arcname)

    etiqueta = f"facturas_{(placa or 'todas')}_{desde or 'inicio'}_{hasta or 'fin'}.zip".replace(" ", "")
    return StreamingResponse(
        zs, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{etiqueta}"'})


@subsidio_router.put("/admin/subsidio/invoices/{invoice_id}/usar-archivo")
async def admin_vincular_archivo_invoice(invoice_id: str, payload: dict,
                                         _: dict = Depends(_require_admin_enered)):
    """Vincula a una factura (p. ej. digitada a mano) el archivo ORIGINAL del cliente,
    tomándolo de otra factura subida ({"desde_invoice_id"}) o de un documento del
    expediente ({"doc_id"}). Desde entonces el visor muestra el archivo real."""
    destino = await db.consumos_subsidio.find_one({"id": invoice_id})
    if not destino:
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    key = filename = ctype = None
    if payload.get("desde_invoice_id"):
        src = await db.consumos_subsidio.find_one({"id": payload["desde_invoice_id"]})
        if not src or not src.get("factura_storage_key"):
            raise HTTPException(status_code=404, detail="La factura origen no tiene archivo")
        key, filename = src["factura_storage_key"], src.get("factura_filename")
        ctype = src.get("factura_content_type")
    elif payload.get("doc_id"):
        src = await db.subsidio_documents.find_one({"id": payload["doc_id"]})
        if not src or not src.get("storage_key"):
            raise HTTPException(status_code=404, detail="El documento origen no tiene archivo")
        key, filename, ctype = src["storage_key"], src.get("filename"), src.get("content_type")
    else:
        raise HTTPException(status_code=400, detail="Falta desde_invoice_id o doc_id")

    await db.consumos_subsidio.update_one({"id": invoice_id}, {"$set": {
        "factura_storage_key": key,
        "factura_filename": filename or "archivo_cliente",
        "factura_content_type": ctype or "application/pdf",
        "archivo_vinculado_desde": payload.get("desde_invoice_id") or payload.get("doc_id"),
        "archivo_vinculado_at": datetime.now(timezone.utc).isoformat(),
    }})
    return {"ok": True, "filename": filename}


@subsidio_router.get("/admin/subsidio/documents/{doc_id}/download")
async def admin_download_document(doc_id: str, dl: int = 0, _: dict = Depends(_require_admin_enered)):
    """Admin descarga cualquier documento del expediente. dl=1 fuerza descarga (attachment)."""
    d = await db.subsidio_documents.find_one({"id": doc_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    return storage.download_response(d["storage_key"], d["filename"],
                                     d.get("content_type", "application/octet-stream"),
                                     inline=not dl)


@subsidio_router.put("/admin/subsidio/expedientes/{user_id}/stage")
async def admin_update_stage(
    user_id: str,
    payload: StageUpdateIn,
    programa: Optional[str] = None,
    _: dict = Depends(_require_admin_enered),
):
    """Admin cambia la etapa del expediente del cliente_subsidio.
    Etapas: solicitud_enviada → evaluacion_atu → aprobada → abonado_en_cuenta
    `programa`: du007 escribe en los campos propios del DU 007 (no comparte etapa con el DU 004).
    """
    u = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    if not u:
        raise HTTPException(status_code=404, detail="Expediente no encontrado")
    now = datetime.now(timezone.utc).isoformat()
    campo, campo_at = ("expediente_stage_du007", "expediente_stage_du007_updated_at") if programa == "du007" \
        else ("expediente_stage", "expediente_stage_updated_at")
    await db.users.update_one(
        {"id": user_id},
        {"$set": {campo: payload.stage, campo_at: now}},
    )
    return {"ok": True, "expediente_stage": payload.stage, "updated_at": now}


@subsidio_router.post("/admin/subsidio/invoices/releer-qr")
async def admin_invoices_releer_qr(empresa: Optional[str] = None, dry: int = 1, limit: int = 40,
                                   user: dict = Depends(_require_admin_enered)):
    """
    Relee el QR SUNAT de las facturas ya guardadas y completa SOLO los campos vacíos
    (importe total, IGV, RUC adquirente). No pisa nada que el cliente haya escrito.
    Sirve para corregir cargas hechas cuando el lector no entendía el QR "SERIE-NÚMERO".
    dry=1 solo reporta; dry=0 aplica.
    """
    from services.extractor_comprobante import extraer_de_qr as _qr
    q = {"$or": [{"importe_total": {"$in": [None, 0, ""]}}, {"importe_total": {"$exists": False}}],
         "factura_storage_key": {"$nin": [None, ""]}}
    if empresa:
        q["empresa"] = empresa
    import asyncio as _asyncio
    pendientes = await db.consumos_subsidio.count_documents(q)
    cur = db.consumos_subsidio.find(q, {"_id": 0, "id": 1, "empresa": 1, "numero_documento": 1, "fecha": 1,
                                        "factura_storage_key": 1, "importe_total": 1, "igv": 1, "ruc_emisor": 1}
                                    ).sort("created_at", -1).limit(max(1, min(limit, 500)))
    revisadas, completadas, detalle = 0, 0, []
    async for d in cur:
        revisadas += 1
        try:
            content = await _asyncio.wait_for(_asyncio.to_thread(storage.get_object_bytes, d["factura_storage_key"]), 20)
            qr = (await _asyncio.wait_for(_asyncio.to_thread(_qr, content), 30)) if content else None
        except Exception:
            qr = None
        if not qr or not qr.get("importe_total"):
            detalle.append({"id": d["id"], "empresa": d.get("empresa"), "comprobante": d.get("numero_documento"),
                            "accion": "omitida: QR no legible (imagen/escaneo sin QR nítido)" if not qr
                            else "omitida: el QR no trae importe"})
            continue
        # Seguridad: el QR debe corresponder al mismo comprobante y al mismo grifo.
        def _sn(x):  # (serie, número sin ceros a la izquierda) para comparar F005-0012505 con F005-00012505
            m = _re.match(r"^\s*([A-Z0-9]+)\s*-+\s*0*(\d+)\s*$", str(x or "").upper())
            return (m.group(1), int(m.group(2))) if m else None
        mismo_num = _sn(qr.get("numero_documento")) is not None and _sn(qr.get("numero_documento")) == _sn(d.get("numero_documento"))
        mismo_ruc = (qr.get("ruc_emisor") == d.get("ruc_emisor"))
        vacia = not (d.get("numero_documento") or d.get("ruc_emisor"))  # nunca se leyó nada: el QR completa todo
        if vacia:
            upd = {"importe_total": qr["importe_total"], "ruc_emisor": qr["ruc_emisor"],
                   "numero_documento": qr.get("numero_documento"), "serie": qr.get("serie"), "numero": qr.get("numero")}
            if qr.get("fecha") and not d.get("fecha"):
                upd["fecha"] = qr["fecha"]
            if qr.get("igv"):
                upd["igv"] = qr["igv"]
            if qr.get("ruc_adquirente"):
                upd["ruc_adquirente"] = qr["ruc_adquirente"]
            detalle.append({"id": d["id"], "empresa": d.get("empresa"), "comprobante": qr.get("numero_documento"),
                            "accion": ("aplicado (factura sin datos → completada desde el QR)" if not dry
                                       else "se aplicaría (factura sin datos → completar desde el QR)"), **upd})
            completadas += 1
            if not dry:
                await db.consumos_subsidio.update_one({"id": d["id"]}, {"$set": {**upd, "importe_fuente": "QR (relectura)"}})
                await _revalidar_tras_cambio(d["id"])
            continue
        if not (mismo_num and mismo_ruc):
            detalle.append({"id": d["id"], "empresa": d.get("empresa"), "comprobante": d.get("numero_documento"),
                            "qr": qr.get("numero_documento"), "ruc_qr": qr.get("ruc_emisor"), "ruc": d.get("ruc_emisor"),
                            "accion": "omitida: el QR no coincide con lo registrado"})
            continue
        upd = {"importe_total": qr["importe_total"]}
        if qr.get("igv") and not d.get("igv"):
            upd["igv"] = qr["igv"]
        if qr.get("ruc_adquirente"):
            upd["ruc_adquirente"] = qr["ruc_adquirente"]
        detalle.append({"id": d["id"], "empresa": d.get("empresa"), "comprobante": d.get("numero_documento"),
                        "accion": ("aplicado" if not dry else "se aplicaría"), **upd})
        completadas += 1
        if not dry:
            await db.consumos_subsidio.update_one({"id": d["id"]}, {"$set": {**upd, "importe_fuente": "QR (relectura)"}})
            await _revalidar_tras_cambio(d["id"])
    return {"ok": True, "dry": bool(dry), "pendientes": pendientes, "revisadas": revisadas,
            "completadas": completadas, "detalle": detalle[:200]}


@subsidio_router.get("/admin/subsidio/invoices/{invoice_id}/download")
async def admin_download_invoice(invoice_id: str, dl: int = 0, _: dict = Depends(_require_admin_enered)):
    """Admin descarga o previsualiza el archivo PDF/imagen de una factura de consumo."""
    from urllib.parse import unquote, quote
    from bson import ObjectId
    import re
    from fastapi.responses import Response, HTMLResponse

    clean_id = unquote(str(invoice_id)).strip()
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

    q = {"$or": or_list}

    inv = await db.consumos_subsidio.find_one(q) or await db.invoices.find_one(q) or await db.empresas_invoices.find_one(q)

    def _html_not_found_msg(msg: str):
        return HTMLResponse(
            status_code=200,
            content=f"""
            <html>
                <body style="display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;background-color:#1e1e1e;color:#aaa;">
                    <div style="text-align:center;padding:20px;">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:1rem;color:#777;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="9" y1="15" x2="15" y2="15"></line></svg>
                        <h3 style="color:#eee;margin:0 0 8px 0;">Documento no adjunto</h3>
                        <p style="font-size:13px;margin:0;">{msg}</p>
                    </div>
                </body>
            </html>
            """
        )

    if not inv:
        return _html_not_found_msg(f"La factura <b>{clean_id}</b> no se encuentra en el sistema.")

    # ── PRIORIDAD ABSOLUTA: factura_storage_key ──────────────────────────────
    # Si el registro tiene factura_storage_key, ese es el archivo original del
    # cliente en R2. Se usa directamente, sin búsquedas alternativas ni
    # generación de comprobantes sustitutos.
    if inv.get("factura_storage_key"):
        primary_key = inv["factura_storage_key"]
        logger.info(f"[admin_download_invoice] factura_storage_key encontrada: {primary_key!r}")

        if storage.object_exists(primary_key):
            # CASO 1: key válida → devolver archivo original directamente
            try:
                data = storage.get_object_bytes(primary_key)
            except Exception as exc:
                logger.error(f"[admin_download_invoice] error leyendo R2 key={primary_key!r}: {exc}")
                return _html_not_found_msg(f"Error al leer el archivo original (key: {primary_key!r})")

            fname = inv.get("factura_filename") or inv.get("pdf_filename") or inv.get("filename")
            n_doc = inv.get("numero_documento") or inv.get("n_doc") or clean_id
            original = fname or f"{n_doc}.pdf"
            ext = original.split(".")[-1].lower() if "." in original else "pdf"
            safe_ndoc = "".join(c for c in str(n_doc) if c.isalnum() or c == "-")
            dl_name = fname or f"Factura_{safe_ndoc}.{ext}"
            encoded_name = quote(dl_name)

            content_type = inv.get("factura_content_type") or inv.get("content_type")
            if not content_type:
                content_type = "image/jpeg" if ext in ("jpg", "jpeg") else "image/png" if ext == "png" else "application/pdf"

            return Response(
                content=data,
                media_type=content_type,
                headers={"Content-Disposition": f"{'attachment' if dl else 'inline'}; filename*=UTF-8''{encoded_name}"},
            )
        else:
            # CASO 2: key en MongoDB pero objeto no existe en R2 → continuar con búsqueda legacy
            logger.warning(
                f"[admin_download_invoice] factura_storage_key={primary_key!r} no encontrada en R2. "
                f"Continuando con búsqueda legacy de candidatos."
            )
    # ── FIN BLOQUE factura_storage_key; continúa búsqueda legacy ─────────────

    # ── BÚSQUEDA LEGACY ──────────────────────────────────────────────────────
    # Para registros sin factura_storage_key, o cuando factura_storage_key
    # existe pero el objeto no se encontró en R2 (CASO 2).
    candidate_keys = []
    if inv.get("storage_key"): candidate_keys.append(inv["storage_key"])
    if inv.get("pdf_key"): candidate_keys.append(inv["pdf_key"])

    empresa = inv.get("empresa") or ""
    n_doc = inv.get("numero_documento") or inv.get("n_doc") or clean_id
    fname = inv.get("factura_filename") or inv.get("pdf_filename") or inv.get("filename")

    # Cross-reference db.invoices y db.empresas_invoices para llaves alternativas
    if n_doc:
        esc_ndoc = re.escape(n_doc)
        doc_q = {"$or": [{"n_doc": {"$regex": f"^{esc_ndoc}$", "$options": "i"}}, {"numero_documento": {"$regex": f"^{esc_ndoc}$", "$options": "i"}}]}
        alt_docs = await db.invoices.find(doc_q).to_list(10) + await db.empresas_invoices.find(doc_q).to_list(10)
        for alt in alt_docs:
            if alt.get("factura_storage_key"): candidate_keys.append(alt["factura_storage_key"])
            if alt.get("storage_key"): candidate_keys.append(alt["storage_key"])
            if alt.get("pdf_key"): candidate_keys.append(alt["pdf_key"])
            alt_fname = alt.get("factura_filename") or alt.get("pdf_filename")
            if alt_fname:
                candidate_keys.append(f"invoices/{empresa}/{alt_fname}")
                candidate_keys.append(f"subsidio/{alt_fname}")
                candidate_keys.append(alt_fname)

    if fname:
        candidate_keys.append(f"invoices/{empresa}/{fname}")
        candidate_keys.append(f"subsidio/{fname}")
        candidate_keys.append(f"tmp_admin/{fname}")
        candidate_keys.append(fname)

    if n_doc:
        candidate_keys.append(f"invoices/{empresa}/{n_doc}.pdf")
        candidate_keys.append(f"subsidio/{n_doc}.pdf")
        candidate_keys.append(f"tmp_admin/{n_doc}.pdf")
        candidate_keys.append(f"{n_doc}.pdf")

    inv_id = inv.get("id") or clean_id
    if inv_id:
        candidate_keys.append(f"subsidio/facturas/{inv_id}.pdf")
        candidate_keys.append(f"subsidio/facturas/{inv_id}.png")
        candidate_keys.append(f"subsidio/facturas/{inv_id}.jpg")
        candidate_keys.append(f"subsidio/facturas/{inv_id}.jpeg")
        candidate_keys.append(f"invoices/{empresa}/{inv_id}.pdf")
        candidate_keys.append(f"invoices/{empresa}/{inv_id}.png")
        candidate_keys.append(f"invoices/{empresa}/{inv_id}.jpg")
        candidate_keys.append(f"invoices/{empresa}/{inv_id}.jpeg")
        candidate_keys.append(f"subsidio/{inv_id}.pdf")
        candidate_keys.append(f"{inv_id}.pdf")

    valid_key = None
    for k in candidate_keys:
        if k and storage.object_exists(k):
            valid_key = k
            break

    if not valid_key and n_doc:
        suffix = f"{n_doc}.pdf"
        try:
            valid_key = storage.find_by_suffix(suffix, prefix="subsidio/")
            if not valid_key:
                valid_key = storage.find_by_suffix(suffix, prefix="invoices/")
        except Exception:
            pass

    # Fallback robusto: el archivo original del cliente se guarda en
    # subsidio/{user_id}/factura_subsidio/{hash}-{factura_filename}. Buscamos por el
    # NOMBRE DE ARCHIVO real (que es confiable), no por numero_documento, que puede
    # venir corrupto del OCR. Esto localiza la factura aunque factura_storage_key
    # apunte a una key inexistente.
    if not valid_key:
        uid = inv.get("user_id")
        # Varias pistas: nombre real, nombre sin espacios (el archivo se saneó al subir)
        # y el número de documento. La primera que aparezca en R2 gana.
        candidatos = [c for c in [
            fname,
            (fname or "").replace(" ", ""),
            f"{n_doc}.pdf" if n_doc else "",
        ] if c]
        for cand in candidatos:
            try:
                if uid:
                    valid_key = storage.find_by_suffix(cand, prefix=f"subsidio/{uid}/")
                if not valid_key:
                    valid_key = storage.find_by_suffix(cand, prefix="subsidio/")
            except Exception:
                valid_key = None
            if valid_key:
                break

    if not valid_key:
        # CASO 4a: registro MANUAL (el admin lo digitó; nunca hubo archivo) → se genera un
        # PDF de REGISTRO INTERNO, claramente rotulado como tal. NO imita una factura:
        # es la ficha de los datos digitados, para poder revisarla/descargarla.
        es_manual = (not inv.get("factura_storage_key")) and (
            (inv.get("factura_filename") or "").startswith("manual_entry")
            or inv.get("raw_ocr_response") == "Manual Entry by Admin"
        )
        if es_manual:
            try:
                from reportlab.lib.pagesizes import A4
                from reportlab.pdfgen import canvas as _canvas
                buf = io.BytesIO()
                p = _canvas.Canvas(buf, pagesize=A4)
                w, h = A4
                p.setFillColorRGB(0.42, 0.16, 0.85)
                p.rect(0, h - 70, w, 70, fill=True, stroke=False)
                p.setFillColorRGB(1, 1, 1)
                p.setFont("Helvetica-Bold", 16)
                p.drawString(40, h - 45, "ENERED · Registro manual de consumo")
                p.setFillColorRGB(0.75, 0.2, 0.2)
                p.setFont("Helvetica-Bold", 11)
                p.drawString(40, h - 95, "DOCUMENTO INTERNO — NO es el comprobante original del grifo.")
                p.setFillColorRGB(0.2, 0.2, 0.2)
                p.setFont("Helvetica", 10)
                y = h - 130
                for etiqueta, valor in [
                    ("Empresa", inv.get("empresa")), ("N° de documento", n_doc),
                    ("Fecha", inv.get("fecha")), ("Placa", inv.get("placa")),
                    ("Producto", inv.get("producto")), ("Galones", inv.get("galones")),
                    ("Importe total (S/)", inv.get("importe_total")),
                    ("RUC del emisor", inv.get("ruc_emisor")), ("Estación", inv.get("estacion")),
                    ("Ciudad", inv.get("ciudad")), ("Registrado", inv.get("created_at", "")[:10]),
                    ("Origen", "Digitado manualmente por el equipo ENERED"),
                ]:
                    p.setFont("Helvetica-Bold", 10)
                    p.drawString(40, y, f"{etiqueta}:")
                    p.setFont("Helvetica", 10)
                    p.drawString(170, y, str(valor if valor not in (None, "") else "—"))
                    y -= 20
                p.setFont("Helvetica-Oblique", 8)
                p.setFillColorRGB(0.5, 0.5, 0.5)
                p.drawString(40, 40, "Generado por ENERED como constancia del registro manual. "
                                     "Para la ATU se requiere el comprobante original.")
                p.showPage(); p.save()
                pdf = buf.getvalue()
                return Response(content=pdf, media_type="application/pdf",
                                headers={"Content-Disposition":
                                         f"{'attachment' if dl else 'inline'}; filename*=UTF-8''Registro_manual_{quote(str(n_doc))}.pdf"})
            except Exception as e:
                logger.error(f"[admin_download_invoice] error generando registro manual: {e}")
        # CASO 4b: debía tener archivo y no se encontró → 404 informativo (no se inventa nada).
        logger.warning(f"[admin_download_invoice] no se encontró ningún archivo para id={clean_id!r}")
        return _html_not_found_msg(
            f"No se encontró el archivo original de la factura <b>{n_doc}</b>. "
            f"El documento no fue localizado en el sistema de almacenamiento."
        )

    try:
        data = storage.get_object_bytes(valid_key)
    except Exception:
        return _html_not_found_msg("Error al leer el archivo en el servidor.")

    original = fname or f"{n_doc}.pdf"
    ext = original.split(".")[-1].lower() if "." in original else "pdf"
    safe_ndoc = "".join(c for c in str(n_doc) if c.isalnum() or c == "-")
    dl_name = f"Factura_{safe_ndoc}.{ext}"
    encoded_name = quote(dl_name)

    content_type = inv.get("factura_content_type") or inv.get("content_type")
    if not content_type:
        content_type = "image/jpeg" if ext in ("jpg", "jpeg") else "image/png" if ext == "png" else "application/pdf"

    return Response(
        content=data,
        media_type=content_type,
        headers={"Content-Disposition": f"{'attachment' if dl else 'inline'}; filename*=UTF-8''{encoded_name}"},
    )


@subsidio_router.delete("/admin/subsidio/documents/{doc_id}")
async def admin_delete_document(doc_id: str, _: dict = Depends(_require_admin_enered)):
    """Admin elimina un documento (empresa o flota) del expediente."""
    d = await db.subsidio_documents.find_one({"id": doc_id})
    if not d:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    if d.get("storage_key"):
        storage.delete_object(d["storage_key"])
    await db.subsidio_documents.delete_one({"id": doc_id})
    return {"status": "ok"}


@subsidio_router.delete("/admin/subsidio/invoices/{invoice_id}")
async def admin_delete_invoice(invoice_id: str, _: dict = Depends(_require_admin_enered)):
    """Admin elimina una factura de consumo. Se descuenta del historial del cliente.

    REGLA DE SEGURIDAD R2:
    El archivo físico en R2 (factura_storage_key) puede estar referenciado desde
    múltiples registros (consumos_subsidio y/o db.invoices). Solo se borra el
    objeto de R2 si NINGÚN otro registro en NINGUNA de las dos colecciones lo
    referencia después de eliminar este registro.
    """
    inv = await db.consumos_subsidio.find_one({"id": invoice_id})
    if not inv:
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    # 1. Eliminar el registro de MongoDB primero
    await db.consumos_subsidio.delete_one({"id": invoice_id})

    # 2. Evaluar si el objeto R2 puede eliminarse de forma segura
    key = inv.get("factura_storage_key")
    if key:
        # Contar referencias restantes en AMBAS colecciones
        refs_consumos = await db.consumos_subsidio.count_documents({"factura_storage_key": key})
        refs_invoices = await db.invoices.count_documents({"factura_storage_key": key})
        total_refs = refs_consumos + refs_invoices
        if total_refs == 0:
            # Ningún otro registro usa este archivo → se puede borrar
            try:
                storage.delete_object(key)
                logger.info(f"[admin_delete_invoice] R2 key eliminada (sin referencias): {key!r}")
            except Exception as exc:
                logger.warning(f"[admin_delete_invoice] No se pudo borrar R2 key={key!r}: {exc}")
        else:
            # Hay otros registros que usan este archivo → NO borrar
            logger.info(
                f"[admin_delete_invoice] R2 key conservada: {key!r} "
                f"({refs_consumos} ref(s) en consumos_subsidio, "
                f"{refs_invoices} ref(s) en invoices)"
            )

    return {"status": "ok"}


@subsidio_router.put("/admin/subsidio/expedientes/{user_id}/representante")
async def admin_update_representante(
    user_id: str,
    payload: RepresentanteUpdateIn,
    _: dict = Depends(_require_admin_enered),
):
    u = await db.users.find_one({"id": user_id})
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "contacto": payload.representante,
            "representante": payload.representante
        }}
    )
    return {"ok": True, "representante": payload.representante}


@subsidio_router.post("/admin/subsidio/reordenar-multiempresa/{user_id}")
async def admin_reordenar_multiempresa(user_id: str, dry: int = 0, _: dict = Depends(_require_admin_enered)):
    """Reordena el expediente de un usuario multi-empresa: cada documento/vehículo/factura
    con placa se asigna a la empresa dueña de esa placa según el MTC (cada empresa tiene
    placas distintas). Los documentos de empresa sin placa se mueven si el nombre del
    archivo menciona a otra de sus empresas. También corrige nombres de empresas_asignadas
    que no calzan con la empresa real (p.ej. 'S.R.L.' vs 'SRL'). Con ?dry=1 solo reporta."""
    import re as _re
    import mtc as _mtc

    u = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    asignadas = u.get("empresas_asignadas") or []
    if len(asignadas) < 2:
        raise HTTPException(status_code=400, detail="El usuario no es multi-empresa")

    def _norm_emp(s):
        return _re.sub(r"[^A-Z0-9]", "", (s or "").upper())

    # 0) Canonizar nombres de asignadas contra las empresas reales del sistema.
    # La forma que un usuario real usa como empresa base MANDA sobre la de empresas_config
    # (p.ej. 'SERVI TRANSP NASCA SRL' del usuario vs 'S.R.L.' en otra parte): así los
    # documentos movidos quedan visibles para ese usuario.
    reales_cfg = {r for r in await db.empresas_config.distinct("empresa") if r}
    reales_users = {r for r in await db.users.distinct("empresa") if r}
    canon = {_norm_emp(r): r for r in reales_cfg}
    canon.update({_norm_emp(r): r for r in reales_users})
    nombres_corregidos = []
    for a in asignadas:
        real = canon.get(_norm_emp(a.get("empresa")))
        if real and real != a.get("empresa"):
            nombres_corregidos.append({"antes": a["empresa"], "despues": real})
            a["empresa"] = real
    if nombres_corregidos and not dry:
        await db.users.update_one({"id": user_id}, {"$set": {"empresas_asignadas": asignadas}})

    # 1) placa → empresa vía MTC (por el RUC de cada empresa asignada).
    def _norm_placa(p):
        return _re.sub(r"[^A-Z0-9]", "", (p or "").upper())
    placa_a_empresa: dict = {}
    errores_mtc = []
    for a in asignadas:
        ruc, emp = (a.get("ruc") or "").strip(), a.get("empresa")
        if not ruc or not emp:
            continue
        try:
            m = await _mtc.consultar("ruc", ruc)
            for aut in m.get("autorizaciones", []):
                for v in aut.get("vehiculos", []):
                    pn = _norm_placa(v.get("placa"))
                    if pn:
                        placa_a_empresa.setdefault(pn, emp)
        except Exception as e:
            errores_mtc.append({"empresa": emp, "ruc": ruc, "error": str(e)[:120]})

    movimientos = []
    cols_con_placa = ["subsidio_documents", "subsidio_vehicles", "consumos_subsidio"]
    for c in cols_con_placa:
        async for d in db[c].find({"user_id": user_id, "placa": {"$nin": [None, ""]}},
                                  {"_id": 0, "id": 1, "placa": 1, "empresa": 1, "filename": 1}):
            destino = placa_a_empresa.get(_norm_placa(d.get("placa")))
            if destino and destino != d.get("empresa"):
                movimientos.append({"col": c, "id": d.get("id"), "placa": d.get("placa"),
                                    "de": d.get("empresa"), "a": destino,
                                    "archivo": d.get("filename", "")})
                if not dry:
                    await db[c].update_one({"id": d["id"]}, {"$set": {"empresa": destino}})
                    if c == "consumos_subsidio":
                        # Espejo en facturación (mismo id): debe seguir a la misma empresa.
                        await db.invoices.update_one({"id": d["id"]}, {"$set": {"empresa": destino}})

    # 1b) Sincronizar el espejo db.invoices con consumos_subsidio (mismo id): si un
    # movimiento anterior solo cambió el consumo, el espejo se quedó en la empresa vieja
    # y el expediente lo mostraba como factura "extra" de esa empresa.
    async for cs in db.consumos_subsidio.find({"user_id": user_id, "empresa": {"$nin": [None, ""]}},
                                              {"_id": 0, "id": 1, "empresa": 1, "placa": 1}):
        esp = await db.invoices.find_one({"id": cs["id"]}, {"_id": 0, "empresa": 1})
        if esp and esp.get("empresa") != cs["empresa"]:
            movimientos.append({"col": "invoices(espejo)", "id": cs["id"], "placa": cs.get("placa"),
                                "de": esp.get("empresa"), "a": cs["empresa"], "archivo": ""})
            if not dry:
                await db.invoices.update_one({"id": cs["id"]}, {"$set": {"empresa": cs["empresa"]}})

    # 2) Docs de empresa sin placa: mover si el nombre del archivo menciona a OTRA empresa.
    genericas = {"TRANSPORTES", "TRANSPORTE", "TRANSP", "IMPORTACIONES", "LOGISTICOS", "LOGISTICA",
                 "OPERACIONES", "CONSTRUCCIONES", "EMPRESA", "SRL", "SAC", "EIRL", "CIA", "P"}
    tokens_emp = {}
    for a in asignadas:
        toks = {t for t in _re.sub(r"[^A-Z0-9 ]", " ", (a.get("empresa") or "").upper()).split()
                if len(t) >= 4 and t not in genericas}
        if toks:
            tokens_emp[a["empresa"]] = toks
    async for d in db.subsidio_documents.find({"user_id": user_id, "$or": [{"placa": None}, {"placa": ""}]},
                                              {"_id": 0, "id": 1, "empresa": 1, "filename": 1, "categoria": 1}):
        fname = (d.get("filename") or "").upper()
        for emp, toks in tokens_emp.items():
            if emp != d.get("empresa") and any(t in fname for t in toks):
                movimientos.append({"col": "subsidio_documents", "id": d.get("id"), "placa": None,
                                    "de": d.get("empresa"), "a": emp, "archivo": d.get("filename", "")})
                if not dry:
                    await db.subsidio_documents.update_one({"id": d["id"]}, {"$set": {"empresa": emp}})
                break

    return {"ok": True, "dry": bool(dry), "nombres_corregidos": nombres_corregidos,
            "placas_mapeadas": len(placa_a_empresa), "errores_mtc": errores_mtc,
            "movimientos": movimientos, "total_movimientos": len(movimientos)}


@subsidio_router.post("/admin/subsidio/backfill-empresa")
async def admin_backfill_empresa(_: dict = Depends(_require_admin_enered)):
    """Asigna empresa a los registros ANTIGUOS del expediente que se grabaron sin ella
    (antes del soporte multi-empresa). Sin empresa, esos registros caen al filtro por
    user_id y un usuario con varias empresas los ve en todas. Se asignan a la empresa
    base del usuario que los subió (el único contexto que existía entonces). Idempotente."""
    cols = ["subsidio_documents", "consumos_subsidio", "subsidio_vehicles",
            "subsidio_bank_accounts", "subsidio_declaraciones", "subsidio_vehicles_excluidos"]
    asignados: dict = {}
    usuarios = 0
    async for u in db.users.find(
        {"role": {"$ne": "admin_enered"}, "empresa": {"$nin": [None, ""]}},
        {"_id": 0, "id": 1, "empresa": 1},
    ):
        usuarios += 1
        for c in cols:
            r = await db[c].update_many(
                {"user_id": u["id"], "$or": [{"empresa": {"$in": [None, ""]}}, {"empresa": {"$exists": False}}]},
                {"$set": {"empresa": u["empresa"]}},
            )
            if r.modified_count:
                asignados[c] = asignados.get(c, 0) + r.modified_count
    return {"ok": True, "usuarios_revisados": usuarios, "asignados": asignados}


@subsidio_router.post("/admin/subsidio/expedientes/{user_id}/vehicles")
async def admin_add_vehicle(
    user_id: str,
    payload: VehicleAdminIn,
    empresa: Optional[str] = None,
    _: dict = Depends(_require_admin_enered),
):
    u = await db.users.find_one({"id": user_id})
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    u = _usuario_en_empresa(u, empresa)
    placa = payload.placa.upper().strip()
    if await db.subsidio_vehicles.find_one({"user_id": user_id, "placa": placa}):
        raise HTTPException(status_code=409, detail="La placa ya está registrada")
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "empresa": u.get("empresa"),
        "placa": placa,
        "categoria": payload.categoria,
        "anio_fabricacion": payload.anio_fabricacion,
        "vigente_desde": payload.vigente_desde,
        "vigente_hasta": payload.vigente_hasta,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.subsidio_vehicles.insert_one(doc)
    doc.pop("_id", None)
    return {"ok": True, "vehicle": doc}


@subsidio_router.put("/admin/subsidio/expedientes/{user_id}/vehicles/{vehicle_id}")
async def admin_update_vehicle(
    user_id: str,
    vehicle_id: str,
    payload: VehicleAdminIn,
    _: dict = Depends(_require_admin_enered),
):
    v = await db.subsidio_vehicles.find_one({"id": vehicle_id})
    if not v:
        raise HTTPException(status_code=404, detail="Vehículo no encontrado")

    t_user = await db.users.find_one({"id": user_id}, {"_id": 0, "id": 1, "empresa": 1}) or {"id": user_id}
    uids = await _get_company_uids(t_user)

    placa_new = payload.placa.upper().strip()
    if placa_new != v["placa"]:
        if await db.subsidio_vehicles.find_one({**_own_q(t_user, uids), "placa": placa_new}):
            raise HTTPException(status_code=409, detail="La nueva placa ya está registrada")

    if placa_new != v["placa"]:
        await db.subsidio_documents.update_many(
            {**_own_q(t_user, uids), "placa": v["placa"]},
            {"$set": {"placa": placa_new}}
        )
        await db.consumos_subsidio.update_many(
            {**_own_q(t_user, uids), "placa": v["placa"]},
            {"$set": {"placa": placa_new}}
        )

    await db.subsidio_vehicles.update_one(
        {"id": vehicle_id},
        {"$set": {
            "placa": placa_new,
            "categoria": payload.categoria,
            "anio_fabricacion": payload.anio_fabricacion,
            "vigente_desde": payload.vigente_desde,
            "vigente_hasta": payload.vigente_hasta,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }}
    )
    return {"ok": True}


@subsidio_router.delete("/admin/subsidio/expedientes/{user_id}/vehicles/{vehicle_id}")
async def admin_delete_vehicle(
    user_id: str,
    vehicle_id: str,
    _: dict = Depends(_require_admin_enered),
):
    v = await db.subsidio_vehicles.find_one({"id": vehicle_id, "user_id": user_id})
    if not v:
        raise HTTPException(status_code=404, detail="Vehículo no encontrado")
    
    placa = v["placa"]
    await db.subsidio_vehicles.delete_one({"id": vehicle_id})
    
    docs = await db.subsidio_documents.find(
        {"user_id": user_id, "placa": placa}, {"_id": 0}
    ).to_list(100)
    for d in docs:
        try:
            storage.delete_object(d["storage_key"])
        except Exception:
            pass
    await db.subsidio_documents.delete_many({"user_id": user_id, "placa": placa})
    return {"ok": True}


_CAMPOS_COMPLETA = ("fecha", "numero_documento", "galones", "importe_total", "ruc_emisor", "placa")


def _programa_estricto_por_fecha(fecha_str) -> Optional[str]:
    """'du004' si la fecha cae en la ventana del DU 004, 'du007' si cae en alguno de sus tres
    periodos, y None si no cae en NINGUNO (p. ej. un año mal tipeado como 2028). Solo con un
    resultado claro se cambia de decreto; si es None, la factura se queda donde está y el
    validador la rechaza como fuera de periodo de SU decreto, sin moverla."""
    from services.validador_facturas import periodo_du007, PERIODO_INICIO, PERIODO_FIN
    from datetime import date as _date
    try:
        f = _date.fromisoformat(str(fecha_str)[:10])
    except (ValueError, TypeError):
        return None
    if periodo_du007(f) is not None:
        return "du007"
    if PERIODO_INICIO <= f <= PERIODO_FIN:
        return "du004"
    return None


def _importe_por_placa(doc: dict) -> Optional[float]:
    """Importe de UNA fila = consumo de esa placa (galones × precio unitario). Una factura con
    varias placas va en varias filas con la misma serie; cada fila lleva su propio importe, no
    el total de la factura repetido (eso multiplicaba el importe del expediente). Si el importe
    guardado difiere más de 1 % del cálculo, se corrige; si no hay precio, se respeta el dado."""
    try:
        g = float(doc.get("galones") or 0)
        p = float(doc.get("precio_unitario") or 0)
    except (TypeError, ValueError):
        return None
    if g <= 0 or p <= 0:
        return None
    calc = round(g * p, 2)
    try:
        actual = float(doc.get("importe_total") or 0)
    except (TypeError, ValueError):
        actual = 0.0
    if actual <= 0 or abs(actual - calc) > max(1.0, calc * 0.01):
        return calc
    return None


async def _razones_sociales_por_ruc(filas: list, max_rucs: int = 40) -> dict:
    """{ruc_emisor: razón social} para los RUC de emisor presentes en `filas`: padrón OSINERGMIN
    (colección local, rápido) y, si el RUC no está, ficha SUNAT (con caché en memoria y timeout
    corto para no frenar la pantalla). Devuelve solo los RUC con nombre conocido."""
    import asyncio as _aio
    from services.padron_grifos import buscar_por_ruc as _bpr
    rucs = [r for r in {str(f.get("ruc_emisor") or "").strip() for f in filas} if len(r) == 11 and r.isdigit()][:max_rucs]
    out = {}
    for r in rucs:
        try:
            g = await _bpr(db, r)
            rs = ((g or {}).get("razon_social") or "").strip() if (g or {}).get("inscrito") else ""
            if not rs:
                ficha = await _aio.wait_for(_sunat_ficha(r), timeout=4)
                rs = ((ficha or {}).get("nombre") or "").strip()
            if rs:
                out[r] = rs
        except Exception:
            continue
    return out


def _precio_derivado(doc: dict) -> Optional[float]:
    """Precio unitario = importe ÷ galones cuando la fila no lo trae (OCR/QR/Excel suelen dar
    total y galones sin precio). Devuelve None si ya tiene precio o faltan datos."""
    try:
        if float(doc.get("precio_unitario") or 0) > 0:
            return None
        g = float(doc.get("galones") or 0)
        imp = float(doc.get("importe_total") or 0)
    except (TypeError, ValueError):
        return None
    if g <= 0 or imp <= 0:
        return None
    return round(imp / g, 4)


def _completar_precio(doc: dict) -> dict:
    """Aplica _precio_derivado sobre el dict (marca precio_derivado=True). Devuelve el mismo dict."""
    p = _precio_derivado(doc)
    if p is not None:
        doc["precio_unitario"] = p
        doc["precio_derivado"] = True
    return doc


def _repartir_importes_por_placa(filas: list) -> dict:
    """Facturas con VARIAS placas cargadas como varias filas (misma serie) donde cada fila trae el
    TOTAL de la factura repetido y sin precio unitario (CASALI: S/ 20,661 en 14 filas → S/ 289 mil
    de un solo comprobante). Si ≥2 filas del mismo comprobante comparten el mismo importe y no
    tienen precio, se reparte ese importe en proporción a los galones de cada fila.
    Devuelve {id: {"importe_total", "precio_unitario", "importe_factura"}} solo para las filas
    a corregir (las que ya tienen precio las corrige _importe_por_placa)."""
    grupos: dict = {}
    for f in filas:
        try:
            g = float(f.get("galones") or 0)
            imp = float(f.get("importe_total") or 0)
            precio = float(f.get("precio_unitario") or 0)
        except (TypeError, ValueError):
            continue
        num = str(f.get("numero_documento") or "").strip().upper()
        if not num or g <= 0 or imp <= 0 or precio > 0 or not f.get("id"):
            continue
        k = (str(f.get("ruc_emisor") or "").strip(), num, round(imp, 2))
        grupos.setdefault(k, []).append((f["id"], g))
    out = {}
    for (_, _, total), miembros in grupos.items():
        if len(miembros) < 2:
            continue
        suma_gal = sum(g for _, g in miembros)
        if suma_gal <= 0:
            continue
        precio = total / suma_gal
        for fid, g in miembros:
            out[fid] = {"importe_total": round(total * g / suma_gal, 2), "precio_unitario": round(precio, 4),
                        "importe_factura": total}
    return out


def _completitud(o: dict) -> int:
    return sum(1 for k in _CAMPOS_COMPLETA if o.get(k))


def _copia_mejor(a: dict, b: dict) -> bool:
    """¿La copia `a` debe considerarse la válida frente a `b`? Más completa gana; en empate,
    la cargada primero."""
    ca, cb = _completitud(a), _completitud(b)
    if ca != cb:
        return ca > cb
    return str(a.get("created_at") or "") < str(b.get("created_at") or "")


async def _revalidar_tras_cambio(doc_id: str) -> None:
    """Después de que un proceso en bloque (relectura de QR, carga masiva…) complete datos de un
    consumo, vuelve a correr el validador y guarda el veredicto nuevo. Antes esos procesos
    llenaban fecha/número/importe pero dejaban el veredicto viejo ("Falta: fecha…", sin periodo)."""
    try:
        doc = await db.consumos_subsidio.find_one({"id": doc_id}, {"_id": 0})
        if not doc:
            return
        u = await db.users.find_one({"id": doc.get("user_id")}, {"_id": 0, "password_hash": 0})
        if not u:
            return
        u = _usuario_en_empresa(u, doc.get("empresa"))
        uids = await _get_company_uids(u)
        patch = await _revalidar_consumo(u, uids, doc, excluir_id=doc_id)
        if patch:
            await db.consumos_subsidio.update_one({"id": doc_id}, {"$set": patch})
    except Exception as _e:
        logger.warning(f"Revalidar tras cambio falló para {doc_id}: {_e}")


async def _revalidar_consumo(u: dict, uids: list, doc: dict, excluir_id: Optional[str] = None) -> dict:
    """Corre el validador sobre un consumo con los datos ACTUALES (flota y duplicados de hoy) y
    devuelve el patch de validación. Lo usan crear/editar desde el admin, que antes NO validaban:
    la factura se quedaba con el veredicto del día del OCR (p. ej. 'faltan datos') aunque el
    admin ya la hubiera completado, y en DU 007 sin periodo asignado (el cliente la veía
    'fuera de periodo' mientras el admin la contaba como reconocida)."""
    from services.validador_facturas import validar_factura as _validar_adm
    placas, cats = await _flota_categorias(u, uids)
    _np = lambda x: _re.sub(r"[^A-Z0-9]", "", (x or "").upper())
    q = _own_q(u, uids)
    if excluir_id:
        q = {**q, "id": {"$ne": excluir_id}}
    otras = await db.consumos_subsidio.find(
        q, {"_id": 0, "ruc_emisor": 1, "numero_documento": 1, "placa": 1, "created_at": 1,
            "fecha": 1, "galones": 1, "importe_total": 1}).to_list(5000)
    _clave = lambda o: (str(o.get("ruc_emisor") or "").strip(), str(o.get("numero_documento") or "").strip().upper(),
                        _np(o.get("placa")))
    vistos = {_clave(o) for o in otras if o.get("numero_documento")}
    # Entre copias iguales (mismo grifo + n° + placa) gana la MÁS COMPLETA (la que el admin
    # terminó de llenar) y, en empate, la más antigua; solo las demás son duplicadas.
    mia = _clave(doc)
    if doc.get("numero_documento") and mia in vistos:
        if not any(_copia_mejor(o, doc) for o in otras if _clave(o) == mia):
            vistos.discard(mia)
    prog = doc.get("programa") if doc.get("programa") in ("du004", "du007") else "du004"
    patch: dict = {}
    # Clasificar por FECHA: una factura de julio no puede ser DU 007 (empieza el 16/08) ni una
    # de setiembre DU 004. Si la fecha manda otro decreto, se reasigna en vez de dejarla
    # 'fuera de periodo' (y en draft) en el panel equivocado.
    if doc.get("fecha"):
        prog_fecha = _programa_estricto_por_fecha(doc.get("fecha"))
        if prog_fecha in ("du004", "du007") and prog_fecha != prog:
            prog = prog_fecha
            patch["programa"] = prog
            doc = {**doc, "programa": prog}
    v = _validar_adm(doc, placas_flota=placas, categoria_por_placa=cats, numeros_existentes=vistos, programa=prog)
    patch.update({"validacion": v, "validacion_estado": v["estado"], "requiere_revision": v["requiere_revision"]})
    patch["periodo_du007"] = v.get("periodo_du007") if prog == "du007" else None
    return patch


@subsidio_router.post("/admin/subsidio/expedientes/{user_id}/invoices")
async def admin_add_invoice(
    user_id: str,
    payload: InvoiceAdminCreateIn,
    empresa: Optional[str] = None,
    _: dict = Depends(_require_admin_enered),
):
    u = await db.users.find_one({"id": user_id})
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    u = _usuario_en_empresa(u, empresa)
    
    placa = payload.placa.upper().strip()
    own = await db.subsidio_vehicles.find_one({"user_id": user_id, "placa": placa})
    placa_match = placa if own else None

    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "empresa": u.get("empresa"),
        "empresa_id": u.get("empresa"),
        "calc_id": u.get("calc_id"),
        "factura_filename": "manual_entry.pdf",
        "factura_storage_key": None,
        "factura_content_type": "application/pdf",
        "factura_size": 0,
        "raw_ocr_response": "Manual Entry by Admin",
        "ocr_ok": True,
        "ocr_error": None,
        "placa_match": placa_match,
        "status": "confirmed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "confirmed_at": datetime.now(timezone.utc).isoformat(),
        "fecha": payload.fecha,
        "hora": "12:00",
        "estacion": payload.estacion,
        "ciudad": normalize_city(payload.ciudad),
        "ruc_emisor": payload.ruc_emisor,
        "placa": placa,
        "producto": payload.producto or "DIESEL B5",
        "galones": payload.galones,
        "precio_unitario": payload.precio_unitario,
        "importe_total": payload.importe_total,
        "numero_documento": payload.numero_documento,
        "confianza": 1.0,
        "programa": payload.programa or "du004",
    }
    # Importe de la fila = consumo de esa placa (galones × precio), no el total de la factura.
    _imp = _importe_por_placa(doc)
    if _imp is not None:
        doc["importe_total"] = _imp
    _completar_precio(doc)
    # Validar al crear (estado + periodo DU 007), igual que cuando sube/edita el cliente.
    try:
        uids_v = await _get_company_uids(u)
        doc.update(await _revalidar_consumo(u, uids_v, doc))
    except Exception as _e:
        logger.warning(f"Validación al crear factura desde admin falló: {_e}")
    if doc.get("validacion_estado") == "RECHAZADA":
        # Rechazada por el validador (fuera de periodo, duplicada, placa ajena…): no se da por
        # confirmada; queda en borrador con el motivo visible para que el admin la corrija.
        doc["status"] = "draft"
        doc.pop("confirmed_at", None)
    await db.consumos_subsidio.insert_one(doc)
    doc.pop("_id", None)
    return {"ok": True, "invoice": doc}


@subsidio_router.put("/admin/subsidio/expedientes/{user_id}/invoices/{invoice_id}")
async def admin_update_invoice(
    user_id: str,
    invoice_id: str,
    payload: InvoiceUpdateIn,
    _: dict = Depends(_require_admin_enered),
):
    """Admin edita los datos de una factura.

    Busca el registro en consumos_subsidio primero; si no existe ahí, busca en
    db.invoices (facturas confirmadas que se muestran en la vista combinada del
    expediente). Aplica el mapeo de nombres de campo correcto para cada
    colección. Devuelve 404 solo si el ID no existe en ninguna de las dos.
    """
    t_user = await db.users.find_one({"id": user_id}, {"_id": 0, "id": 1, "empresa": 1}) or {"id": user_id}
    uids = await _get_company_uids(t_user)

    # --- 1. Buscar en consumos_subsidio ---
    inv = await db.consumos_subsidio.find_one({"id": invoice_id})
    if inv:
        target_collection = db.consumos_subsidio
        # Campos directos: el modelo InvoiceUpdateIn coincide 1-a-1 con consumos_subsidio
        patch = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None}
        if "placa" in patch and patch["placa"]:
            placa = patch["placa"].upper().strip()
            patch["placa"] = placa
            own = await db.subsidio_vehicles.find_one({**_own_q(t_user, uids), "placa": placa})
            patch["placa_match"] = placa if own else None
        patch["updated_at"] = datetime.now(timezone.utc).isoformat()
        _imp = _importe_por_placa({**inv, **patch})
        if _imp is not None:
            patch["importe_total"] = _imp
        # Revalidar con los datos corregidos, como ya hace la edición del cliente. Se usa la
        # empresa de la propia factura (multi-empresa) para flota y duplicados.
        try:
            u_v = {"id": user_id, "empresa": inv.get("empresa") or t_user.get("empresa")}
            patch.update(await _revalidar_consumo(u_v, uids, {**inv, **patch}, excluir_id=invoice_id))
        except Exception as _e:
            logger.warning(f"Revalidación al editar factura desde admin falló: {_e}")
        # Si el admin completó una factura que estaba en borrador, pasa a CONFIRMADA. Antes se
        # quedaba en draft para siempre (solo el cliente confirmaba) y no contaba en el expediente
        # aunque tuviera todos los datos. No se confirma si es nula o si el validador la rechazó.
        futuro = {**inv, **patch}
        completa = all(futuro.get(k) for k in ("fecha", "numero_documento", "galones", "importe_total", "ruc_emisor", "placa"))
        if (inv.get("status") == "draft" and completa and not futuro.get("invalida")
                and futuro.get("validacion_estado") != "RECHAZADA"):
            patch["status"] = "confirmed"
            patch["confirmed_at"] = datetime.now(timezone.utc).isoformat()
            patch["confirmado_por"] = "admin"
        await target_collection.update_one({"id": invoice_id}, {"$set": patch})
        return {"ok": True, "source": "consumos_subsidio",
                "status": patch.get("status", inv.get("status")),
                "validacion_estado": patch.get("validacion_estado", inv.get("validacion_estado")),
                "motivos": (patch.get("validacion") or inv.get("validacion") or {}).get("motivos", []),
                "programa": patch.get("programa", inv.get("programa") or "du004")}

    # --- 2. Si no está en consumos_subsidio, buscar en db.invoices ---
    inv_enered = await db.invoices.find_one({"id": invoice_id})
    if not inv_enered:
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    # db.invoices usa nombres de campo distintos al modelo del frontend.
    # El frontend envía: numero_documento, fecha, importe_total.
    # db.invoices almacena:  n_doc,           f_emision, monto_total.
    FIELD_MAP_TO_INVOICES = {
        "numero_documento": "n_doc",
        "fecha": "f_emision",
        "importe_total": "monto_total",
    }
    raw_patch = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None}
    inv_patch: dict = {}
    for field, value in raw_patch.items():
        mapped = FIELD_MAP_TO_INVOICES.get(field, field)
        inv_patch[mapped] = value

    if "placa" in inv_patch and inv_patch["placa"]:
        inv_patch["placa"] = inv_patch["placa"].upper().strip()

    inv_patch["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db.invoices.update_one({"id": invoice_id}, {"$set": inv_patch})
    return {"ok": True, "source": "invoices"}


@subsidio_router.delete("/admin/subsidio/expedientes/{user_id}")
async def admin_delete_expediente(user_id: str, _: dict = Depends(_require_admin_enered)):
    u = await db.users.find_one({"id": user_id})
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    empresa_name = u.get("empresa")
    email = (u.get("email") or "").lower().strip()
    ruc = u.get("ruc")
    calc_id = u.get("calc_id")

    deleted = {
        "user": 0, "calculations": 0, "leads": 0, "bank_accounts": 0,
        "vehicles": 0, "declaraciones": 0, "documents": 0, "invoices": 0,
        "empresas_config": 0, "storage_objects": 0,
    }

    # 1) Cálculo asociado (por calc_id) y leads por múltiples claves
    if calc_id:
        r = await db.calculations.delete_one({"id": calc_id})
        deleted["calculations"] += r.deleted_count or 0
    lead_filter = {"$or": []}
    if calc_id: lead_filter["$or"].append({"calc_id": calc_id})
    if email:   lead_filter["$or"].append({"email": email})
    if ruc:     lead_filter["$or"].append({"ruc": ruc})
    if lead_filter["$or"]:
        r = await db.subsidio_leads.delete_many(lead_filter)
        deleted["leads"] += r.deleted_count or 0

    # 2) Datos accesorios del cliente
    r = await db.subsidio_bank_accounts.delete_many({"user_id": user_id})
    deleted["bank_accounts"] += r.deleted_count or 0
    r = await db.subsidio_vehicles.delete_many({"user_id": user_id})
    deleted["vehicles"] += r.deleted_count or 0
    r = await db.subsidio_declaraciones.delete_many({"user_id": user_id})
    deleted["declaraciones"] += r.deleted_count or 0

    # 3) Documentos + storage
    docs = await db.subsidio_documents.find({"user_id": user_id}, {"_id": 0, "storage_key": 1}).to_list(5000)
    for d in docs:
        if d.get("storage_key"):
            try:
                storage.delete_object(d["storage_key"])
                deleted["storage_objects"] += 1
            except Exception:
                pass
    r = await db.subsidio_documents.delete_many({"user_id": user_id})
    deleted["documents"] += r.deleted_count or 0

    # 4) Facturas/consumos + storage
    invs = await db.consumos_subsidio.find({"user_id": user_id}, {"_id": 0, "factura_storage_key": 1}).to_list(5000)
    for i in invs:
        if i.get("factura_storage_key"):
            try:
                storage.delete_object(i["factura_storage_key"])
                deleted["storage_objects"] += 1
            except Exception:
                pass
    r = await db.consumos_subsidio.delete_many({"user_id": user_id})
    deleted["invoices"] += r.deleted_count or 0

    # 5) Usuario
    r = await db.users.delete_one({"id": user_id})
    deleted["user"] += r.deleted_count or 0

    # 6) empresas_config (solo si NO queda ningún otro usuario en esa empresa)
    if empresa_name:
        remaining = await db.users.count_documents({"empresa": empresa_name})
        if remaining == 0:
            r = await db.empresas_config.delete_one({"empresa": empresa_name})
            deleted["empresas_config"] += r.deleted_count or 0

    logger.info(f"[admin_delete_expediente] user_id={user_id} empresa={empresa_name} deleted={deleted}")
    return {"ok": True, "deleted": deleted}


@subsidio_router.post("/admin/subsidio/expedientes/{user_id}/migrate")
async def admin_migrate_expediente(user_id: str, _: dict = Depends(_require_admin_enered)):
    u = await db.users.find_one({"id": user_id})
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado o ya migrado")
        
    empresa_name = u.get("empresa")
    if empresa_name:
        await db.empresas_config.update_one(
            {"empresa": empresa_name},
            {"$set": {
                "tipo_cliente": "enered",
                "servicios.plataforma": True,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        
    await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "role": "administrador",
            "expediente_status": "migrated",
            "expediente_stage": "abonado_en_cuenta"
        }}
    )
    
    return {"ok": True}
