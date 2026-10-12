import React, { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ShieldAlert, ArrowRight } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { rutaFirmaPendiente } from "./FirmasPendientes";

/* Emergente OBLIGATORIO (Giuliana, 25/09/2026): un cliente de subsidio con facturas cargadas y
   la constancia sin firmar no puede usar la plataforma
   hasta firmar — así se asegura el envío de su expediente y la responsabilidad queda declarada.
   Solo se oculta donde se firma (DU 007), en el aviso de cierre DU 004, en las públicas y para el
   admin o cuando impersona. Re-verifica en cada cambio de ruta. */
const RUTAS_FIRMA = ["/subsidio/documentos", "/subsidio/du007"];
const RUTAS_PUBLICAS = ["/login", "/forgot-password", "/registro-subsidio", "/subsidio", "/precios", "/privacidad"];

export default function FirmaObligatoriaModal() {
  const { user } = useAuth();
  const loc = useLocation();
  const navigate = useNavigate();
  const [firmas, setFirmas] = useState(null);

  // Admin impersonando una empresa: también lo ve (para comprobar lo que ve el cliente), pero
  // puede cerrarlo con "Continuar como admin" (queda cerrado el resto de la sesión del navegador).
  const impersonando = (() => { try { return !!localStorage.getItem("enered_impersonate"); } catch (_) { return false; } })();
  const esAdmin = !!user && (user.role === "admin_enered" || !!user._admin_id || !!user._impersonando);
  const [cerradoAdmin, setCerradoAdmin] = useState(() => { try { return sessionStorage.getItem("firma_obligatoria_admin_ok") === "1"; } catch (_) { return false; } });
  const esSubsidio = !!user && !user.es_guest && (impersonando || !esAdmin)
    && (user.role === "cliente_subsidio" || user.tipo_cliente === "subsidio" || !!user.servicios?.subsidio || impersonando);
  const enPublica = RUTAS_PUBLICAS.includes(loc.pathname) || loc.pathname.startsWith("/captura/");
  const enFirma = RUTAS_FIRMA.some((r) => loc.pathname.startsWith(r));

  useEffect(() => {
    if (!esSubsidio || enPublica) { setFirmas(null); return; }
    let vivo = true;
    api.get("/subsidio/firmas").then(({ data }) => { if (vivo) setFirmas(data); }).catch(() => { if (vivo) setFirmas(null); });
    return () => { vivo = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [esSubsidio, enPublica, loc.pathname]);

  if (!esSubsidio || enPublica || enFirma || !firmas || (esAdmin && cerradoAdmin)) return null;
  // Obligatoria: SOLO la Constancia de términos del servicio (ENERGIX), y solo para clientes que
  // ya cargaron facturas. Las declaraciones juradas de veracidad son recomendadas, no bloquean.
  if (firmas.constancia || !firmas.tiene_facturas) return null;
  const items = ["Constancia de Información y Condiciones del Servicio (obligatoria)"];
  for (const k of (firmas.dj_pendientes || []).filter((k) => k !== "du004")) items.push(`Declaración jurada DU 007 · Periodo ${k.replace("du007_p", "")} (recomendada)`);
  const destino = rutaFirmaPendiente(firmas) || "/subsidio/du007?etapa=declaracion";

  return (
    <div className="fixed inset-0 z-[85] bg-neutral-900/70 backdrop-blur-sm flex items-center justify-center p-4" data-testid="firma-obligatoria">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg p-6">
        <div className="flex items-start gap-3">
          <div className="w-11 h-11 rounded-full bg-red-100 flex items-center justify-center flex-shrink-0"><ShieldAlert className="w-6 h-6 text-red-600" /></div>
          <div>
            <div className="text-[10px] uppercase tracking-widest font-bold text-red-600">Firma obligatoria</div>
            <h2 className="font-cabinet text-xl font-bold text-neutral-900 mt-0.5">Falta aceptar la Constancia de términos del servicio</h2>
            <p className="text-sm text-neutral-600 mt-2">
              Ya cargaste facturas de combustible. Para que ENERED gestione tu expediente ante la ATU debes leer y aceptar la <b>Constancia de Información y Condiciones del Servicio</b>. Es un paso obligatorio de un minuto.
            </p>
          </div>
        </div>
        <ul className="mt-4 space-y-1.5 text-sm text-neutral-800 bg-red-50 border border-red-200 rounded-xl p-3">
          {items.map((t) => <li key={t}>• {t}</li>)}
        </ul>
        <button onClick={() => navigate(destino)}
          className="mt-5 w-full py-3 bg-brand hover:bg-brand-hover text-white font-bold rounded-xl flex items-center justify-center gap-2"
          data-testid="firma-obligatoria-ir">
          Firmar ahora <ArrowRight className="w-4 h-4" />
        </button>
        <p className="text-[11px] text-neutral-400 mt-3 text-center">Podrás seguir usando la plataforma en cuanto firmes.</p>
        {esAdmin && (
          <button onClick={() => { try { sessionStorage.setItem("firma_obligatoria_admin_ok", "1"); } catch (_) {} setCerradoAdmin(true); }}
            className="mt-2 w-full text-xs text-neutral-500 underline hover:text-neutral-800" data-testid="firma-obligatoria-admin">
            Soy admin de ENERED: continuar sin firmar (el cliente NO ve este botón)
          </button>
        )}
      </div>
    </div>
  );
}
