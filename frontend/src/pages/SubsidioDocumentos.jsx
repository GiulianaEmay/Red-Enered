import React, { useEffect, useMemo, useState, useRef } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Loader2, Upload, CheckCircle2, AlertTriangle, AlertCircle, Trash2, Plus, Building2, Truck, Fuel, FileText, Save, ScanLine, ShieldCheck, Send, Lock } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import ValidacionPendiente from "../components/ValidacionPendiente";
import ComprobantesTabla, { CargaMasiva } from "../components/ComprobantesTabla";
import ConstanciaApartado from "../components/ConstanciaApartado";
import FirmasPendientes from "../components/FirmasPendientes";
import QrSubidaCelular from "../components/QrSubidaCelular";
import { EmpresaEtapa, FlotaEtapa, EtapaHeader, calcVerificacionTotals } from "../components/SubsidioVerificacion";

// --- Factura subida: muestra lo que ENERED leyó del comprobante y su validación ---
const ESTADO_FACTURA = {
  CONFORME:  { txt: "CONFORME",  cls: "bg-emerald-600 text-white", card: "border-emerald-200 bg-emerald-50/40" },
  OBSERVADA: { txt: "OBSERVADA", cls: "bg-amber-500 text-white",   card: "border-amber-200 bg-amber-50/40" },
  RECHAZADA: { txt: "RECHAZADA", cls: "bg-red-600 text-white",     card: "border-red-200 bg-red-50/40" },
};

function InvoiceRow({ item, deleteRow }) {
  const est = ESTADO_FACTURA[item.validacion_estado] || null;
  const motivos = item.validacion?.motivos || [];
  const fmtGal = (g) => g ? `${Number(g).toLocaleString("es-PE", { minimumFractionDigits: 2, maximumFractionDigits: 3 })} gal` : null;
  const fmtSol = (n) => n ? `S/ ${Number(n).toLocaleString("es-PE", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}` : null;
  const fecha = item.fecha ? new Date(item.fecha + "T00:00:00").toLocaleDateString("es-PE") : null;
  const datos = [
    item.numero_documento && { l: "Comprobante", v: item.numero_documento, fuerte: true },
    fecha && { l: "Emisión", v: fecha },
    item.placa && { l: "Placa", v: item.placa, fuerte: true },
    fmtGal(item.galones) && { l: "Volumen", v: fmtGal(item.galones), fuerte: true },
    item.producto && { l: "Producto", v: String(item.producto).slice(0, 26) },
    fmtSol(item.importe_total) && { l: "Total", v: fmtSol(item.importe_total) },
    item.estacion && { l: "Grifo", v: String(item.estacion).slice(0, 28) },
    item.ruc_emisor && { l: "RUC grifo", v: item.ruc_emisor },
  ].filter(Boolean);

  return (
    <div className={`bg-white border rounded-xl p-3.5 shadow-sm mb-3 ${est?.card || "border-neutral-200"}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="w-9 h-9 rounded-lg bg-brand/10 flex items-center justify-center flex-shrink-0">
            <FileText className="w-4 h-4 text-brand" />
          </div>
          <div className="min-w-0">
            <span className="block font-medium text-sm text-neutral-800 truncate" title={item.factura_filename}>{item.factura_filename}</span>
            {datos.length === 0 && (
              <span className="text-[11px] text-neutral-500">Subida ✓ · ENERED está leyendo el comprobante…</span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {est && <span className={`text-[10px] font-black px-2 py-1 rounded-full ${est.cls}`}>{est.txt}</span>}
          <button onClick={() => deleteRow(item.id)} className="text-neutral-400 hover:text-red-500" title="Eliminar archivo">
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Datos leídos del comprobante */}
      {datos.length > 0 && (
        <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] pl-12">
          {datos.map((d) => (
            <span key={d.l}>
              <span className="text-neutral-400">{d.l} </span>
              <span className={d.fuerte ? "font-bold text-neutral-900" : "text-neutral-700"}>{d.v}</span>
            </span>
          ))}
        </div>
      )}

      {/* Qué hay que corregir */}
      {motivos.length > 0 && (
        <ul className="mt-2 pl-12 space-y-0.5">
          {motivos.slice(0, 3).map((m, i) => (
            <li key={i} className="text-[11px] text-amber-800 flex items-start gap-1.5">
              <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />{m}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/* El diagnóstico por RUC vive ahora en su propia página: Subsidios → Diagnóstico. */
const ETAPAS = [
  { id: "empresa",      n: 1, label: "Verificación empresa",     icon: Building2,  short: "Verificación empresa", hint: "Solo PDF" },
  { id: "flota",        n: 2, label: "Verificación flota",       icon: Truck,      short: "Verificación flota",   hint: "PDF, PNG o JPG" },
  { id: "combustible",  n: 3, label: "Facturas de combustible",  icon: Fuel,       short: "Combustible",  hint: "Solo PDF" },
  { id: "declaracion",  n: 4, label: "Declaración jurada y términos", icon: ShieldCheck,short: "Declaración",  hint: "Firma electrónica" },
];

const PRODUCTOS = ["DIESEL B5", "DIESEL B20", "DIESEL B5 S50"];
const TARGET_DATE = new Date("2026-09-28T23:59:59");

export default function SubsidioDocumentos() {
  const navigate = useNavigate();
  const { user, setUser } = useAuth();
  const bloqueaEtapas = user?.acceso_etapa0 === true;  // entró solo por RUC → Etapa 1+ bloqueadas
  const [data, setData] = useState(null);
  // Máximo recuperable del subsidio (total_monto del diagnóstico por RUC); el
  // dashboard solo se usa de respaldo mientras llega o si no hay RUC.
  const [estimadoResumen, setEstimadoResumen] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeLeft, setTimeLeft] = useState({ days: 0, hours: 0, minutes: 0, seconds: 0 });
  const pad = (num) => String(num).padStart(2, '0');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const diff = TARGET_DATE.getTime() - now.getTime();
      if (diff <= 0) {
        setTimeLeft({ days: 0, hours: 0, minutes: 0, seconds: 0 });
      } else {
        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
        const minutes = Math.floor((diff / 1000 / 60) % 60);
        const seconds = Math.floor((diff / 1000) % 60);
        setTimeLeft({ days, hours, minutes, seconds });
      }
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);
  const [activeEtapa, setActiveEtapa] = useState("empresa");
  // ?etapa=declaracion (viene del emergente de firma obligatoria / aviso rojo): abre esa etapa
  // directamente y también si la URL cambia estando ya en la página.
  const locEtapa = useLocation();
  const etapaUrl = new URLSearchParams(locEtapa.search).get("etapa");
  useEffect(() => { if (etapaUrl) setActiveEtapa(etapaUrl); }, [locEtapa.search]); // eslint-disable-line react-hooks/exhaustive-deps
  const [showSuccessOverlay, setShowSuccessOverlay] = useState(false);
  const [createdDeclaracion, setCreatedDeclaracion] = useState(null);

  const load = async () => {
    try {
      const { data } = await api.get("/subsidio/dashboard");
      setData(data);
      // Nota: el ahorro estimado lo trae Etapa0Card (una sola llamada a /subsidio/resumen) y nos
      // lo reporta por onResumen → evita pedir el resumen dos veces en la primera carga.
      // Auto-jump to first incomplete stage on first load (salvo entrada solo-RUC → queda en Etapa 0)
      if (loading && user?.acceso_etapa0 !== true) {
        const pedida = new URLSearchParams(window.location.search).get("etapa");
        // Con la DJ (o la constancia) pendiente, lo PRIMERO que ve el cliente es la Etapa 4 —
        // así se ubica de inmediato y firma. Si no, la primera etapa incompleta, como siempre.
        let firmaPend = false;
        try {
          const { data: f } = await api.get("/subsidio/firmas");
          firmaPend = !!(f && !f.constancia);
        } catch (_) { /* sin datos → flujo normal */ }
        const next = pedida || (firmaPend ? "declaracion" : pickNextEtapa(data));
        if (next) setActiveEtapa(next);
      }
    } catch (err) {
      console.error("Error loading SubsidioDocumentos:", err);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  // Ahorro estimado = máximo recuperable según el diagnóstico por RUC (cacheado en backend).
  useEffect(() => {
    if (!user?.ruc) return;
    let alive = true;
    api.get("/subsidio/resumen", { params: { ruc: user.ruc } })
      .then(({ data: r }) => { if (alive && r?.subsidio?.total_monto != null) setEstimadoResumen(r.subsidio.total_monto); })
      .catch(() => {});
    return () => { alive = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.ruc]);

  // ---------- Progress totals (memoized; before early-return) ----------
  const totals = useMemo(() => calcTotals(data), [data]);

  if (loading) {
    return <div className="min-h-[400px] flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-brand" /></div>;
  }
  if (!data) return null;

  const { ahorro_estimado, ahorro_reconocido, checklist, vehicles, bank_account, declaracion } = data;

  const isComplete = (id) => totals.byEtapa[id]?.done >= totals.byEtapa[id]?.total && totals.byEtapa[id]?.total > 0;
  const enviado = !!declaracion;

  if (showSuccessOverlay) {
    const decl = createdDeclaracion || {};
    const expedNo = decl.id ? `DU-2026-${decl.id.slice(0, 8).toUpperCase()}` : "";
    return (
      <div className="min-h-[500px] flex items-center justify-center bg-[#F6F7FB] p-4 animate-fade-in" data-testid="envio-success">
        <div className="bg-white border border-neutral-200 rounded-2xl p-8 max-w-lg w-full text-center shadow-lg space-y-6">
          <div className="w-20 h-20 mx-auto rounded-full bg-emerald-500 text-white flex items-center justify-center mb-4">
            <CheckCircle2 className="w-10 h-10 animate-bounce" />
          </div>
          <h3 className="font-cabinet text-3xl font-bold text-neutral-900">¡Envío exitoso!</h3>
          <p className="text-sm text-neutral-600 max-w-md mx-auto">
            Tu expediente del subsidio DU 004-2026 quedó registrado y será presentado ante la ATU.
          </p>
          {expedNo && (
            <div className="inline-flex items-center gap-2 bg-neutral-50 border border-neutral-200 rounded-xl px-4 py-2 text-sm font-semibold text-neutral-700">
              N° de expediente: <span className="text-brand font-mono font-bold">{expedNo}</span>
            </div>
          )}
          <div className="pt-2 text-xs text-neutral-400 flex items-center justify-center gap-1.5">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-brand" />
            Redirigiendo a tu dashboard en unos segundos...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="subsidio-documentos">
      <ValidacionPendiente contexto="los indicadores de tu flota" />
      <FirmasPendientes actual="du004" />
      {/* HEADER */}
      <div className="bg-white border border-neutral-200 rounded-2xl p-6 shadow-sm">
        <div className="flex items-start justify-between flex-wrap gap-4 mb-6">
          <div>
            <span className="text-[10px] uppercase tracking-widest font-bold text-brand">Asistente de subsidio · DU 004-2026</span>
            <h2 className="font-cabinet text-2xl font-bold tracking-tight mt-1">Subsidio DU-004</h2>
            <p className="text-neutral-500 mt-1 max-w-2xl text-sm">Completa las 4 etapas para enviar tu expediente a la ATU. Tu diagnóstico está en Subsidios → Diagnóstico.</p>
          </div>
          <div className="flex items-center gap-3 flex-wrap w-full sm:w-auto">
            <div className="px-4 py-2.5 bg-emerald-50 border border-emerald-200 rounded-xl">
              <div className="text-[10px] uppercase tracking-widest font-bold text-emerald-700">Ahorro estimado</div>
              <div className="font-cabinet font-black text-xl text-emerald-700">S/ {Number(estimadoResumen ?? ahorro_estimado).toLocaleString("es-PE", { maximumFractionDigits: 0 })}</div>
            </div>
            <div className="px-4 py-2.5 bg-brand/10 border border-brand/30 rounded-xl">
              <div className="text-[10px] uppercase tracking-widest font-bold text-brand">Ahorro reconocido</div>
              <div className="font-cabinet font-black text-xl text-brand">S/ {Number(ahorro_reconocido).toLocaleString("es-PE", { maximumFractionDigits: 0 })}</div>
            </div>
            {/* Reloj con cuenta regresiva resaltado en rojo */}
            <div className="bg-[#B91C1C] border border-red-500/25 rounded-[14px] p-[8px_16px] flex items-center shadow-[0_4px_20px_rgba(185,28,28,0.45)] text-white select-none">
              {/* Left Side: icon and deadline */}
              <div className="flex items-center gap-[6px]">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" className="text-white">
                  <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.2" />
                  <path d="M12 7v5l3 2" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
                </svg>
                <span className="text-[11px] font-black tracking-wider uppercase">28 SEP</span>
              </div>
              
              {/* Divider */}
              <div className="w-[1.5px] h-[26px] bg-white/20 mx-3.5" />
              
              {/* Countdown Numbers */}
              <div className="flex items-center gap-[5px]">
                {/* Days */}
                <div className="flex flex-col items-center min-w-[20px]">
                  <span className="font-cabinet text-[16px] font-black leading-none">{pad(timeLeft.days)}</span>
                  <span className="text-[9px] font-bold text-white/50 tracking-wider mt-[3px]">D</span>
                </div>
                <span className="text-[14px] font-bold text-white/50 relative top-[-3px]">:</span>
                {/* Hours */}
                <div className="flex flex-col items-center min-w-[20px]">
                  <span className="font-cabinet text-[16px] font-black leading-none">{pad(timeLeft.hours)}</span>
                  <span className="text-[9px] font-bold text-white/50 tracking-wider mt-[3px]">H</span>
                </div>
                <span className="text-[14px] font-bold text-white/50 relative top-[-3px]">:</span>
                {/* Minutes */}
                <div className="flex flex-col items-center min-w-[20px]">
                  <span className="font-cabinet text-[16px] font-black leading-none">{pad(timeLeft.minutes)}</span>
                  <span className="text-[9px] font-bold text-white/50 tracking-wider mt-[3px]">M</span>
                </div>
                <span className="text-[14px] font-bold text-white/50 relative top-[-3px]">:</span>
                {/* Seconds */}
                <div className="flex flex-col items-center min-w-[20px]">
                  <span className="font-cabinet text-[16px] font-black leading-none text-rose-300 animate-pulse">{pad(timeLeft.seconds)}</span>
                  <span className="text-[9px] font-bold text-white/50 tracking-wider mt-[3px]">S</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Línea de etapas */}
        <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-2 mb-3">
          {ETAPAS.map((e) => {
            const Ic = e.icon;
            const active = activeEtapa === e.id;
            const done = isComplete(e.id) || (e.id === "declaracion" && enviado);
            const canVisit = !bloqueaEtapas;
            return (
              <button
                key={e.id}
                onClick={() => canVisit && setActiveEtapa(e.id)}
                disabled={!canVisit}
                data-testid={`etapa-tab-${e.id}`}
                className={`text-left p-3 rounded-xl border-2 transition-all min-h-[78px] ${
                  active ? "border-brand bg-brand/5 shadow-md" :
                  done ? "border-emerald-300 bg-emerald-50/40 hover:border-emerald-400" :
                  "border-neutral-200 bg-white hover:border-neutral-300"
                } ${!canVisit ? "opacity-40 cursor-not-allowed" : ""}`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className={`text-[10px] uppercase tracking-widest font-bold ${active ? "text-brand" : "text-neutral-400"}`}>Etapa {e.n}</span>
                  <span className={`w-6 h-6 rounded-md flex items-center justify-center ${
                    done ? "bg-emerald-100 text-emerald-700" : active ? "bg-brand text-white" : "bg-neutral-100 text-neutral-500"
                  }`}>
                    {done ? <CheckCircle2 className="w-3.5 h-3.5" /> : !canVisit ? <Lock className="w-3.5 h-3.5" /> : <Ic className="w-3.5 h-3.5" />}
                  </span>
                </div>
                <div className="font-bold text-[13px] text-neutral-900 leading-tight">{e.short}</div>
                <div className="text-[10px] text-neutral-500 mt-0.5">{e.hint}</div>
              </button>
            );
          })}
        </div>

        {/* Barra única continua */}
        <div className="mt-5">
          <div className="flex items-baseline justify-between mb-2">
            <div className="text-sm">
              <span className="font-cabinet font-black text-brand text-xl">{totals.pct}%</span>
              <span className="text-neutral-500 ml-2 text-xs">{totals.done} de {totals.total} ítems completados</span>
            </div>
            <div className="text-[10px] text-neutral-400 uppercase tracking-widest font-bold">Tu ruta para cobrar</div>
          </div>
          <div className="relative h-3 bg-neutral-100 rounded-full overflow-hidden">
            <div
              className="absolute inset-y-0 left-0 bg-gradient-to-r from-brand to-violet-500 rounded-full transition-all duration-700"
              style={{ width: `${totals.pct}%` }}
            />
          </div>
        </div>
      </div>

      {/* CONTENIDO de la etapa activa */}
      {bloqueaEtapas ? (
        /* Sesión invitada (entró solo por RUC): puede ver el módulo, pero las etapas
           se activan con el equipo ENERED. Su diagnóstico vive en Subsidios → Diagnóstico. */
        <div className="bg-white border border-neutral-200 rounded-2xl p-10 text-center shadow-sm" data-testid="du004-guest-gate">
          <Lock className="w-10 h-10 text-brand mx-auto" />
          <h3 className="font-cabinet font-black text-xl text-neutral-900 mt-3">Activa tu expediente DU-004</h3>
          <p className="text-sm text-neutral-500 mt-2 max-w-md mx-auto">
            Ya tienes tu diagnóstico en <b>Subsidios → Diagnóstico</b>. Para cargar los documentos
            de tu empresa y flota, y presentar tu expediente a la ATU, activa tu cuenta con el equipo ENERED.
          </p>
          <div className="mt-5 flex items-center justify-center gap-3 flex-wrap">
            <a
              href={`https://wa.me/51997389536?text=${encodeURIComponent(`Hola ENERED, soy ${user?.empresa || ""} (RUC ${user?.ruc || ""}). Quiero activar mi expediente del DU 004.`)}`}
              target="_blank" rel="noreferrer"
              className="inline-flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white font-black px-6 py-3 rounded-xl text-sm">
              Activar por WhatsApp
            </a>
            <button onClick={() => navigate("/subsidio/diagnostico")}
              className="px-5 py-3 rounded-xl text-sm font-bold text-brand hover:bg-brand/5 border border-brand/30">
              Ver mi diagnóstico
            </button>
          </div>
        </div>
      ) : (
      <div className="bg-white border border-neutral-200 rounded-2xl p-6 shadow-sm" data-testid={`etapa-content-${activeEtapa}`}>
        {activeEtapa === "empresa" && (
          <EmpresaEtapa items={checklist.empresa} bank={bank_account} evidenciaCci={data.evidencia_cci || []} onChange={load} />
        )}
        {activeEtapa === "flota" && (
          <FlotaEtapa items={checklist.flota} vehicles={vehicles} onChange={load} />
        )}
        {activeEtapa === "combustible" && (
          <CombustibleEtapa onAnyChange={load} confirmedCountFromDashboard={data?.invoices?.confirmed ?? 0}
            data={data} totals={totals} />
        )}
        {activeEtapa === "declaracion" && (
          <DeclaracionEtapa
            data={data}
            totals={totals}
            onAccepted={async (decl) => {
              setCreatedDeclaracion(decl);
              setShowSuccessOverlay(true);
              const me = await api.get("/auth/me").catch(() => null);
              if (me?.data?.user) setUser?.(me.data.user);
              setTimeout(() => {
                navigate("/dashboard");
              }, 3500);
            }}
          />
        )}

        {/* Navegación */}
        <div className="flex items-center justify-between mt-6 pt-5 border-t border-neutral-100">
          <button
            onClick={() => {
              const idx = ETAPAS.findIndex((c) => c.id === activeEtapa);
              if (idx > 0) setActiveEtapa(ETAPAS[idx - 1].id);
            }}
            disabled={activeEtapa === ETAPAS[0].id}
            className="px-4 py-2 text-sm font-bold text-neutral-600 hover:bg-neutral-100 rounded-lg disabled:opacity-30 disabled:cursor-not-allowed"
            data-testid="etapa-prev"
          >
            ← Etapa anterior
          </button>
          {activeEtapa !== "declaracion" && (
            <button
              onClick={() => {
                const idx = ETAPAS.findIndex((c) => c.id === activeEtapa);
                if (idx < ETAPAS.length - 1) {
                  setActiveEtapa(ETAPAS[idx + 1].id);
                }
              }}
              className="px-4 py-2 text-sm font-bold text-brand hover:bg-brand/5 rounded-lg"
              data-testid="etapa-next"
            >
              Siguiente etapa →
            </button>
          )}
        </div>
      </div>
      )}
    </div>
  );
}

/* ============================================================ */
/* Helpers                                                       */
/* ============================================================ */
function calcTotals(data) {
  if (!data) return { pct: 0, done: 0, total: 1, byEtapa: {} };
  const verification = calcVerificacionTotals(data);
  const { done: empresaDone, total: empresaTot } = verification.byEtapa.empresa;
  const { done: flotaDone, total: flotaTot } = verification.byEtapa.flota;
  // Combustible: cuenta facturas CARGADAS (borrador o confirmada). La constancia y la DJ se
  // firman ANTES de "Enviar reporte" (el envío exige ambas), así que un borrador ya habilita la Etapa 4.
  const confirmedCount = data?.invoices?.confirmed ?? 0;
  const cargadasCount = confirmedCount + (data?.invoices?.draft ?? 0);
  const combDone = cargadasCount > 0 ? 1 : 0;
  const combTot = 1;
  const declDone = data.declaracion ? 1 : 0;

  const byEtapa = {
    ...verification.byEtapa,
    combustible: { done: combDone, total: combTot, pct: combDone * 100, confirmedCount, cargadasCount },
    declaracion: { done: declDone, total: 1, pct: declDone * 100 },
  };
  const done = empresaDone + flotaDone + combDone + declDone;
  const total = empresaTot + flotaTot + combTot + 1;
  return { pct: pct(done, total), done, total, byEtapa };
}
function pct(d, t) { return Math.round((d / Math.max(t, 1)) * 100); }

function pickNextEtapa(data) {
  const t = calcTotals(data);
  if (data.declaracion) return "declaracion";
  if (t.byEtapa.empresa.done < t.byEtapa.empresa.total) return "empresa";
  if (t.byEtapa.flota.done < t.byEtapa.flota.total) return "flota";
  if (t.byEtapa.combustible.done === 0) return "combustible";
  return "declaracion";
}

/* ============================================================ */
/* Etapa 3 — Combustible: OCR inline (upload + draft preview + confirm) */
/* ============================================================ */
function CombustibleEtapa({ onAnyChange, confirmedCountFromDashboard, data, totals }) {
  // Candado: "Enviar reporte" exige la Constancia de términos del servicio y la Declaración
  // jurada de veracidad firmadas. Si faltan, se abre aquí mismo la Etapa 4 para firmarlas.
  const [firmasModal, setFirmasModal] = useState(null); // null | {constancia, declaracion}
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState([]);
  const [vehicles, setVehicles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState({ done: 0, total: 0 });
  const [savingId, setSavingId] = useState(null);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const fileRef = useRef(null);
  const [confirmedList, setConfirmedList] = useState([]);

  const load = async () => {
    try {
      const [{ data: prev }, { data: conf }] = await Promise.all([
        api.get("/subsidio/invoices/preview").catch(() => ({ data: { items: [], vehicles: [] } })),
        api.get("/subsidio/invoices/confirmed").catch(() => ({ data: { items: [] } })),
      ]);
      setItems(prev.items || []);
      setVehicles(prev.vehicles || []);
      setConfirmedList(conf.items || []);
    } catch (err) {
      console.error("Error loading invoices data:", err);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, []);
  const confirmedCount = confirmedList.length || confirmedCountFromDashboard || 0;

  const handleUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;
    const capped = files.slice(0, 40);
    setUploading(true); setUploadProgress({ done: 0, total: capped.length }); setError(null); setSuccess(null);
    try {
      const batch = 5;
      for (let i = 0; i < capped.length; i += batch) {
        const fd = new FormData();
        capped.slice(i, i + batch).forEach((f) => fd.append("files", f));
        await api.post("/subsidio/invoices/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
        setUploadProgress({ done: Math.min(i + batch, capped.length), total: capped.length });
      }
      await load();
      onAnyChange?.();
    } catch (err) {
      setError(err?.response?.data?.detail || "Error al procesar las facturas");
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const setField = (id, field, value) =>
    setItems((prev) => prev.map((it) => (it.id === id ? { ...it, [field]: value, _dirty: true } : it)));

  const saveRow = async (item) => {
    setSavingId(item.id);
    try {
      await api.put(`/subsidio/invoices/${item.id}`, {
        fecha: item.fecha, hora: item.hora, estacion: item.estacion, ciudad: item.ciudad,
        ruc_emisor: item.ruc_emisor, placa: item.placa, producto: item.producto,
        galones: nz(item.galones), precio_unitario: nz(item.precio_unitario), importe_total: nz(item.importe_total),
        numero_documento: item.numero_documento,
      });
      setItems((prev) => prev.map((it) => (it.id === item.id ? { ...it, _dirty: false } : it)));
    } catch (e) { alert(e?.response?.data?.detail || "Error al guardar"); }
    finally { setSavingId(null); }
  };
  const deleteRow = async (id) => {
    if (!window.confirm("¿Eliminar esta factura?")) return;
    await api.delete(`/subsidio/invoices/${id}`); await load(); onAnyChange?.();
  };

  const enviarReporte = async () => {
    setError(null); setSuccess(null);

    const dirty = items.filter((it) => it._dirty);
    if (dirty.length > 0 && !window.confirm("Hay cambios sin guardar. ¿Confirmar de todos modos?")) return;
    setConfirming(true);
    try {
      // 1) ¿Ya firmó la constancia y la declaración jurada? Si no, se firman antes de enviar.
      const { data: firmas } = await api.get("/subsidio/firmas").catch(() => ({ data: null }));
      if (firmas && !firmas.listo) { setFirmasModal(firmas); return; }
      await api.post("/subsidio/invoices/confirm");
      await load(); onAnyChange?.();
      setSuccess(`✅ Reporte enviado: ${items.length} factura(s) registrada(s). Puedes adjuntar más facturas cuando quieras.`);
    } catch (e) {
      const d = e?.response?.data?.detail;
      if (d && typeof d === "object" && d.codigo === "firmas_pendientes") { setFirmasModal(d); return; }
      setError(typeof d === "string" ? d : (d?.message || "Error al confirmar"));
    } finally { setConfirming(false); }
  };

  if (loading) return <div className="py-10 text-center"><Loader2 className="w-6 h-6 animate-spin text-brand mx-auto" /></div>;

  return (
    <div>
      <EtapaHeader n={3} icon={Fuel} title="Facturas de combustible" subtitle="Carga todas tus facturas desde aquí" />

      <div className="bg-amber-50 border border-amber-200 rounded-xl p-3 mb-4 text-xs text-amber-900 flex gap-2">
        <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
        <div>
          <strong>Requisitos:</strong> comprobante electrónico, con placa, Diésel B5/B20 (azufre ≤50 ppm), fecha 29 may–28 jul 2026, grifo con Osinergmin vigente.
          {confirmedCount > 0 && <div className="mt-1 text-emerald-700 font-bold">✓ Llevas {confirmedCount} factura(s) confirmada(s) · {vehicles.length} placa(s) en flota: {vehicles.map(v => v.placa).join(", ")}</div>}
        </div>
      </div>

      {/* Uploader */}
      <div className="bg-white border-2 border-dashed border-brand/40 rounded-2xl p-5 mb-4">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-start gap-3">
            <div className="w-11 h-11 bg-brand/10 rounded-xl flex items-center justify-center flex-shrink-0">
              <ScanLine className="w-5 h-5 text-brand" />
            </div>
            <div>
              <h4 className="font-cabinet font-bold">Carga tus facturas de combustible</h4>
              <p className="text-xs text-neutral-500">Sin meses · sin orden · sube todas juntas</p>
            </div>
          </div>
          <label className={`px-4 py-2.5 ${uploading ? "bg-neutral-300" : "bg-brand hover:bg-brand-hover"} text-white font-bold rounded-lg flex items-center gap-2 cursor-pointer text-sm`} data-testid="combustible-upload">
            {uploading ? (<><Loader2 className="w-4 h-4 animate-spin" /> Procesando {uploadProgress.done}/{uploadProgress.total}…</>) : (<><Upload className="w-4 h-4" /> {items.length === 0 ? "Subir facturas" : "Adjuntar más"}</>)}
            <input ref={fileRef} type="file" hidden multiple accept="application/pdf,.pdf" onChange={handleUpload} disabled={uploading} data-testid="combustible-upload-input" />
          </label>
          <QrSubidaCelular programa="du004" onNuevas={async () => { await load(); onAnyChange?.(); }} />
        </div>
        {uploading && uploadProgress.total > 0 && (
          <div className="mt-3 h-2 bg-neutral-100 rounded-full overflow-hidden"><div className="h-full bg-brand transition-all" style={{ width: `${(uploadProgress.done / uploadProgress.total) * 100}%` }} /></div>
        )}
      </div>

      {/* Carga masiva por plantilla (formato ENERED, compatible con la ATU) */}
      <CargaMasiva programa="du004" onDone={(r) => { setSuccess(`Se guardaron ${r.guardadas} comprobante(s)${r.omitidas ? ` · ${r.omitidas} omitido(s) por errores` : ""}.`); load(); onAnyChange?.(); }} />

      {items.length === 0 ? (
        confirmedCount > 0 ? (
          <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-5" data-testid="combustible-confirmadas">
            <div className="flex items-center gap-2 mb-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-700" />
              <strong className="font-cabinet text-base">Ya tienes {confirmedCount} factura(s) confirmada(s)</strong>
            </div>
            <p className="text-xs text-emerald-900 mb-3">Estas facturas ya alimentan tus Reportes de Consumo. Puedes adjuntar más con el botón de arriba o pasar a la Etapa 4 (Declaración Jurada).</p>
            <ul className="space-y-1 text-xs bg-white border border-emerald-200 rounded-lg p-3 max-h-48 overflow-auto">
              {confirmedList.slice(0, 10).map((c) => (
                <li key={c.id} className="flex justify-between gap-2 py-1 border-b border-neutral-100 last:border-0">
                  <span className="truncate"><FileText className="w-3 h-3 inline mr-1 text-neutral-400" />{c.factura_filename || "factura"}</span>
                  <span className="font-mono text-neutral-600">{c.placa || "—"} · {c.galones ?? "?"} gl · S/ {c.importe_total ?? "?"}</span>
                </li>
              ))}
              {confirmedList.length > 10 && <li className="text-center text-neutral-500 pt-1">… y {confirmedList.length - 10} más</li>}
            </ul>
          </div>
        ) : (
          <div className="bg-neutral-50 border-2 border-dashed border-neutral-300 rounded-xl p-8 text-center">
            <FileText className="w-8 h-8 text-neutral-300 mx-auto mb-2" />
            <p className="text-sm text-neutral-500">No tienes facturas en borrador. Sube tus comprobantes arriba ⬆️</p>
          </div>
        )
      ) : (
        <>
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-3 text-sm text-blue-900 flex gap-2 mb-3">
            <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <div>
              <strong>Tienes {items.length} factura(s) en borrador pendiente(s) de envío.</strong> Haz clic en "Enviar reporte" para registrarlas.
            </div>
          </div>
          <div className="mt-4">
            <ComprobantesTabla items={items} vehicles={vehicles} onChange={load} />
          </div>
        </>
      )}

      {error && <div className="mt-4 bg-red-50 border border-red-200 text-red-700 rounded-xl p-3 text-sm" data-testid="combustible-error">{typeof error === "string" ? error : JSON.stringify(error)}</div>}
      {success && <div className="mt-4 bg-emerald-50 border border-emerald-200 text-emerald-700 rounded-xl p-3 text-sm">{success}</div>}

      {/* Actions footer */}
      <div className="mt-4 flex items-center justify-end gap-3 flex-wrap">
        <label className="px-4 py-2 border border-neutral-300 bg-white rounded-lg text-sm font-bold flex items-center gap-1.5 cursor-pointer hover:bg-neutral-50" data-testid="combustible-add-more">
          <Plus className="w-4 h-4" /> Adjuntar más
          <input type="file" hidden multiple accept="application/pdf,.pdf" onChange={handleUpload} disabled={uploading} />
        </label>
        <button onClick={enviarReporte} disabled={confirming || items.length === 0}
          className="px-5 py-2 bg-brand hover:bg-brand-hover text-white font-bold rounded-lg text-sm flex items-center gap-1.5 disabled:opacity-50"
          data-testid="combustible-enviar-reporte">
          {confirming ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          Enviar reporte ({items.length})
        </button>
      </div>

      {firmasModal && (
        <div className="fixed inset-0 z-[80] bg-black/50 flex items-start justify-center p-4 overflow-y-auto" data-testid="firmas-modal">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-3xl my-6">
            <div className="p-5 border-b border-neutral-200 flex items-start justify-between gap-3">
              <div>
                <div className="text-[10px] uppercase tracking-widest font-bold text-brand">Antes de enviar tu reporte</div>
                <h3 className="font-cabinet text-xl font-bold mt-1">Firma pendiente</h3>
                <p className="text-sm text-neutral-600 mt-1">
                  Para registrar tus facturas ante ENERED debes aceptar la <b>Constancia de términos del servicio</b> (obligatoria).
                  La declaración jurada de veracidad es recomendada. Acepta la constancia aquí y el reporte se enviará solo.
                </p>
              </div>
              <button onClick={() => setFirmasModal(null)} className="text-neutral-400 hover:text-neutral-700 text-xl leading-none" aria-label="Cerrar">×</button>
            </div>
            <div className="p-5">
              {data && totals ? (
                <DeclaracionEtapa data={data} totals={totals} embebida
                  onAccepted={async () => { setFirmasModal(null); onAnyChange?.(); await enviarReporte(); }}
                  onConstancia={async (ok) => {
                    // La constancia es lo único obligatorio: al aceptarla se envía el reporte.
                    if (ok) { setFirmasModal(null); await enviarReporte(); }
                  }} />
              ) : (
                <p className="text-sm text-neutral-600">Ve a la <b>Etapa 4 · Declaración jurada y términos del servicio</b>, fírmalas y vuelve a "Enviar reporte".</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ============================================================ */
/* Etapa 4 — Declaración jurada                                  */
/* ============================================================ */
function DeclaracionEtapa({ data, totals, onAccepted, onConstancia, embebida = false }) {
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const already = data.declaracion;

  // Términos del servicio: la Constancia se acepta en su apartado (ConstanciaApartado);
  // aquí solo guardamos si ya está aceptada para condicionar el firmado de la DJ.
  const [constanciaOk, setConstanciaOkRaw] = useState(false);
  const setConstanciaOk = (ok) => { setConstanciaOkRaw(ok); onConstancia?.(ok); };

  const empresa = data.user?.empresa || "[RAZÓN SOCIAL]";
  // Representante legal: primero el registrado en SUNAT (ficha de la empresa), luego el contacto
  const repLegal = data.user?.representante_legal;
  const repre = repLegal?.nombre || data.user?.contacto || data.user?.name || "[REPRESENTANTE LEGAL]";
  const repreDni = repLegal?.numero_documento || "";

  const empresaOk = totals.byEtapa.empresa.done === totals.byEtapa.empresa.total;
  const flotaOk = totals.byEtapa.flota.done === totals.byEtapa.flota.total;
  const combOk = totals.byEtapa.combustible.done > 0;
  const canSign = empresaOk && flotaOk && combOk && constanciaOk;
  const missingList = [
    !empresaOk && `Etapa 1 · Empresa (${totals.byEtapa.empresa.done}/${totals.byEtapa.empresa.total})`,
    !flotaOk && `Etapa 2 · Flota (${totals.byEtapa.flota.done}/${totals.byEtapa.flota.total})`,
    !combOk && `Etapa 3 · al menos 1 factura cargada`,
    !constanciaOk && `Aceptar la constancia de términos del servicio (arriba)`,
  ].filter(Boolean);

  const submit = async () => {
    setBusy(true); setError(null);
    try {
      const res = await api.post("/subsidio/declaracion", { accepted: true, representante: repre, representante_dni: repreDni || undefined });
      onAccepted?.(res.data?.declaracion);
    } catch (e) {
      const d = e?.response?.data?.detail;
      setError(typeof d === "string" ? d : (d?.message || "Error al firmar"));
    } finally { setBusy(false); }
  };

  if (already) {
    return (
      <div>
        <EtapaHeader n={4} icon={ShieldCheck} title="Declaración jurada y términos del servicio" subtitle="Firmada electrónicamente ✓" />
        <ConstanciaApartado onEstado={setConstanciaOk} />
        <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-5 text-sm">
          <div className="flex items-center gap-2 mb-2"><CheckCircle2 className="w-5 h-5 text-emerald-700" /><strong className="font-cabinet text-base">Declaración firmada</strong></div>
          <ul className="space-y-1 text-emerald-900">
            <li><strong>Fecha y hora:</strong> {new Date(already.accepted_at).toLocaleString("es-PE")}</li>
            <li><strong>Empresa:</strong> {already.empresa} (RUC {already.ruc})</li>
            <li><strong>Representante:</strong> {already.representante}{already.representante_dni ? ` · DNI ${already.representante_dni}` : ""}</li>
          </ul>
        </div>
      </div>
    );
  }

  return (
    <div>
      <EtapaHeader n={4} icon={ShieldCheck} title="Declaración jurada y términos del servicio" subtitle="Acepta los términos del servicio y confirma que tu información es veraz antes de presentar tu solicitud a la ATU" />

      <ConstanciaApartado onEstado={setConstanciaOk} />

      {!canSign && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-3 text-sm text-amber-900 flex gap-2 mb-4" data-testid="declaracion-missing">
          <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <div>
            <strong>Para firmar te falta completar:</strong>
            <ul className="list-disc pl-5 mt-1">
              {missingList.map((m, i) => <li key={i}>{m}</li>)}
            </ul>
          </div>
        </div>
      )}

      <div className="bg-neutral-50 border border-neutral-200 rounded-xl p-5">
        <h4 className="font-cabinet font-bold text-base mb-2">Declaración jurada de veracidad</h4>
        <p className="text-sm text-neutral-700 mb-3">
          Antes de presentar tu solicitud a la ATU, necesitamos que confirmes que tu información es veraz. La solicitud
          del subsidio tiene carácter de declaración jurada ante el Estado.
        </p>
        <blockquote className="bg-white border-l-4 border-brand rounded-r-lg p-4 text-sm text-neutral-700 italic mb-4">
          Declaro bajo juramento que la información, documentos y comprobantes presentados para acceder al subsidio
          económico del Decreto de Urgencia N.° 004-2026 son verdaderos, exactos y corresponden a unidades con
          habilitación vigente. Reconozco que la presentación de información falsa, adulterada o inexacta genera la
          pérdida automática del subsidio, sin perjuicio de las responsabilidades administrativas, civiles y penales
          que correspondan.
        </blockquote>

        <label className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer border ${accepted ? "bg-brand/5 border-brand" : "bg-white border-neutral-300"} ${!canSign ? "opacity-50 cursor-not-allowed" : "hover:bg-brand/5"}`}>
          <input type="checkbox" checked={accepted} disabled={!canSign}
            onChange={(e) => setAccepted(e.target.checked)} className="mt-1 w-5 h-5 accent-violet-600"
            data-testid="declaracion-checkbox" />
          <span className="text-sm text-neutral-800">
            He leído y acepto la declaración de veracidad. Acepto en nombre de <strong>{empresa}</strong>, representada por <strong>{repre}</strong>.
          </span>
        </label>
        <p className="text-[11px] text-neutral-500 mt-2">
          Al marcar esta casilla, tu aceptación queda registrada con fecha, hora y usuario. Esto reemplaza la firma física
          para efectos de tu gestión con Enered.
        </p>

        {error && <div className="mt-3 bg-red-50 border border-red-200 text-red-700 rounded-lg p-3 text-sm" data-testid="declaracion-error">{error}</div>}

        <div className="mt-4 flex items-center justify-end">
          <button onClick={submit} disabled={!accepted || !canSign || busy}
            className="px-5 py-2.5 bg-brand hover:bg-brand-hover text-white font-bold rounded-lg flex items-center gap-2 disabled:opacity-50"
            data-testid="declaracion-submit">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            Firmar y enviar a la ATU
          </button>
        </div>
      </div>
    </div>
  );
}

// Etapa 5 eliminada y reubicada en overlay dinámico al firmar

/* ============================================================ */
/* UI helpers compartidos                                        */
/* ============================================================ */
const nz = (v) => (v === "" || v == null ? null : Number(v));
