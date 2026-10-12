import React, { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { uploadSubsidioInvoices, invoiceUploadFailure } from "../lib/uploadSubsidioInvoices";
import { useLocation } from "react-router-dom";
import QrSubidaCelular from "../components/QrSubidaCelular";
import FirmasPendientes from "../components/FirmasPendientes";
import ConstanciaApartado from "../components/ConstanciaApartado";
import { useAuth } from "../context/AuthContext";
import ComprobantesTabla, { CargaMasiva } from "../components/ComprobantesTabla";
import { EmpresaEtapa, FlotaEtapa, calcVerificacionTotals } from "../components/SubsidioVerificacion";
import {
  Fuel, FileCheck2, Loader2, Upload, CheckCircle2, AlertTriangle,
  MessageCircle, Lock, ShieldCheck, Building2, Truck,
} from "lucide-react";

const WSP = "51997389536";
const fmtNum = (n) => (Number(n) || 0).toLocaleString("es-PE", { maximumFractionDigits: 2 });

/* Empresa y flota se verifican una sola vez y se comparten entre los 3 periodos.
   Combustible y declaración conservan sus registros propios del DU 007. */
const ETAPAS = [
  { id: "empresa", n: "Etapa 1", titulo: "Verificación empresa", sub: "Solo PDF · una sola vez", icon: Building2 },
  { id: "flota", n: "Etapa 2", titulo: "Verificación flota", sub: "PDF, PNG o JPG · una sola vez", icon: Truck },
  { id: "combustible", n: "Etapa 3", titulo: "Combustible", sub: "Solo PDF · por periodo", icon: Fuel },
  { id: "declaracion", n: "Etapa 4", titulo: "Declaración", sub: "Una por periodo", icon: FileCheck2 },
];

const etapaDeUrl = (search) => {
  const id = new URLSearchParams(search).get("etapa");
  return ETAPAS.some((etapa) => etapa.id === id) ? id : null;
};

const PERIODOS_INFO = {
  1: { consumo: "16 ago – 15 set", presenta: "16 set – 15 oct" },
  2: { consumo: "16 set – 15 oct", presenta: "16 oct – 15 nov" },
  3: { consumo: "16 oct – 15 nov", presenta: "16 nov – 15 dic" },
};

export default function SubsidioDU007() {
  const { user } = useAuth();
  const esGuest = !!user?.es_guest;
  const [etapa, setEtapa] = useState(() => etapaDeUrl(window.location.search) || "empresa");
  const locEtapa = useLocation();
  useEffect(() => {
    const e = etapaDeUrl(locEtapa.search);
    if (e) setEtapa(e);
  }, [locEtapa.search]);
  const [items, setItems] = useState([]);
  const [vehicles, setVehicles] = useState([]);
  const [estado, setEstado] = useState(null);   // { periodos, declaraciones }
  const [verificacion, setVerificacion] = useState(null);
  const [cargandoVerificacion, setCargandoVerificacion] = useState(!esGuest);
  const [cargandoPeriodos, setCargandoPeriodos] = useState(!esGuest);
  const [errorVerificacion, setErrorVerificacion] = useState("");
  const [errorPeriodos, setErrorPeriodos] = useState("");
  const [subiendo, setSubiendo] = useState(false);
  const [progresoCarga, setProgresoCarga] = useState(null);
  const [aviso, setAviso] = useState(null);
  const fileRef = useRef(null);
  const etapaElegidaRef = useRef(null);

  const load = async () => {
    if (esGuest) { setCargandoVerificacion(false); setCargandoPeriodos(false); return; }
    if (!verificacion) setCargandoVerificacion(true);
    if (!estado) setCargandoPeriodos(true);
    setErrorVerificacion(""); setErrorPeriodos("");
    // Una consulta de verificación externa lenta o fallida no bloquea los periodos.
    const periodosTask = (async () => {
      try {
        const [prev, est] = await Promise.all([
          api.get("/subsidio/invoices/preview", { params: { programa: "du007" } }),
          api.get("/subsidio/du007/estado"),
        ]);
        setItems(prev.data.items || []);
        setVehicles(prev.data.vehicles || []);
        setEstado(est.data);
        return est.data;
      } catch (error) {
        setErrorPeriodos("No se pudieron cargar los periodos del DU-007. Vuelve a intentarlo.");
        throw error;
      } finally { setCargandoPeriodos(false); }
    })();
    const verificacionTask = (async () => {
      try {
        const { data } = await api.get("/subsidio/dashboard");
        setVerificacion(data);
        return data;
      } catch (error) {
        setErrorVerificacion("No se pudo cargar la verificación de empresa y flota. Tus documentos se conservan; vuelve a intentarlo.");
        throw error;
      } finally { setCargandoVerificacion(false); }
    })();
    const [periodosResult, verificacionResult] = await Promise.allSettled([periodosTask, verificacionTask]);
    if (!etapaDeUrl(window.location.search) && !primeraCargaRef.current && verificacionResult.status === "fulfilled") {
      primeraCargaRef.current = true;
      const pasos = calcVerificacionTotals(verificacionResult.value).byEtapa;
      if (pasos.empresa.done < pasos.empresa.total) setEtapa("empresa");
      else if (pasos.flota.done < pasos.flota.total) setEtapa("flota");
      else {
        setEtapa("combustible");
        if (periodosResult.status === "fulfilled") {
          try {
            const { data: f } = await api.get("/subsidio/firmas");
            if (!etapaElegidaRef.current && !etapaDeUrl(window.location.search) && f && !f.constancia && (periodosResult.value.periodos || []).some((p) => p.facturas > 0)) setEtapa("declaracion");
          } catch (_) {}
        }
      }
    }
  };
  const primeraCargaRef = useRef(false);
  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);
  const seleccionarEtapa = (id) => { etapaElegidaRef.current = id; primeraCargaRef.current = true; setEtapa(id); };
  const cargando = etapa === "empresa" || etapa === "flota" ? cargandoVerificacion : cargandoPeriodos;

  const subir = async (fileList) => {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    setSubiendo(true); setAviso(null);
    try {
      const result = await uploadSubsidioInvoices(files, api, setProgresoCarga);
      const guardadas = result.items.filter((x) => x.id).length;
      const mal = result.items.filter((x) => x.ok === false);
      setAviso({
        tipo: result.error ? "err" : mal.length ? "warn" : "ok",
        texto: `${guardadas} factura${guardadas === 1 ? "" : "s"} guardada${guardadas === 1 ? "" : "s"} al DU 007.` +
               (mal.length ? ` ${mal.length} con problema: ${mal.map((m) => m.error || "Requiere revisión").join("; ")}` : "") +
               (result.error ? ` ${invoiceUploadFailure(result)}` : ""),
      });
      await load();
    } catch (e) {
      setAviso({ tipo: "err", texto: e?.response?.data?.detail || "No se pudieron subir los archivos." });
    } finally {
      setSubiendo(false);
      setProgresoCarga(null);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  // Constancia de términos del servicio: obligatoria antes de firmar la DJ de cualquier periodo
  // (mismo respaldo legal que en el DU 004). El backend también lo exige (409 firmas_pendientes).
  const [constanciaOk, setConstanciaOk] = useState(false);
  const [firmasKey, setFirmasKey] = useState(0);

  const firmar = async (periodo) => {
    if (!constanciaOk) { alert("Primero acepta la Constancia de términos del servicio (arriba)."); return; }
    if (!window.confirm(
      `Vas a firmar la declaración jurada del PERIODO ${periodo} del DU 007.\n\n` +
      "Declaras que los consumos presentados son exactos y corresponden a unidades M2/M3/N1/N2/N3 " +
      "con habilitación vigente. ¿Confirmas?"
    )) return;
    try {
      const { data } = await api.post("/subsidio/du007/declaracion", { periodo });
      alert(`✅ Declaración del periodo ${periodo} firmada (${data.facturas_incluidas} facturas incluidas).`);
      await load();
      setFirmasKey((k) => k + 1);
    } catch (e) {
      const d = e?.response?.data?.detail;
      alert(typeof d === "string" ? d : (d?.message || "No se pudo firmar la declaración."));
    }
  };

  const declaradaEl = (p) =>
    (estado?.declaraciones || []).find((d) => d.periodo === p)?.accepted_at;

  const pasosVerificacion = calcVerificacionTotals(verificacion).byEtapa;

  const wspMsg = encodeURIComponent(
    `Hola ENERED, soy ${user?.empresa || ""} (RUC ${user?.ruc || ""}). Quiero activar mi expediente del DU 007.`);

  const BloquGuest = ({ titulo }) => (
    <div className="bg-white border border-neutral-200 rounded-2xl p-10 text-center shadow-sm">
      <Lock className="w-10 h-10 text-brand mx-auto" />
      <h3 className="font-cabinet font-black text-xl text-neutral-900 mt-3">{titulo}</h3>
      <p className="text-sm text-neutral-500 mt-2 max-w-md mx-auto">
        Para verificar tu empresa y flota, cargar combustible y firmar la declaración del DU 007, activa tu cuenta con el equipo ENERED.
      </p>
      <a href={`https://wa.me/${WSP}?text=${wspMsg}`} target="_blank" rel="noreferrer"
        className="mt-5 inline-flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white font-black px-6 py-3 rounded-xl text-sm">
        <MessageCircle className="w-4 h-4" /> Activar por WhatsApp
      </a>
    </div>
  );

  return (
    <div className="space-y-5">
      {!esGuest && <FirmasPendientes key={firmasKey} actual="du007" />}
      {/* Verificación compartida + combustible y declaración por periodo */}
      <div className="bg-white border border-neutral-200 rounded-2xl p-6 shadow-sm">
        <div className="text-[11px] font-bold uppercase tracking-widest text-brand mb-1">Asistente de subsidio · DU 007-2026</div>
        <h1 className="font-cabinet font-black text-3xl text-neutral-900">Subsidio DU-007</h1>
        <p className="text-neutral-500 mt-1 text-sm">Verifica tu empresa y flota una sola vez. Tres periodos, una presentación por periodo. Tu diagnóstico está en Subsidios → Diagnóstico.</p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-5">
          {ETAPAS.map((e) => {
            const Ic = e.icon;
            const activa = etapa === e.id;
            const paso = pasosVerificacion[e.id];
            const verificada = !!verificacion && !!paso && paso.done === paso.total;
            return (
              <button key={e.id} onClick={() => seleccionarEtapa(e.id)}
                className={`text-left border rounded-xl p-4 relative transition-all ${
                  activa ? "border-brand bg-brand/5 ring-4 ring-brand/10" : verificada ? "border-emerald-300 bg-emerald-50/40 hover:border-emerald-400" : "border-neutral-200 bg-white hover:border-neutral-300"}`}
                data-testid={`du007-etapa-${e.id}`}>
                <div className="text-[10px] font-bold uppercase tracking-widest text-neutral-400">{e.n}</div>
                <div className={`font-bold mt-1 ${activa ? "text-brand" : "text-neutral-900"}`}>{e.titulo}</div>
                <div className="text-[11px] text-neutral-400 mt-0.5">{e.sub}</div>
                <span className={`absolute top-3.5 right-3.5 w-8 h-8 rounded-lg flex items-center justify-center ${
                  verificada ? "bg-emerald-100 text-emerald-700" : activa ? "bg-brand text-white" : "bg-neutral-100 text-neutral-400"}`}>
                  {verificada ? <CheckCircle2 className="w-4 h-4" aria-label="Verificación completa" /> : <Ic className="w-4 h-4" />}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {cargando && <div className="flex justify-center py-10" role="status" aria-label="Cargando expediente"><Loader2 className="w-8 h-8 animate-spin text-brand" /></div>}
      {(errorVerificacion || errorPeriodos) && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700" role="alert">
          {errorVerificacion && <p>{errorVerificacion}</p>}
          {errorPeriodos && <p>{errorPeriodos}</p>}
          <button onClick={load} className="ml-3 font-bold underline">Reintentar</button>
        </div>
      )}

      {/* Datos únicos de empresa y flota, incluidos los registrados antes para DU-004. */}
      {(etapa === "empresa" || etapa === "flota") && (esGuest ? <BloquGuest titulo={etapa === "empresa" ? "Verificación empresa" : "Verificación flota"} /> : verificacion && (
        <div className="bg-white border border-neutral-200 rounded-2xl p-6 shadow-sm" data-testid={`du007-verificacion-${etapa}`}>
          <p className="text-xs text-neutral-500 mb-5">
            Esta verificación se realiza una sola vez para los tres periodos del DU-007. Si ya cargaste documentos en el DU-004, se mantienen aquí.
          </p>
          {etapa === "empresa" ? (
            <EmpresaEtapa items={verificacion.checklist?.empresa} bank={verificacion.bank_account} evidenciaCci={verificacion.evidencia_cci || []} onChange={load} />
          ) : (
            <FlotaEtapa items={verificacion.checklist?.flota} vehicles={verificacion.vehicles} onChange={load} />
          )}
          <div className="flex items-center justify-between mt-6 pt-5 border-t border-neutral-100">
            <button onClick={() => seleccionarEtapa("empresa")} disabled={etapa === "empresa"} className="px-4 py-2 text-sm font-bold text-neutral-600 hover:bg-neutral-100 rounded-lg disabled:opacity-30 disabled:cursor-not-allowed">← Etapa anterior</button>
            <button onClick={() => seleccionarEtapa(etapa === "empresa" ? "flota" : "combustible")} className="px-4 py-2 text-sm font-bold text-brand hover:bg-brand/5 rounded-lg">Siguiente etapa →</button>
          </div>
        </div>
      ))}

      {/* ETAPA 3 · Combustible: mismo bucket DU-007 y los mismos 3 periodos. */}
      {etapa === "combustible" && (esGuest ? <BloquGuest titulo="Carga de combustible" /> : estado && (
        <div className="space-y-4">
          <div className="bg-white border border-neutral-200 rounded-2xl p-6 shadow-sm">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div>
                <h3 className="font-cabinet font-bold text-lg text-neutral-900 flex items-center gap-2">
                  <Fuel className="w-5 h-5 text-brand" /> Combustible del DU 007
                </h3>
                <p className="text-xs text-neutral-500 mt-1">
                  Solo PDF. Cada factura se valida contra los 3 periodos del decreto
                  (P1: {PERIODOS_INFO[1].consumo} · P2: {PERIODOS_INFO[2].consumo} · P3: {PERIODOS_INFO[3].consumo})
                  y se asigna sola a su periodo. Unidades M2, M3, N1, N2 y N3.
                </p>
              </div>
              <input ref={fileRef} type="file" hidden multiple accept="application/pdf,.pdf"
                onChange={(e) => subir(e.target.files)} data-testid="du007-upload-input" />
              <button onClick={() => fileRef.current?.click()} disabled={subiendo}
                className="btn-brand px-5 py-3 rounded-xl text-sm font-bold flex items-center gap-2 disabled:opacity-60"
                data-testid="du007-upload-btn">
                {subiendo ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                {subiendo ? `Leyendo factura ${progresoCarga?.current || 1} de ${progresoCarga?.total || 1}…` : "Subir facturas (PDF)"}
              </button>
              <QrSubidaCelular programa="du007" onNuevas={load} />
            </div>
            {aviso && (
              <div className={`mt-3 text-sm rounded-lg px-4 py-2.5 font-semibold border ${
                aviso.tipo === "ok" ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                : aviso.tipo === "warn" ? "bg-amber-50 border-amber-200 text-amber-800"
                : "bg-red-50 border-red-200 text-red-700"}`}>
                {aviso.texto}
              </div>
            )}
            {/* Resumen por periodo: solo facturas VÁLIDAS, agrupadas por su fecha de emisión */}
            {estado && (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4">
                  {estado.periodos.map((p) => (
                    <div key={p.periodo} className="border border-neutral-200 rounded-xl p-3">
                      <div className="text-[11px] font-bold text-brand">PERIODO {p.periodo} <span className="text-neutral-400 font-medium">· consumo {PERIODOS_INFO[p.periodo].consumo}</span></div>
                      <div className="text-sm mt-1 text-neutral-700">
                        <b>{p.facturas}</b> factura{p.facturas === 1 ? "" : "s"} válida{p.facturas === 1 ? "" : "s"} · {fmtNum(p.galones)} gal · S/ {fmtNum(p.importe)}
                      </div>
                    </div>
                  ))}
                </div>
                {(estado.fuera_periodo > 0 || estado.rechazadas > 0) && (
                  <div className="mt-3 flex items-start gap-2 text-sm bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-2.5 font-semibold">
                    <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                    <span>
                      {estado.fuera_periodo > 0 && (
                        <>{estado.fuera_periodo} factura{estado.fuera_periodo === 1 ? "" : "s"} con fecha de emisión
                        {" "}<b>fuera de los 3 periodos</b> del DU 007 — no cuentan para el subsidio.{" "}</>
                      )}
                      {estado.rechazadas > 0 && (
                        <>{estado.rechazadas} rechazada{estado.rechazadas === 1 ? "" : "s"} por otras observaciones.</>
                      )}
                    </span>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Carga masiva por plantilla (formato ENERED, compatible con la ATU) — propio bucket DU 007 */}
          <CargaMasiva programa="du007" onDone={(r) => {
            setAviso({ tipo: "ok", texto: `Se guardaron ${r.guardadas} comprobante(s) al DU 007${r.omitidas ? ` · ${r.omitidas} omitido(s) por errores` : ""}.` });
            load();
          }} />

          {items.length > 0 && <ComprobantesTabla items={items} vehicles={vehicles} onChange={load} />}
        </div>
      ))}

      {/* ETAPA 4 · Declaración: una por periodo, sin repetir empresa o flota. */}
      {etapa === "declaracion" && (esGuest ? <BloquGuest titulo="Declaración jurada" /> : estado && (
        <>
        <ConstanciaApartado onEstado={setConstanciaOk} />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {(estado?.periodos || []).map((p) => {
            const firmada = declaradaEl(p.periodo);
            const puede = p.facturas > 0 && !firmada && constanciaOk;
            return (
              <div key={p.periodo} className="bg-white border border-neutral-200 rounded-2xl p-5 shadow-sm flex flex-col">
                <div className="text-[11px] font-bold uppercase tracking-widest text-brand">Periodo {p.periodo}</div>
                <div className="text-xs text-neutral-500 mt-1">
                  Consumo {PERIODOS_INFO[p.periodo].consumo} · presentas {PERIODOS_INFO[p.periodo].presenta}
                </div>
                <div className="mt-4 text-sm text-neutral-700 space-y-1">
                  <div><b>{p.facturas}</b> factura{p.facturas === 1 ? "" : "s"} cargada{p.facturas === 1 ? "" : "s"}</div>
                  <div>{fmtNum(p.galones)} galones · S/ {fmtNum(p.importe)}</div>
                  <div className="text-emerald-700">{p.conformes} conforme{p.conformes === 1 ? "" : "s"}</div>
                </div>
                <div className="mt-auto pt-4">
                  {firmada ? (
                    <div className="flex items-center gap-2 text-emerald-700 text-sm font-bold bg-emerald-50 border border-emerald-200 rounded-lg px-3 py-2.5">
                      <ShieldCheck className="w-4 h-4" /> Firmada el {String(firmada).slice(0, 10)}
                    </div>
                  ) : (
                    <button onClick={() => firmar(p.periodo)} disabled={!puede}
                      className="w-full btn-brand py-2.5 rounded-lg text-sm font-bold disabled:opacity-50 flex items-center justify-center gap-2">
                      {puede ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                      {p.facturas === 0 ? "Facturas pendientes de carga" : !constanciaOk ? "Acepta la constancia (arriba)" : "Firmar declaración"}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
        </>
      ))}
    </div>
  );
}
