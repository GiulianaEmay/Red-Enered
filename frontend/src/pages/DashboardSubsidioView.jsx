import React, { useEffect, useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Fuel, Banknote, Truck, FileCheck2, CheckCircle2, ShieldCheck, FileText, Clock, RefreshCw, Gift, MessageCircle } from "lucide-react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, Cell,
  PieChart, Pie,
} from "recharts";
import { api } from "../lib/api";
import TrackerSubsidio from "../components/TrackerSubsidio";
import ValidacionPendiente from "../components/ValidacionPendiente";

const STAGE_ICONS = {
  solicitud_enviada:   FileCheck2,
  evaluacion_atu:      ShieldCheck,
  aprobada:            CheckCircle2,
  abonado_en_cuenta:   Banknote,
};

export default function DashboardSubsidioView() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [serieView, setSerieView] = useState("galones"); // galones | importe
  const [topUView, setTopUView] = useState("galones");
  const [topEView, setTopEView] = useState("galones");

  const fetchData = useCallback(async (silent = false) => {
    if (silent) setRefreshing(true);
    try {
      const { data } = await api.get("/subsidio/dashboard-data");
      setData(data);
    } catch (err) {
      console.error("Error loading Subsidio Dashboard:", err);
    } finally {
      if (silent) setRefreshing(false);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Refetch al volver el foco a la pestaña (p.ej. tras confirmar facturas en otra ruta)
    const onFocus = () => fetchData(true);
    const onVisibility = () => { if (!document.hidden) fetchData(true); };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [fetchData]);

  const {
    stages = [], kpis = {}, serie_semanal = [],
    top_unidades = [], top_estaciones = [],
    documentos_semaforo = { items: [], summary: {} },
    pending_drafts = 0,
    verificacion = null,
  } = data || {};

  const fmt = (n) => Number(n || 0).toLocaleString("es-PE", { maximumFractionDigits: 2 });
  const hasNoData =
    (kpis.galones_reconocidos || 0) === 0 &&
    (kpis.gasto_total || 0) === 0 &&
    serie_semanal.length === 0 &&
    top_unidades.length === 0;

  // Estado de validación de facturas por ENERED.
  const invoicesConfirmed = kpis.invoices_confirmed || 0;
  // Hay facturas cargadas que ENERED todavía está validando (aún no reflejan datos).
  const enValidacion = pending_drafts > 0 || (invoicesConfirmed > 0 && hasNoData);
  // No se ha cargado ninguna factura todavía.
  const sinFacturas = hasNoData && pending_drafts === 0 && invoicesConfirmed === 0;
  // WhatsApp para acelerar la validación.
  const WA_VALIDACION = `https://wa.me/51997389536?text=${encodeURIComponent("Hola ENERED, cargué mis facturas de combustible y quisiera acelerar la validación para ver mis resultados.")}`;

  const donutData = useMemo(() => {
    if (!top_estaciones || top_estaciones.length === 0) {
      return [];
    }
    const total = top_estaciones.reduce((sum, item) => sum + (item.importe || 0), 0);
    if (total === 0) {
      return [];
    }
    const sorted = [...top_estaciones].sort((a, b) => b.importe - a.importe);
    const first = sorted[0];
    const second = sorted[1];
    const firstPct = Math.round((first.importe / total) * 100);
    const secondPct = second ? Math.round((second.importe / total) * 100) : 0;
    const otherPct = 100 - firstPct - secondPct;

    const cleanName = (name) => {
      if (name.toLowerCase().includes("trujillo")) return "Trujillo";
      if (name.toLowerCase().includes("chiclayo")) return "Chiclayo";
      if (name.toLowerCase().includes("lima")) return "Lima";
      return name.split(/[\s.-]+/)[0] || name;
    };

    const res = [
      { name: cleanName(first.estacion), value: firstPct, color: "#8039F4" },
    ];
    if (second) {
      res.push({ name: cleanName(second.estacion), value: secondPct, color: "#A78BFA" });
    }
    if (otherPct > 0) {
      res.push({ name: "Otras", value: otherPct, color: "#E9D5FF" });
    }
    return res;
  }, [top_estaciones]);

  const docRows = useMemo(() => {
    const items = documentos_semaforo?.items || [];
    const rank = { expired: 0, expiring: 1, missing: 2, unknown: 3, active: 4 };
    const style = (st) => {
      if (st === "expired")  return { badge: "VENCIDO",    bg: "bg-red-50/60 border-red-200 text-red-700",       dot: "bg-red-500",     badgeColor: "text-red-600" };
      if (st === "expiring") return { badge: "POR VENCER", bg: "bg-red-50/60 border-red-200 text-red-700",       dot: "bg-red-500",     badgeColor: "text-red-600" };
      if (st === "missing")  return { badge: "ATENCIÓN",   bg: "bg-amber-50/60 border-amber-200 text-amber-700", dot: "bg-amber-500",   badgeColor: "text-amber-600" };
      if (st === "unknown")  return { badge: "SIN DATO",   bg: "bg-neutral-50/60 border-neutral-200 text-neutral-500", dot: "bg-neutral-400", badgeColor: "text-neutral-500" };
      return { badge: "EN REGLA", bg: "bg-emerald-50/60 border-emerald-200 text-emerald-700", dot: "bg-emerald-500", badgeColor: "text-emerald-600" };
    };
    // Primero lo urgente (vencido → por vencer → pendiente); lo verificado en regla se resume abajo.
    const alertas = items
      .filter((d) => d.status !== "active")
      .sort((a, b) => (rank[a.status] ?? 9) - (rank[b.status] ?? 9) || ((a.days_remaining ?? 9999) - (b.days_remaining ?? 9999)));
    const res = alertas.slice(0, 3).map((d) => ({
      title: `${d.label}${d.placa ? " - " + d.placa : ""}`,
      desc: d.detalle || (typeof d.days_remaining === "number" ? `vence en ${d.days_remaining} días` : ""),
      ...style(d.status),
    }));
    const total = kpis.unidades_incluidas ?? 0;
    const enRegla = kpis.unidades_en_regla ?? 0;
    const restantes = alertas.length - res.length;
    if (restantes > 0) {
      res.push({
        title: `${restantes} alerta${restantes > 1 ? "s" : ""} más`,
        desc: "revisa el detalle en Documentación",
        ...style("missing"),
      });
    }
    res.push({
      title: `Unidades en regla - ${enRegla} de ${total}`,
      desc: total === 0
        ? "No se han registrado vehículos aún"
        : enRegla > 0 ? "habilitación MTC y vigencias al día" : "ninguna unidad con todo verificado y vigente",
      badge: total === 0 ? "SIN DATOS" : enRegla > 0 ? "EN REGLA" : "ATENCIÓN",
      bg: total === 0 ? "bg-neutral-50/60 border-neutral-200 text-neutral-500"
        : enRegla > 0 ? "bg-emerald-50/60 border-emerald-200 text-emerald-700" : "bg-amber-50/60 border-amber-200 text-amber-700",
      dot: total === 0 ? "bg-neutral-400" : enRegla > 0 ? "bg-emerald-500" : "bg-amber-500",
      badgeColor: total === 0 ? "text-neutral-500" : enRegla > 0 ? "text-emerald-600" : "text-amber-600",
    });
    return res;
  }, [documentos_semaforo, kpis]);

  if (loading) {
    return (
      <div className="min-h-[400px] flex items-center justify-center" data-testid="dashboard-subsidio-loading">
        <Loader2 className="w-8 h-8 animate-spin text-brand" />
      </div>
    );
  }
  if (!data) return null;

  return (
    <div className="space-y-6" data-testid="dashboard-subsidio">
      {/* Header buttons row */}
      <div className="flex items-center justify-end gap-2 mb-2">
        <button
          onClick={() => fetchData(true)}
          disabled={refreshing}
          className="h-10 px-3 border border-neutral-300 hover:border-brand text-neutral-600 hover:text-brand text-sm font-bold rounded-lg flex items-center gap-2 disabled:opacity-50 bg-white"
          data-testid="dashboard-subsidio-refresh"
          title="Actualizar datos"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`} />
          {refreshing ? "Actualizando..." : "Actualizar"}
        </button>
        <button
          onClick={() => navigate("/subsidio/du007?etapa=combustible")}
          className="px-4 py-2 bg-brand hover:bg-brand-hover text-white text-sm font-bold rounded-lg flex items-center gap-2"
          data-testid="dashboard-subsidio-cta-expediente"
        >
          <FileCheck2 className="w-4 h-4" /> Subir más facturas
        </button>
      </div>

      {/* Banner: ENERED está validando las facturas cargadas */}
      {enValidacion && (
        <div
          className="bg-gradient-to-r from-brand/5 to-cyan-50 border border-brand/25 rounded-2xl p-4 flex items-start gap-3 shadow-sm"
          data-testid="dashboard-validando-banner"
        >
          <div className="w-10 h-10 rounded-lg bg-brand text-white flex items-center justify-center flex-shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div className="flex-1">
            <div className="font-cabinet font-bold text-neutral-900 flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin text-brand" /> Estamos validando tus facturas
            </div>
            <p className="text-xs text-neutral-600 mt-0.5">
              ENERED está revisando {pending_drafts > 0 ? `las ${pending_drafts} ` : "las "}facturas que cargaste.
              En cuanto se validen, verás aquí tu consumo, KPIs y rankings actualizados.
            </p>
          </div>
          <a
            href={WA_VALIDACION}
            target="_blank"
            rel="noreferrer"
            className="px-4 py-2 bg-brand hover:bg-brand-hover text-white text-sm font-bold rounded-lg flex items-center gap-2 flex-shrink-0"
            data-testid="dashboard-validando-cta"
          >
            <MessageCircle className="w-4 h-4" /> Obtener resultados ahora
          </a>
        </div>
      )}

      {/* Banner: sin facturas cargadas todavía */}
      {sinFacturas && (
        <div
          className="bg-gradient-to-r from-brand/5 to-cyan-50 border border-brand/20 rounded-2xl p-4 flex items-start gap-3 shadow-sm"
          data-testid="dashboard-empty-banner"
        >
          <div className="w-10 h-10 rounded-lg bg-brand text-white flex items-center justify-center flex-shrink-0">
            <Fuel className="w-5 h-5" />
          </div>
          <div className="flex-1">
            <div className="font-cabinet font-bold text-neutral-900">Aún no has cargado facturas</div>
            <p className="text-xs text-neutral-600 mt-0.5">
              Carga tus comprobantes de combustible. ENERED los validará y aquí verás tus KPIs, evolución semanal y rankings.
            </p>
          </div>
          <button
            onClick={() => navigate("/subsidio/du007?etapa=combustible")}
            className="px-4 py-2 bg-brand hover:bg-brand-hover text-white text-sm font-bold rounded-lg flex items-center gap-2 flex-shrink-0"
            data-testid="dashboard-empty-banner-cta"
          >
            <FileCheck2 className="w-4 h-4" /> Subir facturas
          </button>
        </div>
      )}

      {/* FILA 1 — Stages */}
      <TrackerSubsidio />

      {/* Aviso: información en validación — explica el consumo en S/0 */}
      <ValidacionPendiente contexto="tu consumo de combustible y tus indicadores" />

      {/* MAIN 3-COLUMN CONTENT GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* COLUMN 1: CONSUMO DE COMBUSTIBLE */}
        <div className="bg-white border border-neutral-200 rounded-3xl p-6 shadow-sm flex flex-col justify-between" data-testid="card-consumo-combustible">
          <div>
            <div className="flex items-center gap-2.5 mb-5">
              <div className="w-10 h-10 rounded-full bg-[#8039F4]/10 flex items-center justify-center text-[#8039F4] flex-shrink-0">
                <Fuel className="w-5 h-5" strokeWidth={2.5} />
              </div>
              <h3 className="font-cabinet font-black text-lg text-[#8039F4] tracking-wider uppercase">CONSUMO DE COMBUSTIBLE</h3>
            </div>

            {/* Row 1: Gasto total & Precio promedio */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-neutral-50 rounded-2xl p-4">
                <span className="text-sm font-bold text-neutral-500 block mb-1">Gasto total diésel</span>
                <div className="font-cabinet font-black text-2xl md:text-3xl text-neutral-800">S/ {fmt(kpis.gasto_total ?? 0)}</div>
                <span className="text-xs text-neutral-400 font-medium block mt-1">
                  {kpis.num_meses ?? 0} meses • {fmt(kpis.galones_reconocidos ?? 0)} gal
                  {(kpis.facturas_sin_importe ?? 0) > 0 && (
                    <span className="block text-amber-600 font-bold mt-0.5">
                      {kpis.facturas_sin_importe} factura{kpis.facturas_sin_importe > 1 ? "s" : ""} sin importe · edítalas en Facturas
                    </span>
                  )}
                </span>
              </div>
              <div className="bg-neutral-50 rounded-2xl p-4">
                <span className="text-sm font-bold text-neutral-500 block mb-1">Precio prom./galón</span>
                <div className="font-cabinet font-black text-2xl md:text-3xl text-neutral-800">S/ {fmt(kpis.precio_promedio_galon ?? 0)}</div>
                <span className="text-xs text-emerald-600 font-bold block mt-1 flex items-center gap-0.5">
                  {kpis.precio_promedio_diff ? `▼ ${fmt(Math.abs(kpis.precio_promedio_diff))} vs mes ant.` : "Sin datos de mes anterior"}
                </span>
              </div>
            </div>

            {/* Row 2: Charts Side by Side */}
            <div className="grid grid-cols-2 gap-4 mt-6 items-center">
              <div>
                <span className="text-sm font-bold text-neutral-600 block mb-3">Evolución semanal del gasto</span>
                {serie_semanal.length === 0 ? (
                  <div className="text-sm text-neutral-400 py-6 text-center border border-dashed border-neutral-100 rounded-lg">Sin datos</div>
                ) : (
                  <ResponsiveContainer width="100%" height={90}>
                    <BarChart data={serie_semanal} margin={{ top: 5, right: 0, left: -25, bottom: 0 }}>
                      <XAxis dataKey="semana" stroke="#d4d4d4" fontSize={11} tickLine={false} axisLine={false} />
                      <Bar dataKey="importe" fill="#8039F4" radius={[3, 3, 0, 0]}>
                        {serie_semanal.map((entry, index) => {
                          const isS6 = entry.semana === "Sem 6";
                          return <Cell key={`cell-${index}`} fill={isS6 ? "#EF4444" : "#A78BFA"} />;
                        })}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>

              <div>
                <span className="text-sm font-bold text-neutral-600 block mb-2">Dónde cargas</span>
                <div className="flex items-center gap-2">
                  <div className="w-20 h-20 flex-shrink-0">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={donutData}
                          cx="50%"
                          cy="50%"
                          innerRadius={22}
                          outerRadius={34}
                          paddingAngle={1}
                          dataKey="value"
                        >
                          {donutData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex flex-col justify-center text-xs space-y-1.5 text-neutral-500">
                    {donutData.map((d, i) => (
                      <div key={i} className="flex items-center gap-1.5 whitespace-nowrap">
                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
                        <span className="font-semibold text-neutral-600">{d.name}</span>
                        <span className="text-neutral-400 font-bold">{d.value}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom section: rankings in text */}
          <div className="grid grid-cols-2 gap-4 border-t border-neutral-100 pt-4 mt-6">
            <div>
              <span className="text-sm font-bold text-neutral-600 block mb-2">Unidades que más gastan</span>
              <div className="space-y-2">
                {top_unidades.length === 0 ? (
                  <div className="text-xs text-neutral-400 py-2">Sin datos</div>
                ) : top_unidades.slice(0, 3).map((item, idx) => {
                  const meta = [item.categoria, item.anio].filter(Boolean).join("·") || "sin datos MTC";
                  return (
                    <div key={idx} className="flex items-center justify-between py-1.5 border-b border-neutral-50/50">
                      <div>
                        <div className="font-bold text-neutral-700 text-sm">{item.placa}</div>
                        <div className="text-xs text-neutral-400">{meta}</div>
                      </div>
                      <div className="font-cabinet font-black text-neutral-800 text-sm">S/ {fmt(item.importe)}</div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <span className="text-sm font-bold text-neutral-600 block mb-2">Estaciones donde más cargas</span>
              <div className="space-y-2">
                {top_estaciones.length === 0 ? (
                  <div className="text-xs text-neutral-400 py-2">Sin datos</div>
                ) : top_estaciones.slice(0, 3).map((item, idx) => {
                  const cleanEst = item.estacion.length > 16 ? item.estacion.slice(0, 16) + "…" : item.estacion;
                  return (
                    <div key={idx} className="flex items-center justify-between py-1.5 border-b border-neutral-50/50">
                      <div>
                        <div className="font-bold text-neutral-700 text-sm">{cleanEst}</div>
                        <div className="text-xs text-neutral-400">Combustible</div>
                      </div>
                      <div className="font-cabinet font-black text-neutral-800 text-sm">S/ {fmt(item.importe)}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* COLUMN 2: ESTADO DE VEHÍCULOS */}
        <div className="bg-white border border-neutral-200 rounded-3xl p-6 shadow-sm flex flex-col justify-between" data-testid="card-estado-vehiculos">
          <div>
            <div className="flex items-center gap-2.5 mb-5">
              <div className="w-10 h-10 rounded-full bg-[#8039F4]/10 flex items-center justify-center text-[#8039F4] flex-shrink-0">
                <Truck className="w-5 h-5" strokeWidth={2.5} />
              </div>
              <h3 className="font-cabinet font-black text-lg text-[#8039F4] tracking-wider uppercase">ESTADO DE VEHÍCULOS</h3>
            </div>

            {/* Row 1 KPIs */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-neutral-50 rounded-2xl p-4">
                <span className="text-sm font-bold text-neutral-500 block mb-1">Unidades incluidas</span>
                <div className="font-cabinet font-black text-2xl md:text-3xl text-neutral-800">
                  {kpis.unidades_incluidas ?? 0}{kpis.unidades_mtc != null ? `/${kpis.unidades_mtc}` : ""}
                </div>
                <span className="text-xs text-neutral-400 font-medium block mt-1">
                  {kpis.unidades_mtc != null ? "en el expediente / habilitadas en el MTC" : "en el expediente"}
                </span>
              </div>
              <div className="bg-neutral-50 rounded-2xl p-4">
                <span className="text-sm font-bold text-neutral-500 block mb-1">Habilitadas y activas</span>
                <div className="font-cabinet font-black text-2xl md:text-3xl text-neutral-800">
                  {kpis.unidades_validas ?? 0}/{kpis.unidades_incluidas ?? 0}
                </div>
                <span className="text-xs text-emerald-600 font-bold block mt-1">
                  {kpis.unidades_validas_pct ?? 0}% habilitadas{verificacion?.mtc ? " · MTC" : ""}
                </span>
              </div>
            </div>

            {/* Row 2 KPIs */}
            <div className="grid grid-cols-2 gap-3 mt-3">
              <div className="bg-neutral-50 rounded-2xl p-4">
                <span className="text-sm font-bold text-neutral-500 block mb-1">Galones reconocidos</span>
                <div className="font-cabinet font-black text-2xl md:text-3xl text-neutral-800">
                  {fmt(kpis.galones_reconocidos ?? 0)}
                </div>
                <span className="text-xs text-neutral-400 font-medium block mt-1">
                  de {kpis.invoices_confirmed ?? 0} comprobantes
                </span>
              </div>
              <div className="bg-neutral-50 rounded-2xl p-4">
                <span className="text-sm font-bold text-neutral-500 block mb-1">Costo prom./unidad</span>
                <div className="font-cabinet font-black text-2xl md:text-3xl text-neutral-800">
                  S/ {fmt(kpis.costo_promedio_unidad ?? 0)}
                </div>
                <span className="text-xs text-neutral-400 font-medium block mt-1">
                  {kpis.num_meses ?? 0} meses
                </span>
              </div>
            </div>
          </div>

          {/* Bottom Card: Antigüedad de flota */}
          <div className="bg-amber-50/50 border border-amber-200 rounded-2xl p-5 mt-6">
            <div className="flex justify-between items-start">
              <span className="text-sm font-bold text-neutral-500">Antigüedad de flota</span>
              <div className="text-right">
                <div className="text-4xl font-cabinet font-black text-amber-600 leading-none">{kpis.older_than_10 ?? 0}</div>
                <div className="text-xs font-bold text-neutral-500 mt-1">unidades +10 años</div>
              </div>
            </div>
            <div className="mt-1 flex items-baseline gap-1">
              <span className="text-4xl font-cabinet font-black text-neutral-800">{fmt(kpis.avg_age ?? 0)}</span>
              <span className="text-sm font-semibold text-neutral-500">años prom.</span>
              <span className="text-xs text-neutral-400 font-medium ml-1">
                {(kpis.anios_conocidos ?? 0) > 0
                  ? `año de fabricación MTC en ${kpis.anios_conocidos} de ${kpis.unidades_incluidas ?? 0}`
                  : "sin año de fabricación verificado"}
              </span>
            </div>
            <p className="text-sm font-bold text-amber-950 mt-3 leading-tight">
              Evaluar mantenimiento o renovación con monitoreo real.
            </p>
          </div>
        </div>

        {/* COLUMN 3: ESTADO DE DOCUMENTACIÓN */}
        <div className="bg-white border border-neutral-200 rounded-3xl p-6 shadow-sm flex flex-col justify-between" data-testid="card-estado-documentacion">
          <div className="space-y-5">
            <div className="flex items-center gap-2.5 mb-5">
              <div className="w-10 h-10 rounded-full bg-[#8039F4]/10 flex items-center justify-center text-[#8039F4] flex-shrink-0">
                <FileText className="w-5 h-5" strokeWidth={2.5} />
              </div>
              <h3 className="font-cabinet font-black text-lg text-[#8039F4] tracking-wider uppercase">ESTADO DE DOCUMENTACIÓN</h3>
            </div>

            {/* Circular progress and title */}
            <div className="flex items-center gap-4 bg-neutral-50/30 border border-neutral-100 rounded-2xl p-4">
              <div className="relative w-14 h-14 flex items-center justify-center flex-shrink-0">
                <svg className="w-full h-full transform -rotate-90">
                  <circle cx="28" cy="28" r="24" stroke="#E5E7EB" strokeWidth="4" fill="transparent" />
                  <circle cx="28" cy="28" r="24" stroke="#10B981" strokeWidth="4" fill="transparent"
                    strokeDasharray={150.8}
                    strokeDashoffset={150.8 * (1 - (kpis.pct_docs ?? 0) / 100)}
                    strokeLinecap="round" />
                </svg>
                <span className="absolute text-xs font-cabinet font-black text-neutral-800">{kpis.pct_docs ?? 0}%</span>
              </div>
              <div>
                <div className="font-bold text-neutral-800 text-sm md:text-base">Documentos en regla</div>
                <div className="text-xs text-neutral-400 mt-0.5">
                  {(verificacion?.fuentes || []).length > 0
                    ? `Verificado en ${verificacion.fuentes.join(" · ")}`
                    : "Semáforo de vencimientos de tu flota"}
                </div>
              </div>
            </div>

            {/* Alert List Rows */}
            <div className="space-y-2.5">
              {docRows.map((row, idx) => (
                <div key={idx} className={`border rounded-2xl p-4 flex items-center justify-between ${row.bg}`}>
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${row.dot}`} />
                    <div className="min-w-0">
                      <div className="font-bold text-neutral-800 text-sm truncate leading-tight">{row.title}</div>
                      <div className="text-xs font-medium text-neutral-600 mt-0.5">{row.desc}</div>
                    </div>
                  </div>
                  <span className={`text-xs font-black tracking-wider whitespace-nowrap ml-2 ${row.badgeColor}`}>{row.badge}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

      {/* BOTTOM PROMOTIONAL BANNER */}
      <div
        className="text-white border border-brand/20 rounded-3xl p-6 shadow-md relative overflow-hidden flex flex-col md:flex-row items-center gap-6 justify-between mt-6"
        style={{ background: "linear-gradient(90deg, #3B0078 0%, #6100C2 100%)" }}
      >
        <div className="absolute top-0 right-0 w-80 h-80 bg-brand/20 rounded-full blur-3xl transform translate-x-10 -translate-y-10 pointer-events-none" />
        
        <div className="flex items-center gap-4 relative z-10 w-full md:w-auto">
          <div className="w-12 h-12 rounded-2xl bg-white/10 text-white flex items-center justify-center flex-shrink-0 shadow-lg shadow-black/10">
            <span className="text-xl">🚀</span>
          </div>
          <div>
            <h3 className="font-cabinet font-black text-sm md:text-base text-white leading-tight">
              Tus {kpis.unidades_incluidas ?? 0} unidades ya viven en ENERED. Conviértelas en control total.
            </h3>
            <div className="flex flex-wrap gap-1.5 mt-2.5">
              <span className="px-2 py-0.5 rounded-full bg-white/10 text-xs font-bold whitespace-nowrap">📍 Ubicación en vivo</span>
              <span className="px-2 py-0.5 rounded-full bg-white/10 text-xs font-bold whitespace-nowrap">⛽ Km/galón real</span>
              <span className="px-2 py-0.5 rounded-full bg-white/10 text-xs font-bold whitespace-nowrap">🚨 Alertas de velocidad</span>
              <span className="px-2 py-0.5 rounded-full bg-white/10 text-xs font-bold whitespace-nowrap">🔧 Mantenimiento predictivo</span>
            </div>
          </div>
        </div>

        <div className="flex flex-col items-center md:items-end flex-shrink-0 relative z-10 w-full md:w-auto">
          <button
            onClick={() => window.open("https://wa.me/51997389536?text=Hola,%20quiero%20agendar%20mi%20activación%20de%20unidades%20en%20ENERED", "_blank")}
            className="bg-white hover:bg-neutral-100 text-[#6100C2] font-cabinet font-black px-5 py-2.5 rounded-2xl shadow-lg transition-all flex items-center gap-2 hover:scale-[1.02] active:scale-[0.98] w-full md:w-auto justify-center text-sm"
          >
            <span>📅</span> Agendar mi activación &gt;
          </button>
          <div className="text-xs text-white/70 font-semibold mt-1.5 text-center md:text-right">
            30 min con un Product Manager • gratis • activas solo lo que necesitas
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================================================ */
/* Stages — Fila 1                                              */
/* ============================================================ */
const fmtStageDate = (isoStr, formatType) => {
  if (!isoStr) return "—";
  try {
    const d = new Date(isoStr);
    const months = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];
    const day = String(d.getDate()).padStart(2, '0');
    const month = months[d.getMonth()];
    const year = d.getFullYear();
    if (formatType === "desde") {
      return `desde ${day} ${month}`;
    }
    return `${day} ${month} ${year}`;
  } catch {
    return "—";
  }
};

/* ============================================================ */
/* Stages — Fila 1                                              */
/* ============================================================ */
function StagesRow({ stages, user, kpis }) {
  const subsidioReconocido = (kpis.galones_reconocidos || 0) * 4;
  const gastoTotal = kpis.gasto_total || 0;
  const pctAhorro = gastoTotal > 0 ? ((subsidioReconocido / gastoTotal) * 100).toFixed(1) : "0.0";

  const num = (v) => Number(v || 0).toLocaleString("es-PE", { maximumFractionDigits: 0 });

  // COUNTDOWN TIMER (Target: September 28, 2026 at 23:59:59)
  const TARGET_DATE = useMemo(() => new Date("2026-09-28T23:59:59"), []);
  const [timeLeft, setTimeLeft] = useState({ days: 0, hours: 0, minutes: 0, seconds: 0 });

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
  }, [TARGET_DATE]);

  const pad = (n) => String(n).padStart(2, "0");

  if (!stages?.length) return null;

  return (
    <div
      className="text-white border border-brand/20 rounded-2xl p-4 shadow-md relative overflow-hidden flex flex-col lg:flex-row items-center gap-6 justify-between"
      style={{ background: "linear-gradient(90deg, #8039F4 0%, #6B26DC 100%)" }}
      data-testid="card-stages"
    >
      {/* Subsidio Reconocido */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-full bg-amber-400 text-[#2D0A4E] flex items-center justify-center flex-shrink-0 shadow-sm">
          <Gift className="w-5 h-5 fill-current" />
        </div>
        <div>
          <div className="text-xs uppercase tracking-wider text-white/70 font-semibold leading-tight">Subsidio Reconocido</div>
          <div className="text-xl lg:text-2xl font-cabinet font-black text-white leading-tight">
            S/ {num(subsidioReconocido)}
          </div>
        </div>
      </div>

      {/* Divider */}
      <div className="hidden lg:block h-10 w-px bg-white/20 self-center" />

      {/* Progress Timeline */}
      <div className="flex-1 flex items-center justify-between relative px-6 min-w-[280px] w-full lg:w-auto">
        {/* line track */}
        <div className="absolute top-[16px] left-[10%] right-[10%] h-[2px] bg-white/25" />
        
        <div className="w-full flex items-center justify-between relative">
          {stages.map((s) => {
            const isDone = s.status === "done";
            const isCurrent = s.status === "current";
            
            let dotCls = "bg-white/20 border-white/30 text-white/50";
            if (isDone || isCurrent) {
              dotCls = "bg-white text-[#8039F4] border-white";
            }

            const getStageLabel = (key, originalLabel) => {
              if (key === "solicitud_enviada") return "Enviado";
              if (key === "evaluacion_atu") return "En evaluación ATU";
              if (key === "aprobada") return "Aprobada";
              if (key === "abonado_en_cuenta") return "Abonado";
              return originalLabel;
            };

            return (
              <div key={s.key} className="flex flex-col items-center relative z-10">
                <div className={`w-8 h-8 rounded-full border-2 flex items-center justify-center transition-all ${dotCls}`}>
                  {isDone ? (
                    <span className="text-xs font-bold text-[#8039F4]">✓</span>
                  ) : isCurrent ? (
                    <span className="w-2.5 h-2.5 rounded-full bg-[#8039F4]" />
                  ) : (
                    <span className="w-2 h-2 rounded-full bg-white/40" />
                  )}
                </div>
                
                <div className="text-xs font-bold mt-1.5 text-white/90 whitespace-nowrap">
                  {getStageLabel(s.key, s.label)}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Divider */}
      <div className="hidden lg:block h-10 w-px bg-white/20 self-center" />

      {/* Ahorro & Countdown Row */}
      <div className="flex items-center gap-6 justify-between w-full lg:w-auto flex-wrap lg:flex-nowrap">
        {/* Ahorro */}
        <div>
          <div className="text-xs uppercase tracking-wider text-white/70 font-semibold leading-tight">Ahorro</div>
          <div className="text-xl lg:text-2xl font-cabinet font-black text-white leading-tight">
            {pctAhorro}%
          </div>
        </div>

        {/* Countdown Red Pill */}
        <div className="bg-[#b91c1c] text-white rounded-2xl px-4 py-2 flex items-center gap-3 border border-red-500 shadow-md">
          <div className="flex items-center gap-1.5">
            <Clock className="w-4 h-4 text-white animate-pulse" />
            <span className="text-xs font-black tracking-wider whitespace-nowrap">28 SEP</span>
          </div>
          <div className="h-6 w-px bg-white/20" />
          <div className="flex gap-2 text-center items-center">
            <div>
              <div className="text-sm lg:text-base font-cabinet font-black leading-none">{pad(timeLeft.days)}</div>
              <div className="text-[10px] font-black opacity-75 mt-0.5">D</div>
            </div>
            <span className="text-sm font-bold leading-none">:</span>
            <div>
              <div className="text-sm lg:text-base font-cabinet font-black leading-none">{pad(timeLeft.hours)}</div>
              <div className="text-[10px] font-black opacity-75 mt-0.5">H</div>
            </div>
            <span className="text-sm font-bold leading-none">:</span>
            <div>
              <div className="text-sm lg:text-base font-cabinet font-black leading-none">{pad(timeLeft.minutes)}</div>
              <div className="text-[10px] font-black opacity-75 mt-0.5">M</div>
            </div>
            <span className="text-sm font-bold leading-none">:</span>
            <div>
              <div className="text-sm lg:text-base font-cabinet font-black leading-none">{pad(timeLeft.seconds)}</div>
              <div className="text-[10px] font-black opacity-75 mt-0.5">S</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================================================ */
/* Documents semáforo — Fila 5                                  */
/* ============================================================ */
function DocsSemaforoCard({ semaforo, navigate }) {
  const { items = [], summary = {} } = semaforo || {};
  const colorFor = (status) => {
    if (status === "active")   return { bg: "bg-emerald-50",  border: "border-emerald-200",  text: "text-emerald-700",  badge: "bg-emerald-500", label: "Activo" };
    if (status === "expiring") return { bg: "bg-amber-50",    border: "border-amber-200",    text: "text-amber-700",    badge: "bg-amber-500",   label: "Por vencer" };
    if (status === "expired")  return { bg: "bg-red-50",      border: "border-red-200",      text: "text-red-700",      badge: "bg-red-500",     label: "Vencido" };
    if (status === "unknown")  return { bg: "bg-neutral-50", border: "border-neutral-200", text: "text-neutral-500", badge: "bg-neutral-300", label: "Sin dato" };
    return { bg: "bg-neutral-50", border: "border-neutral-200", text: "text-neutral-500", badge: "bg-neutral-300", label: "Falta" };
  };

  return (
    <div className="bg-white border border-neutral-200 rounded-2xl p-5 shadow-sm" data-testid="card-docs-semaforo">
      <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
        <div>
          <h3 className="font-cabinet text-lg font-bold flex items-center gap-2">
            <FileText className="w-5 h-5 text-brand" /> Vencimiento de documentos
          </h3>
          <p className="text-xs text-neutral-500">Vigencias verificadas en SUNAT, MTC y el motor de placas. Renueva antes que venzan.</p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <SummaryBadge color="emerald" label="Activos" value={summary.active || 0} testid="semaforo-summary-active" />
          <SummaryBadge color="amber"   label="Por vencer" value={summary.expiring || 0} testid="semaforo-summary-expiring" />
          <SummaryBadge color="red"     label="Vencidos" value={summary.expired || 0} testid="semaforo-summary-expired" />
          {(summary.missing || 0) > 0 && (
            <SummaryBadge color="neutral" label="Faltantes" value={summary.missing} testid="semaforo-summary-missing" />
          )}
        </div>
      </div>

      {items.length === 0 ? (
        <Empty msg="Aún no has cargado documentos de empresa." />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {items.map((d) => {
            const c = colorFor(d.status);
            return (
              <div key={`${d.categoria}-${d.placa || ""}`} className={`border rounded-xl p-4 ${c.bg} ${c.border}`} data-testid={`semaforo-item-${d.categoria}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="text-sm font-bold text-neutral-900 leading-tight">{d.label}{d.placa ? ` — ${d.placa}` : ""}</div>
                  <span className={`w-3 h-3 rounded-full ${c.badge} flex-shrink-0 mt-1`} aria-label={c.label} />
                </div>
                <div className={`text-xs uppercase tracking-widest font-bold mt-2 ${c.text}`}>{c.label}</div>
                <div className="mt-2 text-xs text-neutral-600">
                  {d.status === "missing" ? (
                    <button
                      onClick={() => navigate(`/subsidio/du007?etapa=${d.placa ? "flota" : "empresa"}`)}
                      className="text-brand font-bold hover:underline"
                      data-testid={`semaforo-upload-${d.categoria}`}
                    >
                      Cargar documento →
                    </button>
                  ) : d.expires_at ? (
                    <>
                      <Clock className="w-3 h-3 inline mr-1" />
                      Vence {new Date(d.expires_at).toLocaleDateString("es-PE")}
                      {typeof d.days_remaining === "number" && (
                        <span className="ml-1 text-neutral-500">
                          ({d.days_remaining < 0 ? `${Math.abs(d.days_remaining)}d vencido` : `${d.days_remaining}d restantes`})
                        </span>
                      )}
                    </>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ============================================================ */
/* UI helpers                                                    */
/* ============================================================ */
function SemanaTooltip({ active, payload, fmt }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="bg-white border border-neutral-200 rounded-lg shadow-md p-2.5 text-xs">
      <div className="font-bold">{p.semana}</div>
      <div className="text-neutral-500">{p.rango}</div>
      <div className="mt-1">
        <span className="text-brand font-bold">{fmt(p.galones)}</span> galones
      </div>
      <div>S/ <span className="font-bold">{fmt(p.importe)}</span></div>
      <div className="text-neutral-500">{p.cargas} cargas</div>
    </div>
  );
}

function Kpi({ icon: Icon, label, value, subValue, subValueColor = "text-neutral-500", testid, iconColor = "text-brand" }) {
  return (
    <div className="bg-white border border-neutral-200 rounded-2xl p-5 shadow-sm hover:shadow-md transition-all duration-200" data-testid={testid}>
      <div className="flex items-center gap-2 mb-3">
        <Icon className={`w-4 h-4 ${iconColor}`} strokeWidth={2.5} />
        <span className="text-xs font-bold text-neutral-500">{label}</span>
      </div>
      <div className="font-cabinet text-2xl font-black text-neutral-900 leading-none">{value}</div>
      <div className={`text-xs font-bold mt-2 ${subValueColor}`}>{subValue}</div>
    </div>
  );
}

function Toggle({ value, onChange, testidPrefix }) {
  return (
    <div className="inline-flex bg-neutral-100 rounded-lg p-0.5 text-xs font-bold">
      <button
        onClick={() => onChange("galones")}
        className={`px-3 py-1 rounded-md transition ${value === "galones" ? "bg-white text-brand shadow" : "text-neutral-500"}`}
        data-testid={`${testidPrefix}-galones`}
      >
        Galones
      </button>
      <button
        onClick={() => onChange("importe")}
        className={`px-3 py-1 rounded-md transition ${value === "importe" ? "bg-white text-brand shadow" : "text-neutral-500"}`}
        data-testid={`${testidPrefix}-importe`}
      >
        Soles
      </button>
    </div>
  );
}

function SummaryBadge({ color, label, value, testid }) {
  const palette = {
    emerald: "bg-emerald-100 text-emerald-700",
    amber:   "bg-amber-100 text-amber-700",
    red:     "bg-red-100 text-red-700",
    neutral: "bg-neutral-100 text-neutral-700",
  }[color];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full ${palette}`} data-testid={testid}>
      <span className="font-bold">{value}</span>
      <span className="opacity-80">{label}</span>
    </span>
  );
}

function Empty({ msg }) {
  return (
    <div className="text-center py-10 text-sm text-neutral-400 border-2 border-dashed border-neutral-200 rounded-xl">
      {msg}
    </div>
  );
}
