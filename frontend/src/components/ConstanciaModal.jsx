import React, { useState, useEffect } from "react";
import { api } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { useLocation } from "react-router-dom";
import { ShieldCheck, Loader2, Building2 } from "lucide-react";
import CONSTANCIA_V2 from "../data/constanciaV2";

// Comunicado obligatorio al iniciar sesión: el cliente del servicio de subsidio debe leer y
// aceptar la Constancia de Información y Condiciones del Servicio (v2.0, texto legal oficial)
// antes de seguir usando la plataforma. Registra el consentimiento vía POST /constancia/aceptar.

function partirTitulo(texto) {
  const i = texto.indexOf(". ");
  if (i > 0 && i < 90) return [texto.slice(0, i + 1), texto.slice(i + 2)];
  return ["", texto];
}

export default function ConstanciaModal() {
  const { user, setUser } = useAuth();
  const [aceptado, setAceptado] = useState(false);
  const [enviando, setEnviando] = useState(false);
  const [error, setError] = useState("");
  const [cliente, setCliente] = useState(null);
  const loc = useLocation();

  // No mostrar el comunicado en páginas públicas / de acceso (login, registro, landing…).
  const RUTAS_PUBLICAS = ["/login", "/forgot-password", "/registro-subsidio", "/subsidio", "/precios", "/privacidad"];
  const enPublica = RUTAS_PUBLICAS.includes(loc.pathname) || loc.pathname.startsWith("/captura/");
  // El módulo cerrado muestra primero su aviso; la constancia sigue exigida en DU-007.
  const visible = !!(user && user.constancia_pendiente) && !enPublica && loc.pathname !== "/subsidio/documentos";

  // Al abrirse, trae los datos del cliente (representante legal, DNI) para rellenar el preámbulo.
  useEffect(() => {
    if (!visible) return;
    let vivo = true;
    api.get("/constancia").then(({ data }) => { if (vivo) setCliente(data?.cliente || null); }).catch(() => {});
    return () => { vivo = false; };
  }, [visible]);

  // Reemplaza los campos [entre corchetes] del preámbulo con los datos reales del cliente.
  const preambulo = React.useMemo(() => {
    let t = CONSTANCIA_V2.preamble;
    if (cliente) {
      if (cliente.representante) t = t.replace("[Nombre del representante legal]", cliente.representante);
      if (cliente.dni) t = t.replace("[DNI]", cliente.dni);
      if (cliente.cargo) t = t.replace("[cargo]", cliente.cargo);
    }
    return t;
  }, [cliente]);

  useEffect(() => {
    if (visible) { document.body.style.overflow = "hidden"; return () => { document.body.style.overflow = ""; }; }
  }, [visible]);

  if (!visible) return null;

  const aceptar = async () => {
    if (!aceptado || enviando) return;
    setEnviando(true); setError("");
    try {
      const { data } = await api.post("/constancia/aceptar", { no_volver_a_mostrar: false }, { timeout: 15000 });
      setUser({ ...user, constancia_pendiente: false, constancia_aceptada_at: data?.aceptada?.at });
    } catch (e) {
      setError(e?.response?.data?.detail || "No se pudo registrar tu aceptación. Revisa tu conexión e intenta de nuevo.");
    } finally {
      setEnviando(false);
    }
  };

  return (
    <div style={ov} role="dialog" aria-modal="true" aria-labelledby="const-title" data-testid="constancia-modal">
      <div style={card}>
        <div style={head}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={mark}>E</div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: "#6D28D9" }}>Comunicado importante · lee antes de continuar</div>
              <div id="const-title" style={{ fontSize: 17.5, fontWeight: 800, color: "#111827", marginTop: 2 }}>Constancia de Información y Condiciones del Servicio</div>
              <div style={{ fontSize: 11.5, color: "#9CA3AF", marginTop: 1 }}>Anexo N° 1 al Contrato · Versión 2.0 · ENERGIX PERÚ E.I.R.L.</div>
            </div>
          </div>
          {user?.empresa && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5, color: "#6b7280", fontWeight: 600 }}>
              <Building2 style={{ width: 14, height: 14 }} /> {user.empresa}
            </div>
          )}
        </div>

        <div style={body}>
          <p style={{ fontSize: 13.2, color: "#6b7280", marginTop: 0, marginBottom: 12 }}>
            Lee el documento completo antes de continuar. Al aceptar, dejas constancia de tu consentimiento; esto no reemplaza tu declaración jurada ante la ATU.
          </p>
          {cliente && (cliente.razon_social || cliente.ruc) && (
            <p style={{ fontSize: 12.8, color: "#111827", marginTop: 0, marginBottom: 10, fontWeight: 600 }}>
              Empresa (EL CLIENTE): {cliente.razon_social || "—"}{cliente.ruc ? ` · RUC: ${cliente.ruc}` : ""}<br />
              Prestador (ENERED): ENERGIX PERÚ E.I.R.L. · RUC 20609304082
            </p>
          )}
          <p style={{ fontStyle: "italic", color: "#4B5563", fontSize: 13, marginTop: 0, marginBottom: 6 }}>{preambulo}</p>
          {CONSTANCIA_V2.secciones.map((sec, si) => (
            <div key={si} style={{ marginTop: 14 }}>
              <div style={secTitle}>{sec.titulo}</div>
              {sec.clausulas.map((c) => {
                const [tit, resto] = partirTitulo(c.texto);
                return (
                  <p key={c.n} style={clausula}>
                    <span style={cnum}>{c.n}.</span>{" "}
                    {tit && <b style={{ color: "#111827" }}>{tit}</b>} <span>{resto}</span>
                  </p>
                );
              })}
            </div>
          ))}
          {CONSTANCIA_V2.declaracion && (
            <div style={{ marginTop: 16 }}>
              <div style={secTitle}>DECLARACIÓN FINAL</div>
              <p style={clausula}>{CONSTANCIA_V2.declaracion}</p>
            </div>
          )}
        </div>

        <div style={foot}>
          <label style={check}>
            <input type="checkbox" checked={aceptado} onChange={(e) => setAceptado(e.target.checked)} data-testid="constancia-check"
              style={{ width: 18, height: 18, accentColor: "#6D28D9", marginTop: 1, flex: "none" }} />
            <span style={{ fontSize: 13.5, color: "#111827", fontWeight: 600 }}>
              Declaro que he leído y acepto de forma libre e íntegra esta Constancia de Información y Condiciones del Servicio. Entiendo que ENERED es una empresa privada que <b>gestiona y presenta mi expediente</b>, que <b>no garantiza la aprobación ni el pago del subsidio</b>, y que la decisión, el monto y la fecha del abono dependen exclusivamente de la ATU.
            </span>
          </label>
          {error && <div style={{ color: "#DC2626", fontSize: 12.5, marginTop: 8, fontWeight: 600 }}>{error}</div>}
          <button onClick={aceptar} disabled={!aceptado || enviando} data-testid="constancia-aceptar"
            style={{ ...btn, background: (!aceptado || enviando) ? "#C4B5FD" : "#6D28D9", cursor: (!aceptado || enviando) ? "not-allowed" : "pointer" }}>
            {enviando ? <Loader2 style={{ width: 16, height: 16, animation: "spin 1s linear infinite" }} /> : <ShieldCheck style={{ width: 16, height: 16 }} />}
            {enviando ? "Registrando…" : "He leído y acepto — Continuar"}
          </button>
        </div>
      </div>
    </div>
  );
}

const ov = { position: "fixed", inset: 0, zIndex: 9999, background: "rgba(24,20,38,.55)", backdropFilter: "blur(3px)", display: "flex", alignItems: "center", justifyContent: "center", padding: 16 };
const card = { width: "100%", maxWidth: 640, maxHeight: "92vh", background: "#fff", borderRadius: 16, boxShadow: "0 24px 60px rgba(0,0,0,.3)", display: "flex", flexDirection: "column", overflow: "hidden" };
const head = { padding: "16px 22px", borderBottom: "1px solid #EEE9F6", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap", background: "linear-gradient(180deg,#F4EFFC,#fff)" };
const mark = { width: 34, height: 34, borderRadius: 9, background: "#6D28D9", color: "#fff", display: "grid", placeItems: "center", fontWeight: 800, fontSize: 18, flex: "none", fontFamily: "Georgia,serif" };
const body = { padding: "18px 22px", overflowY: "auto" };
const list = { listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 10 };
const item = { display: "grid", gridTemplateColumns: "26px 1fr", gap: 11, fontSize: 13.6, lineHeight: 1.5, alignItems: "start" };
const num = { fontFamily: "Georgia,serif", fontWeight: 700, color: "#6D28D9", fontSize: 15 };
const sec_ = { marginTop: 10, background: "#FAF8FE", border: "1px solid #EEE9F6", borderRadius: 10, padding: "10px 14px" };
const secSummary = { cursor: "pointer", fontWeight: 800, color: "#4C1D95", fontSize: 12.8, listStyle: "none", userSelect: "none" };
const secTitle = { fontWeight: 800, color: "#4C1D95", fontSize: 12.5, letterSpacing: ".02em", margin: "4px 0 6px", textTransform: "none" };
const clausula = { fontSize: 12.6, color: "#374151", lineHeight: 1.55, margin: "0 0 8px" };
const cnum = { fontFamily: "Georgia,serif", fontWeight: 700, color: "#6D28D9" };
const foot = { padding: "16px 22px", borderTop: "1px solid #EEE9F6", background: "#FAF8FE" };
const check = { display: "flex", gap: 10, alignItems: "flex-start", cursor: "pointer" };
const btn = { marginTop: 12, width: "100%", padding: "13px 18px", color: "#fff", border: "none", borderRadius: 10, fontSize: 15, fontWeight: 800, display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 8 };
