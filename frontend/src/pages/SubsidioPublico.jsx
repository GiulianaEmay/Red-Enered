import React, { useState } from "react";
import { Navigate } from "react-router-dom";
import { api } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import EmayFooter from "../components/EmayFooter";
import PortadaShell from "../components/PortadaShell";

const VERAS = [
  <><b>Tu monto máximo</b> en cada periodo del D.U. 007</>,
  <><b>Placa por placa:</b> cuáles califican, cuáles son regularizables y cuáles no aplican</>,
  <><b>Los días exactos</b> que te quedan en cada ventana de presentación</>,
];

export default function SubsidioPublico() {
  const { user, checking } = useAuth();
  const [ruc, setRuc] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Un cliente REAL ya logueado va directo a su expediente (el invitado sí puede consultar).
  if (checking) return null;
  // ?ver=1 fuerza mostrar la página pública aunque haya sesión de cliente activa
  // (útil para el equipo ENERED al demostrar el diagnóstico sin cerrar sesión).
  const forzarVista = new URLSearchParams(window.location.search).get("ver") === "1";
  if (!forzarVista && user && user.role === "cliente_subsidio" && !user.es_guest) return <Navigate to="/subsidio/du007" replace />;

  async function consultar() {
    const r = ruc.trim();
    if (!/^\d{11}$/.test(r)) { setError("Ingresa un RUC válido de 11 dígitos"); return; }
    setLoading(true); setError("");
    try {
      // Sesión INVITADA: entra a la plataforma SIN crear usuario en la BD.
      // La primera vista de la evaluación es el submódulo Diagnóstico.
      const { data } = await api.post("/subsidio/entrar", { ruc: r });
      if (data.access_token) localStorage.setItem("enered_token", data.access_token);
      window.location.href = "/subsidio/diagnostico";
    } catch (e) {
      setError(e?.response?.data?.detail || "No se pudo consultar. Intenta de nuevo.");
      setLoading(false);
    }
  }

  const ico = { viewBox: "0 0 24 24", strokeLinecap: "round", strokeLinejoin: "round" };

  return (
    <PortadaShell>
      <div className="sp-eyebrow">Diagnóstico gratuito</div>
      <h2 className="sp-h2">Consulta tu subsidio</h2>
      <p className="sp-sub">
        Con tu RUC calculamos tu monto máximo en los dos decretos y revisamos placa por placa cuál califica.
      </p>

      <div className="sp-form">
        <label htmlFor="sp-ruc">Tu RUC</label>
        <div className="sp-field">
          <svg {...ico}><path d="M3 21h18M5 21V7l7-4 7 4v14M9 9h.01M15 9h.01M9 13h.01M15 13h.01M9 17h.01M15 17h.01" /></svg>
          <input
            id="sp-ruc" inputMode="numeric" maxLength={11} placeholder="20123456789" autoComplete="off" autoFocus
            data-testid="sub-ruc" value={ruc}
            onChange={(e) => { setRuc(e.target.value.replace(/\D/g, "").slice(0, 11)); setError(""); }}
            onKeyDown={(e) => e.key === "Enter" && consultar()}
          />
        </div>

        {error ? (
          <p className="sp-hint sp-err">
            <svg {...ico}><path d="M12 9v4.5M12 17.2h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" /></svg>
            {error}
          </p>
        ) : (
          <p className="sp-hint">
            <svg viewBox="0 0 24 24"><path d="M4 12l6 6L20 6" /></svg>
            No pedimos tu Clave SOL ni acceso a tu ATU. Solo tu RUC público.
          </p>
        )}

        <button className="sp-go" onClick={consultar} disabled={loading} data-testid="sub-consultar">
          {loading ? "Ingresando…" : "Ver mi diagnóstico"}
          {loading
            ? <svg className="sp-spin" {...ico}><path d="M21 12a9 9 0 11-6.2-8.6" /></svg>
            : <svg {...ico}><path d="M5 12h13M12 5l7 7-7 7" /></svg>}
        </button>
      </div>

      <div className="sp-gives">
        <h3>Lo que verás enseguida</h3>
        {VERAS.map((v, i) => (
          <div className="sp-give" key={i}>
            <span className="sp-tick"><svg viewBox="0 0 24 24"><path d="M4 12l6 6L20 6" /></svg></span>
            <span>{v}</span>
          </div>
        ))}
      </div>

      <p className="sp-login">¿Ya tienes cuenta? <a href="/login">Inicia sesión</a></p>

      <div className="sp-emay"><EmayFooter variant="compact" /></div>
    </PortadaShell>
  );
}
