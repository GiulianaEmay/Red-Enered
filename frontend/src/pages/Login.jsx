import { api } from "../lib/api";
import { rutaFirmaPendiente } from "../components/FirmasPendientes";
import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { formatApiError } from "../lib/utils";
import EmayFooter from "../components/EmayFooter";
import PortadaShell from "../components/PortadaShell";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const u = await login(email, password);
      // Clientes de subsidio (por rol o por tipo de cliente de su empresa): la primera
      // vista es el expediente vigente DU-007, reutilizando sus datos de empresa y flota.
      if (u?.role === "cliente_subsidio" || u?.tipo_cliente === "subsidio") {
        let destino = "/subsidio/du007";
        try {
          const { data: f } = await api.get("/subsidio/firmas");
          // Con firmas pendientes se aterriza DIRECTO en la etapa de Declaración del decreto que falta.
          destino = rutaFirmaPendiente(f) || destino;
        } catch (_) { /* sin datos → DU 007 */ }
        navigate(destino);
      } else {
        navigate("/dashboard");
      }
    } catch (e2) {
      setError(formatApiError(e2.response?.data?.detail) || "Error al iniciar sesión");
    } finally {
      setLoading(false);
    }
  };

  const ico = { viewBox: "0 0 24 24", strokeLinecap: "round", strokeLinejoin: "round" };

  return (
    <PortadaShell>
      <div className="sp-eyebrow">Acceso clientes</div>
      <h2 className="sp-h2">Inicia sesión</h2>
      <p className="sp-sub">
        Entra a tu plataforma ENERED: subsidios, combustible, flota y todos tus módulos en un solo lugar.
      </p>

      <form onSubmit={onSubmit} className="sp-form" data-testid="login-form">
        <label htmlFor="lg-email">Tu cuenta</label>
        <div className="sp-field">
          <svg {...ico}><circle cx="12" cy="8" r="4" /><path d="M4 21c.8-3.6 4-6 8-6s7.2 2.4 8 6" /></svg>
          <input
            id="lg-email" type="email" required autoComplete="email" autoFocus
            placeholder="correo@empresa.com" value={email}
            onChange={(e) => setEmail(e.target.value)}
            data-testid="login-email"
          />
        </div>
        <div className="sp-field lg-password-field">
          <svg {...ico}><rect x="4" y="10" width="16" height="10" rx="2.5" /><path d="M8 10V7a4 4 0 018 0v3" /></svg>
          <input
            id="lg-pass" type={showPassword ? "text" : "password"} required autoComplete="current-password"
            aria-label="Contraseña"
            placeholder="Contraseña" value={password}
            onChange={(e) => setPassword(e.target.value)}
            data-testid="login-password"
          />
          <button
            type="button" className="lg-password-toggle"
            onClick={() => setShowPassword((visible) => !visible)}
            aria-label={showPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
            aria-controls="lg-pass" aria-pressed={showPassword}
            title={showPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
          >
            <svg {...ico} aria-hidden="true">
              <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" />
              <circle cx="12" cy="12" r="3" />
              {showPassword && <path d="M3 3l18 18" />}
            </svg>
          </button>
        </div>

        {error ? (
          <p className="sp-hint sp-err" data-testid="login-error">
            <svg {...ico}><path d="M12 9v4.5M12 17.2h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" /></svg>
            {error}
          </p>
        ) : (
          <p className="sp-hint">
            <svg viewBox="0 0 24 24"><path d="M4 12l6 6L20 6" /></svg>
            Conexión segura. Tus credenciales nunca se comparten.
          </p>
        )}

        <button className="sp-go" type="submit" disabled={loading} data-testid="login-submit">
          {loading ? "Ingresando…" : "Ingresar"}
          {loading
            ? <svg className="sp-spin" {...ico}><path d="M21 12a9 9 0 11-6.2-8.6" /></svg>
            : <svg {...ico}><path d="M5 12h13M12 5l7 7-7 7" /></svg>}
        </button>

        <p className="sp-login">
          <Link to="/forgot-password">¿Has olvidado tu contraseña?</Link>
        </p>
      </form>

      <div className="sp-gives">
        <h3>Para nuestros clientes</h3>
        <p className="lg-contact">
          Si aún no tienes tu usuario y/o clave, comunícate con nuestros ejecutivos corporativos:
        </p>
        <p className="lg-contact-data">
          (044) 659-3519 · +51 972 228 870 · <a href="mailto:hola@enered.pe">hola@enered.pe</a>
        </p>
      </div>

      <p className="sp-login">¿Quieres tu diagnóstico gratis? <a href="/subsidio">Consulta con tu RUC</a></p>

      <p className="lg-legal">
        ENERED | Soluciones en Energías · © {new Date().getFullYear()} Energix Perú ·{" "}
        <a href="https://www.energix.pe" target="_blank" rel="noreferrer">www.energix.pe</a>
      </p>

      <div className="sp-emay"><EmayFooter variant="compact" /></div>

      <style>{`
.sp-field.lg-password-field input{padding-right:58px}
.lg-password-toggle{position:absolute;right:8px;top:50%;transform:translateY(-50%);display:flex;align-items:center;justify-content:center;width:40px;height:40px;padding:0;border:0;border-radius:8px;background:transparent;color:var(--sp-ink-3);cursor:pointer}
.lg-password-toggle:hover{color:var(--sp-violet-600);background:rgba(124,58,237,.06)}
.lg-password-toggle:focus-visible{outline:2px solid var(--sp-violet-500);outline-offset:2px}
.lg-password-toggle svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8}
.lg-contact{font-size:12.5px;line-height:1.5;color:var(--sp-ink-2)}
.lg-contact-data{margin-top:8px;font-size:12.5px;font-weight:600;color:var(--sp-ink)}
.lg-contact-data a{color:var(--sp-violet-600);text-decoration:none}
.lg-legal{margin-top:16px;padding-top:14px;border-top:1px solid var(--sp-line);font-size:10.5px;color:var(--sp-ink-3);text-align:center}
.lg-legal a{color:var(--sp-ink-3)}
      `}</style>
    </PortadaShell>
  );
}
