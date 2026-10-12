import React, { useState, useEffect, useRef } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { Loader2, CheckCircle2, AlertCircle, ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../context/AuthContext";


const HERO_IMG = "https://customer-assets.emergentagent.com/job_ui-update-11/artifacts/mbmk49w0_WhatsApp%20Image%202026-06-10%20at%206.26.35%20PM.jpeg";
const LOGO_IMG = "https://customer-assets.emergentagent.com/job_enered-insight/artifacts/hrbrugb8_image.png";

export default function RegistroSubsidio() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { setUser } = useAuth();
  const calcId = params.get("calc_id");

  const [calc, setCalc] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [touched, setTouched] = useState({});
  const [showAllErrors, setShowAllErrors] = useState(false);

  // SUNAT lookup state
  const [rucLookup, setRucLookup] = useState({ loading: false, ok: false, error: "" });
  const lastLookupRef = useRef("");

  const [form, setForm] = useState({
    ruc: "", razon_social: "", contacto: "", telefono: "",
    email: "", password: "", password2: "",
  });

  useEffect(() => {
    if (!calcId) {
      setLoading(false);
      return;
    }
    (async () => {
      try {
        const { data } = await api.get(`/calculations/${calcId}`);
        setCalc(data);
      } catch {
        setError("No encontramos tu cálculo. Vuelve a calcular en la calculadora.");
      } finally {
        setLoading(false);
      }
    })();
  }, [calcId]);

  // Auto-consulta SUNAT cuando RUC llega a 11 dígitos
  useEffect(() => {
    const ruc = form.ruc;
    if (ruc.length !== 11) {
      setRucLookup({ loading: false, ok: false, error: "" });
      return;
    }
    if (lastLookupRef.current === ruc) return;
    lastLookupRef.current = ruc;

    const t = setTimeout(async () => {
      setRucLookup({ loading: true, ok: false, error: "" });
      try {
        const { data } = await api.get(`/sunat/ruc/${ruc}`);
        setForm((p) => ({ ...p, razon_social: data.razon_social || p.razon_social }));
        setRucLookup({ loading: false, ok: true, error: "", estado: data.estado, condicion: data.condicion });
      } catch (e) {
        const msg = e?.response?.data?.detail || "No pudimos validar el RUC en SUNAT";
        setRucLookup({ loading: false, ok: false, error: msg });
      }
    }, 350);
    return () => clearTimeout(t);
  }, [form.ruc]);

  const upd = (k, v) => setForm((p) => ({ ...p, [k]: v }));
  const blur = (k) => setTouched((p) => ({ ...p, [k]: true }));

  // Errores por campo
  const errors = {};
  if (!form.ruc) errors.ruc = "Ingresa el RUC.";
  else if (form.ruc.length !== 11) errors.ruc = "El RUC debe tener exactamente 11 dígitos.";

  if (!form.razon_social.trim()) errors.razon_social = "La razón social es obligatoria.";
  else if (form.razon_social.trim().length < 3) errors.razon_social = "Razón social demasiado corta.";

  if (!form.contacto.trim()) errors.contacto = "Ingresa tu nombre completo.";
  else if (form.contacto.trim().length < 3) errors.contacto = "El nombre debe tener al menos 3 caracteres.";

  const phoneDigits = form.telefono.replace(/\D/g, "");
  if (!form.telefono.trim()) errors.telefono = "Ingresa un teléfono.";
  else if (phoneDigits.length < 6) errors.telefono = "Teléfono inválido (mínimo 6 dígitos).";

  if (!form.email.trim()) errors.email = "Ingresa un correo.";
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) errors.email = "Formato de correo inválido (ej. usuario@empresa.com).";

  if (!form.password) errors.password = "Crea una contraseña.";
  else if (form.password.length < 8) errors.password = "Debe tener al menos 8 caracteres.";

  if (!form.password2) errors.password2 = "Confirma la contraseña.";
  else if (form.password !== form.password2) errors.password2 = "Las contraseñas no coinciden.";

  const valid = Object.keys(errors).length === 0 && !rucLookup.loading;
  const showErr = (k) => (touched[k] || showAllErrors) && errors[k];

  const submit = async (e) => {
    e.preventDefault();
    if (!valid) {
      setShowAllErrors(true);
      // scroll al primer error
      setTimeout(() => {
        const first = document.querySelector('[data-error-anchor="true"]');
        if (first) first.scrollIntoView({ behavior: "smooth", block: "center" });
      }, 50);
      return;
    }
    setSubmitting(true);
    setError("");
    try {
      const { data } = await api.post("/auth/register-from-calculator", {
        calc_id: calcId,
        ruc: form.ruc,
        razon_social: form.razon_social.trim(),
        contacto: form.contacto.trim(),
        telefono: form.telefono.trim(),
        email: form.email.trim().toLowerCase(),
        password: form.password,
      });
      if (data.access_token) localStorage.setItem("enered_token", data.access_token);
      setUser(data.user);
      navigate("/subsidio/du007", { replace: true });
    } catch (e2) {
      setError(e2?.response?.data?.detail || "No se pudo crear la cuenta. Revisa los campos e intenta nuevamente.");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-brand" /></div>;
  }
  if (!calcId || !calc) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-neutral-50 px-4">
        <div className="bg-white rounded-2xl shadow-sm border border-neutral-200 p-8 max-w-md text-center">
          <AlertCircle className="w-10 h-10 text-amber-500 mx-auto" />
          <h2 className="font-bold text-xl mt-3">Calcula primero tu subsidio</h2>
          <p className="text-neutral-600 text-sm mt-2">El registro solo está disponible después de usar la calculadora.</p>
          <Link to="/login" className="inline-block mt-5 text-brand font-bold hover:underline">Volver al login</Link>
        </div>
      </div>
    );
  }

  // Para anclar el primer error visible
  let firstErrAnchored = false;
  const anchor = (k) => {
    if (!showErr(k) || firstErrAnchored) return {};
    firstErrAnchored = true;
    return { "data-error-anchor": "true" };
  };

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-white" data-testid="registro-subsidio">
      {/* Left hero */}
      <div
        className="hidden lg:block lg:w-1/2 xl:w-[55%] bg-black bg-cover bg-center"
        style={{ backgroundImage: `url(${HERO_IMG})` }}
        data-testid="registro-hero"
      />
      <div
        className="lg:hidden h-36 bg-cover bg-center bg-top"
        style={{ backgroundImage: `url(${HERO_IMG})` }}
      />

      {/* Form panel */}
      <div className="flex-1 flex flex-col justify-between px-6 py-8 md:px-12 md:py-10 lg:px-16 xl:px-24 bg-white">
        <div className="w-full max-w-md mx-auto flex-1 flex flex-col justify-center">
          <div className="mb-8">
            <img src={LOGO_IMG} alt="ENERED" className="h-10 md:h-12 w-auto" />
          </div>

          <div className="bg-gradient-to-br from-brand to-brand-hover text-white rounded-2xl p-5 mb-7 shadow-md">
            <div className="text-[10px] uppercase tracking-widest opacity-80 font-bold">Tu estimación anterior · DU-004 finalizado</div>
            <div className="font-cabinet text-4xl font-bold mt-1 leading-tight">
              S/ {Number(calc.subsidio_estimado || 0).toLocaleString("es-PE", { maximumFractionDigits: 0 })}
            </div>
            <div className="text-xs opacity-90 mt-1">DU 004-2026 · Periodo finalizado · Continúa con el DU-007</div>
          </div>

          <h1 className="text-brand text-3xl md:text-4xl font-bold font-cabinet mb-2" style={{ letterSpacing: "-0.01em" }}>
            Crea tu cuenta
          </h1>
          <p className="text-neutral-600 text-sm mb-7">
            Para continuar con el expediente DU 007-2026 necesitamos los datos de tu empresa. Su verificación y la de tu flota se realizan una sola vez.
          </p>

          <form onSubmit={submit} className="space-y-4" data-testid="registro-subsidio-form" noValidate>
            {/* RUC con auto-consulta SUNAT */}
            <Field label="RUC (11 dígitos)" hint="Lo consultamos en SUNAT y completamos la razón social automáticamente">
              <div className="relative" {...anchor("ruc")}>
                <input
                  className={`ru-input pr-12 ${showErr("ruc") ? "ru-input-error" : ""}`}
                  placeholder="20123456789"
                  maxLength={11}
                  inputMode="numeric"
                  value={form.ruc}
                  onChange={(e) => upd("ruc", e.target.value.replace(/\D/g, ""))}
                  onBlur={() => blur("ruc")}
                  data-testid="reg-ruc"
                  aria-invalid={!!errors.ruc}
                />
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  {rucLookup.loading && <Loader2 className="w-5 h-5 animate-spin text-brand" data-testid="reg-ruc-loading" />}
                  {!rucLookup.loading && rucLookup.ok && <CheckCircle2 className="w-5 h-5 text-emerald-500" data-testid="reg-ruc-ok" />}
                  {!rucLookup.loading && rucLookup.error && form.ruc.length === 11 && <AlertCircle className="w-5 h-5 text-amber-500" />}
                </div>
              </div>
              {rucLookup.ok && rucLookup.estado && (
                <div className="text-xs text-emerald-700 mt-1.5 flex items-center gap-1.5" data-testid="reg-ruc-estado">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  SUNAT: <strong className="font-bold">{rucLookup.estado}</strong>
                  {rucLookup.condicion && <span className="text-neutral-500">· {rucLookup.condicion}</span>}
                </div>
              )}
              {!rucLookup.loading && rucLookup.error && form.ruc.length === 11 && (
                <div className="text-xs text-amber-600 mt-1.5 flex items-start gap-1" data-testid="reg-ruc-warning">
                  <AlertCircle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                  <span>No se pudo verificar: {rucLookup.error}. Ingresa la razón social manualmente.</span>
                </div>
              )}
              <FieldError msg={showErr("ruc")} testid="reg-ruc-error" />
            </Field>

            {/* Razón social (auto-rellenada por SUNAT) */}
            <Field label="Razón social">
              <input
                className={`ru-input ${showErr("razon_social") ? "ru-input-error" : ""}`}
                value={form.razon_social}
                onChange={(e) => upd("razon_social", e.target.value)}
                onBlur={() => blur("razon_social")}
                data-testid="reg-razon"
                placeholder="Transportes Juan SAC"
                {...anchor("razon_social")}
              />
              <FieldError msg={showErr("razon_social")} testid="reg-razon-error" />
            </Field>

            <div className="grid sm:grid-cols-2 gap-4">
              <Field label="Nombre de contacto">
                <input
                  className={`ru-input ${showErr("contacto") ? "ru-input-error" : ""}`}
                  value={form.contacto}
                  onChange={(e) => upd("contacto", e.target.value)}
                  onBlur={() => blur("contacto")}
                  data-testid="reg-contacto"
                  {...anchor("contacto")}
                />
                <FieldError msg={showErr("contacto")} testid="reg-contacto-error" />
              </Field>
              <Field label="Teléfono">
                <input
                  className={`ru-input ${showErr("telefono") ? "ru-input-error" : ""}`}
                  value={form.telefono}
                  onChange={(e) => upd("telefono", e.target.value)}
                  onBlur={() => blur("telefono")}
                  data-testid="reg-telefono"
                  placeholder="+51 987 654 321"
                  {...anchor("telefono")}
                />
                <FieldError msg={showErr("telefono")} testid="reg-telefono-error" />
              </Field>
            </div>

            <Field label="Email">
              <input
                type="email"
                className={`ru-input ${showErr("email") ? "ru-input-error" : ""}`}
                value={form.email}
                onChange={(e) => upd("email", e.target.value.trim())}
                onBlur={() => blur("email")}
                data-testid="reg-email"
                {...anchor("email")}
              />
              <FieldError msg={showErr("email")} testid="reg-email-error" />
            </Field>

            <div className="grid sm:grid-cols-2 gap-4">
              <Field label="Contraseña (mín. 8)">
                <input
                  type="password"
                  className={`ru-input ${showErr("password") ? "ru-input-error" : ""}`}
                  value={form.password}
                  onChange={(e) => upd("password", e.target.value)}
                  onBlur={() => blur("password")}
                  data-testid="reg-password"
                  {...anchor("password")}
                />
                <FieldError msg={showErr("password")} testid="reg-password-error" />
              </Field>
              <Field label="Repite la contraseña">
                <input
                  type="password"
                  className={`ru-input ${showErr("password2") ? "ru-input-error" : ""}`}
                  value={form.password2}
                  onChange={(e) => upd("password2", e.target.value)}
                  onBlur={() => blur("password2")}
                  data-testid="reg-password2"
                  {...anchor("password2")}
                />
                <FieldError msg={showErr("password2")} testid="reg-password2-error" />
              </Field>
            </div>

            {/* Resumen global de errores cuando intentan enviar inválido */}
            {showAllErrors && Object.keys(errors).length > 0 && (
              <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl p-3 text-sm" data-testid="reg-summary-errors">
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <div>
                    <strong>No pudimos crear la cuenta.</strong> Corrige lo siguiente:
                    <ul className="list-disc pl-5 mt-1 space-y-0.5">
                      {Object.entries(errors).map(([k, v]) => (
                        <li key={k}><strong className="font-bold">{FIELD_LABELS[k] || k}:</strong> {v}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* Error del backend (RUC duplicado, etc.) */}
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl p-3 text-sm flex gap-2 items-start" data-testid="reg-error">
                <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" /> {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full h-14 bg-brand hover:bg-brand-hover active:bg-brand-active text-white font-bold rounded-2xl text-base flex items-center justify-center gap-2 transition-all shadow-sm hover:shadow-md disabled:opacity-60"
              data-testid="reg-submit"
            >
              {submitting ? <Loader2 className="w-5 h-5 animate-spin" /> : <CheckCircle2 className="w-5 h-5" />}
              {submitting ? "Creando cuenta..." : "Crear cuenta y continuar"}
            </button>

            <p className="text-center text-xs text-neutral-500 pt-1">
              Al continuar aceptas los Términos y la Política de Privacidad de Enered.
            </p>

            <div className="text-center pt-2">
              <span className="text-sm text-neutral-500">¿Ya tienes cuenta? </span>
              <Link to="/login" className="text-sm font-medium text-brand hover:text-brand-hover hover:underline">
                Inicia sesión
              </Link>
            </div>
          </form>

        </div>

        <div className="w-full max-w-md mx-auto pt-6 text-center border-t border-neutral-100">
          <div className="text-[11px] text-neutral-400 leading-relaxed">
            ENERED | Soluciones en Energías | Copyright © {new Date().getFullYear()} | Energix Perú | Todos los derechos reservados.
          </div>
          <div className="text-[11px] text-neutral-400 mt-1 flex items-center justify-center gap-1 flex-wrap">
            <span>Desarrollado por <strong className="text-neutral-500">EMAY TECH</strong></span>
            <span className="text-neutral-300">·</span>
            <a href="https://www.emay.space" target="_blank" rel="noreferrer" className="hover:text-brand transition-colors">www.emay.space</a>
            <span className="text-neutral-300">·</span>
            <span>+51 973 982 417</span>
            <span className="text-neutral-300">·</span>
            <span>© {new Date().getFullYear()}</span>
          </div>
        </div>
      </div>

      <style>{`
        .ru-input { width:100%; height:48px; padding:0 16px; border:1px solid #d4d4d4; border-radius:12px; background:#fff; transition:all .15s; font-size:15px; }
        .ru-input:focus { outline:none; border-color:#7c3aed; box-shadow:0 0 0 3px rgba(124,58,237,0.1); }
        .ru-input-error { border-color:#ef4444 !important; background:#fef2f2; }
        .ru-input-error:focus { border-color:#ef4444 !important; box-shadow:0 0 0 3px rgba(239,68,68,0.1) !important; }
      `}</style>
    </div>
  );
}

const FIELD_LABELS = {
  ruc: "RUC",
  razon_social: "Razón social",
  contacto: "Nombre de contacto",
  telefono: "Teléfono",
  email: "Email",
  password: "Contraseña",
  password2: "Confirmación de contraseña",
};

function Field({ label, hint, children }) {
  return (
    <div>
      <label className="block text-sm font-bold text-neutral-800 mb-1.5">{label}</label>
      {children}
      {hint && <div className="text-[11px] text-neutral-500 mt-1">{hint}</div>}
    </div>
  );
}

function FieldError({ msg, testid }) {
  if (!msg) return null;
  return (
    <div className="text-xs text-red-600 mt-1.5 flex items-start gap-1" data-testid={testid}>
      <AlertCircle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
      <span>{msg}</span>
    </div>
  );
}
