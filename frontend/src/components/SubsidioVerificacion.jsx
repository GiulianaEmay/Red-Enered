import React, { useState } from "react";
import { Loader2, Upload, CheckCircle2, AlertCircle, Trash2, Plus, Building2, Truck, Banknote, FileText, Save, Lock } from "lucide-react";
import { api } from "../lib/api";

// Empresa, flota y cuenta bancaria se guardan a nivel de empresa, sin programa
// ni periodo, para reutilizar los documentos ya cargados en cualquier subsidio.
export function calcVerificacionTotals(data) {
  const empresa = data?.checklist?.empresa || [];
  const flota = data?.checklist?.flota || [];
  const empresaDone = empresa.filter((item) => item.uploaded || item.opcional).length + (data?.bank_account ? 1 : 0);
  const empresaTotal = empresa.length + 1;
  const flotaDone = flota.filter((item) => item.uploaded).length;
  const flotaTotal = Math.max(flota.length, 1);
  const percentage = (done, total) => Math.round((done / Math.max(total, 1)) * 100);
  const done = empresaDone + flotaDone;
  const total = empresaTotal + flotaTotal;
  return {
    done,
    total,
    pct: percentage(done, total),
    byEtapa: {
      empresa: { done: empresaDone, total: empresaTotal, pct: percentage(empresaDone, empresaTotal) },
      flota: { done: flotaDone, total: flotaTotal, pct: percentage(flotaDone, flotaTotal) },
    },
  };
}

/* ============================================================ */
/* Etapa 1 — Empresa (PDF only) + cuenta bancaria + nota seguridad */
/* ============================================================ */
export function EmpresaEtapa({ items = [], bank, evidenciaCci = [], onChange }) {
  const hints = {
    ficha_ruc: "PDF descargado de SUNAT",
    resolucion_autorizacion: "MTC / Gobierno Regional / Municipalidad · Art. 3.4.1",
    dni_representante: "Ambas caras · firma la declaración jurada",
  };
  return (
    <div>
      <EtapaHeader n={1} icon={Building2} title="Documentos de la empresa" subtitle="Identidad, autorización y cuenta bancaria · solo PDF" />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="space-y-3">
          {items.map((it) => (
            <DocItem key={it.categoria} item={it} hint={hints[it.categoria]} onChange={onChange} accept=".pdf" acceptLabel="PDF" />
          ))}
        </div>
        <BankAccountCard bank={bank} evidencia={evidenciaCci} onSaved={onChange} />
      </div>
    </div>
  );
}

/** Evidencia que respalda la cuenta: captura del banco / constancia con el CCI visible. */
function EvidenciaCCI({ files = [], onChange, esBN }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const subir = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setErr("");
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("categoria", "evidencia_cci");
      await api.post("/subsidio/documents", fd, { headers: { "Content-Type": "multipart/form-data" } });
      onChange?.();
    } catch (e2) {
      setErr(e2?.response?.data?.detail || "No se pudo subir el archivo");
    } finally { setBusy(false); e.target.value = ""; }
  };

  const borrar = async (id) => {
    if (!window.confirm("¿Eliminar esta evidencia?")) return;
    setBusy(true);
    try { await api.delete(`/subsidio/documents/${id}`); onChange?.(); }
    finally { setBusy(false); }
  };

  return (
    <div className="mt-4 bg-white border border-neutral-200 rounded-lg p-3">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="font-bold text-sm text-neutral-900 flex items-center gap-2">
            <FileText className="w-4 h-4 text-brand" /> Evidencia de la cuenta
            {files.length > 0 && <CheckCircle2 className="w-4 h-4 text-emerald-600" />}
          </div>
          <p className="text-xs text-neutral-500 mt-0.5">
            {esBN
              ? "Captura o constancia del Banco de la Nación donde se vea tu número de cuenta."
              : "Captura o constancia del banco donde se vea el CCI y el titular."}
          </p>
        </div>
        <label className="px-3 py-1.5 border border-neutral-300 bg-white rounded-lg text-xs font-bold cursor-pointer hover:bg-neutral-50 flex items-center gap-1.5 flex-shrink-0">
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
          {files.length > 0 ? "Agregar otra" : "Subir evidencia"}
          <input type="file" hidden onChange={subir} accept="application/pdf,image/*" />
        </label>
      </div>
      {files.length > 0 && (
        <ul className="mt-2 space-y-1">
          {files.map((f) => (
            <li key={f.id} className="flex items-center justify-between bg-neutral-50 rounded-lg px-3 py-1.5 text-xs">
              <span className="truncate flex items-center gap-2"><FileText className="w-3.5 h-3.5 text-neutral-400" />{f.filename}</span>
              <button onClick={() => borrar(f.id)} disabled={busy} className="text-neutral-400 hover:text-red-500" aria-label="Eliminar"><Trash2 className="w-3.5 h-3.5" /></button>
            </li>
          ))}
        </ul>
      )}
      {err && <div className="mt-2 text-xs text-red-600">{err}</div>}
    </div>
  );
}

function BankAccountCard({ bank, evidencia = [], onSaved }) {
  const [ba, setBa] = useState(() => bank || { es_banco_nacion: true, banco: "Banco de la Nación", tipo_cuenta: "ahorros", numero_cuenta: "", moneda: "PEN", cci: "" });
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);

  const save = async () => {
    setBusy(true); setSaved(false);
    try { await api.put("/subsidio/bank-account", ba); setSaved(true); onSaved?.(); }
    catch (e) { alert(e?.response?.data?.detail || "Error al guardar"); }
    finally { setBusy(false); setTimeout(() => setSaved(false), 2000); }
  };

  return (
    <div className="bg-neutral-50 border border-neutral-200 rounded-xl p-4">
      <div className="flex items-center gap-2 mb-1">
        <Banknote className="w-5 h-5 text-brand" />
        <h4 className="font-cabinet font-bold text-base">Cuenta para el depósito del subsidio</h4>
        {ba.es_banco_nacion && <span className="ml-auto px-2 py-0.5 bg-brand/10 text-brand text-[10px] font-bold rounded-full">Recomendada</span>}
      </div>
      <p className="text-xs text-neutral-500 mb-3">Con Banco de la Nación el depósito es directo y no requiere CCI.</p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Field label="Banco">
          <select className="field-input" value={ba.es_banco_nacion ? "BN" : "OTRO"}
            onChange={(e) => { const isBN = e.target.value === "BN"; setBa({ ...ba, es_banco_nacion: isBN, banco: isBN ? "Banco de la Nación" : "" }); }} data-testid="bank-select">
            <option value="BN">Banco de la Nación</option>
            <option value="OTRO">Otro banco</option>
          </select>
        </Field>
        {!ba.es_banco_nacion && (
          <Field label="Nombre del banco">
            <input className="field-input" value={ba.banco} onChange={(e) => setBa({ ...ba, banco: e.target.value })} />
          </Field>
        )}
        <Field label="Tipo de cuenta">
          <select className="field-input" value={ba.tipo_cuenta} onChange={(e) => setBa({ ...ba, tipo_cuenta: e.target.value })}>
            <option value="ahorros">Ahorros</option><option value="corriente">Corriente</option>
          </select>
        </Field>
        <Field label="N° de cuenta">
          <input className="field-input" value={ba.numero_cuenta} onChange={(e) => setBa({ ...ba, numero_cuenta: e.target.value })} data-testid="bank-numero" />
        </Field>
        <Field label="Moneda">
          <input className="field-input bg-neutral-100 text-neutral-600" value="PEN (Soles)" disabled readOnly />
          <p className="text-[11px] text-neutral-400 mt-1">El subsidio se abona solo en soles. No se aceptan cuentas en dólares.</p>
        </Field>
        {!ba.es_banco_nacion && (
          <Field label="CCI (20 dígitos)" full>
            <input className="field-input" value={ba.cci || ""} maxLength={20} inputMode="numeric"
              onChange={(e) => setBa({ ...ba, cci: e.target.value.replace(/\D/g, "") })} data-testid="bank-cci" />
          </Field>
        )}
      </div>

      {/* Evidencia del CCI: captura o constancia del banco que respalda la cuenta */}
      <EvidenciaCCI files={evidencia} onChange={onSaved} esBN={ba.es_banco_nacion} />

      {/* Nota de seguridad bancaria */}
      <div className="mt-4 bg-violet-50 border border-violet-200 rounded-lg p-3 flex gap-2 text-xs text-violet-900">
        <Lock className="w-4 h-4 mt-0.5 flex-shrink-0" />
        <p>
          <strong>Seguridad Bancaria:</strong> Tus datos bancarios solo se usan para que la ATU te deposite el subsidio
          (vía Banco de la Nación u otro banco de tu preferencia). Ni Enered ni la ATU te pedirán nunca claves,
          contraseñas, PIN, datos de tarjeta, tokens ni acceso a tu banca por internet.
        </p>
      </div>

      <div className="mt-4 flex items-center justify-end gap-3">
        {saved && <span className="text-emerald-600 text-sm font-bold">Guardado ✓</span>}
        <button onClick={save} disabled={busy} className="px-4 py-2 bg-brand hover:bg-brand-hover text-white font-bold rounded-lg flex items-center gap-2 text-sm" data-testid="bank-save">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} Guardar cuenta
        </button>
      </div>
      <style>{FIELD_CSS}</style>
    </div>
  );
}

/* ============================================================ */
/* Etapa 2 — Flota (PDF/PNG/JPG)                                 */
/* ============================================================ */
export function FlotaEtapa({ items = [], vehicles = [], onChange }) {
  const [adding, setAdding] = useState(false);
  const [placa, setPlaca] = useState("");
  const [categoria, setCategoria] = useState("N2");
  const [error, setError] = useState(null);
  const [importando, setImportando] = useState(false);
  const [aviso, setAviso] = useState(null);

  const addVehicle = async () => {
    setError(null);
    if (!placa.trim()) return;
    try { await api.post("/subsidio/vehicles", { placa: placa.toUpperCase(), categoria }); setPlaca(""); setAdding(false); onChange(); }
    catch (e) { setError(e?.response?.data?.detail || "Error"); }
  };

  // Trae las placas que el diagnóstico (Etapa 0) ya encontró en el MTC para este RUC.
  const importarDelDiagnostico = async () => {
    setImportando(true); setError(null); setAviso(null);
    try {
      const { data } = await api.post("/subsidio/vehicles/importar-diagnostico", {}, { timeout: 60000 });
      const base = data.importadas > 0
        ? `Se agregaron ${data.importadas} unidad${data.importadas === 1 ? "" : "es"} de tu diagnóstico.`
        : data.encontradas > 0
          ? "Tus unidades del diagnóstico ya estaban registradas."
          : data.omitidas > 0
            ? "Las unidades de tu RUC en el MTC son remolques o M1, que no aplican al subsidio."
            : "No encontramos unidades en el MTC para tu RUC. Agrégalas manualmente.";
      setAviso(data.nota ? `${base} ${data.nota}.` : base);
      onChange();
    } catch (e) {
      setError(e?.response?.data?.detail || "No se pudieron traer las unidades");
    } finally { setImportando(false); }
  };
  const removeVehicle = async (p) => {
    if (!window.confirm(`¿Quitar placa ${p}? Se borrarán también sus documentos.`)) return;
    await api.delete(`/subsidio/vehicles/${p}`); onChange();
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-5 flex-wrap gap-3">
        <EtapaHeader n={2} icon={Truck} title={`Documentos de flota · ${vehicles.length} unidad${vehicles.length === 1 ? "" : "es"}`} subtitle="Tarjetas de habilitación y propiedad · PDF, PNG o JPG" inline />
        <div className="flex items-center gap-2">
          <button onClick={importarDelDiagnostico} disabled={importando}
            className="px-3 py-2 border-2 border-brand text-brand rounded-lg text-sm font-bold flex items-center gap-1.5 hover:bg-brand/5 disabled:opacity-60"
            data-testid="flota-importar-diagnostico">
            {importando ? <Loader2 className="w-4 h-4 animate-spin" /> : <Truck className="w-4 h-4" />}
            {importando ? "Consultando el MTC…" : "Traer unidades de mi diagnóstico"}
          </button>
          <button onClick={() => setAdding(!adding)} className="px-3 py-2 border border-neutral-300 rounded-lg text-sm font-bold flex items-center gap-1.5 hover:bg-neutral-50" data-testid="flota-toggle-add">
            <Plus className="w-4 h-4" /> {adding ? "Cancelar" : "Agregar unidad"}
          </button>
        </div>
      </div>

      {aviso && (
        <div className="mb-4 text-sm bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-lg px-4 py-2.5 font-semibold">
          {aviso}
        </div>
      )}
      {error && !adding && (
        <div className="mb-4 text-sm bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-2.5 font-semibold">
          {error}
        </div>
      )}

      {adding && (
        <div className="bg-white border-2 border-brand/30 rounded-xl p-4 mb-4 flex flex-wrap gap-3 items-end">
          <div className="flex-1 min-w-[140px]">
            <label className="block text-xs font-bold text-neutral-700 mb-1">Placa</label>
            <input className="field-input" placeholder="ABC-123" value={placa} onChange={(e) => setPlaca(e.target.value.toUpperCase())} data-testid="flota-add-placa" />
          </div>
          <div className="flex-1 min-w-[140px]">
            <label className="block text-xs font-bold text-neutral-700 mb-1">Categoría</label>
            <select className="field-input" value={categoria} onChange={(e) => setCategoria(e.target.value)} data-testid="flota-add-cat">
              {["M2", "M3", "N1", "N2", "N3"].map(c => <option key={c}>{c}</option>)}
            </select>
          </div>
          <button onClick={addVehicle} className="h-[42px] px-4 bg-brand hover:bg-brand-hover text-white font-bold rounded-lg" data-testid="flota-add-confirm">Agregar</button>
          {error && <div className="w-full text-sm text-red-600">{error}</div>}
        </div>
      )}

      {vehicles.length === 0 && !adding && (
        <div className="text-center text-sm text-neutral-500 bg-neutral-50 border-2 border-dashed border-neutral-300 rounded-xl p-8">
          Aún no has registrado unidades. Usa <b>“Traer unidades de mi diagnóstico”</b> para cargar
          automáticamente las placas que encontramos en el MTC, o agrégalas manualmente.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {vehicles.map((v) => (
          <div key={v.placa} className="bg-neutral-50 border border-neutral-200 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Truck className="w-4 h-4 text-brand" />
                <strong className="font-cabinet">{v.placa}</strong>
                <span className="px-2 py-0.5 bg-white border border-neutral-200 rounded-full text-xs font-bold">{v.categoria}</span>
              </div>
              <button onClick={() => removeVehicle(v.placa)} className="text-neutral-400 hover:text-red-500"><Trash2 className="w-4 h-4" /></button>
            </div>
            <div className="space-y-2">
              {items.filter((it) => it.placa === v.placa).map((it) => (
                <DocItem key={it.categoria + "-" + it.placa} item={it} onChange={onChange} accept=".pdf,.jpg,.jpeg,.png" acceptLabel="PDF / JPG / PNG"
                  hint={it.categoria === "tarjeta_habilitacion" ? "Art. 3.4.2 — habilita la unidad para servicio público" : "Define la categoría (M/N)"} />
              ))}
            </div>
          </div>
        ))}
      </div>
      <style>{FIELD_CSS}</style>
    </div>
  );
}

export function EtapaHeader({ n, icon: Ic, title, subtitle, inline }) {
  return (
    <div className={`flex items-center gap-3 ${inline ? "" : "mb-5"}`}>
      <span className="w-10 h-10 rounded-lg bg-brand/10 text-brand flex items-center justify-center"><Ic className="w-5 h-5" /></span>
      <div>
        <span className="text-[10px] uppercase tracking-widest font-bold text-brand">Etapa 0{n}</span>
        <h3 className="font-cabinet text-xl font-bold">{title}</h3>
        {subtitle && <p className="text-xs text-neutral-500">{subtitle}</p>}
      </div>
    </div>
  );
}

function DocItem({ item, onChange, hint, accept, acceptLabel }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const handleUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setErr(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("categoria", item.categoria);
      if (item.placa) fd.append("placa", item.placa);
      await api.post("/subsidio/documents", fd, { headers: { "Content-Type": "multipart/form-data" } });
      onChange?.();
    } catch (e2) {
      setErr(e2?.response?.data?.detail || "Error al subir");
    } finally { setBusy(false); }
  };
  const handleDelete = async (docId) => {
    if (!window.confirm("¿Eliminar este documento?")) return;
    setBusy(true);
    try { await api.delete(`/subsidio/documents/${docId}`); onChange?.(); }
    finally { setBusy(false); }
  };
  // Documento que ENERED verifica en línea (SUNAT/MTC) COMO APOYO. El adjunto sigue siendo obligatorio.
  if (item.auto_validado) {
    const ok = item.validado;      // resultado de la verificación en línea
    const subido = item.uploaded;  // el archivo adjunto (obligatorio)
    const s = item.sunat;          // Ficha RUC (SUNAT)
    const m = item.mtc;            // Habilitación vehicular por placa (MTC)
    const a = item.autorizacion;   // Autorización del transportista (MTC)
    return (
      <div className={`border rounded-xl p-4 ${subido ? "bg-neutral-50 border-neutral-200" : "bg-white border-neutral-200"}`}>
        <div className="flex items-start gap-3">
          <span className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${subido ? "bg-emerald-100 text-emerald-700" : item.opcional ? "bg-neutral-100 text-neutral-500" : "bg-red-100 text-red-600"}`}>
            {subido ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
          </span>
          <div className="flex-1 min-w-0">
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2">
              <div className="min-w-0">
                <div className="font-bold text-neutral-900 text-sm flex items-center gap-2 flex-wrap">
                  {item.placa ? item.label.split(" — ")[0] : item.label}
                  {item.opcional && <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-neutral-100 text-neutral-500 uppercase tracking-wider">Opcional</span>}
                </div>
                <div className="text-xs text-neutral-500 mt-0.5 line-clamp-1">{item.detalle}{item.opcional && !subido ? " No es obligatorio adjuntarla para firmar la declaración." : ""}</div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <span className={`text-[10px] font-black px-2 py-1 rounded-full whitespace-nowrap ${ok ? "bg-emerald-600 text-white" : "bg-amber-500 text-white"}`}>
                  {ok ? `✓ ${(m || a) ? "MTC" : "SUNAT"}` : "POR VERIFICAR"}
                </span>
                <label className="px-3 py-1.5 border border-neutral-300 bg-white rounded-lg text-xs font-bold cursor-pointer hover:bg-neutral-50 flex items-center gap-1.5">
                  {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                  {subido ? "Reemplazar" : "Subir"}
                  <input type="file" hidden onChange={handleUpload} accept={accept} />
                </label>
              </div>
            </div>
            {item.files?.length > 0 && (
              <ul className="mt-2 space-y-1">
                {item.files.map((f) => (
                  <li key={f.id} className="flex items-center justify-between bg-white rounded-lg px-3 py-1.5 text-xs border border-neutral-100">
                    <span className="truncate flex items-center gap-2"><FileText className="w-3.5 h-3.5 text-neutral-400" />{f.filename}</span>
                    <button onClick={() => handleDelete(f.id)} disabled={busy} className="text-neutral-400 hover:text-red-500" aria-label="Eliminar"><Trash2 className="w-3.5 h-3.5" /></button>
                  </li>
                ))}
              </ul>
            )}
            {err && <div className="mt-2 text-xs text-red-600">{err}</div>}

            {/* Datos verificados en línea — en una sola línea compacta */}
            {(s || m || (a && a.encontrada)) && (
              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-neutral-600">
                {s && <>
                  <span className="font-semibold text-neutral-800 truncate max-w-[240px]">{s.nombre}</span>
                  <span><b className={s.estado === "ACTIVO" ? "text-emerald-700" : "text-red-600"}>{s.estado}</b>
                    {s.condicion && <> · <b className={s.condicion === "HABIDO" ? "text-emerald-700" : "text-red-600"}>{s.condicion}</b></>}</span>
                  {s.ubicacion && <span className="text-neutral-400 truncate max-w-[220px]">{s.ubicacion}</span>}
                </>}
                {m && <>
                  <span><span className="text-neutral-400">Constancia</span> <b>{m.constancia || "—"}</b></span>
                  <span><span className="text-neutral-400">Vence</span> <b className={m.vencida ? "text-red-600" : "text-emerald-700"}>{m.vigencia || "—"}</b></span>
                </>}
                {a && a.encontrada && <>
                  <span><span className="text-neutral-400">N°</span> <b>{a.codigo || "—"}</b></span>
                  <span><b className={a.habilitado ? "text-emerald-700" : "text-red-600"}>{a.estado || "—"}</b></span>
                  <span><span className="text-neutral-400">Vence</span> <b className={a.vencida ? "text-red-600" : "text-emerald-700"}>{a.vigencia || "—"}</b></span>
                  {a.total_unidades ? <span className="text-neutral-400">{a.total_unidades} unidades</span> : null}
                </>}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-neutral-50 border border-neutral-200 rounded-xl p-4">
      <div className="flex items-start gap-3">
        <span className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${item.uploaded ? "bg-emerald-100 text-emerald-700" : "bg-red-100 text-red-600"}`}>
          {item.uploaded ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
        </span>
        <div className="flex-1 min-w-0">
          <div className="font-bold text-neutral-900 text-sm">{item.label}</div>
          {hint && <div className="text-xs text-neutral-500 mt-0.5">{hint}</div>}
          <div className="text-[10px] text-neutral-400 mt-0.5 uppercase tracking-wider font-bold">Acepta: {acceptLabel}</div>
          {item.files?.length > 0 && (
            <ul className="mt-2 space-y-1">
              {item.files.map((f) => (
                <li key={f.id} className="flex items-center justify-between bg-white rounded-lg px-3 py-1.5 text-xs">
                  <span className="truncate flex items-center gap-2"><FileText className="w-3.5 h-3.5 text-neutral-400" />{f.filename}</span>
                  <button onClick={() => handleDelete(f.id)} disabled={busy} className="text-neutral-400 hover:text-red-500" aria-label="Eliminar"><Trash2 className="w-3.5 h-3.5" /></button>
                </li>
              ))}
            </ul>
          )}
          {err && <div className="mt-2 text-xs text-red-600">{err}</div>}
        </div>
        <label className="px-3 py-1.5 border border-neutral-300 bg-white rounded-lg text-xs font-bold cursor-pointer hover:bg-neutral-50 flex items-center gap-1.5">
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
          {item.uploaded ? "Reemplazar" : "Subir"}
          <input type="file" hidden onChange={handleUpload} accept={accept} />
        </label>
      </div>
    </div>
  );
}

function Field({ label, children, full }) {
  return (
    <div className={full ? "col-span-2 md:col-span-2" : ""}>
      <label className="block text-[10px] font-bold text-neutral-700 uppercase tracking-wider mb-1">{label}</label>
      {children}
    </div>
  );
}

const FIELD_CSS = `.field-input{width:100%;height:42px;padding:0 12px;border:1px solid #d4d4d4;border-radius:10px;background:#fff;font-size:14px;}.field-input:focus{outline:none;border-color:#7c3aed;box-shadow:0 0 0 3px rgba(124,58,237,0.1);}`;
