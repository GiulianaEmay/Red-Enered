import React, { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, ArrowLeft, CheckCircle2, AlertTriangle, Trash2, Save, FileText, Upload, ScanLine } from "lucide-react";
import { api } from "../lib/api";

const PRODUCTOS = [
  "DIESEL B5", "DIESEL B20", "DIESEL B5 S50",
];

function InvoiceRow({ item, setField, saveRow, deleteRow, vehicles, saving }) {
  const isVehicleOk = vehicles.some((v) => v.placa === item.placa);
  const placaColor = !item.placa ? "border-red-300 bg-red-50" : isVehicleOk ? "border-green-300 bg-green-50" : "border-yellow-300 bg-yellow-50";

  return (
    <div className="bg-white border border-neutral-200 rounded-xl p-4 shadow-sm mb-4 relative">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 truncate">
          <FileText className="w-4 h-4 text-neutral-400" />
          <span className="font-medium text-sm text-neutral-800 truncate" title={item.factura_filename}>{item.factura_filename}</span>
        </div>
        <button onClick={() => deleteRow(item.id)} className="text-neutral-400 hover:text-red-500" title="Eliminar archivo">
          <Trash2 className="w-4 h-4" />
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 text-sm">
        <div>
          <label className="block text-[10px] font-bold text-neutral-500 uppercase mb-1">Proveedor</label>
          <input type="text" className="w-full border border-neutral-300 rounded p-1.5 focus:border-brand focus:outline-none" value={item.estacion || ""} onChange={(e) => setField(item.id, "estacion", e.target.value)} />
        </div>
        <div>
          <label className="block text-[10px] font-bold text-neutral-500 uppercase mb-1">Fecha Emisión</label>
          <input type="text" placeholder="YYYY-MM-DD" className="w-full border border-neutral-300 rounded p-1.5 focus:border-brand focus:outline-none" value={item.fecha || ""} onChange={(e) => setField(item.id, "fecha", e.target.value)} />
        </div>
        <div>
          <label className="block text-[10px] font-bold text-neutral-500 uppercase mb-1">F. Vencimiento</label>
          <input type="text" placeholder="YYYY-MM-DD" className="w-full border border-neutral-300 rounded p-1.5 focus:border-brand focus:outline-none" value={item.fecha_vencimiento || ""} onChange={(e) => setField(item.id, "fecha_vencimiento", e.target.value)} />
        </div>
        <div>
          <label className="block text-[10px] font-bold text-neutral-500 uppercase mb-1">Placa</label>
          <input type="text" className={`w-full border rounded p-1.5 focus:outline-none ${placaColor}`} value={item.placa || ""} onChange={(e) => setField(item.id, "placa", e.target.value)} />
        </div>
        <div>
          <label className="block text-[10px] font-bold text-neutral-500 uppercase mb-1">Cantidad (Gal)</label>
          <input type="number" step="0.01" className="w-full border border-neutral-300 rounded p-1.5 focus:border-brand focus:outline-none" value={item.galones ?? ""} onChange={(e) => setField(item.id, "galones", e.target.value)} />
        </div>
        <div>
          <label className="block text-[10px] font-bold text-neutral-500 uppercase mb-1">Precio Uni</label>
          <input type="number" step="0.01" className="w-full border border-neutral-300 rounded p-1.5 focus:border-brand focus:outline-none" value={item.precio_unitario ?? ""} onChange={(e) => setField(item.id, "precio_unitario", e.target.value)} />
        </div>
        <div>
          <label className="block text-[10px] font-bold text-neutral-500 uppercase mb-1">Importe Total</label>
          <input type="number" step="0.01" className="w-full border border-neutral-300 rounded p-1.5 focus:border-brand focus:outline-none" value={item.importe_total ?? ""} onChange={(e) => setField(item.id, "importe_total", e.target.value)} />
        </div>
      </div>

      {item._dirty && (
        <div className="mt-3 flex justify-end">
          <button
            onClick={() => saveRow(item)}
            disabled={saving}
            className="px-3 py-1.5 bg-brand hover:bg-brand-hover text-white text-xs font-bold rounded flex items-center gap-2 disabled:opacity-50"
          >
            {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
            Guardar cambios
          </button>
        </div>
      )}
    </div>
  );
}

export default function SubsidioVerificar() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [confirming, setConfirming] = useState(false);
  const [items, setItems] = useState([]);
  const [vehicles, setVehicles] = useState([]);
  const [savingId, setSavingId] = useState(null);
  const [error, setError] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState({ done: 0, total: 0 });
  const fileRef = useRef(null);

  const load = async () => {
    try {
      const { data } = await api.get("/subsidio/invoices/preview");
      setItems(data.items || []);
      setVehicles(data.vehicles || []);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, []);

  const handleUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;
    // Silent 40-file cap
    const capped = files.slice(0, 40);
    setUploading(true);
    setUploadProgress({ done: 0, total: capped.length });
    setError(null);
    try {
      // Subir en lotes de 5 para no saturar el OCR
      const batchSize = 5;
      for (let i = 0; i < capped.length; i += batchSize) {
        const batch = capped.slice(i, i + batchSize);
        const fd = new FormData();
        batch.forEach((f) => fd.append("files", f));
        await api.post("/subsidio/invoices/upload", fd, {
          headers: { "Content-Type": "multipart/form-data" },
        });
        setUploadProgress({ done: Math.min(i + batchSize, capped.length), total: capped.length });
      }
      await load();
    } catch (err) {
      setError(err?.response?.data?.detail || "Error al procesar las facturas");
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const setField = (id, field, value) => {
    setItems((prev) => prev.map((it) => it.id === id ? { ...it, [field]: value, _dirty: true } : it));
  };

  const saveRow = async (item) => {
    setSavingId(item.id);
    try {
      const patch = {
        estacion: item.estacion, ciudad: item.ciudad,
        ruc_emisor: item.ruc_emisor, placa: item.placa,
        producto: item.producto,
        fecha: item.fecha,
        fecha_vencimiento: item.fecha_vencimiento,
        galones: item.galones === "" || item.galones == null ? null : Number(item.galones),
        precio_unitario: item.precio_unitario === "" || item.precio_unitario == null ? null : Number(item.precio_unitario),
        importe_total: item.importe_total === "" || item.importe_total == null ? null : Number(item.importe_total),
        numero_documento: item.numero_documento,
      };
      await api.put(`/subsidio/invoices/${item.id}`, patch);
      setItems((prev) => prev.map((it) => it.id === item.id ? { ...it, _dirty: false } : it));
    } catch (e) {
      alert(e?.response?.data?.detail || "Error al guardar");
    } finally {
      setSavingId(null);
    }
  };

  const deleteRow = async (id) => {
    if (!window.confirm("¿Eliminar esta factura?")) return;
    await api.delete(`/subsidio/invoices/${id}`);
    load();
  };

  const confirmAll = async () => {
    setError(null);
    const dirty = items.filter((it) => it._dirty);
    if (dirty.length > 0 && !window.confirm("Hay cambios sin guardar. ¿Confirmar de todos modos? (se perderán los cambios sin guardar)")) {
      return;
    }
    setConfirming(true);
    try {
      await api.post("/subsidio/invoices/confirm");
      await api.get("/auth/me").catch(() => {});
      // Forzar refresh para que el AuthProvider levante el nuevo expediente_status
      window.location.assign("/dashboard");
    } catch (e) {
      setError(e?.response?.data?.detail || "Error al confirmar");
    } finally {
      setConfirming(false);
    }
  };

  if (loading) {
    return <div className="min-h-[400px] flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-brand" /></div>;
  }

  return (
    <div className="space-y-6" data-testid="subsidio-verificar">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate("/subsidio/du007")} className="p-2 hover:bg-neutral-100 rounded-lg" data-testid="verificar-back">
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div className="flex-1">
          <span className="text-[10px] uppercase tracking-widest font-bold text-brand">Paso 2 · OCR Gemini Vision</span>
          <h2 className="font-cabinet text-2xl font-bold mt-1">Verifica los datos de tus facturas</h2>
          <p className="text-sm text-neutral-500 mt-1">
            Sube tus facturas de combustible. Extraemos los datos automáticamente. Revisa y confirma.
          </p>
        </div>
      </div>

      {/* Uploader */}
      <div className="bg-white border-2 border-dashed border-brand/40 rounded-2xl p-6">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-start gap-3">
            <div className="w-12 h-12 bg-brand/10 rounded-xl flex items-center justify-center flex-shrink-0">
              <ScanLine className="w-6 h-6 text-brand" />
            </div>
            <div>
              <h3 className="font-cabinet font-bold text-lg">Subir facturas de combustible</h3>
              <p className="text-sm text-neutral-500">Acepta archivos PDF · máx 40 por carga</p>
            </div>
          </div>
          <label className={`px-5 py-3 ${uploading ? "bg-neutral-300" : "bg-brand hover:bg-brand-hover"} text-white font-bold rounded-xl flex items-center gap-2 cursor-pointer`}>
            {uploading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Procesando {uploadProgress.done}/{uploadProgress.total}…
              </>
            ) : (
              <>
                <Upload className="w-4 h-4" />
                Elegir archivos
              </>
            )}
            <input
              ref={fileRef}
              type="file"
              hidden
              multiple
              accept=".pdf"
              onChange={handleUpload}
              disabled={uploading}
              data-testid="subsidio-upload-input"
            />
          </label>
        </div>
        {uploading && uploadProgress.total > 0 && (
          <div className="mt-4 h-2 bg-neutral-100 rounded-full overflow-hidden">
            <div
              className="h-full bg-brand transition-all"
              style={{ width: `${(uploadProgress.done / uploadProgress.total) * 100}%` }}
            />
          </div>
        )}
      </div>

      {items.length === 0 ? (
        <div className="bg-white border-2 border-dashed border-neutral-300 rounded-2xl p-12 text-center">
          <FileText className="w-10 h-10 text-neutral-300 mx-auto mb-3" />
          <p className="text-neutral-500">Aún no has subido facturas. Empieza arriba ⬆️</p>
        </div>
      ) : (
        <>
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-sm text-amber-900 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <div>
              <strong>{items.length} factura(s)</strong> en revisión. Verifica especialmente <strong>placa, fecha, galones e importe</strong>.
              {vehicles.length > 0 && (
                <span> Tu flota: {vehicles.map(v => v.placa).join(", ")}.</span>
              )}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-4">
              <h4 className="font-cabinet font-bold text-lg text-neutral-800">Archivos cargados</h4>
            </div>
            
            <div className="space-y-4">
              {items.map((it) => (
                <InvoiceRow
                  key={it.id}
                  item={it}
                  setField={setField}
                  saveRow={saveRow}
                  deleteRow={deleteRow}
                  vehicles={vehicles}
                  saving={savingId === it.id}
                />
              ))}
            </div>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl p-3 text-sm" data-testid="verificar-error">
              {typeof error === "string" ? error : JSON.stringify(error)}
            </div>
          )}

          <div className="bg-white border-2 border-brand rounded-2xl p-6 flex items-center justify-between flex-wrap gap-3">
            <div>
              <h3 className="font-cabinet text-lg font-bold">Confirmar todas las facturas</h3>
              <p className="text-sm text-neutral-600">Al confirmar se desbloquean los módulos del dashboard.</p>
            </div>
            <button
              onClick={confirmAll}
              disabled={confirming}
              className="px-6 py-3 bg-brand hover:bg-brand-hover text-white font-bold rounded-xl flex items-center gap-2 disabled:opacity-50"
              data-testid="verificar-confirm-all"
            >
              {confirming ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
              Confirmar {items.length} factura(s)
            </button>
          </div>
        </>
      )}
    </div>
  );
}
