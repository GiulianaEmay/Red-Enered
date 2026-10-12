import React, { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../lib/api";
import { Camera, Loader2, CheckCircle2, AlertTriangle, XCircle, Send, Trash2, Images, ScanLine, Sun, Layers } from "lucide-react";

/* Página MÓVIL pública (sin login): la abre el cliente al escanear el QR de la PC.
   El enlace temporal autoriza la subida; las fotos van al mismo OCR/validador de siempre. */
export default function CapturaMovil() {
  const { token } = useParams();
  const [info, setInfo] = useState(null);
  const [err, setErr] = useState(null);
  const [fotos, setFotos] = useState([]);          // [{file, url}]
  const [enviando, setEnviando] = useState(false);
  const [resultados, setResultados] = useState([]);
  const [ultimoEnvio, setUltimoEnvio] = useState(0);
  const camRef = useRef(null);
  const galRef = useRef(null);

  useEffect(() => {
    api.get(`/captura/${token}`).then((r) => setInfo(r.data))
      .catch((e) => setErr(e?.response?.data?.detail || "Este enlace no es válido o ya venció. Genera un QR nuevo desde la computadora."));
  }, [token]);

  // Normaliza la foto en el propio celular: la reduce a máx. 2000 px y la convierte a JPEG
  // (así un HEIC de iPhone o una foto de 5 MB llega ligera y en un formato que el lector entiende).
  const normalizar = (file) => new Promise((resolve) => {
    if (!file.type.startsWith("image/") && !/\.(heic|heif|jpg|jpeg|png|webp)$/i.test(file.name || "")) return resolve(file);
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      const MAX = 2000;
      const esc = Math.min(1, MAX / Math.max(img.width, img.height));
      const c = document.createElement("canvas");
      c.width = Math.round(img.width * esc); c.height = Math.round(img.height * esc);
      c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
      c.toBlob((b) => {
        URL.revokeObjectURL(url);
        if (!b) return resolve(file);
        resolve(new File([b], (file.name || "foto").replace(/\.[^.]+$/, "") + ".jpg", { type: "image/jpeg" }));
      }, "image/jpeg", 0.88);
    };
    img.onerror = () => { URL.revokeObjectURL(url); resolve(file); };
    img.src = url;
  });
  const agregar = async (e) => {
    const fs = Array.from(e.target.files || []);
    e.target.value = "";
    const listas = await Promise.all(fs.map(normalizar));
    setFotos((p) => [...p, ...listas.map((f) => ({ file: f, url: URL.createObjectURL(f) }))]);
  };
  const quitar = (i) => setFotos((p) => p.filter((_, k) => k !== i));

  const enviar = async () => {
    if (!fotos.length || enviando) return;
    setEnviando(true); setErr(null);
    try {
      const fd = new FormData();
      fotos.forEach((f, i) => fd.append("files", f.file, f.file.name || `foto-${i + 1}.jpg`));
      const { data } = await api.post(`/captura/${token}/fotos`, fd, { timeout: 300000 });
      setResultados((p) => [...(data.items || []), ...p]);
      setUltimoEnvio((data.items || []).filter((r) => r.id).length);
      setFotos([]);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (e) {
      setErr(e?.response?.data?.detail || "No se pudieron enviar las fotos. Revisa tu señal e intenta de nuevo.");
    } finally { setEnviando(false); }
  };

  const decreto = info?.programa === "du007" ? "DU 007" : "DU 004";
  const chip = (e) => e === "CONFORME" ? "bg-emerald-100 text-emerald-800" : e === "OBSERVADA" ? "bg-amber-100 text-amber-800" : e === "RECHAZADA" ? "bg-red-100 text-red-700" : "bg-neutral-100 text-neutral-600";

  return (
    <div className="min-h-screen bg-[#F6F3FC] text-neutral-900" style={{ paddingBottom: 110 }}>
      {/* Cabecera */}
      <div className="px-5 pt-6 pb-8 text-white rounded-b-[28px]" style={{ background: "linear-gradient(135deg,#4C1D95 0%,#6D28D9 60%,#8B5CF6 100%)" }}>
        <div className="flex items-center gap-2">
          <div className="w-9 h-9 rounded-xl bg-white/15 flex items-center justify-center font-cabinet font-bold text-lg">E</div>
          <div className="text-[11px] font-bold tracking-[.2em] uppercase opacity-85">ENERED · Subsidio {info ? decreto : ""}</div>
        </div>
        <div className="font-cabinet font-bold text-[26px] leading-tight mt-3">Fotografía tus facturas</div>
        {info?.empresa && <div className="text-sm opacity-90 mt-1 truncate">{info.empresa}</div>}
      </div>

      <div className="px-4 -mt-4 space-y-4">
        {err && !info && (
          <div className="bg-white border border-red-200 rounded-2xl p-5 text-sm shadow-sm">
            <div className="flex items-center gap-2 text-red-700 font-bold mb-1"><XCircle className="w-5 h-5" /> Enlace no disponible</div>
            <p className="text-neutral-700">{err}</p>
          </div>
        )}

        {info && (
          <>
            {ultimoEnvio > 0 && (
              <div className="bg-emerald-600 text-white rounded-2xl p-4 shadow-lg shadow-emerald-600/25 flex items-center gap-3">
                <CheckCircle2 className="w-8 h-8 flex-shrink-0" />
                <div>
                  <div className="font-cabinet font-bold text-base">¡Listo! {ultimoEnvio} factura{ultimoEnvio === 1 ? "" : "s"} enviada{ultimoEnvio === 1 ? "" : "s"}</div>
                  <div className="text-xs opacity-90">Ya aparecen en la computadora. Puedes seguir tomando más.</div>
                </div>
              </div>
            )}

            <div className="bg-white rounded-2xl p-4 shadow-sm border border-violet-100">
              <div className="font-cabinet font-bold text-neutral-900 mb-2.5">Para que se lea bien</div>
              <div className="grid grid-cols-3 gap-2 text-center">
                {[[Layers, "Completa", "Toda la factura dentro"], [ScanLine, "QR nítido", "El código de SUNAT enfocado"], [Sun, "Con luz", "Sin sombras ni brillos"]].map(([Icon, t, d]) => (
                  <div key={t} className="rounded-xl bg-violet-50 p-2.5">
                    <Icon className="w-5 h-5 text-brand mx-auto" />
                    <div className="text-xs font-bold text-neutral-900 mt-1">{t}</div>
                    <div className="text-[10.5px] text-neutral-500 leading-tight">{d}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <button onClick={() => camRef.current?.click()} disabled={enviando}
                className="text-white rounded-2xl py-6 font-cabinet font-bold text-base flex flex-col items-center gap-2 active:scale-[0.98] disabled:opacity-60 shadow-lg shadow-brand/30"
                style={{ background: "linear-gradient(135deg,#6D28D9,#7C3AED)" }} data-testid="captura-tomar-foto">
                <Camera className="w-9 h-9" /> Tomar foto
              </button>
              <button onClick={() => galRef.current?.click()} disabled={enviando}
                className="bg-white border-2 border-brand/60 text-brand rounded-2xl py-6 font-cabinet font-bold text-base flex flex-col items-center gap-2 active:scale-[0.98] disabled:opacity-60">
                <Images className="w-9 h-9" /> De la galería
              </button>
              <input ref={camRef} type="file" accept="image/*" capture="environment" hidden onChange={agregar} />
              <input ref={galRef} type="file" accept="image/*,application/pdf" multiple hidden onChange={agregar} />
            </div>

            {fotos.length > 0 && (
              <div className="bg-white rounded-2xl p-3 shadow-sm border border-neutral-200">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-xs font-bold text-neutral-700">{fotos.length} foto{fotos.length === 1 ? "" : "s"} lista{fotos.length === 1 ? "" : "s"}</div>
                  <button onClick={() => setFotos([])} className="text-[11px] text-neutral-500 hover:text-red-600">Quitar todas</button>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {fotos.map((f, i) => (
                    <div key={i} className="relative aspect-[3/4] rounded-xl overflow-hidden border border-neutral-200 bg-neutral-100">
                      {f.file.type === "application/pdf"
                        ? <div className="w-full h-full flex items-center justify-center text-[11px] text-neutral-500 px-1 text-center break-all">{f.file.name}</div>
                        : <img src={f.url} alt="" className="w-full h-full object-cover" />}
                      <span className="absolute top-1 left-1 bg-brand text-white text-[10px] font-bold rounded-full w-5 h-5 flex items-center justify-center">{i + 1}</span>
                      <button onClick={() => quitar(i)} className="absolute top-1 right-1 bg-black/60 text-white rounded-full p-1" aria-label="Quitar"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {err && info && <div className="bg-red-50 border border-red-200 text-red-800 rounded-2xl p-3 text-sm">{err}</div>}

            {resultados.length > 0 && (
              <div className="bg-white rounded-2xl p-3 shadow-sm border border-neutral-200">
                <div className="text-xs font-bold text-neutral-700 mb-2">Enviadas ({resultados.length})</div>
                <ul className="space-y-2">
                  {resultados.map((r, i) => (
                    <li key={r.id || i} className="flex items-start gap-2.5 rounded-xl bg-neutral-50 p-2.5">
                      {r.ok ? <CheckCircle2 className="w-5 h-5 text-emerald-600 mt-0.5 flex-shrink-0" /> : <AlertTriangle className="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" />}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-sm truncate">{r.numero || "Número no leído"}</span>
                          {r.estado && <span className={`ml-auto px-1.5 py-0.5 rounded text-[10px] font-bold ${chip(r.estado)}`}>{r.estado}</span>}
                        </div>
                        <div className="text-xs text-neutral-500">{r.placa || "sin placa"} · {r.galones ?? "—"} gal · {r.fecha || "sin fecha"}</div>
                        {(() => {
                          const faltan = [!r.numero && "número", !r.fecha && "fecha", !r.placa && "placa", (r.galones == null) && "galones", (r.importe == null) && "importe"].filter(Boolean);
                          return r.error_code === "rate_limited" ? (
                            <div className="mt-1 text-[11px] text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-2 py-1">
                              El servicio de lectura automática alcanzó su límite. Tu factura quedó guardada;
                              revisa o completa los datos en la computadora. No necesitas volver a tomar la foto por este aviso.
                            </div>
                          ) : faltan.length > 0 ? (
                            <div className="mt-1 text-[11px] text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-2 py-1">
                              No se pudo leer: <b>{faltan.join(", ")}</b>. Toma otra foto más cerca, sin sombra y con toda la factura, o corrígelo luego en la computadora.
                            </div>
                          ) : null;
                        })()}
                      </div>
                    </li>
                  ))}
                </ul>
                <p className="text-[11px] text-neutral-500 mt-2">Si algo no se leyó bien, se corrige en la computadora.</p>
              </div>
            )}
          </>
        )}
      </div>

      {info && (
        <div className="fixed bottom-0 inset-x-0 bg-white/95 backdrop-blur border-t border-neutral-200 p-3" style={{ paddingBottom: "max(12px, env(safe-area-inset-bottom))" }}>
          <button onClick={enviar} disabled={!fotos.length || enviando}
            className="w-full rounded-2xl py-4 font-cabinet font-bold text-base flex items-center justify-center gap-2 text-white disabled:bg-neutral-300 shadow-lg"
            style={!fotos.length || enviando ? {} : { background: "linear-gradient(135deg,#059669,#10B981)" }} data-testid="captura-enviar">
            {enviando ? <><Loader2 className="w-5 h-5 animate-spin" /> Leyendo facturas…</> : <><Send className="w-5 h-5" /> {fotos.length ? `Enviar ${fotos.length} foto${fotos.length === 1 ? "" : "s"}` : "Toma una foto para enviar"}</>}
          </button>
        </div>
      )}
    </div>
  );
}
