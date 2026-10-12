import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { api } from "../lib/api";

/* El DU 004 finalizó. El aviso dirige al DU 007: constancia compartida y una declaración
   por periodo; las firmas históricas del DU 004 se conservan sin volver a solicitarlas. */
/* Solo la CONSTANCIA de términos del servicio es obligatoria (Giuliana, 25/09/2026); las DJ de
   veracidad se muestran como recomendadas. La constancia se acepta en la etapa de Declaración
   del DU 007. */
export function rutaFirmaPendiente(f) {
  if (!f || f.constancia || !f.tiene_facturas) return null;
  return "/subsidio/du007?etapa=declaracion";
}

export default function FirmasPendientes({ actual, onCargado }) {
  const [f, setF] = useState(null);
  const navigate = useNavigate();
  useEffect(() => {
    let vivo = true;
    api.get("/subsidio/firmas").then(({ data }) => { if (vivo) { setF(data); onCargado?.(data); } }).catch(() => {});
    return () => { vivo = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  if (!f) return null;
  const items = [];
  const aquiTo = "/subsidio/du007";
  if (!f.constancia) items.push({ k: "constancia", txt: "Constancia de términos del servicio", to: aquiTo });
  for (const p of (f.du007?.periodos_pendientes || [])) items.push({ k: `du007_p${p}`, txt: `Declaración jurada DU 007 · Periodo ${p}`, to: "/subsidio/du007" });
  if (items.length === 0) return null;
  const obligatoria = !f.constancia;
  const tono = obligatoria
    ? { box: "bg-red-50 border-red-200", icon: "text-red-600", txt: "text-red-900", sub: "text-red-800", link: "text-red-700 hover:text-red-900" }
    : { box: "bg-amber-50 border-amber-200", icon: "text-amber-600", txt: "text-amber-900", sub: "text-amber-800", link: "text-amber-700 hover:text-amber-900" };
  return (
    <div className={`${tono.box} border rounded-2xl p-4 flex items-start gap-3`} data-testid="firmas-pendientes">
      <ShieldAlert className={`w-5 h-5 ${tono.icon} mt-0.5 flex-shrink-0`} />
      <div className={`text-sm ${tono.txt} flex-1`}>
        <div className="font-bold">{obligatoria ? "Firma obligatoria pendiente" : "Firmas recomendadas pendientes"}</div>
        <div className={`${tono.sub} mt-0.5`}>
          {obligatoria
            ? "Para que ENERED gestione tu expediente debes aceptar la Constancia de términos del servicio (obligatoria). La declaración jurada de veracidad es recomendada."
            : "La declaración jurada de veracidad es opcional, pero te recomendamos firmarla: respalda tu expediente ante la ATU."}
        </div>
        <ul className="mt-2 space-y-1">
          {items.map((it) => {
            // La constancia se acepta en la etapa de Declaración de cualquiera de los dos decretos.
            const aqui = it.k === "constancia" || (actual === "du004" && it.to === "/subsidio/documentos") || (actual === "du007" && it.to === "/subsidio/du007");
            return (
              <li key={it.k} className="flex items-center gap-2 flex-wrap">
                <span>• {it.txt}{it.k === "constancia" ? <b> (obligatoria)</b> : <span className="opacity-70"> (recomendada)</span>}</span>
                <button onClick={() => navigate(`${it.to}?etapa=declaracion&t=${Date.now()}`)}
                  className={`text-xs font-bold underline ${tono.link}`}>
                  {aqui ? "Ir a la etapa de Declaración →" : "Ir a firmar →"}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
