import React, { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ArrowRight, CalendarCheck2 } from "lucide-react";
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle,
} from "../components/ui/dialog";

export default function SubsidioDU004Finalizado() {
  const navigate = useNavigate();
  const location = useLocation();
  const [abierto, setAbierto] = useState(true);
  useEffect(() => { setAbierto(true); }, [location.key]);

  const irAlDu007 = () => navigate("/subsidio/du007");

  return (
    <div className="space-y-5" data-testid="du004-finalizado">
      <div className="bg-white border border-neutral-200 rounded-2xl p-6 shadow-sm">
        <div className="text-[11px] font-bold uppercase tracking-widest text-brand mb-1">Asistente de subsidio · DU 004-2026</div>
        <h1 className="font-cabinet font-black text-3xl text-neutral-900">Subsidio DU-004</h1>
        <span className="mt-3 inline-flex bg-amber-50 border border-amber-200 text-amber-800 rounded-full px-3 py-1 text-[11px] font-bold">Periodo finalizado</span>
        <p className="text-neutral-500 mt-4 text-sm">
          El periodo del DU-004 ha finalizado. Continúa la recuperación de tu subsidio con el DU-007.
        </p>
        <button onClick={irAlDu007} className="mt-5 btn-brand px-5 py-3 rounded-xl text-sm font-bold inline-flex items-center gap-2">
          Ir al DU-007 <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      <Dialog open={abierto} onOpenChange={setAbierto}>
        <DialogContent className="w-[calc(100%_-_2rem)] rounded-2xl bg-white p-6" data-testid="du004-cierre-modal">
          <div className="w-12 h-12 rounded-xl bg-brand/10 text-brand flex items-center justify-center">
            <CalendarCheck2 className="w-6 h-6" />
          </div>
          <DialogHeader>
            <DialogTitle className="font-cabinet font-black text-2xl text-neutral-900">
              El periodo del DU-004 ha finalizado
            </DialogTitle>
            <DialogDescription className="text-sm text-neutral-600 leading-relaxed pt-2">
              Continúa la recuperación de tu subsidio con el DU-007. Los documentos de tu empresa y flota
              que ya registraste se reutilizan para sus tres periodos.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col sm:flex-row gap-3 mt-2">
            <button onClick={irAlDu007} className="btn-brand px-5 py-3 rounded-xl text-sm font-bold inline-flex items-center justify-center gap-2" data-testid="du004-ir-du007">
              Ir al DU-007 <ArrowRight className="w-4 h-4" />
            </button>
            <button onClick={() => setAbierto(false)} className="border border-neutral-200 text-neutral-600 px-5 py-3 rounded-xl text-sm font-bold hover:bg-neutral-50">
              Cerrar aviso
            </button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
