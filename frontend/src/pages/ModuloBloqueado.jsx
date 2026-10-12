import React from "react";
import { useNavigate } from "react-router-dom";
import { Gift, CalendarCheck, FileCheck2, ArrowRight, Lock } from "lucide-react";

export default function ModuloBloqueado({
  titulo,
  descripcion,
  variant = "demo",   // "demo" | "subsidio"
  ctaTexto,
  ctaTo,
}) {
  const navigate = useNavigate();

  const abrirWhatsApp = () => {
    window.open(
      "https://wa.me/51997389536?text=Hola, quiero activar el demo de 30 días del módulo " + (titulo || ""),
      "_blank"
    );
  };
  const agendarConfig = () => {
    window.open(
      "https://wa.me/51997389536?text=Hola, quiero agendar la configuración del módulo " + (titulo || ""),
      "_blank"
    );
  };

  const isSubsidio = variant === "subsidio";

  return (
    <div className="relative min-h-[calc(100vh-200px)] flex items-center justify-center" data-testid="modulo-bloqueado">
      <div className="absolute inset-0 bg-gradient-to-br from-brand/5 via-white to-brand/10 blur-sm" />
      <div className="relative z-10 bg-white rounded-3xl shadow-xl border border-neutral-100 p-8 md:p-10 max-w-md w-full mx-4 text-center">
        <div className="mx-auto w-20 h-20 bg-brand rounded-full flex items-center justify-center mb-6 shadow-lg shadow-brand/30">
          {isSubsidio ? (
            <Lock className="w-9 h-9 text-white" strokeWidth={1.5} />
          ) : (
            <Gift className="w-9 h-9 text-white" strokeWidth={1.5} />
          )}
        </div>

        <div className="inline-flex items-center gap-2 bg-brand/10 text-brand px-4 py-1.5 rounded-full text-xs font-bold tracking-wide mb-6">
          {isSubsidio ? (
            <>
              <FileCheck2 className="w-4 h-4" />
              EXPEDIENTE PENDIENTE
            </>
          ) : (
            <>
              <Gift className="w-4 h-4" />
              DEMO GRATIS • 30 DÍAS
            </>
          )}
        </div>

        <h1 className="font-cabinet font-black text-2xl md:text-3xl text-neutral-900 mb-2">
          {isSubsidio ? `${titulo}` : `Módulo de ${titulo}`}
        </h1>
        <p className="text-neutral-400 text-sm mb-6">
          {isSubsidio ? "Disponible al completar tu expediente" : "Disponible para ti en tu plataforma"}
        </p>

        <p className="text-neutral-600 text-sm leading-relaxed mb-8">
          {descripcion}
        </p>

        {isSubsidio ? (
          <button
            onClick={() => navigate(ctaTo || "/subsidio/du007")}
            className="w-full bg-brand hover:bg-brand-hover text-white font-bold py-3.5 px-6 rounded-xl flex items-center justify-center gap-2 transition-all shadow-lg shadow-brand/20"
            data-testid="modulo-bloqueado-cta"
          >
            {ctaTexto || "Completar mi expediente"}
            <ArrowRight className="w-5 h-5" />
          </button>
        ) : (
          <>
            <button
              onClick={abrirWhatsApp}
              className="w-full bg-brand hover:bg-brand-hover text-white font-bold py-3.5 px-6 rounded-xl flex items-center justify-center gap-2 transition-all shadow-lg shadow-brand/20 mb-3"
            >
              <Gift className="w-5 h-5" />
              Activar demo de 30 días
            </button>
            <button
              onClick={agendarConfig}
              className="w-full bg-white hover:bg-neutral-50 text-neutral-600 font-semibold py-3.5 px-6 rounded-xl border border-neutral-200 flex items-center justify-center gap-2 transition-all"
            >
              <CalendarCheck className="w-5 h-5" />
              Agendar mi configuración
            </button>
          </>
        )}
      </div>
    </div>
  );
}
