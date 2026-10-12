import React from "react";

/* Nodos del anillo: los 8 módulos de ENERED. Los "free" (Diagnóstico y Subsidio) van en lima. */
const NODOS = [
  { k: "04", t: "Documentación", lado: "l", left: "24.3%", top: "17.2%",
    path: <><rect x="3" y="5" width="18" height="14" rx="2.5" /><path d="M7 10h10M7 14h6" /></> },
  { k: "05", t: "Vehículos", lado: "r", left: "75.7%", top: "17.2%",
    path: <><rect x="3" y="5" width="18" height="12" rx="2.5" /><path d="M3 12h18M7 20v-3M17 20v-3" /></> },
  { k: "06", t: "Seguridad", lado: "r", left: "89.6%", top: "37.1%",
    path: <><path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.2-7.5 9.5-4.4-1.3-7.5-4.9-7.5-9.5V6z" /><path d="M9 12l2.2 2.2L15.5 10" /></> },
  { k: "07", t: "Mantenimiento", lado: "r", left: "90.1%", top: "61.5%",
    path: <><circle cx="12" cy="12" r="3.2" /><path d="M12 2.8v2.6M12 18.6v2.6M21.2 12h-2.6M5.4 12H2.8M18.5 5.5l-1.9 1.9M7.4 16.6l-1.9 1.9M18.5 18.5l-1.9-1.9M7.4 7.4L5.5 5.5" /></> },
  { k: "08", t: "Conductores", lado: "r", left: "76.8%", top: "81.9%",
    path: <><circle cx="12" cy="12" r="8.4" /><circle cx="12" cy="12" r="3" /><path d="M12 3.6V9M4.4 15.6L9.6 13.4M19.6 15.6L14.4 13.4" /></> },
  { k: "03", t: "Combustible", lado: "l", left: "10.4%", top: "37.1%",
    path: <><path d="M4 20V6a2 2 0 012-2h6a2 2 0 012 2v14M3 20h13M7 9h4" /><path d="M14 10h2.6a2 2 0 012 2v4a1.6 1.6 0 003.2 0v-6l-2.4-2.4" /></> },
  { k: "02", t: "Subsidio", lado: "l", left: "9.9%", top: "61.5%", free: true,
    path: <><rect x="3" y="6" width="18" height="13" rx="2.5" /><path d="M3 11h18M7 15h5" /></> },
  { k: "01", t: "Diagnóstico", lado: "l", left: "23.2%", top: "81.9%", free: true,
    path: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="M20 20l-4.8-4.8" /></> },
];

/**
 * Cascarón de la portada ENERED: lado oscuro con el anillo de módulos (idéntico en
 * /subsidio y /login) + panel claro a la derecha cuyo contenido llega por children.
 */
export default function PortadaShell({ children }) {
  const ico = { viewBox: "0 0 24 24", strokeLinecap: "round", strokeLinejoin: "round" };

  return (
    <div className="sp-page">
      {/* ==================== LADO OSCURO ==================== */}
      <section className="sp-stage">
        <div className="sp-logo"><b>ENERED</b><em>Soluciones en Energías</em></div>

        <div className="sp-decrees">
          <span className="sp-dec"><i /><b>D.U. 004-2026</b> · finalizado</span>
          <span className="sp-dec sp-live"><i /><b>D.U. 007-2026</b> · consumo corriendo ahora</span>
        </div>

        <h1 className="sp-h1">¡Consolida tu expediente,<br />cobra tu subsidio y optimiza tu flota!</h1>
        <span className="sp-kick">Recupera tu subsidio con el D.U. 007 y ten todo listo en un solo lugar</span>
        <p className="sp-lead">
          Ingresa tu RUC y en 10 segundos sabes cuánto te toca en cada periodo del D.U. 007,
          qué unidades califican y qué te falta para cobrar.
        </p>

        <div className="sp-ring-wrap">
          <div className="sp-ring">
            <svg viewBox="0 0 720 720" aria-hidden="true">
              <defs>
                <linearGradient id="spRingGrad" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#C4B5FD" stopOpacity=".9" />
                  <stop offset="55%" stopColor="#7C3AED" stopOpacity=".55" />
                  <stop offset="100%" stopColor="#12C7E0" stopOpacity=".7" />
                </linearGradient>
                <path id="spArcTop" d="M150,360 a210,210 0 0,1 420,0" fill="none" />
                <path id="spArcBot" d="M570,360 a210,210 0 0,1 -420,0" fill="none" />
              </defs>

              <circle cx="360" cy="360" r="300" fill="none" stroke="url(#spRingGrad)" strokeWidth="1.6" />
              <circle cx="360" cy="360" r="210" fill="none" stroke="rgba(196,181,253,.15)" strokeWidth="1" strokeDasharray="3 7" />

              <text className="sp-arc"><textPath href="#spArcTop" startOffset="26%">Control</textPath></text>
              <text className="sp-arc"><textPath href="#spArcTop" startOffset="70%">Integración</textPath></text>
              <text className="sp-arc"><textPath href="#spArcBot" startOffset="12%">Optimización</textPath></text>
              <text className="sp-arc"><textPath href="#spArcBot" startOffset="40%">Sostenibilidad</textPath></text>
              <text className="sp-arc"><textPath href="#spArcBot" startOffset="80%">Recuperación</textPath></text>
            </svg>

            {/* hub superior */}
            <div className="sp-node sp-hub" style={{ left: "50%", top: "8.3%" }}>
              <div className="sp-bubble">
                <svg {...ico}>
                  <circle cx="12" cy="12" r="2.4" /><circle cx="12" cy="4" r="1.8" /><circle cx="12" cy="20" r="1.8" />
                  <circle cx="4.8" cy="8" r="1.8" /><circle cx="19.2" cy="8" r="1.8" />
                  <circle cx="4.8" cy="16" r="1.8" /><circle cx="19.2" cy="16" r="1.8" />
                  <path d="M12 6v3.6M12 14.4V18M6.4 9l3.5 2M14.1 13l3.5 2M6.4 15l3.5-2M14.1 11l3.5-2" />
                </svg>
              </div>
            </div>

            {NODOS.map((n) => (
              <div key={n.k} className={`sp-node sp-${n.lado}${n.free ? " sp-free" : ""}`} style={{ left: n.left, top: n.top }}>
                <div className="sp-bubble"><svg {...ico}>{n.path}</svg></div>
                <div className="sp-lbl">
                  <span className="sp-k">{n.k}</span>
                  <span className="sp-t">{n.t}</span>
                  {n.free && <><br /><span className="sp-free-tag">GRATIS</span></>}
                </div>
              </div>
            ))}

            {/* núcleo de datos */}
            <div className="sp-core">
              <div className="sp-big">S/ 105 M</div>
              <div className="sp-big-l">en juego a nivel nacional</div>
              <hr />
              <div className="sp-duo">
                <div><b>3</b><span>periodos del D.U. 007</span></div>
                <div><b>1</b><span>sola presentación por periodo</span></div>
              </div>
            </div>
          </div>
        </div>

        <div className="sp-alert">
          <svg {...ico}><path d="M12 9v4.5M12 17.2h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" /></svg>
          <p>
            <b>El D.U. 007 ya empezó a contar el 16 de agosto.</b> Cada factura de combustible sin la
            placa y sin decir “diésel B5 o B20” queda fuera del subsidio, y eso no se puede corregir después.
          </p>
        </div>
      </section>

      {/* ==================== LADO CLARO ==================== */}
      <section className="sp-panel-wrap">
        <div className="sp-panel">
          {children}
        </div>
      </section>

      <style>{`
.sp-page{--sp-violet-600:#6D28D9;--sp-violet-500:#7C3AED;--sp-violet-300:#C4B5FD;--sp-violet-100:#EDE9FE;
  --sp-lime:#C4F82A;--sp-cyan:#12C7E0;--sp-ink:#15102E;--sp-ink-2:#4B4666;--sp-ink-3:#8B87A3;
  --sp-line:#E7E4F2;--sp-ok:#0EA46B;
  display:grid;grid-template-columns:1.3fr 1fr;min-height:100vh;color:var(--sp-ink);background:#fff}
.sp-page *{box-sizing:border-box}

/* ---------- lado oscuro ---------- */
.sp-stage{position:relative;overflow:hidden;padding:22px 40px 24px;color:#fff;
  display:flex;flex-direction:column;align-items:center;min-height:0;
  background:radial-gradient(720px 520px at 50% 58%,rgba(109,40,217,.42),transparent 66%),
             radial-gradient(560px 420px at 10% 4%,rgba(124,58,237,.28),transparent 62%),
             linear-gradient(165deg,#0A0620,#150A38 52%,#0D0729)}
.sp-stage::before{content:"";position:absolute;inset:0;opacity:.5;pointer-events:none;
  background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);
  background-size:58px 58px;
  -webkit-mask-image:radial-gradient(circle at 50% 42%,#000,transparent 76%);
          mask-image:radial-gradient(circle at 50% 42%,#000,transparent 76%)}
.sp-stage>*{position:relative;z-index:1;width:100%;flex:none}

.sp-logo{display:flex;align-items:center;justify-content:center;gap:11px;margin-bottom:14px}
.sp-logo b{font-family:"Cabinet Grotesk",system-ui,sans-serif;font-size:clamp(19px,1.7vw,24px);font-weight:800;letter-spacing:.18em}
.sp-logo em{font-style:normal;font-size:11px;color:var(--sp-violet-300);border-left:1px solid rgba(255,255,255,.28);padding-left:11px}

.sp-decrees{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-bottom:13px}
.sp-dec{display:flex;align-items:center;gap:7px;padding:6px 13px;border-radius:99px;font-size:11.5px;font-weight:500;
  background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.16)}
.sp-dec i{width:6px;height:6px;border-radius:50%;background:var(--sp-cyan);flex:none}
.sp-dec.sp-live i{background:var(--sp-lime);animation:sp-pulse 2.6s infinite}
@keyframes sp-pulse{0%{box-shadow:0 0 0 0 rgba(196,248,42,.65)}70%{box-shadow:0 0 0 8px rgba(196,248,42,0)}100%{box-shadow:0 0 0 0 rgba(196,248,42,0)}}
.sp-dec b{font-weight:700}

.sp-h1{font-family:"Cabinet Grotesk",system-ui,sans-serif;font-size:clamp(22px,2.35vw,36px);font-weight:800;
  line-height:1.05;text-align:center;text-transform:uppercase;max-width:780px;margin:0 auto}
.sp-kick{display:block;color:var(--sp-lime);font-size:clamp(12.5px,1.05vw,15px);text-align:center;margin:10px auto 6px;font-weight:600}
.sp-lead{font-size:clamp(11.5px,.92vw,13.5px);line-height:1.5;color:#CFC6EE;text-align:center;max-width:620px;margin:0 auto}

.sp-ring-wrap{flex:1 1 auto!important;min-height:0;display:flex;align-items:center;justify-content:center;padding:6px 0}
.sp-ring{position:relative;height:100%;aspect-ratio:1/1;max-width:100%}
.sp-ring>svg{position:absolute;inset:0;width:100%;height:100%;overflow:visible}
.sp-arc{font-size:12px;font-weight:500;fill:#E6DEFF;letter-spacing:.06em}

.sp-node{position:absolute;transform:translate(-50%,-50%)}
.sp-bubble{width:56px;height:56px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(150deg,var(--sp-violet-500),var(--sp-violet-600));
  box-shadow:0 0 0 6px rgba(124,58,237,.14),0 10px 26px -12px rgba(124,58,237,.95);transition:transform .18s}
.sp-node:hover .sp-bubble{transform:scale(1.08)}
.sp-bubble>svg{position:static;display:block;width:25px;height:25px;stroke:#fff;fill:none;strokeWidth:1.8;stroke-width:1.8}
.sp-node.sp-free .sp-bubble{background:linear-gradient(150deg,#D8FF4F,var(--sp-lime));
  box-shadow:0 0 0 6px rgba(196,248,42,.14),0 10px 26px -12px rgba(196,248,42,.9)}
.sp-node.sp-free .sp-bubble>svg{stroke:#1A2400}
.sp-node.sp-hub .sp-bubble{width:48px;height:48px}
.sp-node.sp-hub .sp-bubble>svg{width:22px;height:22px}

.sp-lbl{position:absolute;top:50%;transform:translateY(-50%);white-space:nowrap;line-height:1.15}
.sp-lbl .sp-k{font-family:"Cabinet Grotesk",system-ui,sans-serif;font-size:18px;font-weight:800;display:block;letter-spacing:.03em}
.sp-lbl .sp-t{font-size:13.5px;color:#F1EDFF;font-weight:500}
.sp-free-tag{display:inline-block;margin-top:4px;background:var(--sp-lime);color:#1A2400;font-size:9px;font-weight:700;
  letter-spacing:.1em;padding:2px 8px;border-radius:5px}
.sp-node.sp-l .sp-lbl{right:calc(100% + 14px);text-align:right}
.sp-node.sp-r .sp-lbl{left:calc(100% + 14px);text-align:left}

.sp-core{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:47%;aspect-ratio:1/1;border-radius:50%;
  display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:9%;
  background:radial-gradient(circle at 50% 32%,rgba(124,58,237,.42),rgba(46,16,101,.5));
  border:1px solid rgba(167,139,250,.4);
  box-shadow:inset 0 0 40px rgba(167,139,250,.16),0 20px 50px -30px rgba(124,58,237,.9);backdrop-filter:blur(6px)}
.sp-core .sp-big{font-family:"Cabinet Grotesk",system-ui,sans-serif;font-size:clamp(22px,2.5vw,34px);font-weight:800;
  line-height:1;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.sp-core .sp-big-l{font-size:10.5px;color:#CFC6EE;margin-top:5px}
.sp-core hr{width:56%;border:0;border-top:1px solid rgba(196,181,253,.3);margin:12px 0}
.sp-duo{display:flex;gap:16px;justify-content:center}
.sp-duo div{max-width:82px}
.sp-duo b{display:block;font-family:"Cabinet Grotesk",system-ui,sans-serif;font-size:17px;font-weight:800;line-height:1}
.sp-duo span{display:block;font-size:9px;color:#CFC6EE;margin-top:3px;line-height:1.3}

.sp-alert{display:flex;gap:12px;align-items:flex-start;max-width:660px;margin:0 auto;padding:13px 16px;border-radius:13px;
  background:rgba(244,63,94,.13);border:1px solid rgba(244,63,94,.38)}
.sp-alert>svg{width:19px;height:19px;flex:none;color:#FDA4AF;margin-top:1px;stroke-width:2;fill:none;stroke:currentColor}
.sp-alert p{font-size:12px;line-height:1.5;color:#FFE0E6}
.sp-alert b{color:#fff}

/* ---------- lado claro ---------- */
.sp-panel-wrap{background:#fff;padding:32px 42px;display:flex;align-items:center;justify-content:center;min-height:0}
.sp-panel{width:100%;max-width:410px}
.sp-eyebrow{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--sp-violet-500);font-weight:700}
.sp-h2{font-family:"Cabinet Grotesk",system-ui,sans-serif;font-size:clamp(24px,2.2vw,30px);font-weight:800;
  letter-spacing:-.02em;margin:9px 0 8px;line-height:1.1;color:var(--sp-ink)}
.sp-sub{font-size:13.5px;color:var(--sp-ink-2);line-height:1.5}
.sp-form{margin-top:22px}
.sp-form label{display:block;font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sp-ink-3);margin-bottom:7px}
.sp-field{position:relative}
.sp-field>svg{position:absolute;left:15px;top:50%;transform:translateY(-50%);width:18px;height:18px;color:var(--sp-ink-3);
  stroke:currentColor;stroke-width:2;fill:none}
.sp-field input{width:100%;padding:15px 16px 15px 45px;border:1.5px solid var(--sp-line);border-radius:13px;
  font-family:"Cabinet Grotesk",system-ui,sans-serif;font-size:17px;letter-spacing:.07em;color:var(--sp-ink);
  background:#FBFAFF;transition:.15s;font-variant-numeric:tabular-nums}
.sp-field input::placeholder{color:#BAB6CC}
.sp-field input:focus{outline:0;border-color:var(--sp-violet-500);background:#fff;box-shadow:0 0 0 4px rgba(124,58,237,.11)}
.sp-field+.sp-field{margin-top:12px}
.sp-hint{margin-top:9px;font-size:11px;color:var(--sp-ink-3);display:flex;align-items:center;gap:7px}
.sp-hint>svg{width:13px;height:13px;color:var(--sp-ok);stroke:currentColor;stroke-width:3;fill:none;flex:none}
.sp-hint.sp-err{color:#DC2626;font-weight:600}
.sp-hint.sp-err>svg{color:#DC2626;stroke-width:2}
.sp-go{width:100%;margin-top:15px;padding:15px;border:0;border-radius:13px;cursor:pointer;font-family:inherit;
  font-size:15px;font-weight:600;color:#fff;background:linear-gradient(115deg,var(--sp-violet-600),var(--sp-violet-500) 62%,#9333EA);
  display:flex;align-items:center;justify-content:center;gap:10px;transition:transform .12s,box-shadow .12s}
.sp-go:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 14px 30px -14px rgba(109,40,217,.8)}
.sp-go:disabled{opacity:.75;cursor:wait}
.sp-go>svg{width:16px;height:16px;stroke:currentColor;stroke-width:2.4;fill:none}
.sp-spin{animation:sp-rot 1s linear infinite}
@keyframes sp-rot{to{transform:rotate(360deg)}}
.sp-gives{margin-top:22px;padding-top:18px;border-top:1px solid var(--sp-line)}
.sp-gives h3{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--sp-ink-3);font-weight:700;margin-bottom:12px}
.sp-give{display:flex;gap:10px;align-items:flex-start;margin-bottom:10px;font-size:12.5px;line-height:1.45;color:var(--sp-ink-2)}
.sp-give b{color:var(--sp-ink);font-weight:600}
.sp-tick{width:19px;height:19px;border-radius:6px;background:var(--sp-violet-100);color:var(--sp-violet-600);
  display:flex;align-items:center;justify-content:center;flex:none;margin-top:1px}
.sp-tick>svg{width:11px;height:11px;stroke:currentColor;stroke-width:3.2;fill:none}
.sp-login{margin-top:18px;font-size:12px;color:var(--sp-ink-3);text-align:center}
.sp-login a{color:var(--sp-violet-600);font-weight:600;text-decoration:none}
.sp-emay{margin-top:20px}

@media (max-width:1150px),(max-height:620px){
  .sp-page{grid-template-columns:1fr;min-height:0}
  .sp-stage{padding:24px 18px 30px}
  .sp-ring{height:auto;width:min(560px,100%)}
  .sp-ring-wrap{padding:18px 0}
  .sp-panel-wrap{padding:34px 20px 44px}
}
@media (max-width:520px){
  .sp-bubble{width:44px;height:44px}
  .sp-bubble>svg{width:20px;height:20px}
  .sp-lbl .sp-k{font-size:15px}
  .sp-lbl .sp-t{font-size:11.5px}
}
@media (prefers-reduced-motion:reduce){.sp-page *{transition:none!important;animation:none!important}}
      `}</style>
    </div>
  );
}
