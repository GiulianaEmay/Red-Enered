import React, { useEffect, useState } from "react";
import { NavLink, useNavigate, useLocation } from "react-router-dom";
import {
  LayoutDashboard, Fuel, Satellite, BarChart3, Receipt, ShieldCheck,
  Users, Database, LogOut, Menu, Search, Bell, Mail,
  FileText, Wrench, Disc, AlertTriangle,
  ClipboardCheck, Car, Route, ChevronDown, ChevronLeft, ChevronRight,
  FolderCheck,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { api } from "../lib/api";
import { ROLE_LABEL } from "../lib/utils";
import EmayFooter from "./EmayFooter";

const LOGO_IMG = "/assets/enered-logo.png";
const WA_LINK = "https://wa.me/51997389536";

const ICON_BASE = "/assets/icons";

const ALL_REGULAR_ROLES = ["admin_enered", "administrador", "logistica", "contabilidad", "cliente_subsidio"];

// Módulos opcionales fuera de la base (Dashboard, Combustible, Cuenta, Vehículos,
// Documentación, que siempre están disponibles). Un usuario de empresa (administrador/
// logística/contabilidad) solo los ve si la empresa tiene "plataforma" activa y, si el
// admin restringió módulos puntuales (modulos_habilitados != null en /auth/me), que ese
// módulo esté en la lista. Mismos nombres que el `titulo` que revisa SubsidioGate.
const MODULOS_OPCIONALES = ["Analytics BI", "Mantenimiento", "Checklist", "Infracciones", "Neumáticos", "Viajes"];

const MENU = [
  {
    label: "Subsidios", icon: FolderCheck, roles: ["cliente_subsidio"], testid: "nav-subsidios",
    // El grupo abre el programa vigente; la flecha despliega ambos decretos.
    clickTo: "/subsidio/du007",
    submenu: [
      { to: "/subsidio/diagnostico", label: "Diagnóstico", testid: "nav-diagnostico" },
      { to: "/subsidio/documentos", label: "DU - 004", testid: "nav-du004", badge: "FINALIZADO", badgeColor: "amber" },
      { to: "/subsidio/du007", label: "DU - 007", testid: "nav-du007", badge: "NUEVO", badgeColor: "cyan" },
    ],
  },
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, roles: ALL_REGULAR_ROLES, testid: "nav-dashboard", mkey: "dashboard" },
  { to: "/dashboard-subsidio", label: "Panel Subsidio", icon: LayoutDashboard, roles: ["admin_enered", "cliente_subsidio", "administrador", "logistica", "contabilidad"], testid: "nav-dashboard-subsidio", requiresSubsidio: true },
  { to: "/analitica", label: "Analytics BI", icon: BarChart3, roles: ALL_REGULAR_ROLES, testid: "nav-analitica", mkey: "analitica" },
  { to: "/monitoreo", label: "Monitoreo", icon: Satellite, roles: ALL_REGULAR_ROLES, testid: "nav-monitoreo", mkey: "monitoreo" },
  { to: "/flotas", label: "Combustible", icon: Fuel, roles: ALL_REGULAR_ROLES, testid: "nav-flotas", mkey: "combustible" },
  { to: "/facturacion", label: "Gestión de Gastos", icon: Receipt, roles: ["admin_enered", "administrador", "contabilidad", "cliente_subsidio"], testid: "nav-estado", mkey: "facturacion" },
  { to: "/mantenimiento", label: "Mantenimiento", icon: Wrench, roles: ALL_REGULAR_ROLES, testid: "nav-mantenimiento", mkey: "mantenimiento" },
  { to: "/checklist", label: "Checklist", icon: ClipboardCheck, roles: ALL_REGULAR_ROLES, testid: "nav-checklist", mkey: "checklist" },
  { to: "/infracciones", label: "Infracciones", icon: AlertTriangle, roles: ALL_REGULAR_ROLES, testid: "nav-infracciones", mkey: "infracciones" },
  { to: "/vehiculos", label: "Vehículos", icon: Car, roles: ALL_REGULAR_ROLES, testid: "nav-vehiculos", mkey: "vehiculos" },
  { to: "/neumaticos", label: "Neumáticos", icon: Disc, roles: ALL_REGULAR_ROLES, testid: "nav-neumaticos", mkey: "neumaticos" },
  { to: "/viajes", label: "Viajes", icon: Route, roles: ALL_REGULAR_ROLES, testid: "nav-viajes", mkey: "viajes" },
  { to: "/documentacion", label: "Documentación", icon: FileText, roles: ALL_REGULAR_ROLES, testid: "nav-documentacion", mkey: "documentacion" },
];

const ADMIN_ITEMS = [
  { to: "/admin/users", label: "Usuarios", icon: Users, testid: "nav-users", mkey: "usuarios" },
  { to: "/admin/empresas", label: "Empresas & Servicios", icon: FolderCheck, testid: "nav-empresas", mkey: "empresas" },
  { to: "/admin/tesoreria", label: "Tesorería", icon: FolderCheck, testid: "nav-tesoreria", mkey: "tesoreria" },
  { to: "/admin/upload", label: "Datos", icon: Database, testid: "nav-upload", mkey: "datos" },
  { to: "/admin/subsidio", label: "Subsidio DU 004", icon: FolderCheck, testid: "nav-subsidio-admin", mkey: "subsidio" },
  { to: "/admin/subsidio-du007", label: "Subsidio DU 007", icon: FolderCheck, testid: "nav-subsidio-admin-du007", mkey: "subsidio_du007" },
  { to: "/admin/bitacora", label: "Bitácora", icon: FileText, testid: "nav-bitacora", mkey: "bitacora" },
  {
    label: "En desarrollo (GIU)", icon: ShieldCheck, testid: "nav-en-desarrollo",
    submenu: [
      { to: "/mtc", label: "Consulta MTC", testid: "nav-mtc", mkey: "mtc" },
      { to: "/atu", label: "Diagnóstico ATU", testid: "nav-atu", mkey: "atu" },
      { to: "/admin/atu-padron", label: "Padrón ATU (macro)", testid: "nav-atu-padron", mkey: "atu" },
      { to: "/admin/atu", label: "Conexión ATU", testid: "nav-admin-atu", mkey: "atu_conexion" },
      { to: "/admin/sire", label: "Compras SUNAT", testid: "nav-admin-sire", mkey: "sire" },
      { to: "/testing", label: "Testing", testid: "nav-testing", mkey: "atu" },
    ],
  },
];

const ROUTE_TITLES = {
  "/dashboard": "Dashboard",
  "/mtc": "Consulta MTC · DGTT",
  "/analitica": "Analytics BI",
  "/monitoreo": "Monitoreo",
  "/flotas": "Combustible",
  "/facturacion": "Gestión Gastos",
  "/calendario": "Calendario",
  "/tickets": "Tickets",
  "/mantenimiento": "Mantenimiento",
  "/checklist": "Checklist",
  "/infracciones": "Infracciones",
  "/vehiculos": "Vehículos",
  "/neumaticos": "Neumáticos",
  "/viajes": "Viajes",
  "/documentacion": "Documentación",
  "/soporte": "Soporte",
  "/admin/users": "Usuarios",
  "/admin/empresas": "Empresas & Servicios",
  "/admin/subsidio": "Subsidio DU 004 · Expedientes",
  "/admin/subsidio-du007": "Subsidio DU 007 · Expedientes",
  "/admin/bitacora": "Bitácora",
  "/admin/atu": "Conexión ATU · Cuenta maestra",
  "/admin/atu-padron": "Padrón ATU · Todas las empresas vs. el subsidio",
  "/admin/upload": "Datos",
  "/admin/qr": "QR",
};

function SidebarLink({ item, onClick, isCollapsed }) {
  const Ic = item.icon;
  const location = useLocation();
  const navigate = useNavigate();
  const [expanded, setExpanded] = React.useState(false);
  const hasSubmenu = item.submenu && item.submenu.length > 0;
  const isSubmenuActive = hasSubmenu && item.submenu.some(sub => location.pathname === sub.to);
  
  // Auto-expandir SOLO al entrar a una ruta del grupo; luego el usuario puede contraerlo.
  React.useEffect(() => {
    if (isSubmenuActive) setExpanded(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSubmenuActive]);

  const content = (active) => (
    <>
      {active && <span className="absolute left-0 top-2 bottom-2 w-1 bg-cyan-300 rounded-r-full" />}
      {item.iconImg ? (
        <img
          src={item.iconImg}
          alt=""
          className="w-5 h-5 object-contain flex-shrink-0"
          style={active ? { filter: "brightness(0) saturate(100%) invert(78%) sepia(60%) saturate(427%) hue-rotate(135deg) brightness(102%) contrast(98%)" } : { filter: "brightness(0) invert(1)", opacity: 0.9 }}
        />
      ) : (
        <Ic className={`w-5 h-5 flex-shrink-0 ${active ? "text-cyan-300" : "text-white/90"}`} strokeWidth={2} />
      )}
      <span className={`text-sm font-semibold flex-1 text-left transition-opacity duration-300 whitespace-nowrap ${
        isCollapsed ? "opacity-0 pointer-events-none" : "opacity-100"
      } ${active ? "text-cyan-300" : "text-white/95"}`}>{item.label}</span>
      {item.badge && (
        <span className={`px-1.5 py-0.5 rounded-full text-[8px] font-black tracking-wider flex-shrink-0 transition-opacity duration-300 ${
          isCollapsed ? "opacity-0 pointer-events-none" : "opacity-100"
        } ${
          item.badgeColor === "cyan" ? "bg-cyan-400 text-[#2D0A4E]" : "bg-amber-400 text-[#2D0A4E]"
        }`}>
          {item.badge}
        </span>
      )}
      {hasSubmenu && (
        <ChevronDown
          onClick={item.clickTo ? (e) => { e.stopPropagation(); setExpanded(!expanded); } : undefined}
          className={`w-4 h-4 flex-shrink-0 transition-opacity duration-300 ${
          isCollapsed ? "opacity-0 pointer-events-none" : "opacity-100"
        } ${expanded ? "rotate-180" : ""} ${active || isSubmenuActive ? "text-cyan-300" : "text-white/70"}`} />
      )}
    </>
  );

  const baseCls = `relative flex items-center rounded-lg transition-all overflow-hidden gap-3 px-[14px] py-2.5`;

  if (item.disabled) {
    return (
      <div className={`${baseCls} opacity-60 cursor-not-allowed`} data-testid={item.testid}>
        {content(false)}
      </div>
    );
  }

  if (hasSubmenu) {
    return (
      <div>
        <button
          onClick={() => {
            // Con clickTo, el clic en el grupo navega directo (Subsidios → DU-007);
            // la flecha es la que despliega/contrae. Sin clickTo, el clic solo despliega.
            if (item.clickTo) { setExpanded(true); navigate(item.clickTo); onClick?.(); }
            else setExpanded(!expanded);
          }}
          data-testid={item.testid}
          className={`${baseCls} w-full ${isSubmenuActive ? "bg-white/15" : "hover:bg-white/10"}`}
        >
          {content(isSubmenuActive)}
        </button>
        {!isCollapsed && expanded && (
          <div className="ml-6 mt-1 space-y-0.5 border-l border-white/20 pl-3">
            {item.submenu.map((sub) => (
              <NavLink
                key={sub.to}
                to={sub.to}
                onClick={onClick}
                data-testid={sub.testid}
                className={({ isActive }) =>
                  `flex items-center gap-2 px-3 py-2 rounded-md text-xs font-medium transition-all ${
                    isActive ? "bg-white/15 text-cyan-300" : "text-white/80 hover:bg-white/10 hover:text-white"
                  }`
                }
              >
                <span className="flex-1">{sub.label}</span>
                {sub.badge && (
                  <span className={`px-1.5 py-0.5 rounded-full text-[8px] font-black tracking-wider flex-shrink-0 ${
                    sub.badgeColor === "cyan" ? "bg-cyan-400 text-[#2D0A4E]" : "bg-amber-400 text-[#2D0A4E]"
                  }`}>
                    {sub.badge}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <NavLink
      to={item.to}
      onClick={onClick}
      data-testid={item.testid}
      className={({ isActive }) =>
        `${baseCls} ${isActive ? "bg-white/15" : "hover:bg-white/10"}`
      }
    >
      {({ isActive }) => content(isActive)}
    </NavLink>
  );
}

function PlanCard({ label, title, color = "violet", testid, onClick, active = false, wide = false }) {
  // wide cards (Cliente, Tipo de Producto): 294 px ancho — 2 juntos + gap = 600 px (igual que Estado General)
  // tarjetas de plan (4): 200 x 60 px, border-radius 20 px
  const base = wide
    ? "rounded-2xl px-4 py-3 border flex flex-col justify-center transition-all w-[294px] flex-shrink-0"
    : "rounded-[20px] px-3 py-2 border flex flex-col justify-center transition-all w-[200px] h-[60px] flex-shrink-0";
  const styles = {
    gray: "bg-neutral-100 text-neutral-800 border-neutral-200",
    violet: "bg-brand text-white border-brand hover:bg-brand-hover cursor-pointer hover:shadow-lg hover:-translate-y-0.5",
    violetDark: "bg-[#6B23B1] text-white border-[#6B23B1] hover:bg-[#5A1E96] cursor-pointer hover:shadow-lg hover:-translate-y-0.5",
    cyan: "bg-cyan-300 text-[#1e1b4b] border-cyan-300 hover:bg-cyan-400 cursor-pointer hover:shadow-lg hover:-translate-y-0.5",
  }[color];

  const activeRing = "";

  const content = (
    <>
      <div className={`text-[10px] font-semibold uppercase tracking-wider truncate ${color === "gray" ? "text-neutral-500" : color === "cyan" ? "text-[#1e1b4b]/70" : "text-white/75"}`}>
        {label}
      </div>
      <div className={`font-bold text-sm mt-0.5 leading-tight truncate ${color === "cyan" ? "text-[#1e1b4b]" : ""}`} title={title}>{title}</div>
      {active && <div className="text-[9px] font-black uppercase tracking-widest text-cyan-300 mt-0.5">● Tu Plan</div>}
    </>
  );

  if (onClick) {
    return (
      <button onClick={onClick} data-testid={testid} className={`${base} ${styles} ${activeRing} text-left`}>
        {content}
      </button>
    );
  }
  return <div className={`${base} ${styles}`} data-testid={testid}>{content}</div>;
}

export default function Layout({ children }) {
  const { user, logout, enterEmpresa, exitEmpresa } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [overview, setOverview] = useState(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [wakingUp, setWakingUp] = useState(false);
  // Impersonación: modal de elección al ingresar como admin_enered
  const [showChooser, setShowChooser] = useState(false);
  const [empresasList, setEmpresasList] = useState([]);
  const [chooserEmpresa, setChooserEmpresa] = useState("");
  const navigate = useNavigate();
  const location = useLocation();

  // Mostrar el modal de elección cuando entra el admin principal (super-admin) y no eligió aún.
  useEffect(() => {
    if (user?.role === "admin_enered" && !user?.impersonando && user?.permisos == null
        && !sessionStorage.getItem("enered_admin_choice")) {
      setShowChooser(true);
      api.get("/empresas").then((r) => setEmpresasList(r.data || [])).catch(() => {});
    }
  }, [user?.id, user?.role, user?.impersonando]);

  useEffect(() => {
    if (user && user.role !== "cliente_subsidio") {
      api.get("/dashboard/overview").then((r) => setOverview(r.data)).catch(() => {});
    }
  }, [user?.id]);

  // Escucha los eventos que emite api.js cuando un request tarda >5s (cold-start Render).
  useEffect(() => {
    const onSlow = () => setWakingUp(true);
    const onIdle = () => setWakingUp(false);
    window.addEventListener("api:slow", onSlow);
    window.addEventListener("api:idle", onIdle);
    return () => {
      window.removeEventListener("api:slow", onSlow);
      window.removeEventListener("api:idle", onIdle);
    };
  }, []);

  if (!user) return null;

  // Cliente de subsidio (entra por enered.netlify.app/subsidio con su RUC): solo ve su Mi Flota
  // y los módulos del expediente. El resto del menú NO aparece. Estos aparecen pero bloqueados
  // (salvo Mi Flota, que es su vista de aterrizaje / Etapa 0).
  const SUBSIDIO_VISIBLES = ["/subsidio/documentos", "/subsidio/du007", "/flotas", "/facturacion", "/vehiculos", "/documentacion"];

  const items = MENU.filter((i) => {
    // Permisos por módulo (equipo ENERED): si el admin tiene una lista de permisos,
    // se ocultan los módulos no incluidos. Super-admin (permisos null) ve todo.
    if (user.role === "admin_enered" && Array.isArray(user.permisos) && i.mkey && !user.permisos.includes(i.mkey)) {
      return false;
    }
    // Solo mientras NO se ha registrado (entró por RUC): menú recortado a los 5.
    // Al registrarse (acceso_etapa0 = false) ve el menú completo (los premium quedan bloqueados).
    // El grupo "Subsidios" (desplegable, sin ruta propia) cuenta como visible si contiene el DU-004.
    if (user.role === "cliente_subsidio" && user.acceso_etapa0 === true) {
      const esGrupoSubsidios = i.submenu?.some((s) => SUBSIDIO_VISIBLES.includes(s.to));
      if (!esGrupoSubsidios && !SUBSIDIO_VISIBLES.includes(i.to)) return false;
    }

    // El grupo "Subsidios" también aplica a usuarios de empresas de subsidio con otro rol
    // (p.ej. administrador con plan Tracking): su vista principal es el expediente DU-007.
    const esEmpresaSubsidio = user?.tipo_cliente === "subsidio" || !!user?.servicios?.subsidio;
    if (!i.roles.includes(user.role) && !(i.testid === "nav-subsidios" && esEmpresaSubsidio)) {
      // "Mi Flota" también accesible si la empresa tiene servicios.subsidio activo
      if (i.to === "/subsidio/documentos" && user?.servicios?.subsidio) return true;
      // El grupo "Subsidios" (desplegable) también es visible si la empresa tiene el servicio.
      if (i.submenu?.some((s) => s.to === "/subsidio/documentos") && user?.servicios?.subsidio) return true;
      return false;
    }
    // Panel Subsidio: Oculto si tiene plataforma activa (porque ya ve el tracker en el Dashboard general)
    if (i.requiresSubsidio) {
      if (user.role === "admin_enered") return true;
      if (user?.servicios?.plataforma) return false;
      if (user.role !== "cliente_subsidio" && !user?.servicios?.subsidio) return false;
    }
    // Dashboard general: solo visible con el servicio "plataforma" (para cualquier rol de empresa,
    // incluido cliente_subsidio). Un cliente solo-subsidio ve únicamente "Panel Subsidio"; al
    // activarle plataforma, se oculta "Panel Subsidio" y aparece el Dashboard con el tracker del
    // trámite como encabezado.
    if (i.to === "/dashboard" && user.role !== "admin_enered") {
      if (!user?.servicios?.plataforma) {
        return false;
      }
    }
    // Módulos opcionales: se ocultan del sidebar directamente (no solo el contenido) para
    // administrador/logística/contabilidad. cliente_subsidio los conserva visibles-pero-
    // bloqueados a propósito (upsell de "Migrar a Plataforma"), así que no se tocan aquí.
    if (MODULOS_OPCIONALES.includes(i.label) && user.role !== "admin_enered" && user.role !== "cliente_subsidio") {
      const habilitados = user.modulos_habilitados;
      const tieneAcceso = user?.servicios?.plataforma === true && (habilitados == null || habilitados.includes(i.label));
      if (!tieneAcceso) return false;
    }

    return true;
  }).map((i) => {
    // Si es Monitoreo y no tiene GPS, le ponemos el badge de DEMO GRATIS
    if (i.to === "/monitoreo" && user.role !== "admin_enered" && (!user?.servicios || !user.servicios.gps)) {
      return { ...i, badge: "DEMO GRATIS", badgeColor: "amber" };
    }
    return i;
  });
  const isAdmin = user.role === "admin_enered";

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const pageTitle = ROUTE_TITLES[location.pathname] || "";
  const initials = (user.name || user.email).split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase();
  const currentPlan = overview?.plan || "tracking";
  const clienteLabel = overview && overview.ruc
    ? `${overview.empresa} - ${overview.ruc}`
    : (overview?.empresa || user.empresa || "ENERED PERÚ");
  const openWA = () => window.open(WA_LINK, "_blank");

  const SidebarContent = ({ isCollapsed, onToggle }) => (
    <>
      {/* Logo */}
      <div className="px-5 pt-6 pb-5 flex-shrink-0 flex items-center justify-center min-h-[70px] relative">
        <img
          src={LOGO_IMG}
          alt="ENERED"
          className={`w-full max-w-[150px] mx-auto h-auto object-contain transition-all duration-300 ${
            isCollapsed ? "opacity-0 scale-75 w-0 pointer-events-none" : "opacity-100 scale-100"
          }`}
        />
        {isCollapsed && (
          <svg viewBox="0 0 24 24" fill="currentColor" className="absolute w-7 h-7 text-white animate-fade-in">
            <rect x="4" y="4" width="4" height="4" rx="1" />
            <rect x="10" y="4" width="4" height="4" rx="1" />
            <rect x="16" y="4" width="4" height="4" rx="1" />
            <rect x="4" y="10" width="4" height="4" rx="1" />
            <rect x="10" y="10" width="4" height="4" rx="1" />
            <rect x="16" y="10" width="4" height="4" rx="1" />
            <rect x="4" y="16" width="4" height="4" rx="1" />
            <rect x="10" y="16" width="4" height="4" rx="1" />
            <rect x="16" y="16" width="4" height="4" rx="1" />
          </svg>
        )}
      </div>

      {/* Divider */}
      <div className={`mx-5 h-px bg-white/15 mb-2 flex-shrink-0 transition-all duration-300 ${isCollapsed ? "mx-3" : "mx-5"}`} />

      <nav className="flex-1 px-3 py-2 flex flex-col space-y-1.5 overflow-y-auto overflow-x-hidden" data-testid="sidebar-nav">
        {items.map((item) => (
          <SidebarLink key={item.to || item.label} item={item} onClick={() => setMobileOpen(false)} isCollapsed={isCollapsed} />
        ))}

        {isAdmin && (
          <>
            <div className={`mx-3 mt-3 mb-1 pt-3 border-t border-white/15 text-[9px] font-bold uppercase tracking-widest text-white/60 transition-all duration-300 whitespace-nowrap overflow-hidden ${
              isCollapsed ? "opacity-0 h-0 mt-0 pt-0 border-t-0" : "opacity-100"
            }`}>
              Admin
            </div>
            {ADMIN_ITEMS
              .map((item) => {
                // Los grupos (submenu) filtran sus submódulos por permiso; el grupo se oculta si queda vacío.
                if (item.submenu) {
                  const submenu = item.submenu.filter((s) => !(Array.isArray(user.permisos) && s.mkey && !user.permisos.includes(s.mkey)));
                  return submenu.length ? { ...item, submenu } : null;
                }
                return Array.isArray(user.permisos) && item.mkey && !user.permisos.includes(item.mkey) ? null : item;
              })
              .filter(Boolean)
              .map((item) => (
                <SidebarLink key={item.to || item.label} item={item} onClick={() => setMobileOpen(false)} isCollapsed={isCollapsed} />
              ))}
          </>
        )}

        <div className="flex-1 min-h-[8px]" />

        {/* Toggle Sidebar Button */}
        {onToggle && (
          <button
            onClick={onToggle}
            className={`hidden md:flex w-full items-center rounded-lg hover:bg-white/10 transition-all duration-300 overflow-hidden gap-3 px-[14px] py-2.5`}
            title={isCollapsed ? "Expandir menú" : "Contraer menú"}
          >
            {isCollapsed ? <ChevronRight className="w-5 h-5 text-white/80 flex-shrink-0" strokeWidth={1.75} /> : <ChevronLeft className="w-5 h-5 text-white/80 flex-shrink-0" strokeWidth={1.75} />}
            <span className={`text-sm font-semibold flex-1 text-left text-white/90 transition-opacity duration-300 whitespace-nowrap ${
              isCollapsed ? "opacity-0 pointer-events-none" : "opacity-100"
            }`}>
              {isCollapsed ? "Expandir" : "Contraer"}
            </span>
          </button>
        )}
      </nav>

      {/* Logout */}
      <div className="px-3 py-3 border-t border-white/15 flex-shrink-0">
        <button
          onClick={handleLogout}
          className={`w-full flex items-center rounded-lg hover:bg-white/10 transition-all duration-300 overflow-hidden gap-3 px-[14px] py-2.5`}
          data-testid="logout-btn"
        >
          <LogOut className="w-5 h-5 text-white/80 flex-shrink-0" strokeWidth={1.75} />
          <span className={`text-sm font-semibold flex-1 text-left text-white/90 transition-opacity duration-300 whitespace-nowrap ${
            isCollapsed ? "opacity-0 pointer-events-none" : "opacity-100"
          }`}>
            Salir
          </span>
        </button>
      </div>
    </>
  );

  return (
    <div className="min-h-screen bg-[#F6F7FB]">
      {/* Modal: elegir ingresar como Admin o como empresa (impersonación) */}
      {showChooser && (
        <div className="fixed inset-0 z-[200] bg-black/60 backdrop-blur-[2px] flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6 overflow-hidden" data-testid="admin-chooser">
            <h3 className="font-cabinet font-black text-xl text-neutral-900 mb-1">¿Cómo quieres ingresar?</h3>
            <p className="text-sm text-neutral-500 mb-5 leading-relaxed">Opera como Administrador ENERED, o entra al contexto de una empresa para ver su información y módulos.</p>
            <button
              onClick={() => { sessionStorage.setItem("enered_admin_choice", "1"); setShowChooser(false); }}
              className="w-full mb-5 px-4 py-3.5 rounded-xl border-2 border-brand bg-brand/5 hover:bg-brand/10 text-left transition-colors"
              data-testid="chooser-admin">
              <div className="font-bold text-brand">Ingresar como Administrador</div>
              <div className="text-xs text-neutral-500 mt-0.5">Acceso total: todas las empresas y módulos de administración.</div>
            </button>
            <div className="relative mb-3">
              <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-neutral-200" /></div>
              <div className="relative flex justify-center">
                <span className="bg-white px-3 text-[11px] font-bold text-neutral-400 uppercase tracking-wide">o entrar como empresa</span>
              </div>
            </div>
            <div className="flex gap-2 items-stretch">
              {/* min-w-0: sin esto, un nombre de empresa largo revienta la fila y empuja el botón fuera */}
              <select value={chooserEmpresa} onChange={(e) => setChooserEmpresa(e.target.value)}
                className="flex-1 min-w-0 h-11 px-3 border border-neutral-300 rounded-lg text-sm bg-white truncate focus:outline-none focus:border-brand focus:ring-4 focus:ring-brand/10"
                data-testid="chooser-empresa-select">
                <option value="">Elige una empresa…</option>
                {empresasList.map((e) => <option key={e} value={e}>{e}</option>)}
              </select>
              <button disabled={!chooserEmpresa}
                onClick={async () => {
                  const eff = await enterEmpresa(chooserEmpresa); setShowChooser(false);
                  const esSubsidio = eff?.role === "cliente_subsidio" || eff?.tipo_cliente === "subsidio";
                  window.location.assign(esSubsidio ? "/subsidio/du007" : "/dashboard");
                }}
                className="flex-shrink-0 px-5 h-11 bg-brand hover:bg-brand-hover text-white font-bold rounded-lg text-sm disabled:opacity-50 transition-colors"
                data-testid="chooser-entrar">Entrar</button>
            </div>
          </div>
        </div>
      )}
      {/* Banner de impersonación */}
      {user.impersonando && (
        <div className="fixed top-0 left-0 right-0 z-[110] bg-amber-500 text-white text-xs font-bold py-2 px-4 text-center flex items-center justify-center gap-3 shadow" data-testid="impersonation-banner">
          <span>👁️ Viendo como <strong>{user.empresa}</strong> (modo empresa)</span>
          <button onClick={async () => { await exitEmpresa(); sessionStorage.removeItem("enered_admin_choice"); navigate("/dashboard"); }}
            className="underline hover:no-underline" data-testid="btn-volver-admin">Volver a Admin</button>
        </div>
      )}
      {/* Banner "Reactivando servidor..." — se muestra si un request tarda >5s (cold-start Render free) */}
      {wakingUp && (
        <div className="fixed top-0 left-0 right-0 z-[100] bg-emerald-500 text-white text-xs font-semibold py-2 px-4 text-center shadow-lg flex items-center justify-center gap-2">
          <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
          Preparando tu flota… cargando vehículos y datos.
        </div>
      )}
      {/* Desktop sidebar */}
      <aside
        className={`hidden md:flex fixed inset-y-0 left-0 flex-col z-40 transition-all duration-300 ease-in-out border-r border-white/10 ${
          isSidebarOpen ? "w-56" : "w-[72px]"
        }`}
        style={{ background: "linear-gradient(180deg, #8039F4 0%, #6B26DC 100%)" }}
      >
        <SidebarContent isCollapsed={!isSidebarOpen} onToggle={() => setIsSidebarOpen(!isSidebarOpen)} />
      </aside>

      {/* Mobile sidebar overlay */}
      {mobileOpen && (
        <>
          <div className="fixed inset-0 bg-black/40 z-50 md:hidden" onClick={() => setMobileOpen(false)} />
          <aside
            className="fixed inset-y-0 left-0 w-56 z-50 flex flex-col md:hidden animate-fade-in"
            style={{ background: "linear-gradient(180deg, #8039F4 0%, #6B26DC 100%)" }}
          >
            <SidebarContent isCollapsed={false} />
          </aside>
        </>
      )}

      {/* Header */}
      <header className={`${isSidebarOpen ? "md:ml-56" : "md:ml-[72px]"} h-20 bg-white sticky top-0 z-30 flex items-center justify-between px-4 md:px-8 border-b border-neutral-100 transition-all duration-300 ease-in-out`}>
        <div className="flex items-center gap-3 min-w-0">
          <button
            className="md:hidden p-2 rounded-md hover:bg-neutral-100"
            onClick={() => setMobileOpen(true)}
            data-testid="mobile-menu-toggle"
          >
            <Menu className="w-5 h-5" />
          </button>
          <h1 className="font-cabinet font-bold text-2xl md:text-3xl text-neutral-900 truncate" data-testid="page-title">
            {pageTitle}
          </h1>
        </div>

        <div className="flex items-center gap-3 md:gap-5">
          <div className="hidden md:flex items-center h-10 w-64 lg:w-80 bg-neutral-50 rounded-full px-4 border border-neutral-200" data-testid="header-search">
            <Search className="w-4 h-4 text-neutral-400" />
            <input
              type="text"
              placeholder="Buscar"
              className="flex-1 ml-3 bg-transparent outline-none text-sm placeholder:text-neutral-400"
            />
          </div>
          <button className="hidden md:flex w-10 h-10 rounded-full bg-neutral-50 border border-neutral-200 items-center justify-center hover:bg-neutral-100 relative" data-testid="header-bell">
            <Bell className="w-4 h-4 text-neutral-700" strokeWidth={1.75} />
            <span className="absolute top-2 right-2.5 w-1.5 h-1.5 bg-brand rounded-full" />
          </button>
          <button className="hidden md:flex w-10 h-10 rounded-full bg-neutral-50 border border-neutral-200 items-center justify-center hover:bg-neutral-100" data-testid="header-mail">
            <Mail className="w-4 h-4 text-neutral-700" strokeWidth={1.75} />
          </button>

          <div className="flex items-center gap-3">
            {/* Selector de empresa: cliente con varias empresas puede alternar sin cerrar sesión */}
            {Array.isArray(user.empresas_asignadas) && user.empresas_asignadas.length >= 2 && (
              <select
                value={user.empresa_activa || user.empresa || ""}
                onChange={async (e) => {
                  await enterEmpresa(e.target.value);
                  // Recarga completa: así TODOS los módulos vuelven a pedir datos con la
                  // nueva empresa (navigate() no remonta si ya estás en la misma ruta).
                  window.location.assign("/subsidio/du007");
                }}
                title="Cambiar de empresa"
                data-testid="header-empresa-switch"
                className="hidden sm:block h-10 px-3 border border-brand/40 bg-brand/5 rounded-lg text-sm font-bold text-brand max-w-[240px] cursor-pointer hover:bg-brand/10"
              >
                {user.empresas_asignadas.map((e) => (
                  <option key={e.ruc || e.empresa} value={e.empresa}>{e.empresa}</option>
                ))}
              </select>
            )}
            <div className="hidden sm:block text-right">
              <div className="text-sm font-bold text-neutral-900 leading-tight truncate max-w-[260px]" data-testid="header-empresa" title={clienteLabel}>
                {clienteLabel}
              </div>
              <div className="text-xs font-bold text-brand leading-tight" data-testid="header-plan">
                Plan {currentPlan.charAt(0).toUpperCase() + currentPlan.slice(1)}
              </div>
            </div>
            <button
              onClick={openWA}
              title="Contactar a ENERED por WhatsApp"
              className="w-11 h-11 rounded-full bg-gradient-to-br from-brand to-[#6B23B1] text-white font-black flex items-center justify-center text-sm border-2 border-white shadow-md hover:scale-105 transition-transform"
              data-testid="header-avatar"
            >
              {initials}
            </button>
          </div>
        </div>
      </header>

      <main className={`${isSidebarOpen ? "md:ml-56" : "md:ml-[72px]"} p-4 md:p-8 space-y-8 page-enter transition-all duration-300 ease-in-out`}>
        {children}
        <EmayFooter variant="compact" />
      </main>

      {/* Botón flotante de soporte por WhatsApp — visible en todos los módulos */}
      <a
        href={`https://wa.me/51997389536?text=${encodeURIComponent("Hola ENERED 👋, necesito soporte con la plataforma.")}`}
        target="_blank"
        rel="noreferrer"
        title="Soporte por WhatsApp"
        data-testid="wsp-soporte"
        className="fixed bottom-5 right-5 z-[120] flex items-center gap-2 group"
      >
        <span className="hidden md:group-hover:flex bg-neutral-900 text-white text-xs font-bold px-3 py-2 rounded-lg shadow-lg whitespace-nowrap items-center">
          ¿Necesitás ayuda? Escribinos
        </span>
        <span className="w-14 h-14 rounded-full bg-[#25D366] hover:bg-[#1EBE57] shadow-[0_6px_20px_rgba(37,211,102,0.5)] flex items-center justify-center transition-colors">
          <svg viewBox="0 0 32 32" width="30" height="30" fill="#fff" aria-hidden="true">
            <path d="M16.003 0h-.006C7.163 0 .001 7.164.001 16c0 3.198.94 6.173 2.559 8.68L.94 32l7.552-1.987A15.9 15.9 0 0016 32c8.837 0 16-7.163 16-16S24.84 0 16.003 0zm9.35 22.6c-.39 1.1-1.94 2.01-3.17 2.28-.84.18-1.94.32-5.64-1.21-4.73-1.96-7.77-6.77-8.01-7.08-.23-.31-1.91-2.54-1.91-4.85 0-2.31 1.21-3.44 1.64-3.91.39-.43.86-.54 1.15-.54.29 0 .58.003.83.014.27.012.63-.1.98.75.36.87 1.22 3.01 1.33 3.23.11.22.18.48.03.79-.14.31-.21.5-.42.77-.21.27-.44.6-.63.81-.21.22-.42.46-.18.87.24.41 1.07 1.77 2.3 2.86 1.58 1.41 2.92 1.85 3.33 2.06.41.21.65.18.89-.11.24-.29 1.02-1.19 1.29-1.6.27-.41.54-.34.91-.2.37.14 2.36 1.11 2.77 1.31.41.2.68.3.78.47.1.17.1.99-.29 2.09z"/>
          </svg>
        </span>
      </a>
    </div>
  );
}
