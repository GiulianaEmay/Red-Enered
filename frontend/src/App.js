import React from "react";
import "@/index.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "sonner";
import { AuthProvider } from "./context/AuthContext";
import { startKeepAlive } from "./lib/api";
import ProtectedRoute from "./components/ProtectedRoute";
import Layout from "./components/Layout";
import SubsidioGate from "./components/SubsidioGate";
import Login from "./pages/Login";
import ForgotPassword from "./pages/ForgotPassword";
import Dashboard from "./pages/Dashboard";
import DashboardSubsidioView from "./pages/DashboardSubsidioView";
import ErrorBoundary from "./components/ErrorBoundary";
import Reportes from "./pages/Reportes";
import Facturacion from "./pages/Facturacion";
import EstadoCuentaHistorial from "./pages/EstadoCuentaHistorial";
import Seguridad from "./pages/Seguridad";
import ControlIntegral from "./pages/ControlIntegral";
import Calendario from "./pages/Calendario";
import Tickets from "./pages/Tickets";
import Checklist from "./pages/Checklist";
import Viajes from "./pages/Viajes";
import Capacitacion from "./pages/Capacitacion";
import Soporte from "./pages/Soporte";
import GestionGastos from "./pages/GestionGastos";
// Analytics BI submódulos
import AnalyticsIndex from "./pages/analytics/index";
import AnalyticsCombustible from "./pages/analytics/Combustible";
import AnalyticsEcodriving from "./pages/analytics/Ecodriving";
import AnalyticsEmisionesCO2 from "./pages/analytics/EmisionesCO2";
import AnalyticsMantenimiento from "./pages/analytics/Mantenimiento";
import AnalyticsNeumaticos from "./pages/analytics/Neumaticos";
import AnalyticsSeguridadVial from "./pages/analytics/SeguridadVial";
import AnalyticsChecklist from "./pages/analytics/Checklist";
import Monitoreo from "./pages/Monitoreo";
import ConsultaMTC from "./pages/ConsultaMTC";
import DiagnosticoATU from "./pages/DiagnosticoATU";
import PadronATU from "./pages/PadronATU";
import AdminConexionATU from "./pages/AdminConexionATU";
import SubsidioPublico from "./pages/SubsidioPublico";
import PreciosPublico from "./pages/PreciosPublico";
import AdminSire from "./pages/AdminSire";
import SubsidioDU007 from "./pages/SubsidioDU007";
import SubsidioDiagnostico from "./pages/SubsidioDiagnostico";
import TestingVerificacion from "./pages/TestingVerificacion";
import AdminUsers from "./pages/AdminUsers";
import AdminUpload from "./pages/AdminUpload";
import AdminQRUpload from "./pages/AdminQRUpload";
import AdminEmpresas from "./pages/AdminEmpresas";
import AdminTesoreria from "./pages/AdminTesoreria";
import Flotas from "./pages/Flotas";
import Documentacion from "./pages/Documentacion";
import Mantenimiento from "./pages/Mantenimiento";
import Neumaticos from "./pages/Neumaticos";
import Infracciones from "./pages/Infracciones";
import Vehiculos from "./pages/Vehiculos";
import RegistroSubsidio from "./pages/RegistroSubsidio";
import SubsidioDU004Finalizado from "./pages/SubsidioDU004Finalizado";
import SubsidioVerificar from "./pages/SubsidioVerificar";
import SubsidioFinalizado from "./pages/SubsidioFinalizado";
import SubsidioAdmin from "./pages/SubsidioAdmin";
import Bitacora from "./pages/Bitacora";
import ConductorApp from "./pages/ConductorApp";
import Privacidad from "./pages/Privacidad";
import CapturaMovil from "./pages/CapturaMovil";
import { useAuth } from "./context/AuthContext";
import ConstanciaModal from "./components/ConstanciaModal";
import FirmaObligatoriaModal from "./components/FirmaObligatoriaModal";
import ActualizadorVersion from "./components/ActualizadorVersion";

function Shell({ children, roles }) {
  return (
    <ProtectedRoute roles={roles}>
      <Layout>{children}</Layout>
    </ProtectedRoute>
  );
}

/** Envuelve una página dentro de Layout y la "gatea" para cliente_subsidio si no tiene expediente. */
function Gated({ children, titulo, roles }) {
  return (
    <ProtectedRoute roles={roles}>
      <Layout>
        <SubsidioGate titulo={titulo}>{children}</SubsidioGate>
      </Layout>
    </ProtectedRoute>
  );
}

/** Render distinto del Dashboard según rol y servicios. */
function DashboardRouter() {
  const { user } = useAuth();
  const s = user?.servicios || {};
  // cliente_subsidio SIN plataforma/combustible/gps → su vista principal es el Panel Subsidio.
  // Al activarle "plataforma" (o combustible/gps) pasa al Dashboard general, que ya incluye el
  // tracker del trámite (TrackerSubsidio) como encabezado.
  if (user?.role === "cliente_subsidio" && !s.plataforma && !s.combustible && !s.gps) {
    return <DashboardSubsidioView />;
  }
  return <Dashboard />;
}

/** Redirección raíz: cliente de subsidio → DU-007; el resto → Dashboard. */
function RootRedirect() {
  const { user } = useAuth();
  if (user?.role === "cliente_subsidio" || user?.tipo_cliente === "subsidio") {
    return <Navigate to="/subsidio/du007" replace />;
  }
  return <Navigate to="/dashboard" replace />;
}

/** Dashboard route: gateado para todos excepto cliente_subsidio (su dashboard es su vista principal). */
function DashboardRoute() {
  return (
    <Gated titulo="Dashboard">
      <DashboardRouter />
    </Gated>
  );
}

function App() {
  React.useEffect(() => { startKeepAlive(); }, []);
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster richColors position="top-right" />
        <ConstanciaModal />
        <FirmaObligatoriaModal />
        <ActualizadorVersion />
        <ErrorBoundary>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/registro-subsidio" element={<RegistroSubsidio />} />
          <Route path="/subsidio" element={<SubsidioPublico />} />
          <Route path="/precios" element={<PreciosPublico />} />
          {/* App del conductor (celular): entra solo con DNI, sin sidebar */}
          <Route path="/conductor" element={<ConductorApp />} />
          {/* Subsidio: páginas DENTRO del Shell (sidebar visible) y NO gateadas */}
          <Route path="/subsidio/diagnostico" element={<Shell roles={["admin_enered", "cliente_subsidio", "administrador", "logistica", "contabilidad"]}><SubsidioDiagnostico /></Shell>} />
          <Route path="/testing" element={<Shell roles={["admin_enered", "cliente_subsidio", "administrador", "logistica", "contabilidad"]}><TestingVerificacion /></Shell>} />
          <Route path="/subsidio/documentos" element={<Shell roles={["admin_enered", "cliente_subsidio", "administrador", "logistica", "contabilidad"]}><SubsidioDU004Finalizado /></Shell>} />
          <Route path="/subsidio/du007" element={<Shell roles={["admin_enered", "cliente_subsidio", "administrador", "logistica", "contabilidad"]}><SubsidioDU007 /></Shell>} />
          <Route path="/dashboard-subsidio" element={<Shell roles={["admin_enered", "cliente_subsidio", "administrador", "logistica", "contabilidad"]}><DashboardSubsidioView /></Shell>} />          <Route path="/subsidio/verificar" element={<Shell roles={["cliente_subsidio"]}><SubsidioVerificar /></Shell>} />
          <Route path="/subsidio/finalizado" element={<ProtectedRoute roles={["cliente_subsidio"]}><SubsidioFinalizado /></ProtectedRoute>} />
          <Route path="/" element={<RootRedirect />} />
          {/* Dashboard: router por rol; gateado para subsidio */}
          <Route path="/dashboard" element={<DashboardRoute />} />
          <Route path="/flotas" element={<Gated titulo="Combustible"><Flotas /></Gated>} />
          <Route path="/reportes" element={<Navigate to="/flotas" replace />} />
          <Route path="/reportes-consumo" element={<Navigate to="/flotas" replace />} />
          <Route path="/qr" element={<Navigate to="/flotas" replace />} />
          {/* Analytics BI - submódulos */}
          <Route path="/analitica" element={<Gated titulo="Analytics BI"><AnalyticsIndex /></Gated>} />
          <Route path="/analitica/combustible" element={<Gated titulo="Analytics BI"><AnalyticsCombustible /></Gated>} />
          <Route path="/analitica/ecodriving" element={<Gated titulo="Analytics BI"><AnalyticsEcodriving /></Gated>} />
          <Route path="/analitica/emisiones" element={<Gated titulo="Analytics BI"><AnalyticsEmisionesCO2 /></Gated>} />
          <Route path="/analitica/mantenimiento" element={<Gated titulo="Analytics BI"><AnalyticsMantenimiento /></Gated>} />
          <Route path="/analitica/neumaticos" element={<Gated titulo="Analytics BI"><AnalyticsNeumaticos /></Gated>} />
          <Route path="/analitica/seguridad" element={<Gated titulo="Analytics BI"><AnalyticsSeguridadVial /></Gated>} />
          <Route path="/analitica/checklist" element={<Gated titulo="Analytics BI"><AnalyticsChecklist /></Gated>} />
          <Route path="/facturacion" element={<Gated titulo="Cuenta" roles={["admin_enered", "administrador", "contabilidad", "cliente_subsidio"]}><Facturacion /></Gated>} />
          <Route path="/facturacion/historial" element={<Gated titulo="Cuenta" roles={["admin_enered", "administrador", "contabilidad", "cliente_subsidio"]}><EstadoCuentaHistorial /></Gated>} />
          <Route path="/control" element={<Navigate to="/flotas" replace />} />
          <Route path="/seguridad" element={<Gated titulo="Seguridad"><Seguridad /></Gated>} />
          <Route path="/monitoreo" element={<Gated titulo="Monitoreo"><Monitoreo /></Gated>} />
          <Route path="/mtc" element={<Gated titulo="Consulta MTC" roles={["admin_enered"]}><ConsultaMTC /></Gated>} />
          <Route path="/atu" element={<Gated titulo="Diagnóstico ATU" roles={["admin_enered"]}><DiagnosticoATU /></Gated>} />
          <Route path="/capacitacion" element={<Gated titulo="Capacitación"><Capacitacion /></Gated>} />
          <Route path="/documentacion" element={<Gated titulo="Documentación"><Documentacion /></Gated>} />
          <Route path="/mantenimiento" element={<Gated titulo="Mantenimiento"><Mantenimiento /></Gated>} />
          <Route path="/neumaticos" element={<Gated titulo="Neumáticos"><Neumaticos /></Gated>} />
          <Route path="/calendario" element={<Gated titulo="Calendario"><Calendario /></Gated>} />
          <Route path="/tickets" element={<Gated titulo="Tickets"><Tickets /></Gated>} />
          <Route path="/checklist" element={<Gated titulo="Checklist"><Checklist /></Gated>} />
          <Route path="/viajes" element={<Gated titulo="Viajes"><Viajes /></Gated>} />
          <Route path="/infracciones" element={<Gated titulo="Infracciones"><Infracciones /></Gated>} />
          <Route path="/vehiculos" element={<Gated titulo="Vehículos"><Vehiculos /></Gated>} />
          <Route path="/gestion-gastos" element={<Gated titulo="Gestión Gastos"><GestionGastos /></Gated>} />
          <Route path="/soporte" element={<Gated titulo="Soporte"><Soporte /></Gated>} />
          <Route path="/admin/users" element={<Shell roles={["admin_enered"]}><AdminUsers /></Shell>} />
          <Route path="/admin/upload" element={<Shell roles={["admin_enered"]}><AdminUpload /></Shell>} />
          <Route path="/admin/qr" element={<Shell roles={["admin_enered"]}><AdminQRUpload /></Shell>} />
          <Route path="/admin/tesoreria" element={<Shell roles={["admin_enered", "contabilidad", "administrador"]}><AdminTesoreria /></Shell>} />
          <Route path="/admin/empresas" element={<Shell roles={["admin_enered"]}><AdminEmpresas /></Shell>} />
          <Route path="/admin/subsidio" element={<Shell roles={["admin_enered"]}><SubsidioAdmin /></Shell>} />
          <Route path="/admin/subsidio-du007" element={<Shell roles={["admin_enered"]}><SubsidioAdmin programa="du007" /></Shell>} />
          <Route path="/admin/bitacora" element={<Shell roles={["admin_enered"]}><Bitacora /></Shell>} />
          <Route path="/admin/atu" element={<Shell roles={["admin_enered"]}><AdminConexionATU /></Shell>} />
          <Route path="/admin/atu-padron" element={<Shell roles={["admin_enered"]}><PadronATU /></Shell>} />
          <Route path="/admin/sire" element={<Shell roles={["admin_enered"]}><AdminSire /></Shell>} />
          <Route path="/privacidad" element={<Privacidad />} />
          <Route path="/captura/:token" element={<CapturaMovil />} />
          <Route path="*" element={<RootRedirect />} />
        </Routes>
        </ErrorBoundary>
      </BrowserRouter>
    </AuthProvider>
  );
}
 
export default App;
