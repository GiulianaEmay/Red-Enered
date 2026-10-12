// Una petición por PDF evita acumular todo el tiempo de OCR en una sola carga.
// Ante una respuesta incierta se detiene el lote, sin reintentar ni duplicar facturas.
export async function uploadSubsidioInvoices(files, api, onProgress) {
  const items = [];
  let completed = 0;
  for (const file of files) {
    onProgress({ current: completed + 1, total: files.length });
    const fd = new FormData();
    fd.append("files", file);
    fd.append("programa", "du007");
    try {
      const { data } = await api.post("/subsidio/invoices/upload", fd, { timeout: 300000 });
      items.push(...(data.items || []));
      completed += 1;
    } catch (error) {
      return { items, completed, failedFile: file.name, error, remaining: files.length - completed - 1 };
    }
  }
  return { items, completed };
}

export function invoiceUploadFailure(result) {
  const { error, failedFile, completed, remaining } = result;
  const status = error?.response?.status;
  const detail = error?.response?.data?.detail;
  let reason;
  if (error?.code === "ECONNABORTED" || error?.code === "ETIMEDOUT") {
    reason = "La lectura superó el tiempo de espera.";
  } else if (!error?.response) {
    reason = "Se perdió la conexión con el servidor.";
  } else if (status === 413) {
    reason = "El archivo supera el tamaño permitido.";
  } else if (status === 401) {
    reason = "Tu sesión venció. Vuelve a iniciar sesión.";
  } else if (status >= 500) {
    reason = `El servidor no pudo completar la carga (error ${status}).`;
  } else {
    reason = typeof detail === "string" ? detail : `No se pudo completar la carga${status ? ` (error ${status})` : ""}.`;
  }
  return `${completed} archivo(s) procesado(s). Se interrumpió la carga de «${failedFile}». ${reason} ` +
    (remaining ? `${remaining} archivo(s) no se enviaron. ` : "") +
    "Revisa la lista de facturas antes de volver a subir archivos: el último PDF podría haber quedado guardado.";
}
