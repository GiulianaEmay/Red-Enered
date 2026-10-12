"""Offline regression tests: no Google, storage or database connections."""
import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from google import genai
from google.genai import errors
from starlette.datastructures import UploadFile, Headers

from services import invoice_ocr


def api_error(code, *, retry_delay=None, retry_after=None):
    details = []
    if retry_delay is not None:
        details.append({"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": retry_delay})
    response = httpx.Response(code, headers={"Retry-After": retry_after}) if retry_after else None
    return errors.ClientError(code, {"error": {
        "message": "Synthetic provider failure",
        "status": {429: "RESOURCE_EXHAUSTED", 503: "UNAVAILABLE", 404: "NOT_FOUND"}.get(code, "UNKNOWN"),
        "details": details,
    }}, response=response)


@pytest.fixture
def provider(monkeypatch):
    clock = [100.0]
    state = SimpleNamespace(calls=[], clients=[], outcomes=[], clock=clock)
    monkeypatch.setattr(invoice_ocr, "_gemini_retry_at", 0.0)
    monkeypatch.setattr(invoice_ocr, "monotonic", lambda: clock[0])
    monkeypatch.setattr(invoice_ocr, "_a_imagen_png", lambda content, ct: (content, "image/jpeg"))
    monkeypatch.setattr(invoice_ocr, "_proveedor_vision", lambda: "gemini")
    monkeypatch.delenv("GEMINI_VISION_MODEL", raising=False)

    class FakeAsyncClient:
        def __init__(self):
            self.models = self
            self.closed = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            self.closed = True

        async def generate_content(self, **kwargs):
            state.calls.append(kwargs["model"])
            outcome = state.outcomes.pop(0) if len(state.outcomes) > 1 else state.outcomes[0]
            if isinstance(outcome, Exception):
                raise outcome
            return SimpleNamespace(text=outcome)

    def make_client(**kwargs):
        client = SimpleNamespace(aio=FakeAsyncClient(), options=kwargs["http_options"])
        state.clients.append(client)
        return client

    monkeypatch.setattr(genai, "Client", make_client)
    return state


def extract():
    return asyncio.run(invoice_ocr.extract_invoice_data(b"synthetic image", "image/jpeg", "offline-test"))


def test_429_does_not_retry_or_rotate_models(provider):
    provider.outcomes = [api_error(429)]
    result = extract()
    assert provider.calls == ["gemini-flash-latest"]
    assert result["error_code"] == "rate_limited"
    assert result["retry_after"] == 60
    assert result["extracted"]["importe_total"] is None
    assert result["extracted"]["fecha"] is None
    assert provider.clients[0].aio.closed
    assert provider.clients[0].options.retry_options.attempts == 1


def test_next_document_uses_cooldown_without_another_request(provider):
    provider.outcomes = [api_error(429)]
    extract()
    provider.clock[0] = 110
    result = extract()
    assert len(provider.calls) == 1
    assert len(provider.clients) == 1
    assert result["error_code"] == "rate_limited"
    assert result["retry_after"] == 50


@pytest.mark.parametrize("delay", ["90s", "90.5s"])
def test_provider_retry_info_is_respected(provider, delay):
    provider.outcomes = [api_error(429, retry_delay=delay)]
    result = extract()
    assert result["retry_after"] == (90 if delay == "90s" else 91)


def test_retry_after_header_is_respected(provider):
    provider.outcomes = [api_error(429, retry_after="120")]
    assert extract()["retry_after"] == 120


@pytest.mark.parametrize("delay", ["bad", "nan", "inf"])
def test_invalid_retry_info_uses_safe_default(provider, delay):
    provider.outcomes = [api_error(429, retry_delay=delay)]
    assert extract()["retry_after"] == 60


def test_reading_recovers_after_cooldown(provider):
    provider.outcomes = [api_error(429), '{"placa":"ABC123","galones":10,"importe_total":100}']
    extract()
    provider.clock[0] = 161
    result = extract()
    assert len(provider.calls) == 2
    assert result["extracted"]["placa"] == "ABC-123"
    assert result["extracted"]["galones"] == 10
    assert "error_code" not in result
    assert all(client.aio.closed for client in provider.clients)


def test_503_keeps_one_short_retry(provider, monkeypatch):
    sleep = AsyncMock()
    monkeypatch.setattr(asyncio, "sleep", sleep)
    provider.outcomes = [api_error(503), '{"importe_total":100}']
    assert extract()["extracted"]["importe_total"] == 100
    assert provider.calls == ["gemini-flash-latest", "gemini-flash-latest"]
    sleep.assert_awaited_once_with(2)


def test_retired_model_falls_back_without_cooldown(provider):
    provider.outcomes = [api_error(404), '{"importe_total":100}']
    assert extract()["extracted"]["importe_total"] == 100
    assert provider.calls == ["gemini-flash-latest", "gemini-3.6-flash"]
    assert invoice_ocr._gemini_retry_at == 0


@pytest.fixture
def upload_pipeline(monkeypatch):
    import subsidio
    from services import pdf_invoice_reader, extractor_comprobante
    inserted, saved = [], {}
    cursor = SimpleNamespace(to_list=AsyncMock(return_value=[]))

    async def insert(document):
        inserted.append(document)

    user = {"id": "offline-user", "empresa": "SYNTHETIC", "role": "cliente_subsidio", "ruc": ""}
    db = SimpleNamespace(
        consumos_subsidio=SimpleNamespace(find=lambda *args, **kwargs: cursor, insert_one=insert),
        users=SimpleNamespace(update_one=AsyncMock(), find_one=AsyncMock(return_value=user)),
        capturas_movil=SimpleNamespace(update_one=AsyncMock()),
    )
    monkeypatch.setattr(subsidio, "db", db)
    monkeypatch.setattr(subsidio, "_get_company_uids", AsyncMock(return_value=[user["id"]]))
    monkeypatch.setattr(subsidio, "_flota_categorias", AsyncMock(return_value=(set(), {})))
    monkeypatch.setattr(subsidio, "_grifo_por_ruc", AsyncMock(return_value=None))
    monkeypatch.setattr(subsidio.storage, "save_object", lambda key, data, ct: saved.update({key: data}))
    monkeypatch.setattr(pdf_invoice_reader, "extract_invoice_data",
                        AsyncMock(return_value={"extracted": {}, "raw_response": ""}))
    monkeypatch.setattr(extractor_comprobante, "extraer", lambda *args: {})
    return SimpleNamespace(module=subsidio, user=user, inserted=inserted, saved=saved)


def pdf_upload(name):
    return UploadFile(file=io.BytesIO(b"%PDF-1.4\nSynthetic PDF\n%%EOF"),
                      filename=name, headers=Headers({"content-type": "application/pdf"}))


def test_quota_failure_preserves_every_uploaded_draft(provider, upload_pipeline):
    provider.outcomes = [api_error(429)]
    result = asyncio.run(upload_pipeline.module.invoices_upload(
        files=[pdf_upload("first.pdf"), pdf_upload("second.pdf")],
        programa="du007", user=upload_pipeline.user))
    assert len(provider.calls) == 1
    assert len(upload_pipeline.saved) == 2
    assert result["uploaded"] == 2
    assert len(upload_pipeline.inserted) == 2
    assert all(doc["status"] == "draft" and doc["requiere_revision"] for doc in upload_pipeline.inserted)
    assert all(item["id"] and not item["ok"] for item in result["items"])
    assert all(item["data"]["ocr_error_code"] == "rate_limited" for item in result["items"])
    assert all(item["data"]["programa"] == "du007" for item in result["items"])


def test_mobile_photo_saved_with_actionable_quota_result(provider, upload_pipeline, monkeypatch):
    from PIL import Image
    provider.outcomes = [api_error(429)]
    module = upload_pipeline.module
    monkeypatch.setattr(module, "_captura_valida", AsyncMock(return_value={
        "user_id": upload_pipeline.user["id"], "empresa": "SYNTHETIC", "programa": "du007"}))
    monkeypatch.setattr(module, "_heredar_ruc", AsyncMock(return_value=upload_pipeline.user))
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16), "white").save(buffer, format="JPEG")
    photo = UploadFile(file=io.BytesIO(buffer.getvalue()), filename="synthetic.jpg",
                       headers=Headers({"content-type": "image/jpeg"}))
    result = asyncio.run(module.captura_fotos("offline-token", files=[photo]))
    assert result["ok"] and result["procesadas"] == 1
    item = result["items"][0]
    assert item["guardada"] and not item["ok"]
    assert item["error_code"] == "rate_limited"
    assert "revisión manual" in item["error"]
    assert len(upload_pipeline.saved) == 1
    assert next(iter(upload_pipeline.saved.values())).startswith(b"%PDF")
    module.db.capturas_movil.update_one.assert_awaited_once()


def test_pdf_text_does_not_depend_on_gemini_quota(provider, upload_pipeline, monkeypatch):
    from services import pdf_invoice_reader
    invoice_ocr._gemini_retry_at = 500
    monkeypatch.setattr(pdf_invoice_reader, "extract_invoice_data", AsyncMock(return_value={
        "extracted": {"importe_total": 100}, "raw_response": "PDF text"}))
    result = asyncio.run(upload_pipeline.module.invoices_upload(
        files=[pdf_upload("text.pdf")], programa="du007", user=upload_pipeline.user))
    assert not provider.calls
    assert result["items"][0]["ok"]
    assert result["items"][0]["data"]["importe_total"] == 100


def test_qr_data_is_preserved_when_vision_is_rate_limited(provider, upload_pipeline, monkeypatch):
    from services import extractor_comprobante
    provider.outcomes = [api_error(429)]
    monkeypatch.setattr(extractor_comprobante, "extraer", lambda *args: {
        "extraccion_ok": True, "numero_documento": "F001-000001",
        "importe_total": 100, "fecha": "2026-10-01",
    })
    result = asyncio.run(upload_pipeline.module.invoices_upload(
        files=[pdf_upload("qr.pdf")], programa="du007", user=upload_pipeline.user))
    item = result["items"][0]
    assert item["data"]["numero_documento"] == "F001-000001"
    assert item["data"]["importe_total"] == 100
    assert item["id"]
    assert len(upload_pipeline.saved) == 1
