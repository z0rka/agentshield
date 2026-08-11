"""Private control-plane client used to obtain authorised scan configuration."""

from __future__ import annotations

import httpx

from agentshield.messaging.contracts import ScanDispatch


class ControlPlaneDispatchClient:
    def __init__(self, base_url: str, token: str, client: httpx.AsyncClient | None = None) -> None:
        if not base_url:
            raise ValueError("AGENTSHIELD_CONTROL_PLANE_URL is required for Kafka worker mode")
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"X-AgentShield-Internal-Token": token},
            timeout=30.0,
        )

    async def fetch(self, scan_id: str) -> ScanDispatch:
        response = await self._client.get(f"/internal/engine/scans/{scan_id}")
        response.raise_for_status()
        return ScanDispatch.model_validate(response.json())

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
