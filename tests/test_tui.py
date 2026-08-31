import pytest
from textual.widgets import DataTable, Static

from wispwire.packets import PacketSummary
from wispwire.tui import WispWireApp


def packet(number: int, protocol: str = "DNS") -> PacketSummary:
    return PacketSummary(
        number=number,
        relative_time="0.000000",
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol=protocol,
        length=72,
        info="Запрос",
    )


@pytest.mark.asyncio
async def test_app_shows_packet_fields_and_selected_details() -> None:
    app = WispWireApp((packet(number=7, protocol="UDP"),), "sample.pcapng")

    async with app.run_test():
        assert "UDP" in app.query_one("#packets", DataTable).get_row_at(0)
        assert "No.: 7" in app.query_one("#details", Static).renderable


@pytest.mark.asyncio
async def test_app_moves_selection_with_down_key() -> None:
    app = WispWireApp((packet(number=1), packet(number=2)), "sample.pcapng")

    async with app.run_test() as pilot:
        await pilot.press("down")

        assert "No.: 2" in app.query_one("#details", Static).renderable
