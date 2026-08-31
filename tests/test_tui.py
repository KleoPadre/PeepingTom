import pytest
from textual.widgets import DataTable, Static

from wispwire.packets import PacketSummary
from wispwire.tui import WispWireApp


def packet(number: int, protocol: str = "DNS", info: str = "Запрос") -> PacketSummary:
    return PacketSummary(
        number=number,
        relative_time="0.000000",
        source="10.0.0.1",
        destination="10.0.0.2",
        protocol=protocol,
        length=72,
        info=info,
    )


@pytest.mark.asyncio
async def test_app_shows_packet_fields_and_selected_details() -> None:
    app = WispWireApp((packet(number=7, protocol="UDP"),), "sample.pcapng")

    async with app.run_test():
        assert "UDP" in [
            str(value) for value in app.query_one("#packets", DataTable).get_row_at(0)
        ]
        assert "No.: 7" in app.query_one("#details", Static).renderable


@pytest.mark.asyncio
async def test_app_moves_selection_with_down_key() -> None:
    app = WispWireApp((packet(number=1), packet(number=2)), "sample.pcapng")

    async with app.run_test() as pilot:
        await pilot.press("down")

        assert "No.: 2" in app.query_one("#details", Static).renderable


@pytest.mark.asyncio
async def test_app_shows_rich_markup_in_packet_info_literally() -> None:
    app = WispWireApp((packet(number=1, info="[bold]Текст[/bold]"),), "sample.pcapng")

    async with app.run_test():
        table = app.query_one("#packets", DataTable)

        assert str(table.get_row_at(0)[-1]) == "[bold]Текст[/bold]"


@pytest.mark.asyncio
async def test_app_shows_minimum_size_warning_below_80x24() -> None:
    app = WispWireApp((packet(number=1),), "sample.pcapng")

    async with app.run_test(size=(79, 23)):
        assert app.query_one("#size-warning", Static).display is True


@pytest.mark.asyncio
async def test_narrow_layout_keeps_number_protocol_and_info_columns() -> None:
    app = WispWireApp((packet(number=1),), "sample.pcapng")

    async with app.run_test(size=(100, 30)):
        table = app.query_one("#packets", DataTable)

        assert [str(column.label) for column in table.ordered_columns] == [
            "No.",
            "Source",
            "Protocol",
            "Info",
        ]


@pytest.mark.asyncio
async def test_resize_keeps_selected_packet_details_and_rows() -> None:
    app = WispWireApp((packet(number=1), packet(number=2)), "sample.pcapng")

    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("down")
        await pilot.resize_terminal(100, 30)

        table = app.query_one("#packets", DataTable)

        assert table.cursor_row == 1
        assert table.row_count == 2
        assert [str(value) for value in table.get_row_at(0)] == [
            "1",
            "10.0.0.1",
            "DNS",
            "Запрос",
        ]
        assert [str(value) for value in table.get_row_at(1)] == [
            "2",
            "10.0.0.1",
            "DNS",
            "Запрос",
        ]
        assert "No.: 2" in app.query_one("#details", Static).renderable


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("size", "expected_columns"),
    [
        ((80, 24), ["No.", "Source", "Protocol", "Info"]),
        (
            (120, 24),
            ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"],
        ),
    ],
)
async def test_layout_uses_expected_columns_at_width_boundaries(
    size: tuple[int, int], expected_columns: list[str]
) -> None:
    app = WispWireApp((packet(number=1),), "sample.pcapng")

    async with app.run_test(size=size):
        table = app.query_one("#packets", DataTable)

        assert app.query_one("#size-warning", Static).display is False
        assert [
            str(column.label) for column in table.ordered_columns
        ] == expected_columns
