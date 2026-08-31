import pytest
from textual.widgets import DataTable, Static

from wispwire.packets import PacketDetails, PacketSummary
from wispwire.tshark import TsharkReadError
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


def read_details(_: PacketSummary) -> PacketDetails:
    return PacketDetails("Frame", "0000  aa")


@pytest.mark.asyncio
async def test_app_shows_packet_fields_and_selected_details() -> None:
    app = WispWireApp(
        (packet(number=7, protocol="UDP"),), "sample.pcapng", read_details
    )

    async with app.run_test():
        assert "UDP" in [
            str(value) for value in app.query_one("#packets", DataTable).get_row_at(0)
        ]
        assert "No.: 7" in app.query_one("#details", Static).renderable


@pytest.mark.asyncio
async def test_app_shows_tree_and_hex_for_selected_packet() -> None:
    app = WispWireApp(
        (packet(7),),
        "sample.pcapng",
        lambda _: PacketDetails("Frame 7", "0000  aa"),
    )

    async with app.run_test():
        text = app.query_one("#details", Static).renderable

        assert "Дерево протоколов:\nFrame 7" in text
        assert "Hex/ASCII:\n0000  aa" in text


@pytest.mark.asyncio
async def test_app_loads_details_for_newly_selected_packet() -> None:
    read_numbers: list[int] = []

    def read_details(selected_packet: PacketSummary) -> PacketDetails:
        read_numbers.append(selected_packet.number)
        return PacketDetails(f"Frame {selected_packet.number}", "0000  aa")

    app = WispWireApp((packet(1), packet(2)), "sample.pcapng", read_details)

    async with app.run_test() as pilot:
        await pilot.press("down")

        assert read_numbers[-1] == 2


@pytest.mark.asyncio
async def test_app_keeps_running_and_shows_local_details_error() -> None:
    def read_details(_: PacketSummary) -> PacketDetails:
        raise TsharkReadError("Повреждённый захват")

    app = WispWireApp((packet(1),), "sample.pcapng", read_details)

    async with app.run_test():
        assert app.is_running
        assert (
            "Не удалось загрузить детали: Повреждённый захват"
            in app.query_one("#details", Static).renderable
        )


@pytest.mark.asyncio
async def test_app_moves_selection_with_down_key() -> None:
    app = WispWireApp(
        (packet(number=1), packet(number=2)), "sample.pcapng", read_details
    )

    async with app.run_test() as pilot:
        await pilot.press("down")

        assert "No.: 2" in app.query_one("#details", Static).renderable


@pytest.mark.asyncio
async def test_app_shows_rich_markup_in_packet_info_literally() -> None:
    app = WispWireApp(
        (packet(number=1, info="[bold]Текст[/bold]"),), "sample.pcapng", read_details
    )

    async with app.run_test():
        table = app.query_one("#packets", DataTable)

        assert str(table.get_row_at(0)[-1]) == "[bold]Текст[/bold]"


@pytest.mark.asyncio
async def test_app_shows_minimum_size_warning_below_80x24() -> None:
    app = WispWireApp((packet(number=1),), "sample.pcapng", read_details)

    async with app.run_test(size=(79, 23)):
        assert app.query_one("#size-warning", Static).display is True


@pytest.mark.asyncio
async def test_narrow_layout_keeps_number_protocol_and_info_columns() -> None:
    app = WispWireApp((packet(number=1),), "sample.pcapng", read_details)

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
    app = WispWireApp(
        (packet(number=1), packet(number=2)), "sample.pcapng", read_details
    )

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
    app = WispWireApp((packet(number=1),), "sample.pcapng", read_details)

    async with app.run_test(size=size):
        table = app.query_one("#packets", DataTable)

        assert app.query_one("#size-warning", Static).display is False
        assert [
            str(column.label) for column in table.ordered_columns
        ] == expected_columns
