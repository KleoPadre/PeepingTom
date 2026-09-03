import subprocess
from pathlib import Path

import pytest
from textual.widgets import DataTable, Input, Static

from wispwire.file_source import PacketQuery, PacketQueryResult
from wispwire.packet_widgets import (
    packet_row_values,
    rebuild_packet_table,
    render_packet_details,
)
from wispwire.packets import PacketDetails, PacketSummary
from wispwire.tshark import TsharkReadError, read_packet_details
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


def details_text(app: WispWireApp) -> str:
    return str(app.query_one("#details-content", Static).renderable)


def test_packet_row_values_uses_literal_text_in_narrow_mode() -> None:
    values = packet_row_values(packet(7, protocol="[bold]UDP[/bold]"), wide=False)

    assert [str(value) for value in values] == [
        "7",
        "10.0.0.1",
        "[bold]UDP[/bold]",
        "Запрос",
    ]


@pytest.mark.asyncio
async def test_rebuild_packet_table_preserves_existing_selected_row() -> None:
    app = WispWireApp((), "sample.pcapng", read_details)

    async with app.run_test():
        table = app.query_one("#packets", DataTable)
        rebuild_packet_table(table, (packet(1), packet(2)), wide=False)
        table.move_cursor(row=1)
        rebuild_packet_table(table, (packet(1), packet(2), packet(3)), wide=True)

        assert table.cursor_row == 1
        assert next(str(value) for value in table.get_row_at(1)) == "2"


def test_render_packet_details_uses_literal_text() -> None:
    details = render_packet_details(
        packet(7, info="[bold]Запрос[/bold]"),
        PacketDetails("[red]Frame 7[/red]", "0000  aa"),
    )

    assert str(details) == (
        "No.: 7\n"
        "Time: 0.000000\n"
        "Source: 10.0.0.1\n"
        "Destination: 10.0.0.2\n"
        "Protocol: DNS\n"
        "Length: 72\n"
        "Info: [bold]Запрос[/bold]\n\n"
        "Дерево протоколов:\n"
        "[red]Frame 7[/red]\n\n"
        "Hex/ASCII:\n"
        "0000  aa"
    )


@pytest.mark.asyncio
async def test_app_shows_packet_fields_and_selected_details() -> None:
    app = WispWireApp(
        (packet(number=7, protocol="UDP"),), "sample.pcapng", read_details
    )

    async with app.run_test():
        assert "UDP" in [
            str(value) for value in app.query_one("#packets", DataTable).get_row_at(0)
        ]
        assert "No.: 7" in details_text(app)


@pytest.mark.asyncio
async def test_app_shows_tree_and_hex_for_selected_packet() -> None:
    app = WispWireApp(
        (packet(7),),
        "sample.pcapng",
        lambda _: PacketDetails("Frame 7", "0000  aa"),
    )

    async with app.run_test():
        text = details_text(app)

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
        await pilot.pause()
        calls_before_selection = len(read_numbers)
        await pilot.press("down")

        assert read_numbers[calls_before_selection:] == [2]


@pytest.mark.asyncio
async def test_app_reads_initial_packet_no_more_than_once() -> None:
    read_numbers: list[int] = []

    def read_details(selected_packet: PacketSummary) -> PacketDetails:
        read_numbers.append(selected_packet.number)
        return PacketDetails(f"Frame {selected_packet.number}", "0000  aa")

    app = WispWireApp((packet(1),), "sample.pcapng", read_details)

    async with app.run_test() as pilot:
        await pilot.pause()

        assert read_numbers == [1]


@pytest.mark.asyncio
async def test_app_keeps_running_and_shows_local_details_error() -> None:
    def read_details(_: PacketSummary) -> PacketDetails:
        raise TsharkReadError("Повреждённый захват")

    app = WispWireApp((packet(1),), "sample.pcapng", read_details)

    async with app.run_test():
        assert app.is_running
        assert "Не удалось загрузить детали: Повреждённый захват" in details_text(app)


@pytest.mark.asyncio
async def test_app_keeps_running_and_shows_local_os_error() -> None:
    def read_details(_: PacketSummary) -> PacketDetails:
        raise OSError("Нет доступа к TShark")

    app = WispWireApp((packet(1),), "sample.pcapng", read_details)

    async with app.run_test():
        assert app.is_running
        assert "Не удалось загрузить детали: Нет доступа к TShark" in details_text(app)


@pytest.mark.asyncio
async def test_app_keeps_running_when_details_reader_times_out() -> None:
    def timing_out_run(
        *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(["tshark"], timeout=5)

    def read_details(_: PacketSummary) -> PacketDetails:
        return read_packet_details(
            Path("capture.pcapng"), Path("tshark"), 1, run=timing_out_run
        )

    app = WispWireApp((packet(1),), "sample.pcapng", read_details)

    async with app.run_test():
        assert app.is_running
        assert "Не удалось загрузить детали: Время ожидания" in details_text(app)


@pytest.mark.asyncio
async def test_app_moves_selection_with_down_key() -> None:
    app = WispWireApp(
        (packet(number=1), packet(number=2)), "sample.pcapng", read_details
    )

    async with app.run_test() as pilot:
        await pilot.press("down")

        assert "No.: 2" in details_text(app)


@pytest.mark.asyncio
async def test_app_shows_rich_markup_in_packet_info_literally() -> None:
    app = WispWireApp(
        (packet(number=1, info="[bold]Текст[/bold]"),), "sample.pcapng", read_details
    )

    async with app.run_test():
        table = app.query_one("#packets", DataTable)

        assert str(table.get_row_at(0)[-1]) == "[bold]Текст[/bold]"


@pytest.mark.asyncio
async def test_app_focuses_display_filter_with_f_key() -> None:
    app = WispWireApp((packet(1),), "sample.pcapng", read_details)

    async with app.run_test() as pilot:
        await pilot.press("f")

        assert app.focused is not None
        assert app.focused.id == "display-filter"


@pytest.mark.asyncio
async def test_app_updates_table_from_info_search() -> None:
    packets = (packet(1, info="telegram"), packet(2, info="example"))
    calls: list[PacketQuery] = []

    def query_packets(query: PacketQuery) -> PacketQueryResult:
        calls.append(query)
        return PacketQueryResult((packets[0],), None)

    app = WispWireApp(
        packets, "sample.pcapng", read_details, query_packets=query_packets
    )

    async with app.run_test() as pilot:
        await pilot.press("/")
        await pilot.press("t", "e", "l")
        await pilot.pause(0.25)

        table = app.query_one("#packets", DataTable)
        assert [str(value) for value in table.get_row_at(0)][-1] == "telegram"
        assert calls[-1].info_query == "tel"


@pytest.mark.asyncio
async def test_app_keeps_rows_details_filters_and_narrow_mode_after_helper_extraction() -> (
    None
):
    packets = (packet(1, info="telegram"), packet(2, info="example"))
    app = WispWireApp(
        packets,
        "sample.pcapng",
        read_details,
        query_packets=lambda _: PacketQueryResult((packets[0],), None),
    )

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("/")
        await pilot.press("t")
        await pilot.pause(0.25)
        table = app.query_one("#packets", DataTable)

        assert [str(column.label) for column in table.ordered_columns] == [
            "No.",
            "Source",
            "Protocol",
            "Info",
        ]
        assert [str(value) for value in table.get_row_at(0)] == [
            "1",
            "10.0.0.1",
            "DNS",
            "telegram",
        ]
        assert "No.: 1" in details_text(app)


@pytest.mark.asyncio
async def test_app_keeps_previous_rows_when_display_filter_has_error() -> None:
    packets = (packet(1, info="telegram"),)

    def query_packets(_query: PacketQuery) -> PacketQueryResult:
        return PacketQueryResult((), "Синтаксическая ошибка display filter")

    app = WispWireApp(
        packets, "sample.pcapng", read_details, query_packets=query_packets
    )

    async with app.run_test() as pilot:
        await pilot.press("f")
        await pilot.press("u", "d", "p", " ", "&", "&")
        await pilot.pause(0.25)

        table = app.query_one("#packets", DataTable)
        assert str(table.get_row_at(0)[-1]) == "telegram"
        assert "Синтаксическая ошибка display filter" in str(
            app.query_one("#filter-status", Static).renderable
        )


@pytest.mark.asyncio
async def test_app_escape_clears_focused_filter() -> None:
    calls: list[PacketQuery] = []
    app = WispWireApp(
        (packet(1),),
        "sample.pcapng",
        read_details,
        query_packets=lambda query: (
            calls.append(query) or PacketQueryResult((packet(1),), None)
        ),
        initial_filter="udp",
    )

    async with app.run_test() as pilot:
        await pilot.press("f")
        await pilot.press("escape")
        await pilot.pause(0.25)

        assert app.query_one("#display-filter", Input).value == ""
        assert calls[-1].display_filter == ""


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
        assert "No.: 2" in details_text(app)


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


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(120, 24), (80, 24)])
async def test_app_focuses_details_and_scrolls_to_the_end(
    size: tuple[int, int],
) -> None:
    long_tree = "\n".join(f"Протокол {number}" for number in range(80))
    long_hex = "\n".join(f"{number:04x}  aa bb cc dd" for number in range(80))
    app = WispWireApp(
        (packet(1),),
        "sample.pcapng",
        lambda _: PacketDetails(long_tree, long_hex),
    )

    async with app.run_test(size=size) as pilot:
        details = app.query_one("#details")

        assert details.can_focus
        await pilot.press("tab", "end")

        assert app.focused is details
        assert details.max_scroll_y > 0
        assert details.scroll_y == details.max_scroll_y
