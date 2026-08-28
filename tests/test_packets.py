import pytest

from wispwire.packets import PacketSummary


def test_packet_summary_is_immutable() -> None:
    packet = PacketSummary(
        1,
        "0.000000",
        "10.0.0.1",
        "10.0.0.2",
        "DNS",
        72,
        "Query",
    )

    with pytest.raises(AttributeError):
        packet.protocol = "UDP"  # type: ignore[misc]
