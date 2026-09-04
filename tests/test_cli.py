from typer.testing import CliRunner

from wispwire.cli import app


def test_cli_shows_russian_help() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "WispWire" in result.stdout
    assert "диагностики" in result.stdout
