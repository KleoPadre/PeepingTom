import typer

app = typer.Typer(
    help="WispWire — терминальная утилита для диагностики сетевого анализа."
)


@app.callback()
def main() -> None:
    """Запустить WispWire."""


if __name__ == "__main__":
    app()
