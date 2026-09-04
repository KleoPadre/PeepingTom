from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[1]
FORMULA = PROJECT_ROOT / "packaging/homebrew/Formula/wispwire.rb"
SMOKE_SCRIPT = PROJECT_ROOT / "scripts/smoke_homebrew_install.sh"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


def test_homebrew_formula_installs_runtime_dependencies() -> None:
    formula = FORMULA.read_text()

    assert 'depends_on "python@3.13"' in formula
    assert 'depends_on "wireshark"' in formula
    assert "virtualenv_install_with_resources" in formula
    assert "wireshark-chmodbpf" in formula
    assert (
        "0000000000000000000000000000000000000000000000000000000000000000"
        not in formula
    )
    assert 'system bin/"wispwire", "doctor"' in formula


def test_homebrew_formula_vendors_all_python_resources() -> None:
    formula = FORMULA.read_text()

    for resource in (
        "annotated-doc",
        "linkify-it-py",
        "markdown-it-py",
        "mdit-py-plugins",
        "mdurl",
        "platformdirs",
        "pygments",
        "rich",
        "shellingham",
        "textual",
        "typer",
        "typing-extensions",
    ):
        assert f'resource "{resource}" do' in formula


def test_sdist_uses_explicit_release_file_set() -> None:
    pyproject = PYPROJECT.read_text()

    assert "[tool.hatch.build.targets.sdist]" in pyproject
    assert '"src/wispwire"' in pyproject
    assert '"CHANGELOG.md"' in pyproject
    assert '"packaging"' not in pyproject


def test_homebrew_smoke_script_rewrites_formula_to_local_sdist() -> None:
    script = SMOKE_SCRIPT.read_text()

    assert "wispwire-0.1.0.tar.gz" in script
    assert "file://" in script
    assert "brew install --formula" in script
    assert "brew test" in script
