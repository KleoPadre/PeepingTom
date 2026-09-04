#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
version="0.1.1"
formula_source="${project_root}/packaging/homebrew/Formula/wispwire.rb"
work_dir="$(mktemp -d /tmp/wispwire-homebrew-smoke.XXXXXX)"
dist_dir="${work_dir}/dist"
sdist="${dist_dir}/wispwire-${version}.tar.gz"
tap_dir="${work_dir}/homebrew-wispwire-smoke"
formula="${tap_dir}/Formula/wispwire.rb"
tap_name="wispwire/smoke"

cleanup() {
  HOMEBREW_NO_INSTALL_CLEANUP=1 brew untap --force "${tap_name}" >/dev/null 2>&1 || true
  rm -rf "${work_dir}"
}
trap cleanup EXIT

cd "${project_root}"
SOURCE_DATE_EPOCH=1788480000 .venv/bin/python -m hatchling build -t sdist -d "${dist_dir}"

sdist_sha="$(shasum -a 256 "${sdist}" | awk '{print $1}')"
mkdir -p "$(dirname "${formula}")"
cp "${formula_source}" "${formula}"

python3 - "${formula}" "${sdist}" "${sdist_sha}" <<'PY'
import re
import sys
from pathlib import Path

formula_path = Path(sys.argv[1])
sdist_path = Path(sys.argv[2])
sdist_sha = sys.argv[3]
formula = formula_path.read_text()
formula = formula.replace(
    'url "https://github.com/KleoPadre/WispWire/releases/download/v0.1.1/wispwire-0.1.1.tar.gz"',
    f'url "file://{sdist_path}"',
)
formula = re.sub(r'sha256 "[0-9a-f]{64}"', f'sha256 "{sdist_sha}"', formula, count=1)
formula_path.write_text(formula)
PY

git -C "${tap_dir}" init --quiet
git -C "${tap_dir}" add Formula/wispwire.rb
git -C "${tap_dir}" commit --quiet -m "Add WispWire smoke formula"

HOMEBREW_NO_INSTALL_CLEANUP=1 brew untap --force "${tap_name}" >/dev/null 2>&1 || true
brew tap "${tap_name}" "${tap_dir}"
if brew list --formula wispwire >/dev/null 2>&1; then
  HOMEBREW_NO_INSTALL_CLEANUP=1 brew reinstall --build-from-source "${tap_name}/wispwire"
else
  HOMEBREW_NO_INSTALL_CLEANUP=1 brew install --formula --build-from-source "${tap_name}/wispwire"
fi
brew test "${tap_name}/wispwire"
"$(brew --prefix)/bin/wispwire" --help >/dev/null
"$(brew --prefix)/bin/wispwire" doctor

printf 'sdist=%s\n' "${sdist}"
printf 'sha256=%s\n' "${sdist_sha}"
printf 'formula=%s\n' "${formula}"
