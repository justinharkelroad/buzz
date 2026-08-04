#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
release="$root/.github/workflows/release.yml"
proof="$root/.github/workflows/desktop-release-cache-proof.yml"
canaries=(
  "$root/.github/workflows/signed-macos-canary.yml"
  "$root/.github/workflows/macos-intel-canary.yml"
  "$root/.github/workflows/windows-canary.yml"
  "$root/.github/workflows/linux-canary.yml"
)

if grep -q 'desktop-rust-release-v1\|desktop-release-cache-key' "$release"; then
  echo "Gate 1 must not alter the release cache path" >&2
  exit 1
fi
for workflow in "${canaries[@]}"; do
  grep -q 'refs/heads/main' "$workflow"
  grep -q 'desktop-native-toolchain-id.sh' "$workflow"
  grep -q 'steps.native_toolchain.outputs.id' "$workflow"
  grep -q 'actions/cache/restore@' "$workflow"
  grep -q 'actions/cache/save@' "$workflow"
  grep -q 'steps.rust_cache.outputs.cache-hit' "$workflow"
  grep -q '!desktop/src-tauri/target/\*\*/release/bundle' "$workflow"
  if grep -q 'restore-keys:.*desktop-rust\|Swatinem/rust-cache' "$workflow"; then
    echo "release Cargo cache must use split actions with no fallback: $workflow" >&2
    exit 1
  fi
done

# GitHub expressions must enter cache-key steps through env, never by direct
# interpolation into generated shell scripts. This blocks shell injection if a
# matrix or upstream output ever becomes attacker-controlled.
python3 - "$proof" "${canaries[@]}" <<'PY'
import pathlib
import re
import sys

for filename in sys.argv[1:]:
    text = pathlib.Path(filename).read_text()
    steps = re.findall(
        r"(?ms)^      - name: Compute exact release cache key\n(.*?)(?=^      - (?:name:|uses:)|\Z)",
        text,
    )
    if not steps:
        raise SystemExit(f"cache-key step missing: {filename}")
    for step in steps:
        run = re.search(r"(?ms)^        run: \|\n(.*?)(?=^        \S|\Z)", step)
        if not run:
            raise SystemExit(f"cache-key run block missing: {filename}")
        if "${{" in run.group(1):
            raise SystemExit(f"GitHub expression interpolated into cache-key shell: {filename}")
        if "NATIVE_TOOLCHAIN_ID: ${{ steps.native_toolchain.outputs.id }}" not in step:
            raise SystemExit(f"native toolchain output not passed through env: {filename}")
PY

# Producer/proof coverage must match all four release targets and features.
for target in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu x86_64-pc-windows-msvc; do
  grep -q -- "$target" "$proof" || { echo "proof missing $target" >&2; exit 1; }
done
grep -q -- '--features mesh-llm' "$proof"
grep -q -- '--features default' "$proof"
[[ $(grep -c 'actions/cache/save@' "$proof") -eq 0 ]]
[[ $(grep -c 'Require exact cache hit' "$proof") -eq 3 ]]
grep -q 'refs/tags/cache-proof-' "$proof"

# No platform may execute tag-controlled proof code until a single read-only
# authorization job binds the tag target to the repository's current default
# branch HEAD.
ruby -E UTF-8:UTF-8 -rpsych - "$proof" <<'RUBY'
path = ARGV.fetch(0)
workflow = Psych.safe_load_file(path, aliases: false)
jobs = workflow.fetch("jobs")
expected_jobs = %w[authorize linux macos windows]
abort "cache proof job set changed without authorization review" unless jobs.keys.sort == expected_jobs

authorize = jobs.fetch("authorize")
abort "authorization must run only in block/buzz" unless authorize.fetch("if") == "github.repository == 'block/buzz'"
abort "authorization must use a short bounded timeout" unless authorize.fetch("timeout-minutes") == 5
steps = authorize.fetch("steps")
abort "authorization must be the only pre-proof operation" unless steps.length == 1
step = steps.fetch(0)
abort "authorization must read the event's default branch" unless step.fetch("env") == {
  "DEFAULT_BRANCH" => "${{ github.event.repository.default_branch }}"
}
run = step.fetch("run")
required_controls = [
  '[[ "$GITHUB_REF" == refs/tags/cache-proof-* ]]',
  'git ls-remote --exit-code --refs "$remote" "$default_ref"',
  '[[ "$resolved_ref" == "$default_ref" ]]',
  '[[ "$default_sha" =~ ^[0-9a-f]{40}$ ]]',
  '[[ "$GITHUB_SHA" == "$default_sha" ]]'
]
required_controls.each do |control|
  abort "cache proof authorization missing #{control.inspect}" unless run.include?(control)
end

%w[linux macos windows].each do |job_name|
  job = jobs.fetch(job_name)
  abort "#{job_name} proof does not require authorization" unless job.fetch("needs") == "authorize"
  abort "#{job_name} proof lost repository boundary" unless job.fetch("if") == "github.repository == 'block/buzz'"
end
RUBY

# Linux producer must match release's default linker, not the CI-only mold path.
if grep -q 'setup-mold\|ubuntu-24.04-mold' "$root/.github/workflows/linux-canary.yml"; then
  echo "Linux cache producer diverges from the release linker" >&2
  exit 1
fi
if grep -q 'setup-mold' "$release"; then
  echo "release linker changed; re-review cache equivalence" >&2
  exit 1
fi

echo "desktop release cache workflow contract passed"
