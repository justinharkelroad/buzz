#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
receipt="$repo_root/deploy/personal-relay/staging-deployment-receipt.example.json"
hash_helper="$repo_root/deploy/personal-relay/canonical-json-sha256.sh"
desktop_workflow="$repo_root/.github/workflows/personal-desktop-release.yml"
gate1_workflow="$repo_root/.github/workflows/personal-relay-gate1.yml"
gate1_receipt="$repo_root/deploy/personal-relay/gate1-receipt.sh"
gate1_receipt_test="$repo_root/deploy/personal-relay/gate1-receipt-test.sh"
gate1_schema="$repo_root/deploy/personal-relay/gate1-finding-dispositions.schema.json"
artifact_downloader="$repo_root/deploy/personal-relay/download-exact-artifact.sh"
artifact_downloader_test="$repo_root/deploy/personal-relay/download-exact-artifact-test.sh"
main_protection_validator="$repo_root/deploy/personal-relay/validate-main-protection.sh"
main_protection_validator_test="$repo_root/deploy/personal-relay/validate-main-protection-test.sh"
desktop_volume_validator="$repo_root/deploy/personal-relay/verify-desktop-dmg-volume.sh"
desktop_audit_validator="$repo_root/deploy/personal-relay/validate-desktop-attestation-audit.sh"
desktop_audit_validator_test="$repo_root/deploy/personal-relay/validate-desktop-attestation-audit-test.sh"
desktop_multi_user_acceptance_example="$repo_root/deploy/personal-relay/desktop-multi-user-acceptance.example.json"
desktop_multi_user_acceptance_validator="$repo_root/deploy/personal-relay/validate-desktop-multi-user-acceptance.sh"
desktop_multi_user_acceptance_test="$repo_root/deploy/personal-relay/validate-desktop-multi-user-acceptance-test.sh"
bundle_script="$repo_root/scripts/bundle-sidecars.sh"
tauri_config="$repo_root/desktop/src-tauri/tauri.conf.json"
release_runbook="$repo_root/docs/personal-relay-release.md"
deploy_runbook="$repo_root/deploy/personal-relay/README.md"
relay_env_example="$repo_root/deploy/personal-relay/env.example"
relay_workflow="$repo_root/.github/workflows/personal-relay-image.yml"
docker_workflow="$repo_root/.github/workflows/docker.yml"
sprig_workflow="$repo_root/.github/workflows/sprig-image.yml"
relay_dockerfile="$repo_root/Dockerfile"
relay_entrypoint="$repo_root/deploy/personal-relay/git-volume-entrypoint.sh"
relay_migrate="$repo_root/deploy/personal-relay/migrate.sh"
relay_runtime_contract="$repo_root/deploy/personal-relay/runtime-contract-test.sh"
relay_smoke_test="$repo_root/deploy/personal-relay/smoke-test.sh"
relay_config="$repo_root/crates/buzz-relay/src/config.rs"
relay_router="$repo_root/crates/buzz-relay/src/router.rs"
web_index="$repo_root/web/index.html"
web_invite_page="$repo_root/web/src/features/invite/ui/InvitePage.tsx"
web_connect_button="$repo_root/web/src/features/repos/ui/ConnectButton.tsx"
web_desktop_deep_link="$repo_root/web/src/shared/lib/desktop-deep-link.ts"
trivy_policy_test="$repo_root/deploy/personal-relay/trivy-report-policy-test.sh"
provider_src="$repo_root/crates/buzz-backend-kubernetes/src"
provider_config="$provider_src/config.rs"

validate_workflow_yaml() {
  local workflow=$1
  ruby -E UTF-8:UTF-8 -rpsych - "$workflow" <<'RUBY'
path = ARGV.fetch(0)

def reject(path, node, message)
  line = node.respond_to?(:start_line) ? node.start_line + 1 : 1
  warn "#{message}: #{path}:#{line}"
  exit 1
end

def walk(path, node)
  if node.respond_to?(:anchor) && node.anchor
    reject(path, node, "workflow YAML anchors are unsupported")
  end

  case node
  when Psych::Nodes::Mapping
    seen = {}
    node.children.each_slice(2) do |key, value|
      unless key.is_a?(Psych::Nodes::Scalar)
        reject(path, key, "workflow mapping keys must be scalar")
      end
      unless key.tag.nil? || key.tag == "tag:yaml.org,2002:str"
        reject(path, key, "workflow mapping keys must be untagged strings")
      end
      if seen.key?(key.value)
        reject(path, key, "duplicate workflow mapping key #{key.value.inspect}")
      end
      seen[key.value] = key.start_line + 1
      walk(path, value)
    end
  when Psych::Nodes::Alias
    reject(path, node, "workflow YAML aliases are unsupported")
  when Psych::Nodes::Stream, Psych::Nodes::Document, Psych::Nodes::Sequence
    node.children.each { |child| walk(path, child) }
  end
end

begin
  walk(path, Psych.parse_file(path))
rescue Psych::SyntaxError => e
  warn "invalid workflow YAML: #{path}:#{e.line}: #{e.problem}"
  exit 1
end
RUBY
}

validate_workflow_action_references() {
  ruby -E UTF-8:UTF-8 -rpsych - "$@" <<'RUBY'
class ActionReferenceContractError < StandardError; end

def require_action_reference(condition, message)
  raise ActionReferenceContractError, message unless condition
end

def collect_action_references(node, location = [], references = [])
  case node
  when Hash
    node.each do |key, value|
      references << [location + [key], value] if key == "uses"
      collect_action_references(value, location + [key], references)
    end
  when Array
    node.each_with_index do |value, index|
      collect_action_references(value, location + [index], references)
    end
  end
  references
end

def validate_action_references!(workflow, label)
  references = collect_action_references(workflow)
  require_action_reference(!references.empty?, "workflow has no action references: #{label}")
  references.each do |location, value|
    require_action_reference(value.is_a?(String), "non-scalar uses value at #{label}:#{location.join('.')}")
    require_action_reference(
      !value.start_with?("./", "docker://"),
      "local or Docker action is forbidden at #{label}:#{location.join('.')}"
    )
    require_action_reference(
      value.match?(/\A[^\s@]+\/[^\s@]+@[0-9a-f]{40}\z/),
      "action is not pinned by a full commit SHA at #{label}:#{location.join('.')}: #{value.inspect}"
    )
  end
end

ARGV.each do |path|
  validate_action_references!(Psych.safe_load_file(path, aliases: false), path)
end

valid_fixture = Psych.safe_load(<<~YAML, aliases: false)
  jobs:
    test:
      steps:
        - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
YAML
validate_action_references!(valid_fixture, "valid fixture")

hostile_fixtures = {
  "flow-map action" => <<~YAML,
    jobs:
      test:
        steps:
          - {uses: attacker/action@main}
  YAML
  "folded action" => <<~YAML,
    jobs:
      test:
        steps:
          - uses: >-
              attacker/action@main
  YAML
  "quoted local action" => <<~YAML
    jobs:
      test:
        steps:
          - "uses": "./candidate-action"
  YAML
}

hostile_fixtures.each do |label, yaml|
  begin
    validate_action_references!(Psych.safe_load(yaml, aliases: false), label)
  rescue ActionReferenceContractError
    next
  end
  raise ActionReferenceContractError, "hostile action-reference fixture was accepted: #{label}"
end
RUBY
}

validate_workflow_permissions() {
  ruby -E UTF-8:UTF-8 -rpsych - "$relay_workflow" "$gate1_workflow" "$desktop_workflow" <<'RUBY'
relay, gate1, desktop = ARGV
expected = {
  relay => {
    "prepare" => {"contents" => "read"},
    "release-approval" => {"actions" => "read", "contents" => "read"},
    "build-check" => {"contents" => "read"},
    "release-gate" => {"actions" => "read", "contents" => "read", "packages" => "read"},
    "build-publish" => {"actions" => "read", "contents" => "read", "packages" => "write"},
    "runtime-validation" => {"actions" => "read", "contents" => "read", "packages" => "read"},
    "scan" => {"contents" => "read", "packages" => "read"},
    "publish" => {
      "actions" => "read", "attestations" => "write", "contents" => "read",
      "id-token" => "write", "packages" => "write"
    }
  },
  gate1 => {
    "contract" => {"contents" => "read"},
    "source-tests" => {"contents" => "read"},
    "source-proof" => {"actions" => "read", "contents" => "read"},
    "image-validation" => {"attestations" => "read", "contents" => "read", "packages" => "read"},
    "validate" => {"actions" => "read", "contents" => "read"},
    "attest" => {
      "actions" => "read", "attestations" => "write",
      "contents" => "read", "id-token" => "write", "packages" => "read"
    }
  },
  desktop => {
    "build" => {"actions" => "read", "contents" => "read", "packages" => "read"},
    "inspect" => {"actions" => "read", "contents" => "read", "packages" => "read"},
    "remount" => {"actions" => "read", "contents" => "read"},
    "attest" => {
      "actions" => "read", "attestations" => "write", "contents" => "read",
      "id-token" => "write", "packages" => "read"
    },
    "audit" => {"actions" => "read", "attestations" => "read", "contents" => "read"}
  }
}

expected.each do |path, expected_jobs|
  workflow = Psych.safe_load_file(path, aliases: false)
  abort "workflow must deny permissions by default: #{path}" unless workflow["permissions"] == {}
  jobs = workflow.fetch("jobs")
  abort "workflow job set changed without a permissions review: #{path}" unless jobs.keys.sort == expected_jobs.keys.sort
  expected_jobs.each do |job_name, permissions|
    actual = jobs.fetch(job_name).fetch("permissions")
    abort "unexpected permission map for #{path} job #{job_name}: #{actual.inspect}" unless actual == permissions
  end
end
RUBY
}

validate_pr_image_workflow_permissions() {
  ruby -E UTF-8:UTF-8 -rpsych - "$docker_workflow" "$sprig_workflow" <<'RUBY'
docker_path, sprig_path = ARGV
checkout_action = "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"
setup_buildx_action = "docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5"
build_action = "docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf"
trusted_event_guards = {
  docker_path => "github.repository == 'block/buzz' && (github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && github.ref_type == 'tag'))",
  sprig_path => "github.repository == 'block/buzz' && (github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'))"
}
pull_request_guard = "github.event_name == 'pull_request' && github.event.pull_request.draft == false"
pull_request_types = %w[opened synchronize reopened ready_for_review]
matrix = {
  "fail-fast" => false,
  "matrix" => {
    "include" => [
      {"platform" => "linux/amd64", "runner" => "ubuntu-24.04", "arch" => "amd64"},
      {"platform" => "linux/arm64", "runner" => "ubuntu-24.04-arm", "arch" => "arm64"}
    ]
  }
}
docker_merge_matrix = {
  "fail-fast" => false,
  "matrix" => {
    "include" => [
      {"variant" => "release", "tag_prefix" => ""},
      {"variant" => "debug", "tag_prefix" => "debug-"}
    ]
  }
}
buildkit_config = "[worker.oci]\n  max-parallelism = 2\n"

checkout_step = lambda do |fetch_depth|
  inputs = {"persist-credentials" => false}
  inputs = {"fetch-depth" => fetch_depth}.merge(inputs) unless fetch_depth.nil?
  {"name" => "Checkout", "uses" => checkout_action, "with" => inputs}
end
setup_step = {
  "name" => "Set up Docker Buildx",
  "uses" => setup_buildx_action,
  "with" => {"buildkitd-config-inline" => buildkit_config}
}
build_step = lambda do |name:, file:, outputs:, cache_from:, target: nil|
  inputs = {"context" => ".", "file" => file}
  inputs["target"] = target unless target.nil?
  inputs.merge!({
    "platforms" => "${{ matrix.platform }}",
    "outputs" => outputs,
    "cache-from" => cache_from
  })
  {"name" => name, "uses" => build_action, "with" => inputs}
end

docker_output = "type=image,name=${{ env.IMAGE_NAME }},push-by-digest=true,name-canonical=true,push=false"
gateway_output = "type=image,name=ghcr.io/block/buzz-push-gateway,push-by-digest=true,name-canonical=true,push=false"

expected_pr_jobs = {
  [docker_path, "build-pr"] => {
    "name" => "Build-only check (${{ matrix.platform }})",
    "if" => pull_request_guard,
    "runs-on" => "${{ matrix.runner }}",
    "timeout-minutes" => 60,
    "permissions" => {"contents" => "read"},
    "strategy" => matrix,
    "steps" => [
      checkout_step.call(0),
      setup_step,
      build_step.call(
        name: "Build release image without registry credentials",
        file: "./Dockerfile",
        target: "runtime",
        outputs: docker_output,
        cache_from: "type=registry,ref=${{ env.IMAGE_NAME }}-buildcache:${{ matrix.arch }}\n"
      ),
      build_step.call(
        name: "Build debug image without registry credentials",
        file: "./Dockerfile",
        target: "runtime-debug",
        outputs: docker_output,
        cache_from: "type=registry,ref=${{ env.IMAGE_NAME }}-buildcache:${{ matrix.arch }}\n"
      )
    ]
  },
  [docker_path, "push-gateway-build-pr"] => {
    "name" => "Build-only public push gateway (${{ matrix.platform }})",
    "if" => pull_request_guard,
    "runs-on" => "${{ matrix.runner }}",
    "timeout-minutes" => 60,
    "permissions" => {"contents" => "read"},
    "strategy" => matrix,
    "steps" => [
      checkout_step.call(0),
      setup_step,
      build_step.call(
        name: "Build without registry credentials",
        file: "./Dockerfile.push-gateway",
        outputs: gateway_output,
        cache_from: "type=registry,ref=ghcr.io/block/buzz-push-gateway-buildcache:${{ matrix.arch }}"
      )
    ]
  },
  [sprig_path, "build-pr"] => {
    "name" => "Build-only check (${{ matrix.platform }})",
    "if" => pull_request_guard,
    "runs-on" => "${{ matrix.runner }}",
    "timeout-minutes" => 60,
    "permissions" => {"contents" => "read"},
    "strategy" => matrix,
    "steps" => [
      checkout_step.call(nil),
      setup_step,
      build_step.call(
        name: "Build without registry credentials",
        file: "./Dockerfile.sprig",
        outputs: docker_output,
        cache_from: "type=registry,ref=${{ env.IMAGE_NAME }}-buildcache:${{ matrix.arch }}\n"
      )
    ]
  }
}

docker_paths = [
  "Dockerfile", "Dockerfile.push-gateway", ".dockerignore",
  ".github/workflows/docker.yml", "Cargo.toml", "Cargo.lock",
  "rust-toolchain.toml", "crates/**", "migrations/**", "admin-web/**",
  "web/**", "package.json",
  "pnpm-lock.yaml", "pnpm-workspace.yaml", "patches/**"
]
sprig_paths = [
  "Dockerfile.sprig", "scripts/sprig-entrypoint.sh",
  ".github/workflows/sprig-image.yml", "Cargo.toml", "Cargo.lock",
  "rust-toolchain.toml", "crates/**"
]

expected_triggers = {
  docker_path => {
    "push" => {"branches" => ["main"], "tags" => ["relay-v[0-9]*"]},
    "pull_request" => {"types" => pull_request_types, "paths" => docker_paths}
  },
  sprig_path => {
    "push" => {
      "branches" => ["main"], "tags" => ["sprig-v[0-9]*"],
      "paths" => sprig_paths
    },
    "pull_request" => {"types" => pull_request_types, "paths" => sprig_paths},
    "workflow_dispatch" => {}
  }
}

expected_root_env = {
  docker_path => {
    "IMAGE_NAME" => "${{ vars.GHCR_IMAGE != '' && vars.GHCR_IMAGE || 'ghcr.io/block/buzz' }}"
  },
  sprig_path => {
    "IMAGE_NAME" => "${{ vars.GHCR_SPRIG_IMAGE != '' && vars.GHCR_SPRIG_IMAGE || 'ghcr.io/block/buzz-sprig' }}"
  }
}

expected_permissions = {
  docker_path => {
    "build-pr" => {"contents" => "read"},
    "build" => {"contents" => "read", "packages" => "write"},
    "merge" => {
      "attestations" => "write", "contents" => "read",
      "id-token" => "write", "packages" => "write"
    },
    "push-gateway-build-pr" => {"contents" => "read"},
    "push-gateway-build" => {"contents" => "read", "packages" => "write"},
    "push-gateway-merge" => {
      "attestations" => "write", "contents" => "read",
      "id-token" => "write", "packages" => "write"
    }
  },
  sprig_path => {
    "build-pr" => {"contents" => "read"},
    "build" => {"contents" => "read", "packages" => "write"},
    "merge" => {
      "attestations" => "write", "contents" => "read",
      "id-token" => "write", "packages" => "write"
    }
  }
}

expected_trusted_needs = {
  [docker_path, "merge"] => "build",
  [docker_path, "push-gateway-merge"] => "push-gateway-build",
  [sprig_path, "merge"] => "build"
}

docker_release_verifier_step = {
  "name" => "Verify tag-bound release source",
  "if" => "github.ref_type == 'tag' || github.event_name == 'workflow_dispatch'",
  "env" => {"INPUT_VERSION" => "${{ inputs.version }}"},
  "run" => "VERSION=\"${INPUT_VERSION:-${GITHUB_REF_NAME#relay-v}}\"\nscripts/verify-release-ref.sh relay-v \"$VERSION\"\n"
}
expected_trusted_prefixes = {
  [docker_path, "build"] => [checkout_step.call(0), docker_release_verifier_step],
  [docker_path, "push-gateway-build"] => [checkout_step.call(0), docker_release_verifier_step]
}
expected_trusted_execution = {
  [docker_path, "build"] => {"runs-on" => "${{ matrix.runner }}", "strategy" => matrix},
  [docker_path, "merge"] => {"runs-on" => "ubuntu-24.04", "strategy" => docker_merge_matrix},
  [docker_path, "push-gateway-build"] => {"runs-on" => "${{ matrix.runner }}", "strategy" => matrix},
  [docker_path, "push-gateway-merge"] => {"runs-on" => "ubuntu-24.04"},
  [sprig_path, "build"] => {"runs-on" => "${{ matrix.runner }}", "strategy" => matrix},
  [sprig_path, "merge"] => {"runs-on" => "ubuntu-24.04"}
}

class ImageWorkflowContractError < StandardError; end

def require_image_contract(condition, message)
  raise ImageWorkflowContractError, message unless condition
end

def validate_image_workflow!(path:, workflow:, permission_map:, trusted_guard:, trusted_needs:,
                             expected_trigger:, expected_env:, expected_pr_jobs:, trusted_prefixes:,
                             trusted_execution:)
  require_image_contract(
    workflow.keys.sort_by(&:to_s) == ["name", true, "concurrency", "permissions", "env", "jobs"].sort_by(&:to_s),
    "image workflow root key set drifted: #{path}"
  )
  require_image_contract(workflow["permissions"] == {}, "image workflow must deny permissions by default: #{path}")
  require_image_contract(workflow["env"] == expected_env, "image workflow root environment drifted: #{path}")

  triggers = workflow[true] || workflow["on"]
  require_image_contract(triggers.is_a?(Hash), "image workflow trigger map is missing: #{path}")
  require_image_contract(
    triggers.keys.sort == %w[pull_request push workflow_dispatch],
    "image workflow trigger set drifted: #{path}"
  )
  require_image_contract(triggers["push"] == expected_trigger.fetch("push"), "image workflow push trigger drifted: #{path}")
  require_image_contract(
    triggers["pull_request"] == expected_trigger.fetch("pull_request"),
    "image workflow pull-request trigger drifted: #{path}"
  )
  if expected_trigger.key?("workflow_dispatch")
    require_image_contract(
      triggers["workflow_dispatch"] == expected_trigger.fetch("workflow_dispatch"),
      "image workflow dispatch trigger drifted: #{path}"
    )
  else
    dispatch = triggers["workflow_dispatch"]
    require_image_contract(dispatch.is_a?(Hash) && dispatch.keys == ["inputs"], "Docker dispatch contract drifted: #{path}")
    inputs = dispatch.fetch("inputs")
    require_image_contract(inputs.keys == ["version"], "Docker dispatch input set drifted: #{path}")
    version = inputs.fetch("version")
    require_image_contract(
      version.keys.sort == %w[description required] && version["required"] == true &&
        version["description"].is_a?(String) && !version["description"].empty?,
      "Docker dispatch version input drifted: #{path}"
    )
  end

  jobs = workflow.fetch("jobs")
  require_image_contract(
    jobs.keys.sort == permission_map.keys.sort,
    "image workflow job set changed without a permission review: #{path}"
  )
  privileged_job_names = permission_map.keys.reject { |job_name| job_name.end_with?("-pr") }
  require_image_contract(
    trusted_execution.keys.sort == privileged_job_names.sort,
    "privileged image job execution-context review is incomplete: #{path}"
  )

  permission_map.each do |job_name, permissions|
    job = jobs.fetch(job_name)
    actual = job.fetch("permissions")
    require_image_contract(
      actual == permissions,
      "unexpected permission map for #{path} job #{job_name}: #{actual.inspect}"
    )

    if job_name.end_with?("-pr")
      expected_job = expected_pr_jobs.fetch([path, job_name])
      require_image_contract(
        job == expected_job,
        "PR image job drifted from its exact credential-free build allowlist: #{path} #{job_name}"
      )
      serialized = job.inspect
      forbidden_patterns = {
        "secrets context" => /\bsecrets\s*(?:\.|\[)/i,
        "GITHUB_TOKEN" => /\bGITHUB_TOKEN\b/,
        "github token context" => /\bgithub\s*(?:\.\s*token|\[\s*['\"]token['\"]\s*\])/i,
        "registry login" => /docker\/login-action@|\b(?:docker|podman|oras|crane|skopeo|helm)\s+login\b/i,
        "write cache or artifact" => /\bcache-to\b|upload-artifact/i
      }
      forbidden_patterns.each do |label, pattern|
        require_image_contract(
          !serialized.match?(pattern),
          "PR image job contains forbidden #{label}: #{path} #{job_name}"
        )
      end
    else
      require_image_contract(
        job["if"] == trusted_guard,
        "privileged image job lacks the trusted-event allowlist: #{path} #{job_name}"
      )
      expected_execution = trusted_execution.fetch(job_name)
      require_image_contract(
        job["runs-on"] == expected_execution.fetch("runs-on"),
        "privileged image job runner drifted: #{path} #{job_name}"
      )
      if expected_execution.key?("strategy")
        require_image_contract(
          job["strategy"] == expected_execution.fetch("strategy"),
          "privileged image job runner matrix drifted: #{path} #{job_name}"
        )
      else
        require_image_contract(
          !job.key?("strategy"),
          "privileged image job gained an unreviewed runner matrix: #{path} #{job_name}"
        )
      end
      if (expected_prefix = trusted_prefixes[job_name])
        %w[defaults container services env].each do |key|
          require_image_contract(
            !job.key?(key),
            "Docker privileged build must not override the verifier execution context with #{key}: #{job_name}"
          )
        end
        steps = job.fetch("steps")
        require_image_contract(
          steps.first(expected_prefix.length) == expected_prefix,
          "Docker privileged build must begin with credentialless checkout and the exact tag-bound verifier: #{job_name}"
        )
        risky_indexes = steps.each_index.select do |index|
          step = steps.fetch(index)
          action = step["uses"].to_s
          serialized = step.inspect
          action.start_with?("docker/login-action@", "docker/build-push-action@") ||
            serialized.match?(/\bGITHUB_TOKEN\b|\bcache-to\b|push=|\b(?:docker|podman|oras|crane|skopeo|helm)\s+(?:login|push)\b/i)
        end
        require_image_contract(
          risky_indexes.all? { |index| index >= expected_prefix.length },
          "Docker tag-bound verifier must precede every credential or publish-capable step: #{job_name}"
        )
        status_override_indexes = steps.each_index.select do |index|
          index >= expected_prefix.length &&
            steps.fetch(index)["if"].to_s.match?(/\b(?:always|failure|cancelled|success)\s*\(/i)
        end
        require_image_contract(
          status_override_indexes.empty?,
          "Docker post-verifier steps must retain the implicit verifier success dependency: #{job_name}"
        )
        risky_indexes.each do |index|
          require_image_contract(
            !steps.fetch(index).key?("if"),
            "Docker credential or publish-capable step may not override the verifier success dependency: #{job_name} step #{index}"
          )
        end
      end
    end
  end

  trusted_needs.each do |job_name, dependency|
    actual = jobs.fetch(job_name).fetch("needs")
    require_image_contract(
      actual == dependency,
      "privileged image merge dependency drifted: #{path} #{job_name}"
    )
  end
end

workflows = {
  docker_path => Psych.safe_load_file(docker_path, aliases: false),
  sprig_path => Psych.safe_load_file(sprig_path, aliases: false)
}

expected_permissions.each do |path, permission_map|
  validate_image_workflow!(
    path: path,
    workflow: workflows.fetch(path),
    permission_map: permission_map,
    trusted_guard: trusted_event_guards.fetch(path),
    trusted_needs: expected_trusted_needs.filter_map do |(candidate_path, job_name), dependency|
      [job_name, dependency] if candidate_path == path
    end.to_h,
    expected_trigger: expected_triggers.fetch(path),
    expected_env: expected_root_env.fetch(path),
    expected_pr_jobs: expected_pr_jobs,
    trusted_prefixes: expected_trusted_prefixes.filter_map do |(candidate_path, job_name), prefix|
      [job_name, prefix] if candidate_path == path
    end.to_h,
    trusted_execution: expected_trusted_execution.filter_map do |(candidate_path, job_name), execution|
      [job_name, execution] if candidate_path == path
    end.to_h
  )
end

def expect_image_contract_rejection(label)
  yield
rescue ImageWorkflowContractError, KeyError
  return
else
  raise ImageWorkflowContractError, "hostile image-workflow mutation was accepted: #{label}"
end

expected_permissions.each do |path, permission_map|
  base = workflows.fetch(path)
  pr_job_name = permission_map.keys.find { |name| name.end_with?("-pr") }
  arguments = {
    path: path,
    permission_map: permission_map,
    trusted_guard: trusted_event_guards.fetch(path),
    trusted_needs: expected_trusted_needs.filter_map do |(candidate_path, job_name), dependency|
      [job_name, dependency] if candidate_path == path
    end.to_h,
    expected_trigger: expected_triggers.fetch(path),
    expected_env: expected_root_env.fetch(path),
    expected_pr_jobs: expected_pr_jobs,
    trusted_prefixes: expected_trusted_prefixes.filter_map do |(candidate_path, job_name), prefix|
      [job_name, prefix] if candidate_path == path
    end.to_h,
    trusted_execution: expected_trusted_execution.filter_map do |(candidate_path, job_name), execution|
      [job_name, execution] if candidate_path == path
    end.to_h
  }

  mutations = {
    "bracket secret context" => lambda do |workflow|
      workflow.fetch("jobs").fetch(pr_job_name)["env"] = {
        "LEAK" => "${{ secrets['PERSONAL_RULESET_EVIDENCE_TOKEN'] }}"
      }
    end,
    "bracket github token context" => lambda do |workflow|
      workflow.fetch("jobs").fetch(pr_job_name)["env"] = {"LEAK" => "${{ github['token'] }}"}
    end,
    "multiline publishing output" => lambda do |workflow|
      build = workflow.fetch("jobs").fetch(pr_job_name).fetch("steps").find do |step|
        step["uses"].to_s.start_with?("docker/build-push-action@")
      end
      build.fetch("with")["outputs"] = "type=registry,name=hostile,push=true\ntype=image,push=false"
    end,
    "explicit push input" => lambda do |workflow|
      build = workflow.fetch("jobs").fetch(pr_job_name).fetch("steps").find do |step|
        step["uses"].to_s.start_with?("docker/build-push-action@")
      end
      build.fetch("with")["push"] = true
    end,
    "credential input" => lambda do |workflow|
      workflow.fetch("jobs").fetch(pr_job_name).fetch("steps").last.fetch("with")["password"] = "${{ secrets.PASSWORD }}"
    end,
    "login action" => lambda do |workflow|
      workflow.fetch("jobs").fetch(pr_job_name).fetch("steps") << {
        "uses" => "docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee"
      }
    end,
    "PR write permission" => lambda do |workflow|
      workflow.fetch("jobs").fetch(pr_job_name).fetch("permissions")["packages"] = "write"
    end,
    "PR guard drift" => lambda do |workflow|
      workflow.fetch("jobs").fetch(pr_job_name)["if"] = "github.event_name == 'pull_request'"
    end,
    "unpinned action" => lambda do |workflow|
      workflow.fetch("jobs").fetch(pr_job_name).fetch("steps").first["uses"] = "actions/checkout@v6"
    end,
    "pull_request_target trigger" => lambda do |workflow|
      (workflow[true] || workflow["on"])["pull_request_target"] = {}
    end
  }

  mutations.each do |label, mutate|
    fixture = Marshal.load(Marshal.dump(base))
    mutate.call(fixture)
    expect_image_contract_rejection("#{File.basename(path)} #{label}") do
      validate_image_workflow!(workflow: fixture, **arguments)
    end
  end
end

docker_arguments = {
  path: docker_path,
  permission_map: expected_permissions.fetch(docker_path),
  trusted_guard: trusted_event_guards.fetch(docker_path),
  trusted_needs: expected_trusted_needs.filter_map do |(candidate_path, job_name), dependency|
    [job_name, dependency] if candidate_path == docker_path
  end.to_h,
  expected_trigger: expected_triggers.fetch(docker_path),
  expected_env: expected_root_env.fetch(docker_path),
  expected_pr_jobs: expected_pr_jobs,
  trusted_prefixes: expected_trusted_prefixes.filter_map do |(candidate_path, job_name), prefix|
    [job_name, prefix] if candidate_path == docker_path
  end.to_h,
  trusted_execution: expected_trusted_execution.filter_map do |(candidate_path, job_name), execution|
    [job_name, execution] if candidate_path == docker_path
  end.to_h
}

%w[build push-gateway-build].each do |job_name|
  verifier_mutations = {
    "verifier deletion" => lambda do |workflow|
      workflow.fetch("jobs").fetch(job_name).fetch("steps").delete_at(1)
    end,
    "verifier reordering" => lambda do |workflow|
      steps = workflow.fetch("jobs").fetch(job_name).fetch("steps")
      verifier = steps.delete_at(1)
      login_index = steps.index { |step| step["uses"].to_s.start_with?("docker/login-action@") }
      steps.insert(login_index + 1, verifier)
    end,
    "verifier command drift" => lambda do |workflow|
      workflow.fetch("jobs").fetch(job_name).fetch("steps").fetch(1)["run"] =
        "scripts/verify-release-ref.sh relay-v \"$INPUT_VERSION\"\n"
    end,
    "verifier shell override" => lambda do |workflow|
      workflow.fetch("jobs").fetch(job_name)["defaults"] = {
        "run" => {"shell" => "/usr/bin/true {0}"}
      }
    end,
    "verifier environment override" => lambda do |workflow|
      workflow.fetch("jobs").fetch(job_name)["env"] = {"BASH_ENV" => "./hostile.sh"}
    end,
    "unrecognized step always after verifier failure" => lambda do |workflow|
      setup = workflow.fetch("jobs").fetch(job_name).fetch("steps").find do |step|
        step["uses"].to_s.start_with?("docker/setup-buildx-action@")
      end
      setup["if"] = "${{ always() }}"
    end,
    "publish always after verifier failure" => lambda do |workflow|
      login = workflow.fetch("jobs").fetch(job_name).fetch("steps").find do |step|
        step["uses"].to_s.start_with?("docker/login-action@")
      end
      login["if"] = "${{ always() }}"
    end
  }

  verifier_mutations.each do |label, mutate|
    fixture = Marshal.load(Marshal.dump(workflows.fetch(docker_path)))
    mutate.call(fixture)
    expect_image_contract_rejection("docker.yml #{job_name} #{label}") do
      validate_image_workflow!(workflow: fixture, **docker_arguments)
    end
  end
end

expected_trusted_execution.each do |(path, job_name), expected_execution|
  arguments = {
    path: path,
    permission_map: expected_permissions.fetch(path),
    trusted_guard: trusted_event_guards.fetch(path),
    trusted_needs: expected_trusted_needs.filter_map do |(candidate_path, candidate_job), dependency|
      [candidate_job, dependency] if candidate_path == path
    end.to_h,
    expected_trigger: expected_triggers.fetch(path),
    expected_env: expected_root_env.fetch(path),
    expected_pr_jobs: expected_pr_jobs,
    trusted_prefixes: expected_trusted_prefixes.filter_map do |(candidate_path, candidate_job), prefix|
      [candidate_job, prefix] if candidate_path == path
    end.to_h,
    trusted_execution: expected_trusted_execution.filter_map do |(candidate_path, candidate_job), execution|
      [candidate_job, execution] if candidate_path == path
    end.to_h
  }

  fixture = Marshal.load(Marshal.dump(workflows.fetch(path)))
  fixture.fetch("jobs").fetch(job_name)["runs-on"] = "self-hosted"
  expect_image_contract_rejection("#{File.basename(path)} #{job_name} self-hosted runner") do
    validate_image_workflow!(workflow: fixture, **arguments)
  end

  fixture = Marshal.load(Marshal.dump(workflows.fetch(path)))
  fixture.fetch("jobs").fetch(job_name)["if"] =
    fixture.fetch("jobs").fetch(job_name).fetch("if").sub("github.repository == 'block/buzz' && ", "")
  expect_image_contract_rejection("#{File.basename(path)} #{job_name} missing upstream repository guard") do
    validate_image_workflow!(workflow: fixture, **arguments)
  end

  next unless expected_execution.key?("strategy")

  fixture = Marshal.load(Marshal.dump(workflows.fetch(path)))
  fixture.fetch("jobs").fetch(job_name).fetch("strategy").fetch("matrix").fetch("include").first["runner"] =
    "self-hosted"
  expect_image_contract_rejection("#{File.basename(path)} #{job_name} self-hosted matrix") do
    validate_image_workflow!(workflow: fixture, **arguments)
  end
end
RUBY
}

validate_release_flow() {
  ruby -E UTF-8:UTF-8 -rpsych - "$relay_workflow" "$relay_dockerfile" <<'RUBY'
path = ARGV.fetch(0)
dockerfile_path = ARGV.fetch(1)
workflow = Psych.safe_load_file(path, aliases: false)
workflow_text = File.read(path)
dockerfile_text = File.read(dockerfile_path)
jobs = workflow.fetch("jobs")

def require_flow(condition, message)
  abort message unless condition
end

def step_index(job, name)
  matches = job.fetch("steps").each_index.select { |index| job.fetch("steps")[index]["name"] == name }
  abort "expected exactly one release step named #{name.inspect}" unless matches.length == 1
  matches.fetch(0)
end

def require_order(job, names)
  indexes = names.map { |name| step_index(job, name) }
  abort "release step ordering drifted: #{names.join(" -> ")}" unless indexes == indexes.sort && indexes.uniq.length == indexes.length
end

def exact_rust_test_list?(text, full_name)
  text.lines.count { |line| line.chomp == "#{full_name}: test" } == 1
end

fixture_test = "module::exact_test"
require_flow(exact_rust_test_list?("#{fixture_test}: test\n", fixture_test), "exact Rust test-list positive fixture failed")
require_flow(!exact_rust_test_list?("", fixture_test), "empty Rust test list must fail closed")
require_flow(!exact_rust_test_list?("#{fixture_test}: test\n#{fixture_test}: test\n", fixture_test), "duplicate Rust test list must fail closed")

approval = jobs.fetch("release-approval")
prepare = jobs.fetch("prepare")
release_gate = jobs.fetch("release-gate")
build = jobs.fetch("build-publish")
runtime = jobs.fetch("runtime-validation")
scan = jobs.fetch("scan")
publish = jobs.fetch("publish")

require_flow(
  dockerfile_text.lines.first&.chomp == "# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
  "Dockerfile frontend must use the reviewed immutable index digest",
)
{
  "ARG RUST_VERSION=1.95" => 1,
  "ARG NODE_VERSION=24" => 1,
  "ARG DEBIAN_VERSION=bookworm" => 1,
}.each do |line, count|
  require_flow(dockerfile_text.lines.count { |candidate| candidate.chomp == line } == count, "Dockerfile base selector drifted: #{line}")
end
require_flow(
  dockerfile_text.lines.count { |line| line.chomp == "    BUZZ_WEB_DESKTOP_SCHEME=buzz" } == 1,
  "generic relay image must default the runtime web desktop scheme exactly once",
)
require_flow(
  !dockerfile_text.include?("buzz-personal-staging"),
  "generic relay image must not bake the personal staging desktop scheme",
)
expected_from = [
  "FROM rust:${RUST_VERSION}-${DEBIAN_VERSION}@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS chef",
  "FROM chef AS planner",
  "FROM chef AS builder",
  "FROM builder AS stripped-binaries",
  "FROM node:${NODE_VERSION}-${DEBIAN_VERSION}-slim@sha256:235600a8101ab264e117b1768e925532262668dc9b581ef1dd7d96ced463b8e7 AS web-builder",
  "FROM debian:${DEBIAN_VERSION}-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime-base",
  "FROM runtime-base AS runtime-debug",
  "FROM runtime-base AS runtime-personal",
  "FROM runtime-base AS runtime",
]
actual_from = dockerfile_text.lines.map(&:chomp).select { |line| line.start_with?("FROM ") }
require_flow(actual_from == expected_from, "Dockerfile complete stage graph and external base indexes must match the exact reviewed contract")
require_flow(dockerfile_text.scan(/@sha256:[0-9a-f]{64}/).length == 4, "Dockerfile must contain exactly one frontend and three external base index digests")
declared_stage_aliases = actual_from.filter_map { |line| line[/\s+AS\s+([^\s]+)\z/i, 1] }
copy_from_lines = dockerfile_text.lines.map(&:chomp).select { |line| line.match?(/\ACOPY\s+.*--from=/) }
copy_from_sources = copy_from_lines.map do |line|
  match = line.match(/\ACOPY\s+--from=([^\s]+)\s+/)
  require_flow(!match.nil?, "Dockerfile COPY --from syntax escaped structural validation: #{line}")
  match[1]
end
expected_copy_from_sources = [
  "planner",
  "web-builder", "web-builder",
  "builder", "builder", "builder",
  "stripped-binaries", "stripped-binaries", "stripped-binaries",
  "stripped-binaries", "stripped-binaries", "stripped-binaries",
]
require_flow(copy_from_sources == expected_copy_from_sources, "Dockerfile COPY --from sources or count drifted from the exact reviewed stage graph")
require_flow(copy_from_sources.all? { |source| declared_stage_aliases.include?(source) }, "Dockerfile COPY --from may reference only declared internal stage aliases")

buildx_action = "docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5"
buildkit_image = "image=moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
expected_buildx = {
  "build-check" => {
    "version" => "v0.34.1",
    "driver-opts" => buildkit_image,
    "buildkitd-config-inline" => "[worker.oci]\n  max-parallelism = 2\n",
  },
  "build-publish" => {
    "version" => "v0.34.1",
    "driver-opts" => buildkit_image,
    "buildkitd-config-inline" => "[worker.oci]\n  max-parallelism = 2\n",
  },
  "publish" => {
    "version" => "v0.34.1",
    "driver-opts" => buildkit_image,
  },
}
expected_buildx.each do |job_name, expected_with|
  matches = jobs.fetch(job_name).fetch("steps").select { |step| step["name"] == "Set up Docker Buildx" }
  require_flow(matches.length == 1, "#{job_name} must contain exactly one Buildx setup")
  require_flow(matches[0]["uses"] == buildx_action, "#{job_name} Buildx action pin drifted")
  require_flow(matches[0]["with"] == expected_with, "#{job_name} Buildx/BuildKit input map drifted")
end
require_flow(
  jobs.values.sum { |job| job.fetch("steps", []).count { |step| step["name"] == "Set up Docker Buildx" } } == 3,
  "relay workflow must contain exactly three reviewed Buildx setups",
)
require_flow(workflow_text.scan('user/packages/container/${package_name}/versions?per_page=100').length == 2, "private user-owned GHCR package checks must use the authenticated-user endpoint")
require_flow(!workflow_text.include?("users/justinharkelroad/packages/container/"), "public-package GHCR versions endpoint is unsafe for the private personal package")
require_flow(!prepare.key?("needs"), "source binding must run before the protected release authorization")
prepare_contract = prepare.fetch("steps")[step_index(prepare, "Verify invocation contract")].fetch("run")
require_flow(prepare_contract.include?("image_name=ghcr.io/justinharkelroad/buzz-relay-personal"), "relay target must be the single hardcoded personal image")
require_flow(!workflow_text.include?("PERSONAL_RELAY_IMAGE"), "mutable PERSONAL_RELAY_IMAGE must not steer publication")
require_flow(approval["needs"] == "prepare", "release authorization must directly need the prepared source binding")
require_flow(approval["environment"] == "personal-relay-release", "release authorization must be the only protected personal-relay-release job")
require_flow(release_gate.fetch("needs").include?("release-approval"), "candidate tests must need release authorization directly")
require_flow(!release_gate.key?("environment"), "candidate release tests must not hold the protected release environment")
require_flow(build.fetch("needs").include?("release-approval"), "platform mutation must need release authorization directly")
require_flow(publish.fetch("needs").include?("release-approval"), "final mutation must need release authorization directly")
require_flow(approval.fetch("outputs").keys.sort == %w[
  authorization_artifact_digest authorization_artifact_expires_at
  authorization_artifact_id authorization_artifact_name
].sort, "authorization artifact outputs changed")
require_order(approval, [
  "Capture and validate protected owner authorization",
  "Stage sealed release authorization evidence",
  "Create trusted authorization secret-scan policy",
  "Reject secrets in sealed release authorization evidence",
  "Bind zero-secret authorization scan report",
  "Resolve release authorization artifact name",
  "Upload sealed release authorization evidence",
  "Bind sealed release authorization artifact identity"
])
capture = approval.fetch("steps")[step_index(approval, "Capture and validate protected owner authorization")].fetch("run")
%w[
  PUBLISH_PERSONAL_RELAY refs/heads/main personal-relay-image.yml@refs/heads/main
  personal-relay-release-main-branch.json personal-relay-release-main-effective-rules.json
  personal-relay-release-main-rulesets.json personal-relay-release-authorization.json
  PERSONAL_APPROVED_RELAY_SHA justinharkelroad GITHUB_ACTOR GITHUB_TRIGGERING_ACTOR
  personal-relay-release-environment.json personal-relay-release-branch-policies.json
  personal-relay-release-run-identity.json personal-relay-release-authorization/v3
  required_reviewers deployment-branch-policies
  ghcr.io/justinharkelroad/buzz-relay-personal candidate_tag image_name sha-${GITHUB_SHA}
].each { |token| require_flow(capture.include?(token), "authorization capture is missing #{token}") }
require_flow(capture.include?('[[ "$GITHUB_RUN_ATTEMPT" == "1" ]]'), "authorization must reject reruns")
require_flow(capture.include?('all(.[] | select(.type == "pull_request"); zero_review_pull_request)'), "release authorization capture must reject any effective PR rule that reintroduces review")
require_flow(capture.include?('all(.[] | select(.type == "required_status_checks"); exact_gate1_status_checks)'), "release authorization capture must reject extra or substituted status checks")
require_flow(capture.include?('all(.[]; .type != "workflows" and .type != "required_deployments")'), "release authorization capture must reject workflow and deployment gates")
require_flow(approval.fetch("steps").none? { |step| step["uses"].to_s.start_with?("actions/checkout@") }, "release authorization must not checkout or execute candidate source")
require_flow(approval.fetch("steps").none? { |step| step.fetch("run", "").match?(/cargo\s|pnpm\s|docker\s+(run|pull|build)/) }, "release authorization must not execute candidate code")
authorization_name = approval.fetch("steps")[step_index(approval, "Resolve release authorization artifact name")].fetch("run")
require_flow(authorization_name.include?("personal-relay-release-authorization-${GITHUB_SHA}-${GITHUB_RUN_ID}-1"), "authorization artifact name is not source/run/attempt bound")
authorization_upload = approval.fetch("steps")[step_index(approval, "Upload sealed release authorization evidence")]
require_flow(authorization_upload.dig("with", "path") == "/tmp/personal-relay-release-authorization-evidence/", "authorization upload root drifted")

require_order(release_gate, [
  "Download exact sealed owner authorization",
  "Revalidate sealed owner authorization before candidate tests",
  "Verify personal release contracts",
  "Fail if the candidate tag already exists",
  "Run workflow engine tests with HTTP support",
  "Run database-backed dispatch regressions"
])
dispatch_regressions = release_gate.fetch("steps")[step_index(release_gate, "Run database-backed dispatch regressions")].fetch("run")
[
  "executor::tests::webhook_dispatch_revalidation_allows_current_admin",
  "executor::tests::webhook_dispatch_denial_precedes_transport_and_disables_workflow",
  "executor::tests::webhook_dispatch_revalidation_preserves_community_scope",
  "--ignored --exact --list --format terse",
  "grep -Fxc --",
  '[[ "$match_count" == 1 ]]',
  "expected exactly one listed Rust test",
].each do |token|
  require_flow(dispatch_regressions.include?(token), "database-backed release regression must fail closed on missing exact test: #{token}")
end
require_flow(release_gate.dig("services", "postgres", "image") == "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193", "release test Postgres service must use the reviewed OCI index digest")
release_gate_download = release_gate.fetch("steps")[step_index(release_gate, "Download exact sealed owner authorization")].fetch("run")
%w[--artifact-id --run-id --name --digest --expires-at --metadata-output --archive-output].each do |argument|
  require_flow(release_gate_download.include?(argument), "candidate test exact approval download is missing #{argument}")
end
release_gate_revalidation = release_gate.fetch("steps")[step_index(release_gate, "Revalidate sealed owner authorization before candidate tests")].fetch("run")
%w[personal-relay-release-authorization/v3 personal-relay-release-environment.json personal-relay-release-branch-policies.json personal-relay-release-run-identity.json candidate_tag image_name justinharkelroad].each do |token|
  require_flow(release_gate_revalidation.include?(token), "candidate test authorization validation is missing #{token}")
end

require_order(build, [
  "Download exact sealed release authorization",
  "Revalidate sealed owner authorization before platform mutation",
  "Log in to personal GHCR",
  "Fresh owner-authorization and protected-main recheck immediately before platform build and push",
  "Build and push platform manifest by digest",
  "Remove GHCR credentials after pinned platform build",
  "Export platform digest",
  "Upload platform digest"
])
build_download = build.fetch("steps")[step_index(build, "Download exact sealed release authorization")].fetch("run")
%w[--artifact-id --run-id --name --digest --expires-at --metadata-output --archive-output].each do |argument|
  require_flow(build_download.include?(argument), "platform mutation exact artifact download is missing #{argument}")
end
build_revalidation = build.fetch("steps")[step_index(build, "Revalidate sealed owner authorization before platform mutation")].fetch("run")
require_flow(build_revalidation.include?("validate-main-protection.sh") && build_revalidation.include?("--rulesets-json"), "platform mutation does not revalidate sealed protection evidence")
%w[personal-relay-release-authorization/v3 personal-relay-release-environment.json personal-relay-release-branch-policies.json personal-relay-release-run-identity.json candidate_tag image_name justinharkelroad].each do |token|
  require_flow(build_revalidation.include?(token), "platform mutation authorization validation is missing #{token}")
end
fresh_platform_name = "Fresh owner-authorization and protected-main recheck immediately before platform build and push"
fresh_platform_step = build.fetch("steps")[step_index(build, fresh_platform_name)]
fresh_platform = fresh_platform_step.fetch("run")
require_flow(fresh_platform_step.dig("env", "BASH_ENV") == "" && fresh_platform_step.dig("env", "ENV") == "", "fresh platform mutation guard must clear shell startup hooks")
require_flow(fresh_platform_step.dig("env", "PATH") == "/usr/bin:/bin", "fresh platform mutation guard must use the trusted absolute PATH")
%w[gh\ api --hostname\ github.com validate-main-protection.sh cmp sealed_branch sealed_rules sealed_rulesets sealed_environment sealed_branch_policies sealed_run_identity AUTHORIZATION_ARTIFACT_EXPIRES_AT fromdateiso8601 candidate_tag image_name justinharkelroad].each do |token|
  require_flow(fresh_platform.include?(token.tr("\\", "")), "fresh platform protection recheck is missing #{token.tr("\\", "")}")
end
require_flow(fresh_platform.scan("fromdateiso8601").length == 1, "fresh platform guard must contain exactly one terminal approval-expiry check")
require_flow(fresh_platform.index("fromdateiso8601") > fresh_platform.rindex('cmp "$sealed_run_identity" "$live_run_identity"'), "fresh platform authorization-expiry check must follow the final run-identity byte comparison")
require_flow(fresh_platform.rstrip.end_with?("' >/dev/null"), "fresh platform approval-expiry check must be the guard's last command")
login_index = step_index(build, "Log in to personal GHCR")
cleanup_index = step_index(build, "Remove GHCR credentials after pinned platform build")
build_action = build.fetch("steps")[step_index(build, "Build and push platform manifest by digest")]
require_flow(step_index(build, fresh_platform_name) + 1 == step_index(build, "Build and push platform manifest by digest"), "fresh platform protection recheck must be immediately adjacent to the registry mutation")
require_flow(build_action["uses"] == "docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf", "candidate Dockerfile must execute only through the pinned build action")
expected_platform_build = {
  "context" => ".",
  "file" => "./Dockerfile",
  "target" => "runtime-personal",
  "platforms" => "${{ matrix.platform }}",
  "labels" => "org.opencontainers.image.source=https://github.com/${{ github.repository }}\norg.opencontainers.image.revision=${{ github.sha }}\norg.opencontainers.image.title=Personal Buzz Relay\n",
  "outputs" => "type=image,name=${{ needs.prepare.outputs.image_name }},push-by-digest=true,name-canonical=true,push=true,oci-artifact=true",
  "provenance" => "mode=max",
  "sbom" => true,
}
require_flow(build_action.fetch("with") == expected_platform_build, "pinned platform build surface or immutable push-by-digest contract drifted")
build.fetch("steps")[login_index..cleanup_index].each_with_index do |step, offset|
  next if login_index + offset == step_index(build, "Build and push platform manifest by digest")
  run = step.fetch("run", "")
  require_flow(!run.match?(/runtime-contract-test\.sh|cargo\s|pnpm\s|docker\s+(run|pull)/), "candidate-controlled execution exists while platform write credentials may be present")
  local_scripts = run.scan(/bash\s+(\.\/[A-Za-z0-9._\/-]+)/).flatten.uniq
  require_flow(local_scripts.all? { |script| script == "./deploy/personal-relay/validate-main-protection.sh" }, "unapproved local script executes while platform write credentials may be present")
  require_flow(!step["uses"].to_s.start_with?("./"), "local candidate action exists while platform write credentials may be present")
end
cleanup_run = build.fetch("steps")[cleanup_index].fetch("run")
require_flow(build.fetch("steps")[cleanup_index]["if"] == "${{ always() }}", "platform credential cleanup must run on every outcome")
%w[shred -L -O rmdir config.json].each { |token| require_flow(cleanup_run.include?(token), "platform credential cleanup is missing #{token}") }

require_flow(runtime.dig("permissions", "packages") == "read" && !runtime.fetch("permissions").value?("write"), "runtime validation must be read-only")
require_order(runtime, [
  "Log in to personal GHCR read-only",
  "Pull exact runtime",
  "Shred GHCR credentials before candidate runtime execution",
  "Verify exact pushed platform runtime without registry credentials"
])
runtime_cleanup_index = step_index(runtime, "Shred GHCR credentials before candidate runtime execution")
runtime_cleanup = runtime.fetch("steps")[runtime_cleanup_index]
require_flow(runtime_cleanup["if"] == "${{ always() }}", "runtime credential cleanup must run on every outcome")
%w[shred -L -O rmdir config.json].each { |token| require_flow(runtime_cleanup.fetch("run").include?(token), "runtime credential cleanup is missing #{token}") }
require_flow(runtime_cleanup_index + 1 == step_index(runtime, "Verify exact pushed platform runtime without registry credentials"), "candidate runtime must execute immediately after credential cleanup")
runtime_test = runtime.fetch("steps")[step_index(runtime, "Verify exact pushed platform runtime without registry credentials")].fetch("run")
require_flow(runtime_test == 'bash ./deploy/personal-relay/runtime-contract-test.sh "$IMAGE_REF"', "runtime contract must execute only in the read-only credential-cleared job")
require_flow(!build.to_s.include?("runtime-contract-test.sh"), "packages-write build job must not execute the candidate runtime script")

require_order(scan, [
  "Log in to personal GHCR read-only",
  "Export exact image vulnerability report",
  "Export attached SPDX vulnerability report with the same database",
  "Remove GHCR credentials before candidate policy execution",
  "Enforce the exact image and attached SPDX report union",
  "Stage exact scan evidence for proactive secret scanning",
  "Reject secrets in exact scan evidence",
  "Bind zero-secret scan-evidence report",
  "Upload exact scan evidence even when policy blocks"
])
scan_cleanup = scan.fetch("steps")[step_index(scan, "Remove GHCR credentials before candidate policy execution")].fetch("run")
scan_cleanup_step = scan.fetch("steps")[step_index(scan, "Remove GHCR credentials before candidate policy execution")]
require_flow(scan_cleanup_step["if"] == "${{ always() }}", "scan credential cleanup must run on every outcome")
%w[shred -L -O rmdir config.json].each { |token| require_flow(scan_cleanup.include?(token), "scan credential cleanup is missing #{token}") }
scan_upload = scan.fetch("steps")[step_index(scan, "Upload exact scan evidence even when policy blocks")]
require_flow(scan_upload["if"].to_s.include?("bind-secret-scan-evidence.outcome == 'success'"), "scan evidence upload must depend on explicit zero-secret report binding")

require_order(publish, [
  "Download exact sealed release authorization",
  "Revalidate sealed owner authorization before final mutation",
  "Log in to personal GHCR",
  "Fresh owner-authorization and protected-main recheck immediately before manifest and tag creation",
  "Create non-overwriting candidate tag and resolve digest",
  "Verify the exact merged descriptor union by digest",
  "Fresh owner-authorization and protected-main recheck immediately before provenance attestation",
  "Attest merged image provenance",
  "Remove GHCR credentials after registry attestation",
  "Write non-secret release ledger",
  "Stage release evidence at one deterministic artifact root",
  "Reject secrets in final release evidence",
  "Bind zero-secret final-evidence report",
  "Upload release evidence"
])
publish_download = publish.fetch("steps")[step_index(publish, "Download exact sealed release authorization")].fetch("run")
%w[--artifact-id --run-id --name --digest --expires-at --metadata-output --archive-output].each do |argument|
  require_flow(publish_download.include?(argument), "final mutation exact artifact download is missing #{argument}")
end
publish_revalidation = publish.fetch("steps")[step_index(publish, "Revalidate sealed owner authorization before final mutation")].fetch("run")
require_flow(publish_revalidation.include?("validate-main-protection.sh") && publish_revalidation.include?("--rulesets-json"), "final mutation does not revalidate sealed protection evidence")
%w[personal-relay-release-authorization/v3 personal-relay-release-environment.json personal-relay-release-branch-policies.json personal-relay-release-run-identity.json candidate_tag image_name justinharkelroad].each do |token|
  require_flow(publish_revalidation.include?(token), "final mutation authorization validation is missing #{token}")
end
require_flow(publish.fetch("steps").none? { |step| step["uses"].to_s.start_with?("./") }, "OIDC/packages-write publish must not execute a local candidate action")
fresh_manifest_name = "Fresh owner-authorization and protected-main recheck immediately before manifest and tag creation"
fresh_attest_name = "Fresh owner-authorization and protected-main recheck immediately before provenance attestation"
require_flow(step_index(publish, fresh_manifest_name) + 1 == step_index(publish, "Create non-overwriting candidate tag and resolve digest"), "fresh manifest protection recheck must be immediately adjacent to tag mutation")
require_flow(step_index(publish, fresh_attest_name) + 1 == step_index(publish, "Attest merged image provenance"), "fresh protection recheck must be immediately adjacent to provenance attestation")
[fresh_manifest_name, fresh_attest_name].each do |name|
  guard_step = publish.fetch("steps")[step_index(publish, name)]
  run = guard_step.fetch("run")
  require_flow(guard_step.dig("env", "BASH_ENV") == "" && guard_step.dig("env", "ENV") == "", "#{name} must clear shell startup hooks")
  require_flow(guard_step.dig("env", "PATH") == "/usr/bin:/bin", "#{name} must use the trusted absolute PATH")
  %w[gh\ api --hostname\ github.com validate-main-protection.sh cmp sealed_branch sealed_rules sealed_rulesets sealed_environment sealed_branch_policies sealed_run_identity AUTHORIZATION_ARTIFACT_EXPIRES_AT fromdateiso8601 candidate_tag image_name justinharkelroad].each do |token|
    require_flow(run.include?(token.tr("\\", "")), "#{name} is missing #{token.tr("\\", "")}")
  end
  require_flow(run.scan("fromdateiso8601").length == 1, "#{name} must contain exactly one terminal approval-expiry check")
  require_flow(run.index("fromdateiso8601") > run.rindex('cmp "$sealed_run_identity" "$live_run_identity"'), "#{name} authorization-expiry check must follow the final run-identity byte comparison")
  require_flow(run.rstrip.end_with?("' >/dev/null"), "#{name} approval-expiry check must be the guard's last command")
end
publish_cleanup = publish.fetch("steps")[step_index(publish, "Remove GHCR credentials after registry attestation")].fetch("run")
publish_cleanup_step = publish.fetch("steps")[step_index(publish, "Remove GHCR credentials after registry attestation")]
provenance_action = publish.fetch("steps")[step_index(publish, "Attest merged image provenance")]
require_flow(provenance_action["uses"] == "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373", "relay provenance action pin drifted")
require_flow(provenance_action.fetch("with") == {
  "subject-name" => "${{ needs.prepare.outputs.image_name }}",
  "subject-digest" => "${{ steps.manifest.outputs.digest }}",
  "push-to-registry" => true,
  "create-storage-record" => false,
  "show-summary" => false,
}, "relay provenance subject, registry, or side-effect contract drifted")
provenance_verify = publish.fetch("steps")[step_index(publish, "Verify repository-scoped attestation and inspect predicate")].fetch("run")
[
  "--predicate-type https://slsa.dev/provenance/v1",
  '--source-digest "$SOURCE_SHA"',
  '--source-ref "$GITHUB_REF"',
  "--signer-workflow github.com/justinharkelroad/buzz/.github/workflows/personal-relay-image.yml",
  '--signer-digest "$SOURCE_SHA"',
  '.predicateType == "https://slsa.dev/provenance/v1"',
  '.subject | type == "array" and length == 1',
  '.subject[0].name == $image',
  '.subject[0].digest == {sha256: $digest}',
].each do |token|
  require_flow(provenance_verify.include?(token), "relay post-attestation verification is missing #{token}")
end
require_flow(
  provenance_verify.include?("    length == 1\n    and all(.[].verificationResult.statement;"),
  "relay post-attestation verification must accept exactly one verification result",
)
require_flow(publish_cleanup_step["if"] == "${{ always() }}", "publish credential cleanup must run on every outcome")
%w[shred -L -O rmdir config.json].each { |token| require_flow(publish_cleanup.include?(token), "publish credential cleanup is missing #{token}") }

jobs.each do |job_name, job|
  job.fetch("steps", []).each do |step|
    run = step.fetch("run", "")
    api_calls = run.scan(/\bgh api\b/).length
    require_flow(api_calls == run.scan(/\bgh api\s+(?:\\\s*)?--hostname github\.com\b/).length, "relay gh api call is not pinned to github.com: #{job_name}: #{step["name"]}")
    attestation_calls = run.scan(/\bgh attestation verify\b/).length
    next if attestation_calls.zero?
    require_flow(run.scan(/--hostname github\.com/).length >= attestation_calls, "relay gh attestation call is not pinned to github.com: #{job_name}: #{step["name"]}")
  end
end
require_flow(workflow_text.scan('RULESET_EVIDENCE_TOKEN: ${{ secrets.PERSONAL_RULESET_EVIDENCE_TOKEN }}').length == 6, "every relay ruleset-detail step must receive the read-only evidence token")
require_flow(workflow_text.scan('GH_TOKEN="$RULESET_EVIDENCE_TOKEN" gh api --hostname github.com').length == 6, "every relay ruleset-detail GET must use the evidence token only for that call")
require_flow(workflow_text.scan('has("bypass_actors")').length >= 6 && workflow_text.scan('(.bypass_actors | type == "array")').length >= 6, "relay ruleset-detail evidence must fail closed when bypass actors are hidden")
require_flow(workflow_text.scan('def canonical:').length == 6, "all sealed/live relay effective-rule captures must recursively canonicalize parameter objects")
require_flow(workflow_text.scan('sort_by(.ruleset_id // 0, .type // "", (.parameters | tojson), .ruleset_source_type // "", .ruleset_source // "")').length == 6, "all sealed/live effective-rule captures must use one canonical order")
require_flow(workflow_text.scan('protection/required_pull_request_reviews').length == 6, "all sealed/live relay branch captures must prove classic review protection is absent")
require_flow(workflow_text.scan('classic_required_pull_request_reviews: false').length == 6, "all sealed/live relay branch captures must record classic review absence")
require_flow(workflow_text.scan('bypass_actors: (.bypass_actors | sort_by(.actor_type // "", .actor_id // 0, .bypass_mode // ""))').length == 6, "all sealed/live ruleset details must canonicalize bypass actors")
require_flow(capture.include?('select(.type == "required_reviewers")] | length) == 0'), "release authorization environment must require no reviewer")
ledger = publish.fetch("steps")[step_index(publish, "Write non-secret release ledger")].fetch("run")
require_flow(ledger.include?('release_authorization: {environment: "personal-relay-release", authorized_owner: "justinharkelroad", image_name: $authorization[0].image_name, candidate_tag: $authorization[0].candidate_tag'), "release ledger must cross-bind the owner, sealed image name, and candidate tag inside release_authorization")
%w[main_protection release_authorization authorized_owner candidate_tag image_name branch_metadata_sha256 effective_rules_sha256 rulesets_sha256 environment_sha256 branch_policies_sha256 run_identity_sha256 authorization_sha256 evidence_artifact authorization_artifact_expires_at].each do |token|
  require_flow(ledger.include?(token), "release ledger is missing protected-main binding #{token}")
end
stage = publish.fetch("steps")[step_index(publish, "Stage release evidence at one deterministic artifact root")].fetch("run")
%w[personal-relay-release-main-branch.json personal-relay-release-main-effective-rules.json personal-relay-release-main-rulesets.json personal-relay-release-environment.json personal-relay-release-branch-policies.json personal-relay-release-run-identity.json personal-relay-release-authorization.json].each do |filename|
  require_flow(stage.include?(filename), "final release evidence omits #{filename}")
end
RUBY
}

validate_desktop_flow() {
  ruby -E UTF-8:UTF-8 -rpsych -ropen3 - "$desktop_workflow" "$desktop_volume_validator" "$desktop_audit_validator" <<'RUBY'
path = ARGV.fetch(0)
volume_validator_path = ARGV.fetch(1)
audit_validator_path = ARGV.fetch(2)
workflow = Psych.safe_load_file(path, aliases: false)
workflow_text = File.read(path)
volume_validator_text = File.read(volume_validator_path)
audit_validator_text = File.read(audit_validator_path)
jobs = workflow.fetch("jobs")
build = jobs.fetch("build")
inspect = jobs.fetch("inspect")
remount = jobs.fetch("remount")
attest = jobs.fetch("attest")
audit = jobs.fetch("audit")
checkout_action = "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"
upload_action = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
attest_action_pin = "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d"
trivy_action = "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25"

def require_desktop(condition, message)
  abort message unless condition
end

def desktop_step(job, name)
  matches = job.fetch("steps").select { |step| step["name"] == name }
  abort "expected exactly one desktop step named #{name.inspect}" unless matches.length == 1
  matches.fetch(0)
end

def desktop_step_index(job, name)
  job.fetch("steps").index(desktop_step(job, name))
end

require_desktop(jobs.keys == %w[build inspect remount attest audit], "desktop workflow must retain the exact build/inspect/remount/attest/audit job order")
expected_job_shape = {
  # The build job must run in a protected environment. Since the lane selector was added it
  # resolves to `personal-production` for the production lane and `personal-staging` otherwise,
  # so the expected value is the EXACT expression rather than a bare literal. This remains as
  # strict as the previous literal check: any other expression, or a plain literal, still fails.
  "build" => {"runs-on" => "macos-latest", "timeout-minutes" => 120, "needs" => nil, "environment" => "${{ inputs.lane == 'production' && 'personal-production' || 'personal-staging' }}"},
  "inspect" => {"runs-on" => "macos-latest", "timeout-minutes" => 45, "needs" => "build", "environment" => nil},
  "remount" => {"runs-on" => "macos-15", "timeout-minutes" => 30, "needs" => %w[build inspect], "environment" => nil},
  "attest" => {"runs-on" => "macos-latest", "timeout-minutes" => 30, "needs" => %w[build inspect remount], "environment" => nil},
  "audit" => {"runs-on" => "ubuntu-24.04", "timeout-minutes" => 60, "needs" => %w[attest build inspect remount], "environment" => nil},
}
expected_job_shape.each do |job_name, expected|
  job = jobs.fetch(job_name)
  require_desktop(job["runs-on"] == expected["runs-on"], "desktop runner drifted: #{job_name}")
  require_desktop(job["timeout-minutes"] == expected["timeout-minutes"], "desktop timeout drifted: #{job_name}")
  require_desktop(job["needs"] == expected["needs"], "desktop dependency graph drifted: #{job_name}")
  require_desktop(job["environment"] == expected["environment"], "desktop protected-environment placement drifted: #{job_name}")
  require_desktop(job["if"] == "github.repository == 'justinharkelroad/buzz'", "desktop repository boundary drifted: #{job_name}")
end

%w[id-token attestations].each do |permission|
  writers = jobs.filter_map do |job_name, job|
    job_name if job.fetch("permissions", {})[permission] == "write"
  end
  require_desktop(writers == ["attest"], "desktop #{permission}:write must belong only to the clean attest job")
end
require_desktop(!workflow.to_s.include?("$GITHUB_ENV"), "desktop trust values must not use mutable GITHUB_ENV")
require_desktop(!build.fetch("env", {}).key?("BASE_PRODUCT_NAME"), "base product name must not be job-scoped")
require_desktop(!build.fetch("env", {}).key?("BASE_BUNDLE_ID"), "base bundle ID must not be job-scoped")
require_desktop(build.fetch("steps").none? { |step| step["uses"].to_s.start_with?("actions/cache/") }, "desktop candidate build must not restore or save a cross-run cache")
candidate_checkout_index = desktop_step_index(build, "Checkout exact owner-authorized source for the desktop build")
build.fetch("steps")[(candidate_checkout_index + 1)..].each do |step|
  next unless step["run"]
  require_desktop(step.dig("env", "BASH_ENV") == "" && step.dig("env", "ENV") == "", "post-candidate desktop run step must blank shell startup hooks: #{step["name"]}")
end
{"inspect" => inspect, "remount" => remount, "attest" => attest, "audit" => audit}.each do |job_name, job|
  job.fetch("steps").each do |step|
    next unless step["run"]
    require_desktop(step.dig("env", "BASH_ENV") == "" && step.dig("env", "ENV") == "", "desktop #{job_name} run step must blank shell startup hooks: #{step["name"]}")
  end
end

workflow.fetch("jobs").each do |job_name, job|
  job.fetch("steps", []).each do |step|
    uses = step["uses"].to_s
    next if uses.empty?
    require_desktop(uses.match?(%r{\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}\z}), "desktop remote action is not pinned to a full SHA: #{job_name}: #{uses}")
  end
  job.fetch("steps", []).each do |step|
    run = step.fetch("run", "")
    api_calls = run.scan(/\bgh api\b/).length
    pinned_api_calls = run.scan(/\bgh api\s+(?:\\\s*)?--hostname github\.com\b/).length
    require_desktop(api_calls == pinned_api_calls, "desktop gh api call is not pinned to github.com: #{job_name}: #{step["name"]}")
    attestation_calls = run.scan(/\bgh attestation verify\b/).length
    next if attestation_calls.zero?
    require_desktop(run.scan(/--hostname github\.com/).length >= attestation_calls, "desktop gh attestation call is not pinned to github.com: #{job_name}: #{step["name"]}")
  end
end

attest_uses = attest.fetch("steps").filter_map { |step| step["uses"] }
require_desktop(
  attest_uses == [checkout_action, attest_action_pin, upload_action],
  "desktop OIDC job action allowlist must be exactly pinned checkout, custom attestation, and upload",
)
attest_text = attest.to_s
require_desktop(!attest_text.match?(/hdiutil/i), "desktop OIDC job must never mount or execute a DMG")
attest_runs = attest.fetch("steps").map { |step| step.fetch("run", "") }.join("\n")
require_desktop(!attest_runs.match?(/^\s*(?:sudo\s+)?trivy(?:\s|$)/i), "desktop OIDC job must never execute a Trivy binary")
require_desktop(!attest_runs.match?(/^\s*docker\s+.*\btrivy\b/i), "desktop OIDC job must never execute Trivy through Docker")
require_desktop(!attest_text.match?(/\b(?:cargo|pnpm|npm|node|rustc)\b/), "desktop OIDC job must never execute candidate build tooling")

allowed_oidc_scripts = %w[
  ./deploy/personal-relay/canonical-json-sha256.sh
  ./deploy/personal-relay/download-exact-artifact.sh
  ./deploy/personal-relay/validate-main-protection.sh
]
attest.fetch("steps").each do |step|
  step.fetch("run", "").scan(/(?:bash[[:space:]]+)?(\.\/[A-Za-z0-9._\/-]+)/).flatten.each do |script|
    require_desktop(allowed_oidc_scripts.include?(script), "desktop OIDC run step invokes unapproved local script: #{script}")
  end
end

expected_inspect_outputs = {
  "artifact_digest" => "${{ steps.uploaded-inspection.outputs.digest }}",
  "artifact_expires_at" => "${{ steps.uploaded-inspection.outputs.expires_at }}",
  "artifact_id" => "${{ steps.uploaded-inspection.outputs.id }}",
  "artifact_name" => "${{ steps.inspection-artifact-name.outputs.name }}",
  "inventory_sha256" => "${{ steps.inspection-receipt.outputs.inventory_sha256 }}",
  "receipt_sha256" => "${{ steps.inspection-receipt.outputs.receipt_sha256 }}",
  "staging_scan_sha256" => "${{ steps.inspection-receipt.outputs.staging_scan_sha256 }}",
  "volume_scan_sha256" => "${{ steps.inspection-receipt.outputs.volume_scan_sha256 }}",
  "volume_artifact_digest" => "${{ steps.uploaded-volume.outputs.digest }}",
  "volume_artifact_expires_at" => "${{ steps.uploaded-volume.outputs.expires_at }}",
  "volume_artifact_id" => "${{ steps.uploaded-volume.outputs.id }}",
  "volume_artifact_name" => "${{ steps.volume-artifact-name.outputs.name }}",
  "volume_attach_layout_sha256" => "${{ steps.volume-record.outputs.attach_layout_sha256 }}",
  "volume_projection_manifest_sha256" => "${{ steps.volume-record.outputs.projection_manifest_sha256 }}",
  "volume_record_sha256" => "${{ steps.volume-record.outputs.record_sha256 }}",
  "volume_sidecar_manifest_sha256" => "${{ steps.volume-record.outputs.sidecar_manifest_sha256 }}",
}
require_desktop(inspect.fetch("outputs") == expected_inspect_outputs, "desktop inspection output identities drifted")
require_desktop(remount.fetch("outputs") == {
  "artifact_digest" => "${{ steps.uploaded-remount.outputs.digest }}",
  "artifact_expires_at" => "${{ steps.uploaded-remount.outputs.expires_at }}",
  "artifact_id" => "${{ steps.uploaded-remount.outputs.id }}",
  "artifact_name" => "${{ steps.remount-artifact-name.outputs.name }}",
  "receipt_sha256" => "${{ steps.remount-evidence.outputs.receipt_sha256 }}",
}, "desktop independent-remount artifact outputs drifted")
require_desktop(attest.fetch("outputs") == {
  "artifact_digest" => "${{ steps.uploaded-attestation.outputs.digest }}",
  "artifact_expires_at" => "${{ steps.uploaded-attestation.outputs.expires_at }}",
  "artifact_id" => "${{ steps.uploaded-attestation.outputs.id }}",
  "artifact_name" => "personal-desktop-staging-attestation-${{ inputs.target }}-${{ github.sha }}",
}, "desktop attestation artifact outputs drifted")
require_desktop(audit.fetch("outputs", {}) == {}, "desktop audit must not export an unreviewed trust value")

build_contract = desktop_step(build, "Create immutable desktop build contract")
controls = desktop_step(build, "Validate protected main and personal-staging controls").fetch("run")
[
  "protection/required_pull_request_reviews",
  "classic_required_pull_request_reviews: false",
  'keys == ["classic_required_pull_request_reviews", "commit", "name", "protected"]',
  '.classic_required_pull_request_reviews == false',
  '(.commit | keys) == ["sha"]',
  "personal-staging-environment.raw.json",
  "protection_rules: [.protection_rules[]] | sort_by(.type)",
  'select(.type == "required_reviewers")] | length) == 0',
  "personal-staging-run-identity.json",
  '.actor.login == "justinharkelroad"',
  '.triggering_actor.login == "justinharkelroad"',
  "def canonical:",
  "parameters: (.parameters | canonical)",
  'sort_by(.ruleset_id // 0, .type // "", (.parameters | tojson)',
  'bypass_actors: (.bypass_actors | sort_by(.actor_type // "", .actor_id // 0, .bypass_mode // ""))'
].each do |token|
  require_desktop(controls.include?(token), "desktop sealed control evidence lacks deterministic normalization: #{token}")
end
require_desktop(
  workflow_text.scan('protection/required_pull_request_reviews').length == 2 &&
    workflow_text.scan('classic_required_pull_request_reviews: false').length == 2,
  "Desktop sealed/live main-branch evidence must prove and record classic review absence",
)
require_desktop(build_contract.dig("env", "BASE_PRODUCT_NAME") == "${{ vars.PERSONAL_DESKTOP_PRODUCT_NAME }}", "desktop build contract lost protected base product input")
require_desktop(build_contract.dig("env", "BASE_BUNDLE_ID") == "${{ vars.PERSONAL_DESKTOP_BUNDLE_ID }}", "desktop build contract lost protected base bundle input")
%w[
  auto_connect_default_relay build_channel bundle_id deep_link_scheme product_name
  receipt_sha256 relay_https relay_wss source_sha target version
].each do |token|
  require_desktop(build_contract.fetch("run").include?(token), "desktop build contract omits #{token}")
end
authorization_stage = desktop_step(build, "Seal pre-candidate authorization and control evidence").fetch("run")
require_desktop(authorization_stage.include?("personal-desktop-build-contract.json"), "desktop authorization artifact omits the build contract")
require_desktop(authorization_stage.include?('== 16'), "desktop authorization artifact file count is not exact")

generate = desktop_step(build, "Generate staging-only Tauri configuration")
%w[
  BUZZ_RELAY_HTTP BUZZ_RELAY_URL EXPECTED_BUILD_CHANNEL EXPECTED_BUNDLE_ID
  EXPECTED_PRODUCT_NAME EXPECTED_URI_SCHEME
].each do |key|
  require_desktop(generate.fetch("env").key?(key), "Tauri configuration lacks immutable #{key}")
end
require_desktop(generate.fetch("run").include?("Info.personal-staging.plist"), "staging Tauri config must use a staging identity plist")
candidate_build = desktop_step(build, "Build unsigned staging binary and unpacked app")
%w[
  BUZZ_BUILD_AUTO_CONNECT_DEFAULT_RELAY BUZZ_BUILD_CHANNEL BUZZ_BUILD_DEEP_LINK_SCHEME
  BUZZ_RELAY_HTTP BUZZ_RELAY_URL DESKTOP_TARGET VITE_BUZZ_BUILD_CHANNEL
  VITE_BUZZ_DEEP_LINK_SCHEME
].each do |key|
  require_desktop(candidate_build.fetch("env").key?(key), "desktop build lacks immutable #{key}")
end
candidate_build_run = candidate_build.fetch("run")
dmg_build = desktop_step(build, "Create DMG from the exact snapshotted unpacked app")
%w[
  BUZZ_BUILD_AUTO_CONNECT_DEFAULT_RELAY BUZZ_BUILD_CHANNEL BUZZ_BUILD_DEEP_LINK_SCHEME
  BUZZ_RELAY_HTTP BUZZ_RELAY_URL DESKTOP_TARGET VITE_BUZZ_BUILD_CHANNEL
  VITE_BUZZ_DEEP_LINK_SCHEME
].each do |key|
  require_desktop(dmg_build.fetch("env").key?(key), "desktop DMG build lacks immutable #{key}")
end
dmg_build_run = dmg_build.fetch("run")
require_desktop(!workflow_text.match?(/\bfeatures=\(\)/), "desktop workflow must not use a nounset-unsafe empty features array")
require_desktop(!workflow_text.match?(/\$\{features\[@\]\}/), "desktop workflow must not expand a nounset-unsafe features array")
[candidate_build_run, dmg_build_run].each do |run|
  require_desktop(run.include?('[[ "$BUZZ_BUILD_CHANNEL" == "$VITE_BUZZ_BUILD_CHANNEL" ]]'), "native and visible desktop build channels must match")
  require_desktop(run.include?('[[ "$BUZZ_BUILD_CHANNEL" == personal-staging ]]'), "native desktop build channel must fail closed to personal staging")
  require_desktop(run.include?('if [[ "$DESKTOP_TARGET" == "aarch64-apple-darwin" ]]; then'), "desktop target branch lost explicit arm64 selection")
  require_desktop(run.include?('elif [[ "$DESKTOP_TARGET" == "x86_64-apple-darwin" ]]; then'), "desktop target branch lost explicit x86_64 selection")
  require_desktop(run.include?('--features mesh-llm'), "arm64 Desktop build lost the reviewed mesh-llm feature")
  require_desktop(run.include?('echo "::error::unsupported desktop target"'), "desktop target selection must fail closed")
end
package_verify = desktop_step(build, "Verify package and exact sidecar parity")
%w[
  EXPECTED_BANNER_ARTIFACT EXPECTED_BUNDLE_ID EXPECTED_PRODUCT_NAME
  FORBIDDEN_BANNER_ARTIFACT RELAY_HTTPS RELAY_WSS HOSTED_HTTPS
  PERSONAL_PRODUCTION_HTTPS
].each do |key|
  require_desktop(package_verify.fetch("env").key?(key), "package verification lacks immutable #{key}")
end
%w[CFBundleIdentifier CFBundleName CFBundleDisplayName CFBundleExecutable].each do |key|
  require_desktop(package_verify.fetch("run").include?(key), "package verification omits #{key}")
end
package_verify_run = package_verify.fetch("run")
[
  'aarch64-apple-darwin) expected_arch=arm64 ;;',
  'x86_64-apple-darwin) expected_arch=x86_64 ;;',
  '[[ -f "$main_executable" && -x "$main_executable" && ! -L "$main_executable" ]]',
  'node desktop/scripts/verify-personal-staging-banner-build.mjs "$frontend_dist"',
  '/usr/bin/grep -rlaF -- "$EXPECTED_BANNER_ARTIFACT" "$frontend_dist"',
  '/usr/bin/grep -rlaF -- "$FORBIDDEN_BANNER_ARTIFACT" "$frontend_dist"',
  'sidecar_names=(',
  'buzz-backend-kubernetes',
  'git-credential-nostr',
  'for sidecar_name in "${sidecar_names[@]}"; do',
  '[[ "$source_sha" == "$embedded_sha" ]]',
  'schema: "personal-desktop-sidecars/v1"',
  'and (.entries | length) == 6',
  'personal-desktop-checksums.txt',
].each do |token|
  require_desktop(package_verify_run.include?(token), "desktop build architecture/parity contract omits #{token}")
end
require_desktop(package_verify_run.scan('/usr/bin/lipo -archs').length == 3, "desktop package verification must architecture-check the app plus each source/embedded sidecar pair")
candidate_stage = desktop_step(build, "Stage unsigned package and exact evidence").fetch("run")
require_desktop(candidate_stage.include?('sidecar_names=('), "desktop candidate stage must enumerate every reviewed sidecar")
require_desktop(candidate_stage.include?('== 10'), "desktop candidate artifact inventory must remain exactly ten files")
%w[personal-desktop-checksums.txt personal-desktop-sidecars.json personal-desktop-staging.json].each do |filename|
  require_desktop(candidate_stage.include?(filename), "desktop candidate artifact omits #{filename}")
end
ledger = desktop_step(build, "Write non-secret staging ledger")
%w[BUILD_CONTRACT_SHA BUNDLE_ID PRODUCT_NAME RELAY_HTTPS RELAY_WSS STAGING_AUTHORIZED_BY].each do |key|
  require_desktop(ledger.fetch("env").key?(key), "desktop ledger lacks immutable #{key}")
end
%w[build_contract_sha256 bundle_id product_name relay_https relay_wss authorized_owner].each do |token|
  require_desktop(ledger.fetch("run").include?(token), "desktop ledger omits #{token}")
end
require_desktop(ledger.fetch("run").include?('schema: "personal-desktop-staging/v2"'), "desktop candidate ledger schema must be personal-desktop-staging/v2")
initial_gate1_receipt_verifier = desktop_step(build, "Validate and independently verify exact Gate 1 receipt").fetch("run")
fresh_ledger_verifier = desktop_step(attest, "Resolve and verify sealed desktop ledger").fetch("run")
[
  '.schema_version == 2',
  '.receipt_type == "personal-relay-gate1"',
  '.gate1_workflow.authorized_owner as $authorized_owner',
  '($authorized_owner | keys | sort) == ["id", "login", "node_id"]',
  '$authorized_owner.login == "justinharkelroad"',
  '.release_evidence.release_authorization.authorized_owner == "justinharkelroad"',
].each do |token|
  [initial_gate1_receipt_verifier, fresh_ledger_verifier].each do |verifier|
    require_desktop(verifier.include?(token), "Desktop Gate 1 receipt verifier omits #{token}")
  end
end
%w[
  personal-desktop-build-contract.json
  authorized_owner
  gate1_eligibility_expires_at
  gate1_release_evidence_expires_at
  build_contract_sha256
].each do |token|
  require_desktop(fresh_ledger_verifier.include?(token), "fresh desktop ledger verification omits #{token}")
end
require_desktop(fresh_ledger_verifier.scan("keys | sort").length >= 8, "fresh desktop ledger verification lost exact top-level or nested key sets")
require_desktop(fresh_ledger_verifier.include?('.schema == "personal-desktop-staging/v2"'), "fresh desktop ledger verifier must reject schema downgrade")
require_desktop(fresh_ledger_verifier.include?(".gate1_eligibility_expires_at == $gate1_eligibility_expires_at"), "desktop eligibility deadline is not bound to the sealed Gate 1 receipt")
require_desktop(fresh_ledger_verifier.include?(".gate1_release_evidence_expires_at == $gate1_release_evidence_expires_at"), "desktop release-evidence deadline is not bound to the sealed Gate 1 receipt")
require_desktop(build.fetch("steps").none? { |step| step["uses"] == trivy_action }, "desktop build must seal immutable candidate bytes before any third-party scanner runs")

inspect_download = desktop_step(inspect, "Download exact sealed desktop artifacts for inspection").fetch("run")
require_desktop(inspect_download.scan("download-exact-artifact.sh").length == 2, "desktop inspection must download exactly the candidate and authorization artifacts")
[
  '--artifact-id "$ARTIFACT_ID"', '--name "$ARTIFACT_NAME"', '--digest "$ARTIFACT_DIGEST"',
  '--expires-at "$ARTIFACT_EXPIRES_AT"', '--output-dir /tmp/personal-desktop-inspect-staging',
  '--artifact-id "$AUTHORIZATION_ARTIFACT_ID"', '--name "$AUTHORIZATION_ARTIFACT_NAME"',
  '--digest "$AUTHORIZATION_ARTIFACT_DIGEST"', '--expires-at "$AUTHORIZATION_ARTIFACT_EXPIRES_AT"',
  '--output-dir /tmp/personal-desktop-inspect-authorization',
].each do |token|
  require_desktop(inspect_download.include?(token), "desktop inspection exact-artifact download omits #{token}")
end
require_desktop(inspect_download.include?('[[ "$GITHUB_RUN_ATTEMPT" == 1 ]]'), "desktop inspection must reject reruns")
require_desktop(inspect_download.include?('[[ "$GITHUB_REF" == "refs/heads/main" && "$REF_PROTECTED" == true ]]'), "desktop inspection must bind protected main")

inspection_inputs = desktop_step(inspect, "Resolve immutable desktop inspection inputs").fetch("run")
[
  '== 10', '== 16', '! -type f', 'personal-desktop-staging.json',
  'personal-desktop-checksums.txt', 'personal-desktop-sidecars.json',
  'buzz-acp-${EXPECTED_TARGET}', 'and (.entries | length) == 6',
  'while IFS=$\'\t\' read -r candidate_name expected_sha; do',
  'cmp -s "$checksums" "$expected_checksums"',
  '[[ -s "$input" && ! -L "$input" ]]', '[[ -s "$checksums" && ! -L "$checksums" ]]',
  '[[ -s "$acp" && ! -L "$acp" ]]', '"$dmg_sha" "$(basename "$dmg")"',
].each do |token|
  require_desktop(inspection_inputs.include?(token), "desktop inspection input contract omits #{token}")
end

mount = desktop_step(inspect, "Mount read-only DMG and project every volume file").fetch("run")
[
  '/usr/bin/hdiutil attach -readonly -nobrowse -noautoopen',
  "/usr/bin/grep -Fq 'read-only'",
  'canonical_mount_root=$(/bin/realpath "$mount_root")',
  '[[ -d "$canonical_mount_root" && ! -L "$canonical_mount_root" ]]',
  '[[ -d "$app" && ! -L "$app" ]]',
  '[[ -L "$applications" && "$(/usr/bin/readlink "$applications")" == /Applications ]]',
  '[[ -d "$background" && ! -L "$background" ]]',
  '[[ -f "$background/dmg-background.png" && ! -L "$background/dmg-background.png" ]]',
  '[[ -f "$mount_root/.DS_Store" && ! -L "$mount_root/.DS_Store" ]]',
  '[[ -f "$mount_root/.VolumeIcon.icns" && ! -L "$mount_root/.VolumeIcon.icns" ]]',
  'done < <(/usr/bin/find "$mount_root" -mindepth 1 -print0)',
  'resolved=$(/bin/realpath "$entry")',
  '"$canonical_mount_root"/*) resolved_relative=${resolved#"$canonical_mount_root"/} ;;',
  'echo "::error::DMG contains an external symlink: $relative"',
  '/bin/cp -p "$entry" "$projection/$relative"',
  '[[ "$(/usr/bin/shasum -a 256 "$projection/$relative" | /usr/bin/awk',
  'sort_by(.path)',
  '{path: ".DS_Store", type: "file", target: null}',
  '{path: ".VolumeIcon.icns", type: "file", target: null}',
  '{path: ".background", type: "directory", target: null}',
  '{path: "Applications", type: "symlink", target: "/Applications"}',
  '{path: $app, type: "directory", target: null}',
  '{path: ".background/dmg-background.png", type: "file"}',
  '[[ "$projection_file_count" == "$inventory_file_count" ]]',
  '[[ -f "$main_executable" && -x "$main_executable" && ! -L "$main_executable" ]]',
  'aarch64-apple-darwin) expected_arch=arm64 ;;',
  'x86_64-apple-darwin) expected_arch=x86_64 ;;',
  'while IFS=$\'\t\' read -r sidecar_name candidate_name source_sha embedded_relative_path manifest_arch; do',
  '[[ "$staged_sha" == "$source_sha" && "$embedded_sha" == "$source_sha" ]]',
  '[[ "$(/usr/bin/lipo -archs "$staged_sidecar")" == "$expected_arch" ]]',
  '[[ "$(/usr/bin/lipo -archs "$embedded_sidecar")" == "$expected_arch" ]]',
  '/usr/bin/cmp -s "$mounted_sidecar_manifest" "$STAGED_SIDECAR_MANIFEST"',
  'embedded_acp_sha=$(jq -r',
].each do |token|
  require_desktop(mount.include?(token), "full-volume projection/architecture contract omits #{token}")
end

volume_stage = desktop_step(inspect, "Stage immutable mounted-volume projection").fetch("run")
%w[
  personal-desktop-mounted-volume-record.json
  personal-desktop-dmg-attach-layout.json
  personal-desktop-mounted-volume-inventory.json
  personal-desktop-volume-projection-manifest.json
  personal-desktop-mounted-sidecars.json
].each do |filename|
  require_desktop(volume_stage.include?(filename), "immutable pre-scan volume artifact omits #{filename}")
end
require_desktop(volume_stage.include?('cp -Rp "${{ steps.mounted-volume.outputs.projection }}/." "$stage/projection/"'), "immutable pre-scan volume artifact must copy the complete projection")
require_desktop(volume_stage.include?('cmp -s /tmp/personal-desktop-staged-volume-actual.json'), "immutable pre-scan volume artifact must rehash and compare every projected file")
volume_upload = desktop_step(inspect, "Upload immutable pre-scan mounted-volume evidence")
require_desktop(volume_upload["uses"] == upload_action, "immutable pre-scan volume upload pin drifted")
require_desktop(volume_upload.dig("with", "include-hidden-files") == true, "immutable pre-scan volume upload must retain hidden app and DMG files")
require_desktop(
  desktop_step_index(inspect, "Upload immutable pre-scan mounted-volume evidence") <
    desktop_step_index(inspect, "Scan exact downloaded staging artifact"),
  "raw mounted-volume evidence must be immutable before any third-party scanner runs",
)

inspect_trivy_steps = inspect.fetch("steps").select { |step| step["uses"] == trivy_action }
require_desktop(inspect_trivy_steps.length == 2, "desktop no-OIDC inspection must contain exactly two pinned Trivy scans")
inspection_scan_contracts = [
  ["Scan exact downloaded staging artifact", "/tmp/personal-desktop-inspect-staging", "/tmp/personal-desktop-inspection-staging-secret.json", "Bind zero-secret staging inspection report"],
  ["Scan full mounted-volume projection", "${{ steps.volume-stage.outputs.projection }}", "/tmp/personal-desktop-inspection-volume-secret.json", "Bind zero-secret full-volume inspection report"],
]
inspection_scan_contracts.each do |scan_name, scan_ref, report, bind_name|
  scan = desktop_step(inspect, scan_name)
  require_desktop(scan["uses"] == trivy_action, "desktop inspection scan action pin drifted: #{scan_name}")
  require_desktop(scan.dig("with", "scan-ref") == scan_ref && scan.dig("with", "output") == report, "desktop inspection scan surface drifted: #{scan_name}")
  binder = desktop_step(inspect, bind_name).fetch("run")
  require_desktop(binder.include?("report=#{report}"), "desktop inspection scan binder uses the wrong report: #{bind_name}")
  %w[SchemaVersion ArtifactType Trivy.Version Secrets].each do |binding|
    require_desktop(binder.include?(binding), "desktop inspection scan binder omits #{binding}: #{bind_name}")
  end
end
full_volume_binder = desktop_step(inspect, "Bind zero-secret full-volume inspection report").fetch("run")
require_desktop(full_volume_binder.include?('${{ steps.volume-stage.outputs.projection }}'), "full-volume scan receipt must bind the immutable pre-scan projection")
require_desktop(full_volume_binder.include?('${{ steps.mounted-volume.outputs.inventory }}'), "full-volume scan receipt must bind the exact inventory")
require_desktop(full_volume_binder.include?('select(.type == "file")'), "full-volume scan must prove projection/inventory file-count parity")
detach = desktop_step(inspect, "Detach inspected staging DMG")
require_desktop(detach["if"] == "always()", "inspection DMG detach must run on every outcome")

inspection_receipt = desktop_step(inspect, "Create exact desktop inspection receipt").fetch("run")
[
  'schema: "personal-desktop-staging-inspection/v1"',
  'candidate_artifact:', 'authorization_artifact:', 'mounted_volume_artifact:',
  'dmg_sha256: $dmg_sha256', 'ledger_sha256: $ledger_sha256',
  'buzz_acp_sha256: $acp_sha256', 'sidecar_manifest_sha256: $sidecar_manifest_sha256',
  'attach_layout_sha256: $attach_layout_sha256',
  'projection_manifest_sha256: $projection_manifest_sha256',
  'record_sha256: $record_sha256',
  'inventory_sha256: $inventory_sha256',
  'sidecar_manifest_sha256: $mounted_sidecar_manifest_sha256',
  'main_executable_sha256: $main_executable_sha256',
  'embedded_buzz_acp_sha256: $embedded_acp_sha256',
  'downloaded_artifact: {', 'artifact_name: $staging_scan_artifact',
  'report_sha256: $staging_scan_sha256',
  'full_volume_projection: {', 'artifact_name: $volume_scan_artifact',
  'report_sha256: $volume_scan_sha256',
  '.mounted_volume.embedded_buzz_acp_sha256 == .candidate.buzz_acp_sha256',
  '.mounted_volume.sidecar_manifest_sha256 == .candidate.sidecar_manifest_sha256',
  'chmod 0400 "$receipt"',
].each do |token|
  require_desktop(inspection_receipt.include?(token), "desktop inspection receipt omits #{token}")
end
inspection_name = desktop_step(inspect, "Resolve inspection artifact name").fetch("run")
require_desktop(inspection_name.include?('name=personal-desktop-staging-inspection-${TARGET}-${GITHUB_SHA}'), "desktop inspection artifact name drifted")
inspection_stage = desktop_step(inspect, "Stage exact desktop inspection evidence").fetch("run")
%w[
  personal-desktop-inspection-receipt.json
  personal-desktop-mounted-volume-inventory.json
  personal-desktop-inspection-staging-secret.json
  personal-desktop-inspection-volume-secret.json
].each do |filename|
  require_desktop(inspection_stage.include?(filename), "desktop inspection artifact omits #{filename}")
end
require_desktop(inspection_stage.include?('== 4'), "desktop inspection artifact inventory must be exact")
inspection_upload = desktop_step(inspect, "Upload exact desktop inspection evidence")
require_desktop(inspection_upload["uses"] == upload_action, "desktop inspection upload pin drifted")
require_desktop(inspection_upload.fetch("with") == {
  "name" => "${{ steps.inspection-artifact-name.outputs.name }}",
  "path" => "${{ steps.inspection-stage.outputs.path }}/",
  "if-no-files-found" => "error",
  "retention-days" => 14,
  "include-hidden-files" => false,
}, "desktop inspection upload map drifted")
inspection_identity = desktop_step(inspect, "Bind inspection artifact identity and expiration").fetch("run")
%w[.id .name .digest .expired .workflow_run.id .expires_at].each do |field|
  require_desktop(inspection_identity.include?(field), "desktop inspection artifact identity omits #{field}")
end
require_desktop(
  [
    "Download exact sealed desktop artifacts for inspection",
    "Resolve immutable desktop inspection inputs",
    "Mount read-only DMG and project every volume file",
    "Seal pre-scan mounted-volume identity",
    "Stage immutable mounted-volume projection",
    "Upload immutable pre-scan mounted-volume evidence",
    "Bind pre-scan mounted-volume artifact identity",
    "Scan exact downloaded staging artifact",
    "Bind zero-secret staging inspection report",
    "Scan full mounted-volume projection",
    "Bind zero-secret full-volume inspection report",
    "Detach inspected staging DMG",
    "Create exact desktop inspection receipt",
    "Stage exact desktop inspection evidence",
    "Upload exact desktop inspection evidence",
    "Bind inspection artifact identity and expiration",
  ].map { |name| desktop_step_index(inspect, name) }.each_cons(2).all? { |left, right| left < right },
  "desktop inspection trust sequence drifted",
)

remount_uses = remount.fetch("steps").filter_map { |step| step["uses"] }
require_desktop(
  remount_uses == [checkout_action, upload_action],
  "fresh-remount job action allowlist must be exactly pinned checkout and artifact upload",
)
require_desktop(remount.fetch("steps").none? { |step| step["uses"] == trivy_action }, "fresh-remount job must not run third-party scanner code")
remount_download = desktop_step(remount, "Download exact candidate and pre-scan volume artifacts").fetch("run")
require_desktop(remount_download.scan("download-exact-artifact.sh").length == 2, "fresh-remount job must exact-download only candidate and pre-scan volume artifacts")
[
  '--artifact-id "$CANDIDATE_ARTIFACT_ID"', '--name "$CANDIDATE_ARTIFACT_NAME"',
  '--digest "$CANDIDATE_ARTIFACT_DIGEST"', '--expires-at "$CANDIDATE_ARTIFACT_EXPIRES_AT"',
  '--output-dir /tmp/personal-desktop-remount-candidate',
  '--artifact-id "$VOLUME_ARTIFACT_ID"', '--name "$VOLUME_ARTIFACT_NAME"',
  '--digest "$VOLUME_ARTIFACT_DIGEST"', '--expires-at "$VOLUME_ARTIFACT_EXPIRES_AT"',
  '--output-dir /tmp/personal-desktop-remount-volume',
  '[[ "$GITHUB_RUN_ATTEMPT" == 1 ]]',
  '[[ "$GITHUB_REF" == "refs/heads/main" && "$REF_PROTECTED" == true ]]',
].each do |token|
  require_desktop(remount_download.include?(token), "fresh-remount exact handoff omits #{token}")
end
require_desktop(remount_download.scan('--run-id "$GITHUB_RUN_ID"').length == 2, "fresh-remount downloads must bind both artifacts to the current run")

remount_evidence = desktop_step(remount, "Freshly remount and seal independent volume evidence").fetch("run")
[
  'expected_candidate_names=$(printf', 'expected_volume_names=$(printf',
  'personal-desktop-independent-remount/v1',
  'bash ./deploy/personal-relay/verify-desktop-dmg-volume.sh',
  '--dmg "$dmg"', '--ledger "$ledger"', '--sidecar-manifest "$sidecars"',
  '--volume-dir "$volume"', '--product-name "$EXPECTED_PRODUCT_NAME"', '--target "$EXPECTED_TARGET"',
  'fresh_runner: true', 'mounted_read_only: true', 'mounted_nobrowse: true',
  'inventory_equal: true', 'projection_hashes_equal: true', 'sidecars_equal: true',
  'candidate_executed: false', 'chmod 0400 "$receipt"',
].each do |token|
  require_desktop(remount_evidence.include?(token), "fresh-remount receipt contract omits #{token}")
end
require_desktop(remount_evidence.include?('[[ "$observed_candidate_names" == "$expected_candidate_names" ]]'), "fresh-remount job must reject candidate-root additions")
require_desktop(remount_evidence.include?('[[ "$observed_volume_names" == "$expected_volume_names" ]]'), "fresh-remount job must reject pre-scan-volume root additions")
require_desktop(remount_evidence.include?('cmp -s "$sidecars" "$mounted_sidecars"'), "fresh-remount job must byte-compare staged and mounted sidecar manifests")

[
  '/usr/bin/hdiutil attach -readonly -nobrowse -noautoopen',
  "/usr/bin/grep -Fq 'read-only'",
  "/usr/bin/grep -Fq 'nobrowse'",
  'trap cleanup EXIT',
  'cmp -s "$inventory" "$sealed_inventory"',
  'cmp -s "$inventory_files" "$sealed_projection_manifest"',
  'candidate code',
].each do |token|
  require_desktop(volume_validator_text.include?(token), "fresh macOS DMG verifier omits #{token}")
end
require_desktop(volume_validator_text.include?('/usr/bin/hdiutil detach "$image_device"'), "fresh macOS DMG verifier must detach the exact image device")
require_desktop(volume_validator_text.include?('! /sbin/mount | /usr/bin/grep -Fq'), "fresh macOS DMG verifier must prove the mount is gone")

remount_upload = desktop_step(remount, "Upload exact independent remount receipt")
require_desktop(remount_upload["uses"] == upload_action, "fresh-remount receipt upload pin drifted")
require_desktop(remount_upload.fetch("with") == {
  "name" => "${{ steps.remount-artifact-name.outputs.name }}",
  "path" => "/tmp/personal-desktop-independent-remount-receipt.json",
  "if-no-files-found" => "error",
  "retention-days" => 14,
  "include-hidden-files" => false,
}, "fresh-remount receipt upload map drifted")
require_desktop(
  [
    "Download exact candidate and pre-scan volume artifacts",
    "Freshly remount and seal independent volume evidence",
    "Resolve independent remount artifact name",
    "Upload exact independent remount receipt",
    "Bind independent remount artifact identity",
  ].map { |name| desktop_step_index(remount, name) }.each_cons(2).all? { |left, right| left < right },
  "fresh-remount trust sequence drifted",
)

attest_download = desktop_step(attest, "Download exact sealed desktop artifact").fetch("run")
require_desktop(attest_download.scan("download-exact-artifact.sh").length == 5, "clean Desktop OIDC job must download exactly candidate, authorization, inspection, pre-scan volume, and fresh-remount artifacts")
%w[
  /tmp/personal-desktop-staging
  /tmp/personal-desktop-authorization
  /tmp/personal-desktop-inspection
  /tmp/personal-desktop-mounted-volume
  /tmp/personal-desktop-independent-remount
].each do |download_root|
  require_desktop(attest_download.include?("--output-dir #{download_root}"), "clean Desktop OIDC job omits exact artifact root #{download_root}")
end
require_desktop(attest_download.include?('--artifact-id "$INSPECTION_ARTIFACT_ID"'), "clean Desktop OIDC job does not bind the inspection artifact ID")
require_desktop(attest_download.include?('--digest "$INSPECTION_ARTIFACT_DIGEST"'), "clean Desktop OIDC job does not bind the inspection artifact digest")
require_desktop(attest_download.include?('--artifact-id "$VOLUME_ARTIFACT_ID"'), "clean Desktop OIDC job does not bind the pre-scan volume artifact ID")
require_desktop(attest_download.include?('--digest "$VOLUME_ARTIFACT_DIGEST"'), "clean Desktop OIDC job does not bind the pre-scan volume artifact digest")
require_desktop(attest_download.include?('--artifact-id "$REMOUNT_ARTIFACT_ID"'), "clean Desktop OIDC job does not bind the fresh-remount artifact ID")
require_desktop(attest_download.include?('--digest "$REMOUNT_ARTIFACT_DIGEST"'), "clean Desktop OIDC job does not bind the fresh-remount artifact digest")

inspection_validation = desktop_step(attest, "Validate exact no-OIDC desktop inspection evidence").fetch("run")
[
  'personal-desktop-inspection-receipt.json',
  'personal-desktop-mounted-volume-inventory.json',
  'personal-desktop-inspection-staging-secret.json',
  'personal-desktop-inspection-volume-secret.json',
  '[[ "$receipt_sha" == "$EXPECTED_INSPECTION_RECEIPT_SHA256" ]]',
  '[[ "$inventory_sha" == "$EXPECTED_INSPECTION_INVENTORY_SHA256" ]]',
  '[[ "$staging_scan_sha" == "$EXPECTED_INSPECTION_STAGING_SCAN_SHA256" ]]',
  '[[ "$volume_scan_sha" == "$EXPECTED_INSPECTION_VOLUME_SCAN_SHA256" ]]',
  '.candidate_artifact == {', '.authorization_artifact == {',
  '.mounted_volume.root_layout == [', '.scans == {',
  '(.expires_at | fromdateiso8601) > $minimum_valid_until',
].each do |token|
  require_desktop(inspection_validation.include?(token), "clean Desktop inspection validation omits #{token}")
end

volume_validation = desktop_step(attest, "Validate immutable pre-scan mounted-volume evidence").fetch("run")
[
  'personal-desktop-mounted-volume-record.json',
  'personal-desktop-dmg-attach-layout.json',
  'personal-desktop-mounted-volume-inventory.json',
  'personal-desktop-volume-projection-manifest.json',
  'personal-desktop-mounted-sidecars.json',
  'expected_names=$(printf', 'observed_names=$(find',
  'cmp -s "$sidecar_manifest" /tmp/personal-desktop-staging/personal-desktop-sidecars.json',
  'cmp -s "$actual_manifest" "$projection_manifest"',
  'cmp -s /tmp/personal-desktop-attest-volume-inventory-files.json "$projection_manifest"',
  '[[ "$(date -juf \'%Y-%m-%dT%H:%M:%SZ\' "$EXPECTED_VOLUME_ARTIFACT_EXPIRES_AT" \'+%s\')" -gt "$minimum_valid_until" ]]',
].each do |token|
  require_desktop(volume_validation.include?(token), "clean Desktop pre-scan volume validation omits #{token}")
end

remount_validation = desktop_step(attest, "Validate independent fresh-remount receipt").fetch("run")
[
  'personal-desktop-independent-remount-receipt.json',
  '[[ "$receipt_sha" == "$EXPECTED_RECEIPT_SHA256" ]]',
  'schema == "personal-desktop-independent-remount/v1"',
  '.candidate_artifact == {', '.mounted_volume_artifact == {',
  'fresh_runner: true', 'mounted_read_only: true', 'mounted_nobrowse: true',
  'inventory_equal: true', 'projection_hashes_equal: true', 'sidecars_equal: true',
  'candidate_executed: false',
  '(.expires_at | fromdateiso8601) > $minimum_valid_until',
].each do |token|
  require_desktop(remount_validation.include?(token), "clean Desktop fresh-remount validation omits #{token}")
end

predicate_step = desktop_step(attest, "Create exact sealed desktop attestation predicate")
predicate = predicate_step.fetch("run")
[
  "/tmp/personal-desktop-staging-attestation-predicate.json",
  '$ledger[0] as $sealed',
  "source_sha: $sealed.source_sha",
  "sha: $sealed.workflow_sha",
  'ref: "refs/heads/main"',
  "workflow_ref: $sealed.workflow_ref",
  "name: $dmg_name",
  "digest: {sha256: $dmg_sha256}",
  "ledger_sha256: $ledger_sha256",
  ".ledger == $ledger[0]",
  "build_contract_sha256: $sealed.build_contract_sha256",
  "target: $sealed.target",
  "version: $sealed.version",
  "bundle_id: $sealed.bundle_id",
  "buzz_acp_sha256: $sealed.buzz_acp_sha256",
  "sidecars:",
  "manifest_sha256: $sealed.sidecar_manifest_sha256",
  "manifest: $sealed.sidecars",
  "authorization_artifact: $sealed.authorization_artifact",
  "candidate_artifact:",
  "id: $candidate_artifact_id",
  "name: $candidate_artifact_name",
  "digest: $candidate_artifact_digest",
  "expires_at: $candidate_artifact_expires_at",
  "inspection:",
  "artifact:",
  "id: $inspection_artifact_id",
  "name: $inspection_artifact_name",
  "digest: $inspection_artifact_digest",
  "expires_at: $inspection_artifact_expires_at",
  "receipt_sha256: $inspection_receipt_sha256",
  "mounted_volume_inventory_sha256: $inspection_inventory_sha256",
  "mounted_volume_artifact:",
  "mounted_volume_record_sha256: $volume_record_sha256",
  "mounted_volume_attach_layout_sha256: $volume_attach_layout_sha256",
  "mounted_volume_projection_manifest_sha256: $volume_projection_manifest_sha256",
  "mounted_volume_sidecar_manifest_sha256: $volume_sidecar_manifest_sha256",
  "downloaded_artifact_scan_sha256: $inspection_staging_scan_sha256",
  "full_volume_projection_scan_sha256: $inspection_volume_scan_sha256",
  "remount:",
  "receipt_sha256: $remount_receipt_sha256",
  "fresh_runner: true",
  "mounted_read_only: true",
  "candidate_executed: false",
  "workflow_sha: $sealed.gate1_workflow_sha",
  "evidence_run_id: $sealed.gate1_evidence_run_id",
  "evidence_run_attempt: $sealed.gate1_evidence_run_attempt",
  "artifact: $sealed.gate1_artifact",
  "receipt_sha256: $sealed.gate1_receipt_sha256",
  "attestation_bundle_sha256: $sealed.gate1_attestation_bundle_sha256",
  "eligibility_expires_at: $sealed.gate1_eligibility_expires_at",
  "release_evidence_expires_at: $sealed.gate1_release_evidence_expires_at",
  ".source_sha == $ledger[0].source_sha",
  ".subject.digest.sha256 == $ledger[0].dmg_sha256",
  ".verifier.sha == $verifier_sha",
  ".verifier.ref == $verifier_ref",
  ".verifier.workflow_ref == $verifier_workflow_ref"
].each do |token|
  require_desktop(predicate.include?(token), "exact Desktop predicate construction is missing #{token}")
end
require_desktop(
  predicate_step.dig("env", "LEDGER_PATH") == "${{ steps.dmg.outputs.ledger_path }}" &&
    predicate_step.dig("env", "DMG_NAME") == "${{ steps.dmg.outputs.name }}" &&
    predicate_step.dig("env", "DMG_SHA256") == "${{ steps.dmg.outputs.sha256 }}" &&
    predicate_step.dig("env", "CANDIDATE_ARTIFACT_ID") == "${{ needs.build.outputs.artifact_id }}" &&
    predicate_step.dig("env", "INSPECTION_ARTIFACT_ID") == "${{ needs.inspect.outputs.artifact_id }}" &&
    predicate_step.dig("env", "VOLUME_ARTIFACT_ID") == "${{ needs.inspect.outputs.volume_artifact_id }}" &&
    predicate_step.dig("env", "REMOUNT_ARTIFACT_ID") == "${{ needs.remount.outputs.artifact_id }}" &&
    predicate_step.dig("env", "REMOUNT_RECEIPT_SHA256") == "${{ steps.remount-evidence.outputs.receipt_sha256 }}" &&
    predicate_step.dig("env", "INSPECTION_RECEIPT_SHA256") == "${{ steps.inspection.outputs.receipt_sha256 }}" &&
    predicate_step.dig("env", "INSPECTION_INVENTORY_SHA256") == "${{ steps.inspection.outputs.inventory_sha256 }}" &&
    predicate_step.dig("env", "INSPECTION_STAGING_SCAN_SHA256") == "${{ steps.inspection.outputs.staging_scan_sha256 }}" &&
    predicate_step.dig("env", "INSPECTION_VOLUME_SCAN_SHA256") == "${{ steps.inspection.outputs.volume_scan_sha256 }}",
  "Desktop custom predicate must bind the verified candidate and exact no-OIDC inspection identities",
)
require_desktop(
  predicate.include?('(keys | sort) == [') && predicate.include?('chmod 0400 "$predicate"'),
  "Desktop custom predicate must have an exact schema and become read-only before OIDC",
)
live = desktop_step(attest, "Revalidate live protected main immediately before OIDC").fetch("run")
%w[validate-main-protection.sh --rulesets-json personal-desktop-live-main-branch.json personal-desktop-live-main-effective-rules.json personal-desktop-live-main-rulesets.json cmp].each do |token|
  require_desktop(live.include?(token), "pre-OIDC live-main revalidation omits #{token}")
end
[
  "protection/required_pull_request_reviews",
  "classic_required_pull_request_reviews: false",
  'keys == ["classic_required_pull_request_reviews", "commit", "name", "protected"]',
  '.classic_required_pull_request_reviews == false',
  '(.commit | keys) == ["sha"]',
  "personal-desktop-live-staging-environment.raw.json",
  "protection_rules: [.protection_rules[]] | sort_by(.type)",
  'select(.type == "required_reviewers")] | length) == 0',
  "def canonical:",
  "parameters: (.parameters | canonical)",
  'sort_by(.ruleset_id // 0, .type // "", (.parameters | tojson)',
  'bypass_actors: (.bypass_actors | sort_by(.actor_type // "", .actor_id // 0, .bypass_mode // ""))'
].each do |token|
  require_desktop(live.include?(token), "Desktop pre-OIDC evidence lacks matching deterministic normalization: #{token}")
end
require_desktop(
  live.include?("cmp -s /tmp/personal-desktop-live-main-branch.json") &&
    live.include?("/tmp/personal-desktop-authorization/personal-desktop-main-branch.json") &&
    !live.include?("personal-desktop-live-main-branch.canonical.json") &&
    !live.include?("personal-desktop-sealed-main-branch.canonical.json"),
  "Desktop live/sealed main-branch comparison must byte-compare the exact stable projections",
)
deadline_fields = %w[
  authorization_artifact.expires_at
  gate1_artifact.expires_at
  gate1_eligibility_expires_at
  gate1_release_evidence_expires_at
]
deadline_fields.each do |field|
  require_desktop(live.scan(field).length == 1, "Desktop pre-OIDC guard must check #{field} exactly once")
end
require_desktop(live.scan("fromdateiso8601").length == 4, "Desktop pre-OIDC guard must have exactly one four-deadline comparison block")
require_desktop(live.scan("+ 2100").length == 1, "Desktop terminal guard must require exactly 2100 seconds of remaining evidence validity")
require_desktop(
  live.index("fromdateiso8601") > live.rindex("/tmp/personal-desktop-sealed-staging-branch-policies.canonical.json"),
  "Desktop deadline block must follow the final environment/policy byte comparison",
)
require_desktop(live.include?(%q{[[ "$(date -juf '%Y-%m-%dT%H:%M:%SZ' "$INSPECTION_ARTIFACT_EXPIRES_AT" '+%s')" -gt "$minimum_valid_until" ]]}), "Desktop terminal guard must apply the 2100-second grace to the inspection artifact")
require_desktop(live.include?(%q{[[ "$(date -juf '%Y-%m-%dT%H:%M:%SZ' "$REMOUNT_ARTIFACT_EXPIRES_AT" '+%s')" -gt "$minimum_valid_until" ]]}), "Desktop terminal guard must apply the 2100-second grace to the independent-remount artifact")
require_desktop(live.include?(%q{[[ "$(date -juf '%Y-%m-%dT%H:%M:%SZ' "$VOLUME_ARTIFACT_EXPIRES_AT" '+%s')" -gt "$minimum_valid_until" ]]}), "Desktop terminal guard must apply the 2100-second grace to the mounted-volume artifact")
require_desktop(live.scan("shasum -a 256").length == 14, "Desktop terminal guard must rehash all candidate, per-sidecar, inspection, volume, and remount evidence")
[
  'dmg_sha=$(shasum -a 256 "$DMG_PATH"',
  'acp_sha=$(shasum -a 256 "$STAGED_ACP_PATH"',
  'ledger_sha=$(shasum -a 256 "$LEDGER_PATH"',
  'receipt_sha=$(shasum -a 256 "$INSPECTION_RECEIPT_PATH"',
  'remount_receipt_sha=$(shasum -a 256 "$REMOUNT_RECEIPT_PATH"',
  'inventory_sha=$(shasum -a 256 /tmp/personal-desktop-inspection/personal-desktop-mounted-volume-inventory.json',
  'staging_scan_sha=$(shasum -a 256 /tmp/personal-desktop-inspection/personal-desktop-inspection-staging-secret.json',
  'volume_scan_sha=$(shasum -a 256 /tmp/personal-desktop-inspection/personal-desktop-inspection-volume-secret.json',
  'sidecar_manifest_sha=$(shasum -a 256 "$staged_sidecars"',
  'volume_record_sha=$(shasum -a 256 "$volume_record"',
  'volume_attach_layout_sha=$(shasum -a 256 "$volume_attach_layout"',
  'volume_projection_manifest_sha=$(shasum -a 256 "$volume_projection_manifest"',
  'volume_sidecar_manifest_sha=$(shasum -a 256 "$volume_sidecars"',
  'cmp -s "$staged_sidecars" "$volume_sidecars"',
  'while IFS=$\'\t\' read -r candidate_name expected_sha; do',
  '[[ "$dmg_sha" == "$(jq -r .dmg_sha256 "$LEDGER_PATH")" ]]',
  '[[ "$acp_sha" == "$(jq -r .buzz_acp_sha256 "$LEDGER_PATH")" ]]',
  '[[ "$ledger_sha" == "$(jq -r .candidate.ledger_sha256 "$INSPECTION_RECEIPT_PATH")" ]]',
  '[[ "$receipt_sha" == "$INSPECTION_RECEIPT_SHA256" ]]',
  '[[ "$remount_receipt_sha" == "$REMOUNT_RECEIPT_SHA256" ]]',
  '[[ "$inventory_sha" == "$INSPECTION_INVENTORY_SHA256" ]]',
  '[[ "$staging_scan_sha" == "$INSPECTION_STAGING_SCAN_SHA256" ]]',
  '[[ "$volume_scan_sha" == "$INSPECTION_VOLUME_SCAN_SHA256" ]]',
  '[[ "$sidecar_manifest_sha" == "$(jq -r .sidecar_manifest_sha256 "$LEDGER_PATH")" ]]',
  '[[ "$volume_record_sha" == "${{ steps.volume-evidence.outputs.record_sha256 }}" ]]',
  '[[ "$volume_attach_layout_sha" == "${{ steps.volume-evidence.outputs.attach_layout_sha256 }}" ]]',
  '[[ "$volume_projection_manifest_sha" == "${{ steps.volume-evidence.outputs.projection_manifest_sha256 }}" ]]',
  '[[ "$volume_sidecar_manifest_sha" == "${{ steps.volume-evidence.outputs.sidecar_manifest_sha256 }}" ]]',
  '.ledger == $ledger[0]',
  '.desktop.sidecars.manifest == $ledger[0].sidecars',
  '.remount == {',
].each do |token|
  require_desktop(live.include?(token), "Desktop terminal rehash guard omits #{token}")
end
require_desktop(live.rstrip.end_with?('\' "$PREDICATE_PATH" >/dev/null'), "Desktop predicate/hash binding must be the terminal pre-OIDC command")
attest_index = desktop_step_index(attest, "Attest staging DMG provenance")
attest_action = desktop_step(attest, "Attest staging DMG provenance")
require_desktop(attest_action["uses"] == attest_action_pin, "Desktop custom attestation action pin drifted")
require_desktop(!workflow.to_s.include?("actions/attest-build-provenance@"), "generic SLSA provenance must not stand in for the built Desktop source binding")
require_desktop(attest_action.fetch("with") == {
  "subject-name" => "${{ steps.dmg.outputs.name }}",
  "subject-digest" => "sha256:${{ steps.dmg.outputs.sha256 }}",
  "predicate-type" => "https://github.com/justinharkelroad/buzz/attestations/personal-desktop-staging/v2",
  "predicate-path" => "/tmp/personal-desktop-staging-attestation-predicate.json",
  "push-to-registry" => false,
  "show-summary" => false,
}, "Desktop custom attestation input map drifted")
require_desktop(attest_action.dig("with", "subject-name") == "${{ steps.dmg.outputs.name }}", "Desktop custom attestation subject name drifted")
require_desktop(attest_action.dig("with", "subject-digest") == "sha256:${{ steps.dmg.outputs.sha256 }}", "Desktop custom attestation subject digest drifted")
require_desktop(attest_action.dig("with", "predicate-type") == "https://github.com/justinharkelroad/buzz/attestations/personal-desktop-staging/v2", "Desktop custom predicate type drifted")
require_desktop(attest_action.dig("with", "predicate-path") == "/tmp/personal-desktop-staging-attestation-predicate.json", "Desktop custom predicate path drifted")
require_desktop(attest_action.dig("with", "push-to-registry") == false && attest_action.dig("with", "show-summary") == false, "Desktop custom attestation must not publish to a registry or mutable summary")
verification_step = desktop_step(attest, "Verify repository-scoped attestation and inspect predicate")
verification = verification_step.fetch("run")
[
  '--bundle personal-desktop-attestation-bundle.json',
  '--predicate-type https://github.com/justinharkelroad/buzz/attestations/personal-desktop-staging/v2',
  '--source-digest "$GITHUB_SHA"',
  '--source-ref "$GITHUB_REF"',
  '--signer-workflow github.com/justinharkelroad/buzz/.github/workflows/personal-desktop-release.yml',
  '--signer-digest "$GITHUB_SHA"',
  "length == 1",
  '.predicateType == "https://github.com/justinharkelroad/buzz/attestations/personal-desktop-staging/v2"',
  '--slurpfile predicate /tmp/personal-desktop-staging-attestation-predicate.json',
  '.predicate == $predicate[0]',
  'any(.subject[]?; .name == $name and .digest.sha256 == $digest)'
].each do |token|
  require_desktop(verification.include?(token), "Desktop exact custom-attestation verification is missing #{token}")
end
require_desktop(verification_step.dig("env", "BUNDLE_PATH") == "${{ steps.attest-dmg.outputs.bundle-path }}", "Desktop verifier must consume the exact emitted custom-attestation bundle")
require_desktop(desktop_step_index(attest, "Verify repository-scoped attestation and inspect predicate") == attest_index + 1, "Desktop custom attestation must be verified immediately")

# Mutation contract: the workflow's required full predicate equality must reject a
# returned statement whose built source drifts while every subject/verifier field stays fixed.
sealed_predicate_fixture = {
  "source_sha" => "a" * 40,
  "subject" => {"name" => "Buzz.dmg", "digest" => {"sha256" => "c" * 64}},
  "verifier" => {"sha" => "d" * 40, "ref" => "refs/heads/main"}
}
source_sha_drift_fixture = Marshal.load(Marshal.dump(sealed_predicate_fixture))
source_sha_drift_fixture["source_sha"] = "b" * 40
require_desktop(sealed_predicate_fixture == sealed_predicate_fixture, "Desktop exact-predicate fixture is invalid")
require_desktop(source_sha_drift_fixture != sealed_predicate_fixture, "Desktop source_sha mutation must fail exact predicate equality")
[
  "Validate immutable pre-scan mounted-volume evidence",
  "Validate exact no-OIDC desktop inspection evidence",
  "Validate independent fresh-remount receipt",
  "Create exact sealed desktop attestation predicate",
  "Revalidate live protected main immediately before OIDC",
].each do |name|
  require_desktop(desktop_step_index(attest, name) < attest_index, "#{name} must precede OIDC attestation")
end
require_desktop(
  desktop_step_index(attest, "Revalidate live protected main immediately before OIDC") == attest_index - 1,
  "live protected-main revalidation must be immediately adjacent to Desktop OIDC attestation",
)

attestation_stage = desktop_step(attest, "Stage exact attestation evidence").fetch("run")
%w[
  personal-desktop-attestation-bundle.json
  personal-desktop-attestation-predicate.json
  personal-desktop-attestation-returned-predicate.json
  personal-desktop-attestation-verification.json
].each do |filename|
  require_desktop(attestation_stage.include?(filename), "Desktop four-file attestation evidence omits #{filename}")
end
require_desktop(attestation_stage.include?('== 4'), "Desktop attestation evidence inventory must remain exactly four files before the audit adds independent evidence")
attestation_upload = desktop_step(attest, "Upload exact attestation evidence")
require_desktop(attestation_upload["uses"] == upload_action, "Desktop attestation evidence upload pin drifted")
require_desktop(attestation_upload.fetch("with") == {
  "name" => "personal-desktop-staging-attestation-${{ inputs.target }}-${{ github.sha }}",
  "path" => "${{ steps.attestation-stage.outputs.path }}/",
  "if-no-files-found" => "error",
  "retention-days" => 14,
  "include-hidden-files" => false,
}, "Desktop attestation evidence upload map drifted")

audit_download = desktop_step(audit, "Download exact attestation evidence and sealed audit inputs").fetch("run")
require_desktop(audit_download.scan("download-exact-artifact.sh").length == 5, "Desktop audit must exact-download attestation, candidate, inspection, mounted-volume, and remount artifacts")
[
  '--artifact-id "$ARTIFACT_ID"', '--run-id "$GITHUB_RUN_ID"',
  '--name "$ARTIFACT_NAME"', '--digest "$ARTIFACT_DIGEST"',
  '--expires-at "$ARTIFACT_EXPIRES_AT"',
  '--output-dir /tmp/personal-desktop-attestation-audit-input',
  '--artifact-id "$CANDIDATE_ARTIFACT_ID"',
  '--name "$CANDIDATE_ARTIFACT_NAME"',
  '--digest "$CANDIDATE_ARTIFACT_DIGEST"',
  '--expires-at "$CANDIDATE_ARTIFACT_EXPIRES_AT"',
  '--output-dir /tmp/personal-desktop-attestation-audit-candidate',
  '--artifact-id "$INSPECTION_ARTIFACT_ID"',
  '--name "$INSPECTION_ARTIFACT_NAME"',
  '--digest "$INSPECTION_ARTIFACT_DIGEST"',
  '--expires-at "$INSPECTION_ARTIFACT_EXPIRES_AT"',
  '--output-dir /tmp/personal-desktop-attestation-audit-inspection',
  '--artifact-id "$VOLUME_ARTIFACT_ID"',
  '--name "$VOLUME_ARTIFACT_NAME"',
  '--digest "$VOLUME_ARTIFACT_DIGEST"',
  '--expires-at "$VOLUME_ARTIFACT_EXPIRES_AT"',
  '--output-dir /tmp/personal-desktop-attestation-audit-volume',
  '--artifact-id "$REMOUNT_ARTIFACT_ID"',
  '--name "$REMOUNT_ARTIFACT_NAME"',
  '--digest "$REMOUNT_ARTIFACT_DIGEST"',
  '--expires-at "$REMOUNT_ARTIFACT_EXPIRES_AT"',
  '--output-dir /tmp/personal-desktop-attestation-audit-remount',
  'personal-desktop-attestation-bundle.json',
  'personal-desktop-attestation-predicate.json',
  'personal-desktop-attestation-returned-predicate.json',
  'personal-desktop-attestation-verification.json',
  '[[ "$observed_names" == "$expected_names" ]]',
  '[[ "$(find "$candidate" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d \'[:space:]\')" == 10 ]]',
  '[[ "$dmg_count" == 1 && -n "$dmg" && ! -L "$dmg" ]]',
  'ledger="$candidate/personal-desktop-staging.json"',
  "jq -e '.schema == \"personal-desktop-staging/v2\"' \"$ledger\" >/dev/null",
  'and .ledger.schema == "personal-desktop-staging/v2"',
  '[[ "$dmg_sha" == "$(jq -r .dmg_sha256 "$ledger")" ]]',
  'personal-desktop-independent-remount-receipt.json',
  '[[ "$(find "$remount" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d \'[:space:]\')" == 1 ]]',
  '[[ "$(sha256sum "$remount_receipt" | awk \'{print $1}\')" == "${{ needs.remount.outputs.receipt_sha256 }}" ]]',
].each do |token|
  require_desktop(audit_download.include?(token), "Desktop exact attestation audit download omits #{token}")
end
require_desktop(audit_download.scan('--run-id "$GITHUB_RUN_ID"').length == 5, "Desktop audit downloads must all be constrained to the current run")
audit_trivy_steps = audit.fetch("steps").select { |step| step["uses"] == trivy_action }
require_desktop(audit_trivy_steps.length == 3, "Desktop audit must independently scan candidate, mounted-volume, and six-file attestation evidence")
audit_verification = desktop_step(audit, "Independently verify exact attestation against immutable DMG").fetch("run")
[
  'gh attestation verify "$dmg"',
  '--bundle "$input/personal-desktop-attestation-bundle.json"',
  '--predicate-type https://github.com/justinharkelroad/buzz/attestations/personal-desktop-staging/v2',
  '--source-digest "$GITHUB_SHA"', '--source-ref refs/heads/main',
  '--signer-workflow github.com/justinharkelroad/buzz/.github/workflows/personal-desktop-release.yml',
  '--signer-digest "$GITHUB_SHA"', '--deny-self-hosted-runners',
  'length == 1', '(.subject | type == "array" and length == 1)',
  '.subject[0] == {name: $name, digest: {sha256: $digest}}',
  '.predicate == $predicate[0]',
  'personal-desktop-attestation-audit-independent-verification.json',
].each do |token|
  require_desktop(audit_verification.include?(token), "Desktop no-OIDC independent attestation verification omits #{token}")
end
audit_scan_stage = desktop_step(audit, "Stage exact post-download audit scan inputs").fetch("run")
[
  'cp /tmp/personal-desktop-attestation-audit-input/*.json "$attestation/"',
  'cp /tmp/personal-desktop-attestation-audit-independent-verification.json "$attestation/"',
  'cp /tmp/personal-desktop-attestation-audit-remount/personal-desktop-independent-remount-receipt.json "$attestation/"',
  'cp -Rp /tmp/personal-desktop-attestation-audit-candidate/. "$candidate/"',
  'cp -Rp /tmp/personal-desktop-attestation-audit-volume/projection/. "$volume/"',
  '[[ "$(find "$attestation" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d \'[:space:]\')" == 6 ]]',
  '[[ "$(find "$candidate" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d \'[:space:]\')" == 10 ]]',
  '[[ -z "$(find "$volume" -type l -print -quit)" ]]',
  '[[ -z "$(find "$volume" -mindepth 1 ! -type d ! -type f -print -quit)" ]]',
].each do |token|
  require_desktop(audit_scan_stage.include?(token), "Desktop exact post-download audit staging omits #{token}")
end
expected_audit_scans = [
  ["Independently reject secrets in exact candidate evidence", "${{ steps.audit-scan-input.outputs.candidate }}", "/tmp/personal-desktop-attestation-audit-candidate-secret.json", false],
  ["Independently reject secrets in fresh volume projection evidence", "${{ steps.audit-scan-input.outputs.volume }}", "/tmp/personal-desktop-attestation-audit-volume-secret.json", true],
  ["Reject secrets in exact attestation evidence", "${{ steps.audit-scan-input.outputs.attestation }}", "/tmp/personal-desktop-attestation-audit-secret.json", true],
]
expected_audit_scans.each do |name, scan_ref, output, skip_setup|
  step = desktop_step(audit, name)
  expected_with = {
    "scan-type" => "fs", "scan-ref" => scan_ref, "scanners" => "secret",
    "format" => "json", "output" => output, "exit-code" => "1",
    "trivy-config" => "/tmp/personal-desktop-attestation-audit-trivy-policy/trivy.yaml",
    "trivyignores" => "/tmp/personal-desktop-attestation-audit-trivy-policy/trivy.ignore",
    "version" => "v0.70.0", "cache" => false,
  }
  expected_with["skip-setup-trivy"] = true if skip_setup
  require_desktop(step.fetch("with") == expected_with, "Desktop independent audit scan map drifted: #{name}")
end

restore = desktop_step(audit, "Restore exact protected terminal audit verifier after scanners")
require_desktop(restore["uses"] == checkout_action, "Desktop terminal audit verifier checkout pin drifted")
require_desktop(restore.fetch("with") == {
  "ref" => "${{ github.sha }}", "path" => "terminal-verifier",
  "fetch-depth" => 1, "persist-credentials" => false,
}, "Desktop terminal audit verifier must be a fresh exact-SHA checkout")
last_scan_index = expected_audit_scans.map { |name, _scan_ref, _output, _skip| desktop_step_index(audit, name) }.max
restore_index = desktop_step_index(audit, "Restore exact protected terminal audit verifier after scanners")
terminal_step = desktop_step(audit, "Terminally validate and cross-bind every attestation input")
terminal_index = desktop_step_index(audit, "Terminally validate and cross-bind every attestation input")
require_desktop(last_scan_index < restore_index && terminal_index == restore_index + 1, "Desktop must restore the protected verifier after all scanners and use it immediately")
require_desktop(terminal_step["working-directory"] == "terminal-verifier", "Desktop terminal audit validator must run from the restored exact-SHA checkout")
terminal = terminal_step.fetch("run")
[
  'schema: "personal-desktop-attestation-audit-expectations/v3"',
  'bind_scan_report \\',
  'diff -qr "$CANDIDATE_SCAN_ROOT" "$candidate"',
  'diff -qr "$VOLUME_SCAN_ROOT" "$volume/projection"',
  'cmp -s "$evidence" "$ATTESTATION_SCAN_ROOT/$(basename "$evidence")"',
  'personal-desktop-independent-remount-receipt.json',
  'bash ./deploy/personal-relay/validate-desktop-attestation-audit.sh',
  '--candidate-dir "$candidate"',
  '--inspection-dir /tmp/personal-desktop-attestation-audit-inspection',
  '--remount-dir /tmp/personal-desktop-attestation-audit-remount',
  '--volume-dir "$volume"',
  '--expectations "$expectations"',
  '--summary-output "$summary"',
  'gh attestation verify "$dmg"',
  'cmp -s "$terminal_verification" \\',
  '$ATTESTATION_SCAN_ROOT/personal-desktop-attestation-audit-independent-verification.json',
].each do |token|
  require_desktop(terminal.include?(token), "Desktop terminal audit cross-binding omits #{token}")
end
require_desktop(terminal.scan("bind_scan_report \\").length == 3, "Desktop terminal verifier must bind all three Trivy reports")
[
  'personal-desktop-attestation-audit-expectations/v3',
  'personal-desktop-attestation-audit-summary/v3',
  'require_exact_root_names "$candidate_dir"',
  'cmp -s "$volume_inventory" "$inspection_inventory"',
  'cmp -s "$volume_sidecar_manifest" "$sidecar_manifest"',
  'signed predicate is not an exact projection of immutable evidence',
].each do |token|
  require_desktop(audit_validator_text.include?(token), "Desktop restored cross-binding validator omits #{token}")
end
audit_binder = desktop_step(audit, "Bind zero-secret attestation audit").fetch("run")
[
  'schema: "personal-desktop-staging-attestation-audit/v4"',
  'attestation_artifact:', 'sealed_input_artifacts:',
  'candidate:', 'inspection:', 'mounted_volume:', 'independent_remount:',
  'bundle_sha256:', 'predicate_sha256:',
  'returned_predicate_sha256:', 'verification_sha256:',
  'independent_verification_sha256:', 'independent_remount_receipt_sha256:',
  'cross_binding:', 'expectations_sha256:', 'summary_sha256:',
  '.cross_binding.summary.schema == "personal-desktop-attestation-audit-summary/v3"',
  'secret_scans:',
  'attestation: {trivy_version: "0.70.0", report_sha256: $attestation_scan_sha}',
  'candidate: {trivy_version: "0.70.0", report_sha256: $candidate_scan_sha}',
  'mounted_volume: {trivy_version: "0.70.0", report_sha256: $volume_scan_sha}',
].each do |token|
  require_desktop(audit_binder.include?(token), "Desktop attestation audit receipt omits #{token}")
end
audit_stage = desktop_step(audit, "Stage exact attestation audit evidence").fetch("run")
[
  'personal-desktop-attestation-audit-receipt.json',
  'personal-desktop-attestation-audit-secret.json',
  'personal-desktop-attestation-audit-candidate-secret.json',
  'personal-desktop-attestation-audit-volume-secret.json',
  'personal-desktop-attestation-audit-independent-verification.json',
  'personal-desktop-independent-remount-receipt.json',
  'personal-desktop-attestation-audit-summary.json',
  '== 7',
].each do |token|
  require_desktop(audit_stage.include?(token), "Desktop seven-file terminal audit evidence omits #{token}")
end
audit_upload = desktop_step(audit, "Upload exact attestation audit evidence")
require_desktop(audit_upload["uses"] == upload_action, "Desktop attestation audit upload pin drifted")
require_desktop(audit_upload.fetch("with") == {
  "name" => "personal-desktop-staging-attestation-audit-${{ inputs.target }}-${{ github.sha }}",
  "path" => "${{ steps.audit-stage.outputs.path }}/",
  "if-no-files-found" => "error",
  "retention-days" => 14,
  "include-hidden-files" => false,
}, "Desktop attestation audit upload map drifted")
require_desktop(
  [
    "Download exact attestation evidence and sealed audit inputs",
    "Independently verify exact attestation against immutable DMG",
    "Stage exact post-download audit scan inputs",
    "Independently reject secrets in exact candidate evidence",
    "Independently reject secrets in fresh volume projection evidence",
    "Reject secrets in exact attestation evidence",
    "Restore exact protected terminal audit verifier after scanners",
    "Terminally validate and cross-bind every attestation input",
    "Bind zero-secret attestation audit",
    "Stage exact attestation audit evidence",
    "Upload exact attestation audit evidence",
    "Bind attestation audit artifact identity",
  ].map { |name| desktop_step_index(audit, name) }.each_cons(2).all? { |left, right| left < right },
  "Desktop post-attestation no-OIDC audit sequence drifted",
)
require_desktop(jobs.keys.last == "audit" && jobs.values.none? { |job| Array(job["needs"]).include?("audit") }, "Desktop audit must remain the terminal release-eligibility job")

# Execute the actual target-selection blocks through /bin/bash. macOS ships
# Bash 3.2, so local contract runs exercise the exact nounset behavior that
# made an empty array expansion fail; non-macOS CI still executes both branches
# under BASH_COMPAT=3.2 while the structural checks above ban that construct.
bash_version, bash_version_stderr, bash_version_status = Open3.capture3("/bin/bash", "-c", 'printf "%s.%s" "$BASH_VERSINFO" "${BASH_VERSINFO[1]}"')
require_desktop(bash_version_status.success?, "unable to identify /bin/bash for Desktop target fixtures: #{bash_version_stderr}")
if RUBY_PLATFORM.include?("darwin")
  require_desktop(bash_version == "3.2", "macOS Desktop fixture must execute with system Bash 3.2, found #{bash_version}")
end
dmg_split = dmg_build_run.split("\n# POST-BUILD DMG PARITY CHECK", 2)
require_desktop(dmg_split.length == 2, "Desktop DMG branch fixture could not isolate the post-build parity check")
require_desktop(dmg_build_run.include?("hdiutil attach"), "Desktop DMG parity check must mount the built DMG read-only")
require_desktop(dmg_build_run.include?("-readonly -nobrowse"), "Desktop DMG parity check must mount read-only and nobrowse")
require_desktop(dmg_build_run.include?("/usr/bin/diff -qr \"$snapshot_app\" \"$mounted_app\""), "Desktop DMG parity check must diff the snapshot against the mounted DMG payload")
require_desktop(dmg_build_run.include?("DMG payload differs from the snapshotted unpacked app"), "Desktop DMG parity check must fail loudly on payload drift")
require_desktop(dmg_build_run.include?("hdiutil detach"), "Desktop DMG parity check must detach the mounted volume")
fixture_scripts = {
  "candidate" => candidate_build_run,
  "dmg" => dmg_split.fetch(0) + "\n",
}
expected_target_output = {
  "aarch64-apple-darwin" => {
    "candidate" => [
      "tauri build --verbose --no-sign --target aarch64-apple-darwin --features mesh-llm --no-bundle --config src-tauri/tauri.personal-staging.conf.json",
      "tauri bundle --verbose --no-sign --target aarch64-apple-darwin --features mesh-llm --bundles app --config src-tauri/tauri.personal-staging.conf.json",
    ],
    "dmg" => [
      "tauri bundle --verbose --no-sign --target aarch64-apple-darwin --features mesh-llm --bundles dmg --config src-tauri/tauri.personal-staging.conf.json",
    ],
  },
  "x86_64-apple-darwin" => {
    "candidate" => [
      "tauri build --verbose --no-sign --target x86_64-apple-darwin --no-bundle --config src-tauri/tauri.personal-staging.conf.json",
      "tauri bundle --verbose --no-sign --target x86_64-apple-darwin --bundles app --config src-tauri/tauri.personal-staging.conf.json",
    ],
    "dmg" => [
      "tauri bundle --verbose --no-sign --target x86_64-apple-darwin --bundles dmg --config src-tauri/tauri.personal-staging.conf.json",
    ],
  },
}
repo_root = File.expand_path("../..", File.dirname(path))
expected_target_output.each do |target, expected_by_script|
  fixture_scripts.each do |label, script|
    harness = <<~BASH + script
      pnpm() { printf '%s\n' "$*"; }
    BASH
    stdout, stderr, status = Open3.capture3(
      {
        "BASH_COMPAT" => "3.2",
        "BUZZ_BUILD_AUTO_CONNECT_DEFAULT_RELAY" => "true",
        "BUZZ_BUILD_CHANNEL" => "personal-staging",
        "BUZZ_BUILD_DEEP_LINK_SCHEME" => "buzz-personal-staging",
        "DESKTOP_TARGET" => target,
        "VITE_BUZZ_BUILD_CHANNEL" => "personal-staging",
        "VITE_BUZZ_DEEP_LINK_SCHEME" => "buzz-personal-staging",
      },
      "/bin/bash", "-c", harness, chdir: repo_root,
    )
    require_desktop(status.success?, "Desktop Bash 3.2 #{label} fixture failed for #{target}: #{stderr}")
    require_desktop(stdout.lines.map(&:chomp) == expected_by_script.fetch(label), "Desktop Bash 3.2 #{label} command parity drifted for #{target}: #{stdout.inspect}")
  end
end

require "tmpdir"
symlink_fixture_root = Dir.mktmpdir("personal-desktop-symlink-contract.", "/tmp")
begin
  File.write(File.join(symlink_fixture_root, "payload.bin"), "fixture\n")
  File.symlink("payload.bin", File.join(symlink_fixture_root, "internal-link"))
  File.symlink("/etc/passwd", File.join(symlink_fixture_root, "external-link"))
  symlink_harness = <<~'BASH'
    set -euo pipefail
    canonical_mount_root=$(/bin/realpath "$FIXTURE_ROOT")
    [[ -d "$canonical_mount_root" && ! -L "$canonical_mount_root" ]]
    resolved=$(/bin/realpath "$FIXTURE_ROOT/$FIXTURE_LINK")
    case "$resolved" in
      "$canonical_mount_root"/*) printf '%s\n' accepted ;;
      *) printf '%s\n' rejected; exit 42 ;;
    esac
  BASH
  internal_stdout, internal_stderr, internal_status = Open3.capture3(
    {"FIXTURE_ROOT" => symlink_fixture_root, "FIXTURE_LINK" => "internal-link"},
    "/bin/bash", "-c", symlink_harness,
  )
  require_desktop(internal_status.success? && internal_stdout == "accepted\n", "canonical /tmp internal-symlink fixture failed: #{internal_stderr}")
  external_stdout, external_stderr, external_status = Open3.capture3(
    {"FIXTURE_ROOT" => symlink_fixture_root, "FIXTURE_LINK" => "external-link"},
    "/bin/bash", "-c", symlink_harness,
  )
  require_desktop(external_status.exitstatus == 42 && external_stdout == "rejected\n", "canonical /tmp external-symlink fixture failed closed incorrectly: #{external_stderr}")
ensure
  %w[internal-link external-link payload.bin].each do |entry|
    candidate = File.join(symlink_fixture_root, entry)
    File.unlink(candidate) if File.exist?(candidate) || File.symlink?(candidate)
  end
  Dir.rmdir(symlink_fixture_root) if Dir.exist?(symlink_fixture_root)
end
RUBY
}

validate_gate1_flow() {
  ruby -E UTF-8:UTF-8 -rpsych - "$gate1_workflow" <<'RUBY'
path = ARGV.fetch(0)
workflow = Psych.safe_load_file(path, aliases: false)
workflow_text = File.read(path)
jobs = workflow.fetch("jobs")

def require_gate1(condition, message)
  abort message unless condition
end

def gate1_step(job, name)
  matches = job.fetch("steps").select { |step| step["name"] == name }
  abort "expected exactly one Gate 1 step named #{name.inspect}" unless matches.length == 1
  matches.fetch(0)
end

def gate1_step_index(job, name)
  job.fetch("steps").index(gate1_step(job, name))
end

source = jobs.fetch("source-tests")
proof = jobs.fetch("source-proof")
validate = jobs.fetch("validate")
attest = jobs.fetch("attest")

capture_controls = gate1_step(validate, "Capture exact run and protected environment evidence").fetch("run")
[
  "protection/required_pull_request_reviews",
  "classic_required_pull_request_reviews: false",
  "def canonical:",
  "parameters: (.parameters | canonical)",
  'sort_by(.ruleset_id // 0, .type, (.parameters | tojson)',
  'bypass_actors: (.bypass_actors | sort_by(.actor_type // "", .actor_id // 0, .bypass_mode // ""))',
  'protection_rules: [.protection_rules[]] | sort_by(.type)',
  'select(.type == "required_reviewers")] | length) == 0',
  '.actor.login == "justinharkelroad"',
  '.triggering_actor.login == "justinharkelroad"',
  "deployment-branch-policies",
  "validate-main-protection.sh",
].each do |token|
  require_gate1(capture_controls.include?(token), "Gate 1 protected-control capture lacks deterministic evidence binding: #{token}")
end
require_gate1(workflow_text.scan('protection/required_pull_request_reviews').length == 2, "Gate 1 sealed/live branch evidence must prove classic review protection is absent twice")
require_gate1(workflow_text.scan('classic_required_pull_request_reviews: false').length == 2, "Gate 1 sealed/live branch evidence must record classic review absence twice")
require_gate1(workflow_text.scan("def canonical:").length == 2, "Gate 1 sealed/live effective-rule evidence must recursively canonicalize parameter objects")
require_gate1(workflow_text.scan('sort_by(.ruleset_id // 0, .type, (.parameters | tojson), .ruleset_source_type, .ruleset_source)').length == 2, "Gate 1 sealed/live effective rules must share one deterministic order")
require_gate1(!workflow_text.include?(".parameters | tostring"), "Gate 1 must not sort parameter objects by insertion-order-sensitive tostring")
require_gate1(workflow_text.scan('bypass_actors: (.bypass_actors | sort_by(.actor_type // "", .actor_id // 0, .bypass_mode // ""))').length == 2, "Gate 1 sealed/live ruleset bypass actors must share one deterministic order")
require_gate1(workflow_text.scan('RULESET_EVIDENCE_TOKEN: ${{ secrets.PERSONAL_RULESET_EVIDENCE_TOKEN }}').length == 2, "both Gate 1 ruleset-detail captures must receive the evidence token")
require_gate1(workflow_text.scan('GH_TOKEN="$RULESET_EVIDENCE_TOKEN" gh api --hostname github.com').length == 2, "Gate 1 ruleset token must be scoped only to the two ruleset detail GETs")

expected_source_steps = [
  "Checkout only the exact published source",
  "Verify unprivileged source-test invocation",
  "Activate exact source Hermit toolchain",
  "Run exact relay and ACP authorization acceptance tests"
]
require_gate1(source.fetch("services") == {
  "postgres" => {
    "image" => "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193",
    "env" => {
      "POSTGRES_DB" => "buzz",
      "POSTGRES_PASSWORD" => "buzz_dev",
      "POSTGRES_USER" => "buzz",
    },
    "ports" => ["5432:5432"],
    "options" => '--health-cmd "pg_isready -U buzz -d buzz" --health-interval 5s --health-timeout 5s --health-retries 12',
  },
  "redis" => {
    "image" => "redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2",
    "ports" => ["6379:6379"],
    "options" => '--health-cmd "redis-cli ping" --health-interval 5s --health-timeout 5s --health-retries 12',
  },
}, "Gate 1 candidate service fixtures must use the exact reviewed Postgres and Redis indexes and health contracts")
require_gate1(!source.key?("outputs"), "candidate source-test job must not expose outputs")
require_gate1(source.fetch("steps").map { |step| step["name"] } == expected_source_steps, "candidate source-test step set/order drifted")
require_gate1(source.fetch("steps").last["name"] == expected_source_steps.last, "candidate execution must be the final declared source-test step")
require_gate1(source.fetch("steps").none? { |step| step["uses"].to_s.include?("upload-artifact") }, "candidate source-test job must not publish artifacts")
require_gate1(!source.to_s.include?("GITHUB_OUTPUT"), "candidate source-test job must not emit trusted outputs")
source_run = gate1_step(source, expected_source_steps.last).fetch("run")
[
  "cargo run --locked -p buzz-admin -- migrate",
  "cargo test --locked -p buzz-relay",
  "workflow_sink::integration_tests::workflow_send_message_p_tags_mentioned_member",
  'cargo test --locked -p buzz-acp "$full_name" -- --exact',
  "require_exact_test()",
  "--list --format terse",
  "grep -Fxc --",
  '[[ "$match_count" == 1 ]]',
  "expected exactly one listed Rust test",
  'require_exact_test buzz-relay "$relay_test" ignored',
  'require_exact_test buzz-acp "$full_name" normal',
  'require_exact_test buzz-acp "$acp_nip11_test" normal',
  'require_exact_test buzz-core "$core_test" normal',
  'require_exact_test buzz-relay "$full_name" normal',
  'require_exact_test buzz-admin "$admin_reconcile_test" ignored',
  'require_exact_test buzz-db "$db_test" ignored',
  'require_exact_test buzz-core "$core_group_role_test" normal',
  'require_exact_test buzz-core "$core_relay_only_test" normal',
  'require_exact_test buzz-relay "$relay_client_discovery_test" normal',
  'require_exact_test buzz-acp "$acp_membership_discovery_test" normal',
  'require_exact_test buzz-acp "$acp_metadata_discovery_test" normal',
  'require_exact_test buzz-core "$core_membership_notification_test" normal',
  'require_exact_test buzz-core "$core_metadata_content_test" normal',
  'require_exact_test buzz-acp "$acp_current_membership_test" normal',
  'require_exact_test buzz-acp "$acp_metadata_shadow_test" normal',
  'require_exact_test buzz-acp "$acp_verified_dm_metadata_test" normal',
  'require_exact_test buzz-acp "$acp_membership_recheck_test" normal',
  'require_exact_test buzz-acp "$acp_setup_membership_test" normal',
  'require_exact_test buzz-acp "$acp_pool_wrong_signer_test" normal',
  'require_exact_test buzz-acp "$acp_pool_malformed_head_test" normal',
  'require_exact_test buzz-relay "$relay_reconciliation_matcher_test" normal',
  'require_exact_test buzz-relay "$relay_missing_members_repair_test" ignored',
  'require_exact_test buzz-admin "$admin_missing_members_repair_test" ignored',
  'require_exact_test buzz-db "$db_duplicate_participants_test" normal',
  'require_exact_test buzz-db "$db_migration_contract_test" normal',
  'require_exact_test buzz-acp "$acp_setup_stale_add_test" normal',
  'require_exact_test buzz-acp "$acp_setup_stale_remove_test" normal',
  'require_exact_test buzz-acp "$acp_readd_subscription_test" normal',
  'require_exact_test buzz-acp "$acp_membership_retry_cap_test" normal',
  'require_exact_test buzz-acp "$acp_readd_background_repair_test" normal',
  'require_exact_test buzz-acp "$acp_exhausted_remove_policy_test" normal',
  'require_exact_test buzz-acp "$acp_membership_removal_cleanup_test" normal',
  'require_exact_test buzz-acp "$acp_setup_exhausted_remove_test" normal',
  'cargo test --locked -p buzz-acp "$acp_nip11_test" -- --exact',
  'cargo test --locked -p buzz-core "$core_test" -- --exact',
  'cargo test --locked -p buzz-admin "$admin_reconcile_test" -- --ignored --exact --test-threads=1',
  'cargo test --locked -p buzz-db "$db_test" -- --ignored --exact --test-threads=1',
  'cargo test --locked -p buzz-core "$core_group_role_test" -- --exact',
  'cargo test --locked -p buzz-core "$core_relay_only_test" -- --exact',
  'cargo test --locked -p buzz-relay "$relay_client_discovery_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_membership_discovery_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_metadata_discovery_test" -- --exact',
  'cargo test --locked -p buzz-core "$core_membership_notification_test" -- --exact',
  'cargo test --locked -p buzz-core "$core_metadata_content_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_current_membership_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_metadata_shadow_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_verified_dm_metadata_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_membership_recheck_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_setup_membership_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_pool_wrong_signer_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_pool_malformed_head_test" -- --exact',
  'cargo test --locked -p buzz-relay "$relay_reconciliation_matcher_test" -- --exact',
  'cargo test --locked -p buzz-relay "$relay_missing_members_repair_test" -- --ignored --exact --test-threads=1',
  'cargo test --locked -p buzz-admin "$admin_missing_members_repair_test" -- --ignored --exact --test-threads=1',
  'cargo test --locked -p buzz-db "$db_duplicate_participants_test" -- --exact',
  'cargo test --locked -p buzz-db "$db_migration_contract_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_setup_stale_add_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_setup_stale_remove_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_readd_subscription_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_membership_retry_cap_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_readd_background_repair_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_exhausted_remove_policy_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_membership_removal_cleanup_test" -- --exact',
  'cargo test --locked -p buzz-acp "$acp_setup_exhausted_remove_test" -- --exact'
].each { |token| require_gate1(source_run.include?(token), "candidate source-test command contract is missing #{token}") }

require_gate1(proof["needs"] == "source-tests", "clean source proof must depend directly on source-tests")
require_gate1(proof.fetch("if").include?("needs.source-tests.result == 'success'"), "clean source proof must require the GitHub-controlled source-test result")
require_gate1(!proof.key?("services"), "clean source proof must use a fresh runner without candidate services")
proof_checkout = gate1_step(proof, "Checkout only the protected Gate 1 verifier")
require_gate1(proof_checkout.dig("with", "ref") == "${{ github.sha }}", "clean source proof must checkout the protected verifier SHA")
require_gate1(proof_checkout.dig("with", "fetch-depth") == 0, "clean source proof must fetch ancestry for the released source")
require_gate1(proof_checkout.dig("with", "persist-credentials") == false, "clean source proof must not persist checkout credentials")
expected_proof_steps = [
  "Checkout only the protected Gate 1 verifier",
  "Verify clean source-proof invocation",
  "Fetch and validate GitHub-controlled source-test result",
  "Re-run trusted non-candidate Gate 1 contract validation",
  "Seal exact control-plane source-test result binding",
  "Create fail-closed source-proof secret-scan policy",
  "Scan sealed source-test proof for secrets before upload",
  "Bind zero-secret source-test proof report",
  "Upload one clean sealed source-test result directory",
  "Validate sealed source-test artifact outputs"
]
require_gate1(proof.fetch("steps").map { |step| step["name"] } == expected_proof_steps, "clean source-proof step set/order drifted")
fetch_result = gate1_step(proof, "Fetch and validate GitHub-controlled source-test result").fetch("run")
%w[--hostname\ github.com attempts/1/jobs source-test-job.json source-test-run.json protected-workflow.yml].each do |token|
  require_gate1(fetch_result.include?(token.tr("\\", "")), "clean source-result fetch is missing #{token.tr("\\", "")}")
end
%w[source-tests\ must\ not\ declare\ job\ outputs candidate\ execution\ must\ be\ the\ final\ workflow\ step source-tests\ must\ not\ publish\ an\ artifact].each do |token|
  require_gate1(fetch_result.include?(token.tr("\\", "")), "clean source isolation assertion is missing #{token.tr("\\", "")}")
end
seal = gate1_step(proof, "Seal exact control-plane source-test result binding").fetch("run")
%w[personal-relay-gate1-source-result/v6 github-controlled-protected-job-conclusion candidate_output_trusted protected_workflow_sha256 source_test_job_metadata_sha256 test_contract trusted_validation].each do |token|
  require_gate1(seal.include?(token), "v6 source-result seal is missing #{token}")
end
%w[
  buzz-admin-migrate buzz-relay-workflow-owner-attribution
  author_gate_tests::trusted_relay_workflow_uses_attributed_owner_for_author_gate
  author_gate_tests::forged_workflow_marker_cannot_replace_actual_signer
  author_gate_tests::relay_signed_non_workflow_event_cannot_replace_actual_signer
  author_gate_tests::missing_trusted_relay_identity_fails_closed_to_actual_signer
  author_gate_tests::invalid_signature_fails_closed_to_actual_signer
  author_gate_tests::wrong_kind_fails_closed_to_actual_signer
  author_gate_tests::duplicate_actor_or_workflow_tags_fail_closed_to_actual_signer
  author_gate_tests::test_allowlist_accepts_explicit_external_pubkey
  author_gate_tests::test_allowlist_rejects_non_sibling_not_in_allowlist
  author_gate_tests::test_owner_only_rejects_stranger_so_no_steer
  author_gate_tests::test_dm_accepts_explicit_allowlisted_external_pubkey
  author_gate_tests::test_dm_rejects_allowlisted_external_pubkey_in_group
  author_gate_tests::test_dm_rejects_external_pubkey_absent_from_allowlist
  author_gate_tests::test_dm_rejects_stranger_under_anyone
  author_gate_tests::test_author_gate_resolver_caches_verified_immutable_dm_metadata
  author_gate_tests::test_author_gate_unknown_metadata_is_immediate_singleflight_and_backed_off
  author_gate_tests::test_dynamic_dm_prefetch_accepts_first_replayed_allowlisted_message
  relay::tests::nip11_identity_lookup_retries_boundedly_and_recovers
  dm::tests::relay_channel_metadata_verifier_is_strict_and_fail_closed
  handlers::side_effects::tests::immutable_dm_admin_routes_reject_in_place_membership_and_visibility_mutations
  handlers::side_effects::tests::immutable_dm_discovery_tags_are_sorted_and_committed
  handlers::side_effects::tests::immutable_dm_reconciliation_matcher_rejects_unmarked_metadata
  nip11::tests::nip11_dev_fallback_identity_is_advertised_for_harness_verification
  tests::channel_reconciliation_schedule_is_durable_beyond_legacy_startup_window
  tests::reconcile_replacement_bumps_past_trusted_wrong_d_and_ignores_wrong_signer
  dm::tests::immutable_dm_database_guards_reject_mutations_and_allow_create_dm
  dm::tests::relay_group_role_discovery_verifier_is_strict_and_fail_closed
  kind::tests::nip29_relay_authored_discovery_snapshots_are_relay_only
  handlers::ingest::tests::relay_authored_discovery_and_membership_triggers_are_rejected_from_client_ingest
  relay::tests::membership_discovery_rejects_forged_invalid_or_stale_snapshots
  relay::tests::merge_discovered_channels_omits_missing_wrong_signer_and_malformed_metadata
  dm::tests::relay_membership_notification_verifier_is_strict_and_target_bound
  dm::tests::relay_channel_metadata_rejects_signed_nonempty_content
  relay::tests::current_membership_state_is_tri_state_and_stale_notification_safe
  relay::tests::merge_discovered_channels_newer_malformed_coordinate_shadows_older_valid_metadata
  relay::tests::merge_discovered_channels_accepts_only_fully_verified_dm_metadata
  relay::tests::membership_recheck_command_reopens_trigger_dedup_without_losing_replay_floor
  setup_mode::tests::setup_membership_notifications_requery_current_signed_39002
  pool::tests::lazy_metadata_lookup_ignores_newer_wrong_signer_sibling
  pool::tests::lazy_metadata_lookup_newer_malformed_trusted_head_shadows_older_valid
  handlers::side_effects::tests::channel_reconciliation_matcher_rejects_wrong_signer_or_stale_regular_metadata
  handlers::side_effects::tests::channel_reconciliation_repairs_missing_members_snapshot_with_valid_metadata
  tests::reconcile_channels_repairs_missing_members_snapshot_with_valid_metadata
  dm::tests::create_dm_rejects_duplicate_participants_before_opening_transaction
  migration::tests::immutable_dm_migration_contract_is_embedded
  setup_mode::tests::setup_membership_stale_add_cannot_override_current_removal_snapshot
  setup_mode::tests::setup_membership_stale_remove_cannot_override_current_member_snapshot
  relay::tests::verified_member_requires_ensure_subscribe_despite_stale_outer_tracking
  relay::tests::membership_unknown_retry_is_bounded_and_distinct_readd_remains_processable
  relay::tests::readd_ensure_subscribe_repairs_closed_drop_despite_stale_outer_tracking
  relay::tests::exhausted_remove_fails_closed_but_add_waits_for_distinct_repair
  membership_removal_cleanup_tests::authoritative_nonmember_and_exhausted_remove_share_full_cleanup_path
  setup_mode::tests::setup_exhausted_remove_fails_closed_through_unsubscribe_path
].each { |id| require_gate1(seal.include?(id), "v6 source-result command contract is missing #{id}") }
proof_upload = gate1_step(proof, "Upload one clean sealed source-test result directory")
require_gate1(proof_upload.dig("with", "path") == "/tmp/personal-relay-gate1-source-proof", "clean source-proof upload path drifted")

require_gate1(validate.fetch("needs").include?("source-proof") && !validate.fetch("needs").include?("source-tests"), "protected validation must consume only the clean source proof")
receipt_run = gate1_step(validate, "Validate all exact evidence and issue a non-deploying receipt").fetch("run")
require_gate1(receipt_run.include?("--source-test-result /tmp/personal-relay-gate1-source-proof/source-test-result.json"), "Gate 1 receipt does not consume the v6 source result")
%w[--authorization-tests --authorization-relay-log --authorization-acp-log].each do |legacy|
  require_gate1(!receipt_run.include?(legacy), "Gate 1 receipt still consumes legacy candidate proof #{legacy}")
end
stage = gate1_step(validate, "Seal validation evidence into one dedicated directory").fetch("run")
%w[
  source-test-result.json source-test-job.json source-test-run.json protected-workflow.yml
  trusted-gate1-receipt-fixtures.log trusted-release-contract-fixtures.log
  personal-relay-release-main-branch.json personal-relay-release-main-effective-rules.json
  personal-relay-release-main-rulesets.json personal-relay-release-environment.json
  personal-relay-release-branch-policies.json personal-relay-release-run-identity.json
  personal-relay-release-authorization.json
].each do |file|
  require_gate1(stage.include?(file), "sealed Gate 1 validation evidence omits #{file}")
end
release_download = gate1_step(validate, "Download exact approved release evidence archive").fetch("run")
%w[
  personal-relay-release-authorization.json
  personal-relay-release-branch-policies.json
  personal-relay-release-environment.json
  personal-relay-release-main-branch.json
  personal-relay-release-main-effective-rules.json
  personal-relay-release-main-rulesets.json
  personal-relay-release-run-identity.json
].each do |file|
  require_gate1(release_download.include?(file), "Gate 1 exact release-authorization inventory omits #{file}")
end
%w[expected_authorization_files actual_authorization_files -mindepth -maxdepth cmp\ -s].each do |token|
  require_gate1(release_download.include?(token.tr("\\", "")), "Gate 1 exact release-authorization inventory lacks #{token.tr("\\", "")}")
end

live_name = "Re-fetch and byte-compare live protections immediately before attestation"
live_index = gate1_step_index(attest, live_name)
attest_index = gate1_step_index(attest, "Attest receipt as the exact image custom predicate")
require_gate1(live_index + 1 == attest_index, "live Gate 1 protections must be revalidated immediately before OIDC attestation")
live = gate1_step(attest, live_name).fetch("run")
%w[--hostname\ github.com validate-main-protection.sh main-effective-rules main-rulesets environment-branch-policies cmp].each do |token|
  require_gate1(live.include?(token.tr("\\", "")), "live Gate 1 revalidation is missing #{token.tr("\\", "")}")
end
[
  "protection/required_pull_request_reviews",
  "classic_required_pull_request_reviews: false",
  "def canonical:",
  "parameters: (.parameters | canonical)",
  'sort_by(.ruleset_id // 0, .type, (.parameters | tojson)',
  'bypass_actors: (.bypass_actors | sort_by(.actor_type // "", .actor_id // 0, .bypass_mode // ""))',
  'cmp -s "$live/main-branch.json"',
  '"$sealed/personal-relay-main-branch.json"',
  'cmp -s "$live/main-effective-rules.json"',
  '"$sealed/personal-relay-main-effective-rules.json"',
  'cmp -s "$live/main-rulesets.json"',
  '"$sealed/personal-relay-gate1-main-rulesets.json"',
].each do |token|
  require_gate1(live.include?(token), "Gate 1 final live evidence lacks deterministic exact comparison: #{token}")
end
require_gate1(!live.include?("main-branch.canonical.json") && !live.include?(".parameters | tostring"), "Gate 1 final live comparison must use already-canonical stable evidence directly")
live_step = gate1_step(attest, live_name)
require_gate1(live_step.dig("env", "BASH_ENV") == "" && live_step.dig("env", "ENV") == "", "Gate 1 final live guard must clear shell startup hooks")
%w[
  eligibility_expires_at
  release_evidence.expires_at
  release_evidence.release_authorization.evidence_artifact.expires_at
].each do |field|
  require_gate1(live.scan(field).length == 1, "Gate 1 terminal deadline block must check #{field} exactly once")
end
require_gate1(live.scan("fromdateiso8601").length == 3, "Gate 1 terminal deadline block must contain exactly three minimum-validity comparisons")
require_gate1(live.scan("+ 1500").length == 1, "Gate 1 terminal deadline block must require exactly 1500 seconds of remaining validity")
require_gate1(live.index("fromdateiso8601") > live.rindex("cmp -s"), "Gate 1 deadline block must follow the final environment/policy byte comparison")
require_gate1(live.rstrip.end_with?('\' "$sealed/personal-relay-gate1-receipt.json" >/dev/null'), "Gate 1 deadline block must be the terminal pre-OIDC command")

attest_action = gate1_step(attest, "Attest receipt as the exact image custom predicate")
require_gate1(attest_action["uses"] == "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d", "Gate 1 custom attestation action pin drifted")
require_gate1(attest_action.fetch("with") == {
  "subject-name" => "${{ inputs.image_name }}",
  "subject-digest" => "${{ inputs.image_digest }}",
  "predicate-type" => "https://github.com/justinharkelroad/buzz/attestations/personal-relay-gate1/v1",
  "predicate-path" => "/tmp/personal-relay-gate1-validation-evidence/personal-relay-gate1-receipt.json",
  "push-to-registry" => false,
  "show-summary" => false,
}, "Gate 1 custom attestation subject, predicate, or side-effect contract drifted")
verification_step = gate1_step(attest, "Verify exact custom receipt attestation without executing the image")
verification = verification_step.fetch("run")
[
  '--bundle /tmp/personal-relay-gate1-attestation-bundle.json',
  '--predicate-type https://github.com/justinharkelroad/buzz/attestations/personal-relay-gate1/v1',
  '--source-digest "$GITHUB_SHA"',
  '--source-ref "$GITHUB_REF"',
  '--signer-workflow github.com/justinharkelroad/buzz/.github/workflows/personal-relay-gate1.yml',
  '--signer-digest "$GITHUB_SHA"',
  "length == 1",
  'any(.subject[]?; .name == $image and .digest.sha256 == $digest)',
  '.predicate == $receipt[0]',
].each do |token|
  require_gate1(verification.include?(token), "Gate 1 emitted-bundle verification is missing #{token}")
end
require_gate1(verification_step.dig("env", "BUNDLE_PATH") == "${{ steps.attest-receipt.outputs.bundle-path }}", "Gate 1 verifier must consume the exact emitted custom-attestation bundle")
require_gate1(gate1_step_index(attest, "Verify exact custom receipt attestation without executing the image") == attest_index + 1, "Gate 1 custom attestation must be verified immediately")

jobs.each do |job_name, job|
  job.fetch("steps", []).each do |step|
    run = step.fetch("run", "")
    api_calls = run.scan(/\bgh api\b/).length
    require_gate1(api_calls == run.scan(/\bgh api\s+(?:\\\s*)?--hostname github\.com\b/).length, "Gate 1 gh api call is not pinned to github.com: #{job_name}: #{step["name"]}")
    attestation_calls = run.scan(/\bgh attestation verify\b/).length
    next if attestation_calls.zero?
    require_gate1(run.scan(/--hostname github\.com/).length >= attestation_calls, "Gate 1 gh attestation call is not pinned to github.com: #{job_name}: #{step["name"]}")
  end
end
RUBY
}

validate_main_protection_callers() {
  ruby -E UTF-8:UTF-8 -rpsych - "$relay_workflow" "$gate1_workflow" "$desktop_workflow" <<'RUBY'
ARGV.each do |path|
  workflow = Psych.safe_load_file(path, aliases: false)
  calls = workflow.fetch("jobs").values.flat_map { |job| job.fetch("steps", []) }
    .filter_map { |step| step["run"] if step.fetch("run", "").include?("validate-main-protection.sh") }
  abort "workflow lost all protected-main validator calls: #{path}" if calls.empty?
  calls.each do |run|
    abort "protected-main call omits ruleset evidence: #{path}" unless run.include?("--rulesets-json")
    abort "protected-main call does not bind exact repository: #{path}" unless run.include?("--expected-repository justinharkelroad/buzz")
  end
end
RUBY
}

validate_workflow_run_syntax() {
  ruby -E UTF-8:UTF-8 -rpsych -ropen3 - "$relay_workflow" "$gate1_workflow" "$desktop_workflow" <<'RUBY'
ARGV.each do |path|
  workflow = Psych.safe_load_file(path, aliases: false)
  workflow.fetch("jobs").each do |job_name, job|
    job.fetch("steps", []).each_with_index do |step, index|
      next unless step["run"]

      script = step["run"].gsub(/\$\{\{.*?\}\}/m, "GITHUB_EXPRESSION")
      _stdout, stderr, status = Open3.capture3("bash", "-n", stdin_data: script)
      abort "invalid bash run block #{path}:#{job_name}:step#{index + 1}: #{stderr}" unless status.success?
    end
  end
end
RUBY
}

validate_trivy_policy_inputs() {
  local release_yaml=$1
  local gate1_yaml=$2
  local desktop_yaml=$3
  ruby -E UTF-8:UTF-8 -rpsych - "$release_yaml" "$gate1_yaml" "$desktop_yaml" <<'RUBY'
release_yaml, gate1_yaml, desktop_yaml = ARGV
trivy_action = "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25"
expected_outputs = {
  release_yaml => [
    "/tmp/personal-relay-release-authorization-secret.json",
    "personal-relay-trivy-image-${{ matrix.arch }}.json",
    "personal-relay-trivy-sbom-${{ matrix.arch }}.json",
    "/tmp/personal-relay-scan-secret-${{ matrix.arch }}.json",
    "/tmp/personal-relay-final-evidence-secret.json"
  ],
  gate1_yaml => [
    "/tmp/personal-relay-gate1-pr-approval-secret.json",
    "/tmp/personal-relay-gate1-source-proof-secret.json",
    "/tmp/personal-relay-gate1-image-proof/personal-relay-trivy-secret-amd64.json",
    "/tmp/personal-relay-gate1-image-proof/personal-relay-trivy-secret-arm64.json",
    "/tmp/personal-relay-gate1-image-proof-secret.json",
    "/tmp/personal-relay-gate1-approval-secret.json",
    "/tmp/personal-relay-gate1-validation-evidence-secret.json",
    "/tmp/personal-relay-gate1-final-evidence-secret.json"
  ],
  desktop_yaml => [
    "/tmp/personal-desktop-inspection-staging-secret.json",
    "/tmp/personal-desktop-inspection-volume-secret.json",
    "/tmp/personal-desktop-attestation-audit-candidate-secret.json",
    "/tmp/personal-desktop-attestation-audit-volume-secret.json",
    "/tmp/personal-desktop-attestation-audit-secret.json"
  ]
}
safe_inherited_trivy_env = {
  "TRIVY_DISABLE_TELEMETRY" => "true",
  "TRIVY_OFFLINE_SCAN" => "true",
  "TRIVY_SKIP_VERSION_CHECK" => "true",
  "TRIVY_SKIP_VEX_REPO_UPDATE" => "true"
}

class TrivyContractError < StandardError; end

def trusted_tmp_path?(path)
  return false unless path.is_a?(String)

  components = path.delete_prefix("/").split("/", -1)
  path.match?(%r{\A/tmp/[A-Za-z0-9._/${} -]+\z}) &&
    components.none? { |component| component.empty? || component == "." || component == ".." }
end

def require_contract(condition, message)
  raise TrivyContractError, message unless condition
end

def validate_trivy_step(step, inherited_env, expected_outputs, trivy_action, label)
  require_contract(step["uses"] == trivy_action, "Trivy action is not pinned exactly: #{label}")
  inputs = step["with"]
  require_contract(inputs.is_a?(Hash), "Trivy step needs a structural with map: #{label}")
  environment = step.fetch("env", {})
  require_contract(environment.is_a?(Hash), "Trivy step needs a structural env map: #{label}")

  inherited_trivy = inherited_env.select { |key, _| key.start_with?("TRIVY_") }
  inherited_trivy.each do |key, value|
    require_contract(value == {
      "TRIVY_DISABLE_TELEMETRY" => "true",
      "TRIVY_OFFLINE_SCAN" => "true",
      "TRIVY_SKIP_VERSION_CHECK" => "true",
      "TRIVY_SKIP_VEX_REPO_UPDATE" => "true"
    }[key], "unapproved inherited Trivy environment #{key}: #{label}")
  end

  require_contract(inputs["version"] == "v0.70.0", "Trivy version drifted: #{label}")
  require_contract(inputs["cache"] == false, "Trivy action cache must be false: #{label}")
  require_contract(inputs["format"] == "json", "Trivy output must be JSON: #{label}")
  require_contract(expected_outputs.include?(inputs["output"]), "unknown Trivy evidence output #{inputs["output"].inspect}: #{label}")
  require_contract(trusted_tmp_path?(inputs["trivy-config"]), "Trivy config is not trusted /tmp input: #{label}")
  require_contract(trusted_tmp_path?(inputs["trivyignores"]), "Trivy ignore file is not trusted /tmp input: #{label}")
  require_contract(inputs["trivy-config"] != inputs["trivyignores"], "Trivy policy files overlap: #{label}")

  case inputs["scanners"]
  when "secret"
    selector_keys = if inputs.key?("image-ref")
                      ["image-ref"]
                    else
                      require_contract(inputs["scan-type"] == "fs", "secret filesystem scan type drifted: #{label}")
                      require_contract(trusted_tmp_path?(inputs["scan-ref"]) || inputs["scan-ref"].to_s.start_with?("${{"), "secret scan-ref is not sealed: #{label}")
                      ["scan-ref", "scan-type"]
                    end
    expected_keys = %w[cache exit-code format output scanners trivy-config trivyignores version] + selector_keys
    if inputs.key?("skip-setup-trivy")
      require_contract(inputs["skip-setup-trivy"] == true, "skip-setup-trivy must be exactly true: #{label}")
      expected_keys << "skip-setup-trivy"
    end
    require_contract(inputs.keys.sort == expected_keys.sort, "secret Trivy with map has suppressor or drift: #{label}: #{inputs.keys.sort.inspect}")
    require_contract(inputs["exit-code"] == "1", "secret Trivy scan must block findings: #{label}")
    expected_env = {
      "TRIVY_CONFIG" => inputs["trivy-config"],
      "TRIVY_IGNOREFILE" => inputs["trivyignores"]
    }
    secret_config = environment["TRIVY_SECRET_CONFIG"]
    require_contract(trusted_tmp_path?(secret_config), "secret config is not a trusted /tmp file: #{label}")
    expected_env["TRIVY_SECRET_CONFIG"] = secret_config
    if inputs.key?("image-ref")
      require_contract(!environment.key?("TRIVY_PLATFORM"), "secret image-ref scan must not rely on TRIVY_PLATFORM (aquasecurity/trivy-action ignores it for the secret scanner; scope the scan with a platform-digest-qualified image-ref instead): #{label}")
    end
    require_contract(environment == expected_env, "secret Trivy env has suppressor or drift: #{label}: #{environment.inspect}")
    require_contract([inputs["trivy-config"], inputs["trivyignores"], secret_config].uniq.length == 3, "secret policy files overlap: #{label}")
  when "vuln"
    common = %w[cache exit-code format list-all-pkgs output scanners severity trivy-config trivyignores version vuln-type]
    if inputs.key?("image-ref")
      expected_keys = common + ["image-ref"]
      require_contract(environment.keys == ["TRIVY_PLATFORM"], "image vulnerability env drifted: #{label}")
      require_contract(environment["TRIVY_PLATFORM"] == "linux/${{ matrix.arch }}", "image vulnerability platform drifted: #{label}")
    else
      expected_keys = common + %w[scan-ref scan-type skip-setup-trivy]
      require_contract(inputs["scan-type"] == "sbom" && inputs["skip-setup-trivy"] == true, "SBOM vulnerability mode drifted: #{label}")
      require_contract(environment == {"TRIVY_SKIP_DB_UPDATE" => "true", "TRIVY_SKIP_JAVA_DB_UPDATE" => "true"}, "SBOM vulnerability env drifted: #{label}")
    end
    require_contract(inputs.keys.sort == expected_keys.sort, "vulnerability Trivy with map has suppressor or drift: #{label}: #{inputs.keys.sort.inspect}")
    require_contract(inputs["exit-code"] == "0", "raw vulnerability export must not hide its report: #{label}")
    require_contract(inputs["vuln-type"] == "os,library", "vulnerability types drifted: #{label}")
    require_contract(inputs["severity"] == "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "vulnerability severity union drifted: #{label}")
    require_contract(inputs["list-all-pkgs"] == true, "vulnerability package union must be complete: #{label}")
  else
    raise TrivyContractError, "unapproved scanner set #{inputs["scanners"].inspect}: #{label}"
  end
end

expected_outputs.each do |path, outputs|
  workflow = Psych.safe_load_file(path, aliases: false)
  root_env = workflow.fetch("env", {})
  observed = []
  deferred_desktop_uploads = []
  workflow.fetch("jobs").each do |job_name, job|
    inherited_env = root_env.merge(job.fetch("env", {}))
    steps = job.fetch("steps", [])
    steps.each_with_index do |step, index|
      next unless step["uses"].to_s.start_with?("aquasecurity/trivy-action@")

      label = "#{path}:#{job_name}:step#{index + 1}"
      validate_trivy_step(step, inherited_env, outputs, trivy_action, label)
      observed << step.fetch("with").fetch("output")
    end
    steps.each_with_index do |step, upload_index|
      next unless step["uses"].to_s.start_with?("actions/upload-artifact@")

      artifact_name = step.dig("with", "name").to_s
      artifact_path = step.dig("with", "path").to_s
      digest_only = artifact_name.start_with?("personal-relay-digest-") &&
        artifact_path == "/tmp/personal-relay-digests/*"
      next if digest_only

      desktop_post_seal_scan_handoff = path == desktop_yaml && [
        ["build", "${{ steps.authorization-name.outputs.name }}", "/tmp/personal-desktop-authorization-evidence/"],
        ["build", "${{ steps.artifact-name.outputs.name }}", "${{ steps.staged-candidate.outputs.path }}/"],
        ["inspect", "${{ steps.volume-artifact-name.outputs.name }}", "${{ steps.volume-stage.outputs.path }}/"],
        ["remount", "${{ steps.remount-artifact-name.outputs.name }}", "/tmp/personal-desktop-independent-remount-receipt.json"],
        ["attest", "personal-desktop-staging-attestation-${{ inputs.target }}-${{ github.sha }}", "${{ steps.attestation-stage.outputs.path }}/"],
      ].include?([job_name, artifact_name, artifact_path])
      if desktop_post_seal_scan_handoff
        deferred_desktop_uploads << [job_name, artifact_name, artifact_path]
        next
      end

      secret_indexes = steps.each_index.select do |index|
        index < upload_index && steps[index].dig("with", "scanners") == "secret"
      end
      abort "content artifact upload lacks a preceding proactive secret scan: #{path}:#{job_name}:#{artifact_name}" if secret_indexes.empty?
      latest_scan = secret_indexes.max
      binder_run = steps[(latest_scan + 1)...upload_index].map { |candidate| candidate.fetch("run", "") }.join("\n")
      %w[SchemaVersion ArtifactType Trivy.Version Secrets].each do |binding|
        abort "content artifact upload lacks explicit zero-secret report binding #{binding}: #{path}:#{job_name}:#{artifact_name}" unless binder_run.include?(binding)
      end
    end
  end
  if path == desktop_yaml
    expected_desktop_handoffs = [
      ["build", "${{ steps.authorization-name.outputs.name }}", "/tmp/personal-desktop-authorization-evidence/"],
      ["build", "${{ steps.artifact-name.outputs.name }}", "${{ steps.staged-candidate.outputs.path }}/"],
      ["inspect", "${{ steps.volume-artifact-name.outputs.name }}", "${{ steps.volume-stage.outputs.path }}/"],
      ["remount", "${{ steps.remount-artifact-name.outputs.name }}", "/tmp/personal-desktop-independent-remount-receipt.json"],
      ["attest", "personal-desktop-staging-attestation-${{ inputs.target }}-${{ github.sha }}", "${{ steps.attestation-stage.outputs.path }}/"],
    ]
    abort "Desktop post-seal scanner handoff set drifted" unless deferred_desktop_uploads == expected_desktop_handoffs
  else
    abort "non-Desktop workflow unexpectedly deferred an artifact scan: #{path}" unless deferred_desktop_uploads.empty?
  end
  abort "Trivy scan surfaces changed: #{path}" unless observed.sort == outputs.sort
end

valid_fixture = {
  "uses" => trivy_action,
  "env" => {
    "TRIVY_CONFIG" => "/tmp/policy/trivy.yaml",
    "TRIVY_IGNOREFILE" => "/tmp/policy/trivy.ignore",
    "TRIVY_SECRET_CONFIG" => "/tmp/policy/trivy.secret.yaml"
  },
  "with" => {
    "cache" => false,
    "exit-code" => "1",
    "format" => "json",
    "output" => "/tmp/report.json",
    "scan-ref" => "/tmp/evidence",
    "scan-type" => "fs",
    "scanners" => "secret",
    "trivy-config" => "/tmp/policy/trivy.yaml",
    "trivyignores" => "/tmp/policy/trivy.ignore",
    "version" => "v0.70.0"
  }
}
validate_trivy_step(valid_fixture, {}, ["/tmp/report.json"], trivy_action, "positive fixture")
{
  "skip-files" => "evidence.json",
  "skip-dirs" => "/tmp/evidence",
  "ignore-policy" => "/tmp/ignore.rego",
  "ignore-unfixed" => true
}.each do |key, value|
  fixture = Marshal.load(Marshal.dump(valid_fixture))
  fixture["with"][key] = value
  begin
    validate_trivy_step(fixture, {}, ["/tmp/report.json"], trivy_action, "negative with fixture #{key}")
  rescue TrivyContractError
    next
  end
  abort "Trivy suppressor fixture was accepted: #{key}"
end
{
  "TRIVY_SKIP_FILES" => "evidence.json",
  "TRIVY_SKIP_DIRS" => "/tmp/evidence",
  "TRIVY_IGNORE_POLICY" => "/tmp/ignore.rego",
  "TRIVY_IGNORE_UNFIXED" => "true"
}.each do |key, value|
  fixture = Marshal.load(Marshal.dump(valid_fixture))
  fixture["env"][key] = value
  begin
    validate_trivy_step(fixture, {}, ["/tmp/report.json"], trivy_action, "negative env fixture #{key}")
  rescue TrivyContractError
    next
  end
  abort "Trivy environment suppressor fixture was accepted: #{key}"
end
RUBY
}

if command -v sha256sum >/dev/null 2>&1; then
  expected=$(jq -cS . "$receipt" | sha256sum | awk '{print $1}')
else
  expected=$(jq -cS . "$receipt" | shasum -a 256 | awk '{print $1}')
fi
actual=$(bash "$hash_helper" "$receipt")
[[ "$actual" == "$expected" ]] || {
  printf '%s\n' "canonical receipt hash does not match the documented jq byte sequence" >&2
  exit 1
}
actual_stdin=$(bash "$hash_helper" - < "$receipt")
[[ "$actual_stdin" == "$expected" ]] || {
  printf '%s\n' "canonical receipt hash from stdin does not match the documented jq byte sequence" >&2
  exit 1
}

canonical_fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/personal-canonical-json-contract.XXXXXXXX")
chmod 700 "$canonical_fixture_root"
cleanup_canonical_fixtures() {
  rm -f -- \
    "$canonical_fixture_root/valid.json" \
    "$canonical_fixture_root/duplicate-top.json" \
    "$canonical_fixture_root/duplicate-nested.json" \
    "$canonical_fixture_root/multiple.json" \
    "$canonical_fixture_root/trailing.json" \
    "$canonical_fixture_root/nan.json" \
    "$canonical_fixture_root/infinity.json" \
    "$canonical_fixture_root/negative-infinity.json" \
    "$canonical_fixture_root/symlink.json" || true
  if [[ -d "$canonical_fixture_root/non-regular" && ! -L "$canonical_fixture_root/non-regular" ]]; then
    rmdir -- "$canonical_fixture_root/non-regular" || true
  fi
  if [[ -d "$canonical_fixture_root" && ! -L "$canonical_fixture_root" ]]; then
    rmdir -- "$canonical_fixture_root" || true
  fi
}
trap 'cleanup_status=$?; trap - EXIT; cleanup_canonical_fixtures; exit "$cleanup_status"' EXIT

printf '%s\n' '{"array":[3,2,1],"nested":{"alpha":true},"number":1.25,"text":"valid"}' \
  > "$canonical_fixture_root/valid.json"
printf '%s\n' '{"decision":"ambiguous","decision":"approved"}' \
  > "$canonical_fixture_root/duplicate-top.json"
printf '%s\n' '{"owner":{"login":"ambiguous","login":"trusted"}}' \
  > "$canonical_fixture_root/duplicate-nested.json"
printf '%s\n%s\n' '{}' '[]' > "$canonical_fixture_root/multiple.json"
printf '%s\n' '{} trailing' > "$canonical_fixture_root/trailing.json"
printf '%s\n' '{"value":NaN}' > "$canonical_fixture_root/nan.json"
printf '%s\n' '{"value":Infinity}' > "$canonical_fixture_root/infinity.json"
printf '%s\n' '{"value":-Infinity}' > "$canonical_fixture_root/negative-infinity.json"
ln -s "$canonical_fixture_root/valid.json" "$canonical_fixture_root/symlink.json"
mkdir "$canonical_fixture_root/non-regular"

expected_valid=$(jq -ceS . "$canonical_fixture_root/valid.json" | {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
})
[[ "$(bash "$hash_helper" "$canonical_fixture_root/valid.json")" == "$expected_valid" ]]

expect_hash_helper_rejected() {
  local label=$1
  local path=$2
  if bash "$hash_helper" "$path" > "$canonical_fixture_root/${label}.stdout" \
    2> "$canonical_fixture_root/${label}.stderr"; then
    printf '%s\n' "canonical JSON helper accepted hostile fixture: $label" >&2
    exit 1
  fi
  rm -f -- "$canonical_fixture_root/${label}.stdout" "$canonical_fixture_root/${label}.stderr"
}

expect_hash_helper_rejected duplicate-top "$canonical_fixture_root/duplicate-top.json"
expect_hash_helper_rejected duplicate-nested "$canonical_fixture_root/duplicate-nested.json"
expect_hash_helper_rejected multiple "$canonical_fixture_root/multiple.json"
expect_hash_helper_rejected trailing "$canonical_fixture_root/trailing.json"
expect_hash_helper_rejected nan "$canonical_fixture_root/nan.json"
expect_hash_helper_rejected infinity "$canonical_fixture_root/infinity.json"
expect_hash_helper_rejected negative-infinity "$canonical_fixture_root/negative-infinity.json"
expect_hash_helper_rejected symlink "$canonical_fixture_root/symlink.json"
expect_hash_helper_rejected non-regular "$canonical_fixture_root/non-regular"

grep -Fq 'object_pairs_hook=unique_object' "$hash_helper"
grep -Fq 'parse_constant=reject_constant' "$hash_helper"
grep -Fq 'source_fd = os.open(input_path, open_flags)' "$hash_helper"
grep -Fq 'snapshot_fd = os.open(snapshot_path, snapshot_flags, 0o600)' "$hash_helper"
grep -Fq 'canonical=$(jq -ceS . "$snapshot")' "$hash_helper"
grep -Fq 'digest=$(bash "$canonical_json_helper" "$path")' "$gate1_receipt"
grep -Fq 'bash "$canonical_json_helper" "$path" >/dev/null' "$gate1_receipt"
grep -Fq '.release_authorization.authorized_owner == "justinharkelroad"' "$gate1_receipt"
grep -Fq 'ledger-non-owner' "$gate1_receipt_test"

cleanup_canonical_fixtures
trap - EXIT

duplicate_yaml_fixture=$(mktemp "${TMPDIR:-/tmp}/personal-relay-duplicate-yaml.XXXXXX")
trap 'rm -f "$duplicate_yaml_fixture"' EXIT
printf '%s\n' 'name: first' 'name: second' > "$duplicate_yaml_fixture"
if validate_workflow_yaml "$duplicate_yaml_fixture" >/dev/null 2>&1; then
  printf '%s\n' "duplicate-key-aware workflow validation accepted a duplicate mapping key" >&2
  exit 1
fi
rm -f "$duplicate_yaml_fixture"
trap - EXIT
for workflow in "$relay_workflow" "$gate1_workflow" "$desktop_workflow" "$docker_workflow" "$sprig_workflow"; do
  validate_workflow_yaml "$workflow"
done
validate_workflow_action_references \
  "$relay_workflow" "$gate1_workflow" "$desktop_workflow" \
  "$docker_workflow" "$sprig_workflow"
validate_workflow_permissions
validate_pr_image_workflow_permissions
validate_release_flow
validate_desktop_flow
validate_gate1_flow
validate_main_protection_callers
validate_workflow_run_syntax

bash -n "$gate1_receipt"
bash -n "$gate1_receipt_test"
bash -n "$artifact_downloader"
bash -n "$artifact_downloader_test"
bash -n "$main_protection_validator"
bash -n "$main_protection_validator_test"
bash -n "$desktop_volume_validator"
bash -n "$desktop_audit_validator"
bash -n "$desktop_audit_validator_test"
bash -n "$desktop_multi_user_acceptance_validator"
bash -n "$desktop_multi_user_acceptance_test"
[[ -f "$desktop_audit_validator_test" && -r "$desktop_audit_validator_test" && -x "$desktop_audit_validator_test" && ! -L "$desktop_audit_validator_test" ]]
[[ $(grep -Fc 'case_root=$(clone_valid_fixture ' "$desktop_audit_validator_test") -eq 12 ]]
grep -Fq 'desktop attestation audit evidence passed' "$desktop_audit_validator_test"
for desktop_audit_mutation in \
  ledger-schema-downgrade \
  ledger-reviewer-controls \
  ledger-non-owner-authorization \
  remount-hash-mismatch \
  remount-semantic-bypass \
  remount-schema-downgrade \
  remount-volume-cross-binding \
  remount-future-timestamp \
  predicate-remount-receipt-substitution \
  predicate-remount-expiry-substitution \
  expectations-schema-downgrade \
  expectations-expiry-format; do
  grep -Fq "clone_valid_fixture $desktop_audit_mutation" "$desktop_audit_validator_test"
done
[[ -f "$desktop_multi_user_acceptance_validator" && -r "$desktop_multi_user_acceptance_validator" && -x "$desktop_multi_user_acceptance_validator" && ! -L "$desktop_multi_user_acceptance_validator" ]]
[[ -f "$desktop_multi_user_acceptance_test" && -r "$desktop_multi_user_acceptance_test" && -x "$desktop_multi_user_acceptance_test" && ! -L "$desktop_multi_user_acceptance_test" ]]
[[ -f "$desktop_multi_user_acceptance_example" && -r "$desktop_multi_user_acceptance_example" && ! -L "$desktop_multi_user_acceptance_example" ]]
[[ $(grep -Ec '^mutate_and_reject ' "$desktop_multi_user_acceptance_test") -eq 124 ]]
[[ $(grep -Ec '^expect_rejected ' "$desktop_multi_user_acceptance_test") -eq 20 ]]
for desktop_acceptance_mutation in \
  identity-impersonation identity-self-claim-false justin-credentials-used \
  credentials-shared wrong-agent-count wrong-agent-order wrong-agent-hash \
  duplicate-agent-id missing-allowlist wrong-apply-action wrong-common-channel \
  missing-common-channel bad-root-binding bad-parent-binding \
  extra-challenge-p-tag missing-response-p-tag wrong-stream-kind \
  duplicate-nonce duplicate-event-id duplicate-cross-surface-event-id \
  duplicate-dm-response-event-id duplicate-cross-surface-nonce \
  missing-dm-recipient-discovery missing-dm-recipient-selection \
  wrong-dm-open-kind open-dm-channel stale-dm-metadata unmarked-dm-channel \
  wrong-dm-metadata-signer bad-dm-metadata-signature wrong-dm-metadata-d-tag \
  public-dm-metadata not-closed-dm-metadata bad-dm-participant-commitment \
  db-immutable-dm-invariant-false missing-dm-private-marker \
  not-hidden-dm-metadata open-marker-on-dm-metadata \
  db-current-membership-false wrong-dm-metadata-participants \
  dm-metadata-before-open duplicate-dm-metadata-event-id \
  wrong-membership-snapshot-kind wrong-membership-snapshot-signer \
  bad-membership-snapshot-signature stale-membership-snapshot \
  wrong-membership-snapshot-d-tag wrong-membership-snapshot-participants \
  wrong-membership-snapshot-roles duplicate-membership-snapshot-event-id \
  membership-snapshot-before-metadata-verification \
  copied-dm-security-receipt copied-membership-snapshot-receipt \
  tampered-stored-db-participant-hash tampered-recomputed-db-participant-hash \
  conflated-db-and-metadata-participant-hashes \
  tampered-recomputed-metadata-participant-commitment wrong-dm-channel-hash \
  wrong-dm-participant-policy-version wrong-dm-channel-type wrong-dm-channel \
  duplicate-dm-channel \
  tampered-dm-participants tampered-dm-opened-by tampered-dm-open-author \
  tampered-dm-open-tag tampered-dm-decision missing-second-dm-turn \
  wrong-dm-turn-order dm-turn-not-started wrong-dm-challenge-kind \
  wrong-dm-response-kind tampered-dm-challenge-author \
  tampered-dm-challenge-tag tampered-dm-response-author tampered-dm-response-tag \
  bad-dm-first-response-root unexpected-dm-first-root bad-dm-followup-root \
  bad-dm-followup-parent bad-dm-followup-response-root \
  bad-dm-followup-response-parent \
  continuity-not-verified duplicate-dm-nonce duplicate-dm-event-id \
  copied-dm-receipt-hash runtime-applied-after-dm-open copied-receipt-hash \
  unauthorized-third-party-identity-substitution \
  negative-probe-aggregate-claim-false missing-negative-probe \
  wrong-negative-probe-order wrong-negative-probe-type wrong-negative-probe-agent \
  wrong-negative-probe-channel-type wrong-negative-probe-channel-id \
  wrong-negative-probe-channel-hash duplicate-negative-probe-channel \
  group-probe-missing-third-party third-party-probe-includes-mary \
  duplicate-negative-probe-nonce duplicate-negative-probe-event-id \
  wrong-negative-probe-kind wrong-group-probe-author \
  wrong-third-party-probe-author wrong-negative-probe-p-tag \
  copied-negative-probe-receipt copied-negative-participant-receipt \
  wrong-group-probe-decision wrong-third-party-probe-decision \
  copied-negative-decision-receipt negative-probe-turn-started \
  negative-probe-has-response negative-probe-observation-start-mismatch \
  negative-probe-wrong-observation-seconds \
  negative-probe-observation-window-mismatch copied-negative-no-turn-receipt \
  negative-probe-after-completion negative-probe-extra-key \
  substituted-source substituted-dmg substituted-hosted \
  substituted-agent-set inventory-charter-swap substituted-evidence-bundle \
  symlink-evidence-bundle hardlink-samefile-evidence-bundle \
  unsafe-evidence-bundle-mode unsafe-manifest-mode \
  substituted-evidence-bundle-record stale expired \
  near-expiry old-fresh-near-now-expiry extra-key legacy-v1-dm-denial \
  fresh-example-only-poison \
  duplicate-top-member duplicate-disjoint-object multiple-json; do
  grep -Fq "$desktop_acceptance_mutation" "$desktop_multi_user_acceptance_test"
done
grep -Fq '"$validator" --input "$valid" --evidence-bundle "$evidence_bundle"' "$desktop_multi_user_acceptance_test"
grep -Fq 'jq -e '\''.example_only == true'\'' "$example"' "$desktop_multi_user_acceptance_test"
grep -Fq 'fail "checked-in example was accepted"' "$desktop_multi_user_acceptance_test"
jq -e '
  . as $record
  | .schema == "personal-desktop-multi-user-acceptance/v3"
  and .example_only == true
  and .all_dm_negative_probes_passed == true
  and (.agents | type == "array" and length == 8)
  and all(.agents[];
    has("dm_conversation")
    and (has("dm_denial") | not)
    and .dm_conversation.channel_type == "dm"
    and .dm_conversation.open_event_kind == 41010
    and .dm_conversation.channel_metadata.kind == 39000
    and .dm_conversation.channel_metadata.author_pubkey == $record.relay.pubkey
    and .dm_conversation.channel_metadata.signature_verified == true
    and .dm_conversation.channel_metadata.current_for_d_tag == true
    and .dm_conversation.channel_metadata.t_tag == "dm"
    and .dm_conversation.channel_metadata.visibility == "private"
    and .dm_conversation.channel_metadata.hidden == true
    and .dm_conversation.channel_metadata.closed == true
    and .dm_conversation.channel_metadata.public_marker_count == 0
    and .dm_conversation.channel_metadata.open_marker_count == 0
    and .dm_conversation.channel_metadata.participant_set_policy == "buzz:dm-participants"
    and .dm_conversation.channel_metadata.participant_set_version == "v1"
    and .dm_conversation.membership_snapshot.kind == 39002
    and .dm_conversation.membership_snapshot.author_pubkey == $record.relay.pubkey
    and .dm_conversation.membership_snapshot.signature_verified == true
    and .dm_conversation.membership_snapshot.current_for_d_tag == true
    and .dm_conversation.membership_snapshot.d_tag == .dm_conversation.channel_metadata.d_tag
    and .dm_conversation.membership_snapshot.participant_p_tags ==
      .dm_conversation.participant_pubkeys
    and .dm_conversation.membership_snapshot.p_role_tags ==
      (.dm_conversation.participant_pubkeys | map([., "member"]))
    and .dm_conversation.db_invariant.immutable_participant_set == true
    and .dm_conversation.db_invariant.current_membership_verified == true
    and .dm_conversation.db_invariant.participant_hash_algorithm ==
      "sha256-concat-sorted-xonly-pubkeys"
    and .dm_conversation.db_invariant.participant_hash_hex ==
      .dm_conversation.db_invariant.recomputed_participant_hash_hex
    and .dm_conversation.db_invariant.participant_hash_hex !=
      .dm_conversation.channel_metadata.participant_set_commitment_sha256
    and .dm_conversation.db_invariant.recomputed_metadata_participant_set_commitment_sha256 ==
      .dm_conversation.channel_metadata.participant_set_commitment_sha256
    and all(.dm_conversation.turns[]; .author_gate_decision == "allowed_explicit_allowlist")
    and (.dm_conversation.turns | length) == 2
    and .dm_conversation.continuity_verified == true
  )
  and (.dm_negative_probes | type == "array" and length == 16)
  and ([.dm_negative_probes[].probe_type]
    | map(select(. == "group_dm"))
    | length) == 8
  and ([.dm_negative_probes[].probe_type]
    | map(select(. == "unauthorized_third_party_dm"))
    | length) == 8
  and all(.dm_negative_probes[];
    .channel_type == "dm"
    and .challenge_kind == 9
    and .challenge_p_tags == [.agent_pubkey]
    and .turn_started == false
    and .response_event_ids == []
    and .observation_seconds == 120
    and (if .probe_type == "group_dm"
      then .challenge_author_pubkey == $record.identities.mary_pubkey
        and .participant_pubkeys == ([$record.identities.mary_pubkey,
          $record.identities.unauthorized_third_party_pubkey,
          .agent_pubkey] | sort)
        and .author_gate_decision == "denied_group_dm"
      else .challenge_author_pubkey == $record.identities.unauthorized_third_party_pubkey
        and .participant_pubkeys == ([$record.identities.unauthorized_third_party_pubkey,
          .agent_pubkey] | sort)
        and .author_gate_decision == "denied_not_allowlisted"
      end)
  )
' "$desktop_multi_user_acceptance_example" >/dev/null
grep -Fq 'same-second parallel positive fixture was rejected' "$desktop_multi_user_acceptance_test"
grep -Fq 'same-agent challenge/response pair in one second was rejected' "$desktop_multi_user_acceptance_test"
grep -Fq 'all 64 interaction event IDs, 40 channel-security event IDs, 16 authorization event IDs, 40 nonces, 24 DM channels, 192 receipt hashes, and 48 decision-record occurrences / 32 decision IDs' "$desktop_multi_user_acceptance_test"
grep -Fq '.schema = "personal-desktop-multi-user-acceptance/v1"' "$desktop_multi_user_acceptance_test"
grep -Fq '.dm_denial = {' "$desktop_multi_user_acceptance_test"
grep -Fq '.schema == "personal-desktop-multi-user-acceptance/v3"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.live_exchange.challenge_p_tags == [$agent.agent_pubkey]' "$desktop_multi_user_acceptance_validator"
grep -Fq '.live_exchange.response_p_tags == [$record.identities.mary_pubkey]' "$desktop_multi_user_acceptance_validator"
grep -Fq '.live_exchange.challenge_kind == 9' "$desktop_multi_user_acceptance_validator"
grep -Fq '.live_exchange.response_kind == 9' "$desktop_multi_user_acceptance_validator"
grep -Fq '($interaction_event_ids | length) == 64' "$desktop_multi_user_acceptance_validator"
grep -Fq '($channel_security_event_ids | length) == 40' "$desktop_multi_user_acceptance_validator"
grep -Fq '($all_event_ids | length) == 120' "$desktop_multi_user_acceptance_validator"
grep -Fq '($positive_nonces | length) == 24' "$desktop_multi_user_acceptance_validator"
grep -Fq '($negative_nonces | length) == 16' "$desktop_multi_user_acceptance_validator"
grep -Fq '($all_nonces | length) == 40' "$desktop_multi_user_acceptance_validator"
grep -Fq '($receipt_hashes | length) == 192' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.recipient_discovered == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.recipient_selected == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_type == "dm"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.participant_pubkeys ==' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.open_event_kind == 41010' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.open_author_pubkey == $record.identities.mary_pubkey' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.open_p_tags == [$agent.agent_pubkey]' "$desktop_multi_user_acceptance_validator"
grep -Fq 'PARTICIPANT_POLICY = "buzz:dm-participants"' "$desktop_multi_user_acceptance_validator"
grep -Fq 'PARTICIPANT_VERSION = "v1"' "$desktop_multi_user_acceptance_validator"
grep -Fq 'PARTICIPANT_DOMAIN = b"buzz:dm-participants:v1\0"' "$desktop_multi_user_acceptance_validator"
grep -Fq 'commitment_input.append(len(participants))' "$desktop_multi_user_acceptance_validator"
grep -Fq 'commitment_input.extend(bytes.fromhex(participant))' "$desktop_multi_user_acceptance_validator"
grep -Fq 'd_tag_sha256 = hashlib.sha256(d_tag.encode("ascii")).hexdigest()' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.kind == 39000' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.author_pubkey == $record.relay.pubkey' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.signature_verified == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.current_for_d_tag == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.t_tag == "dm"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.visibility == "private"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.hidden == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.closed == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.public_marker_count == 0' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.open_marker_count == 0' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.participant_set_policy == "buzz:dm-participants"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.channel_metadata.participant_set_version == "v1"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.membership_snapshot.kind == 39002' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.membership_snapshot.author_pubkey == $record.relay.pubkey' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.membership_snapshot.signature_verified == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.membership_snapshot.current_for_d_tag == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.membership_snapshot.participant_p_tags ==' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.membership_snapshot.p_role_tags ==' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.db_invariant.immutable_participant_set == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.db_invariant.current_membership_verified == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '"sha256-concat-sorted-xonly-pubkeys"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.db_invariant.participant_hash_hex ==' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.db_invariant.participant_hash_hex !=' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.db_invariant.recomputed_metadata_participant_set_commitment_sha256 ==' "$desktop_multi_user_acceptance_validator"
grep -Fq '$dm_open_at <= $dm_metadata_at' "$desktop_multi_user_acceptance_validator"
grep -Fq '$dm_metadata_verified_at <= $dm_membership_at' "$desktop_multi_user_acceptance_validator"
grep -Fq '$dm_membership_verified_at <= $dm_db_checked_at' "$desktop_multi_user_acceptance_validator"
grep -Fq '$dm_db_checked_at <= $dm_first_challenge_at' "$desktop_multi_user_acceptance_validator"
grep -Fq '.author_gate_decision == "allowed_explicit_allowlist"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.turns | type == "array" and length == 2' "$desktop_multi_user_acceptance_validator"
grep -Fq '[.dm_conversation.turns[].ordinal] == [1, 2]' "$desktop_multi_user_acceptance_validator"
grep -Fq '$dm_followup.challenge_parent_event_id == $dm_first.response_event_id' "$desktop_multi_user_acceptance_validator"
grep -Fq '$dm_followup.response_parent_event_id == $dm_followup.challenge_event_id' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_conversation.continuity_verified == true' "$desktop_multi_user_acceptance_validator"
grep -Fq '$applied <= $dm_open_at' "$desktop_multi_user_acceptance_validator"
grep -Fq '$dm_followup_response_at <= $completed' "$desktop_multi_user_acceptance_validator"
grep -Fq -- '--expected-unauthorized-third-party-pubkey' "$desktop_multi_user_acceptance_validator"
grep -Fq '.dm_negative_probes | type == "array" and length == 16' "$desktop_multi_user_acceptance_validator"
grep -Fq '.author_gate_decision == "denied_group_dm"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.author_gate_decision == "denied_not_allowlisted"' "$desktop_multi_user_acceptance_validator"
grep -Fq '.challenge_p_tags == [$agent.agent_pubkey]' "$desktop_multi_user_acceptance_validator"
grep -Fq '.turn_started == false' "$desktop_multi_user_acceptance_validator"
grep -Fq '.response_event_ids == []' "$desktop_multi_user_acceptance_validator"
grep -Fq '.observation_seconds == 120' "$desktop_multi_user_acceptance_validator"
grep -Fq '($observed_until - $observed_from) == .observation_seconds' "$desktop_multi_user_acceptance_validator"
grep -Fq 'fail "acceptance manifest does not satisfy the v3 contract"' "$desktop_multi_user_acceptance_validator"
grep -Fq '$expires >= ($now + 3600)' "$desktop_multi_user_acceptance_validator"
grep -Fq 'if not hasattr(os, "O_NOFOLLOW")' "$desktop_multi_user_acceptance_validator"
grep -Fq 'manifest_fd = os.open(manifest_path, open_flags)' "$desktop_multi_user_acceptance_validator"
grep -Fq 'stat.S_IMODE(manifest_stat.st_mode) & 0o077' "$desktop_multi_user_acceptance_validator"
grep -Fq 'bundle_fd = os.open(bundle_path, open_flags)' "$desktop_multi_user_acceptance_validator"
grep -Fq '(manifest_stat.st_dev, manifest_stat.st_ino) == (bundle_stat.st_dev, bundle_stat.st_ino)' "$desktop_multi_user_acceptance_validator"
grep -Fq 'snapshot_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW' "$desktop_multi_user_acceptance_validator"
grep -Fq 'snapshot_fd = os.open(snapshot_path, snapshot_flags, 0o600)' "$desktop_multi_user_acceptance_validator"
grep -Fq '# SEALED_MANIFEST_READS_BEGIN: never reopen the caller-controlled input below.' "$desktop_multi_user_acceptance_validator"
grep -Fq 'fail "validator reopens caller-controlled input after sealing the manifest"' "$desktop_multi_user_acceptance_test"
grep -Fq 'umask 077' "$desktop_multi_user_acceptance_test"
grep -Fq 'authorizes production cutover.' "$desktop_multi_user_acceptance_validator"
desktop_acceptance_summary_builder=$(awk '/^jq -cnS \\/ { keep = 1 } keep { print }' "$desktop_multi_user_acceptance_validator")
for desktop_acceptance_summary_assertion in \
  'manifest_claimed_all_agents_passed: true' \
  'manifest_claimed_all_dm_conversations_passed: true' \
  'manifest_claimed_all_dm_channels_current_and_safe: true' \
  'manifest_claimed_all_dm_negative_probes_passed: true' \
  'dm_conversation_count: 8' \
  'dm_channel_metadata_count: 8' \
  'dm_membership_snapshot_count: 8' \
  'dm_db_invariant_check_count: 8' \
  'dm_turn_count: 16' \
  'dm_negative_probe_count: 16' \
  'group_dm_denial_probe_count: 8' \
  'unauthorized_third_party_dm_denial_probe_count: 8' \
  'manifest_contract_passed: true' \
  'evidence_bundle_authenticated: false' \
  'cutover_authorized: false'; do
  grep -Fq "$desktop_acceptance_summary_assertion" <<<"$desktop_acceptance_summary_builder"
  grep -Fq ".${desktop_acceptance_summary_assertion/: / == }" "$desktop_multi_user_acceptance_test"
done
if grep -Eq '^[[:space:]]+all_agents_passed:' <<<"$desktop_acceptance_summary_builder"; then
  printf '%s\n' "Desktop acceptance summary must not emit unqualified all_agents_passed" >&2
  exit 1
fi
jq empty "$gate1_schema"
bash "$artifact_downloader_test" >/dev/null
bash "$main_protection_validator_test" >/dev/null
bash "$gate1_receipt_test" >/dev/null
bash "$desktop_audit_validator_test" >/dev/null
bash "$desktop_multi_user_acceptance_test" >/dev/null

for job in source-tests image-validation validate attest; do
  grep -Eq "^  ${job}:$" "$gate1_workflow"
done
gate1_pull_request_trigger=$(awk '
  /^  pull_request:$/ { keep = 1; next }
  /^  workflow_dispatch:$/ { exit }
  keep { print }
' "$gate1_workflow")
expected_gate1_pull_request_trigger='    types: [opened, synchronize, reopened, ready_for_review]'
[[ "$gate1_pull_request_trigger" == "$expected_gate1_pull_request_trigger" ]] || {
  printf '%s\n' "Gate 1 contract check must use the exact approved pull-request lifecycle events without path filters" >&2
  exit 1
}
contract_job=$(awk '/^  contract:$/ { keep=1 } /^  source-tests:$/ { exit } keep { print }' "$gate1_workflow")
grep -Fq 'name: Gate 1 receipt contract' <<<"$contract_job"
grep -Fq 'bash ./deploy/personal-relay/release-contract-test.sh' <<<"$contract_job"
[[ $(grep -Fc 'environment: personal-relay-gate1' "$gate1_workflow") -eq 2 ]]
[[ $(grep -Fc 'id-token: write' "$gate1_workflow") -eq 1 ]]
! grep -Fq 'artifact-metadata: write' "$gate1_workflow"
! grep -Fq 'packages: write' "$gate1_workflow"
! grep -Fq 'deployments: write' "$gate1_workflow"
grep -Fq 'actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d' "$gate1_workflow"
grep -Fq 'push-to-registry: false' "$gate1_workflow"
grep -Fq 'gate1-workflow-run-attempt "$GITHUB_RUN_ATTEMPT"' "$gate1_workflow"
grep -Fq 'download-exact-artifact.sh' "$gate1_workflow"
grep -Fq -- '--source-test-result /tmp/personal-relay-gate1-source-proof/source-test-result.json' "$gate1_workflow"
for legacy_source_proof in authorization-tests authorization-relay-log authorization-acp-log relay-workflow-owner.log acp-author-gate.log; do
  if grep -Fq -- "$legacy_source_proof" "$gate1_workflow"; then
    printf '%s\n' "Gate 1 workflow still trusts legacy candidate proof: $legacy_source_proof" >&2
    exit 1
  fi
done
grep -Fq 'personal-relay-gate1-approval-secret.json' "$gate1_workflow"
grep -Fq 'personal-relay-gate1-source-result/v6' "$gate1_workflow"
grep -Fq 'personal-relay-gate1-source-result/v6' "$gate1_receipt"
grep -Fq '(.test_contract.commands | length) == 55' "$gate1_workflow"
for exact_source_command_id in \
  buzz-admin-migrate \
  buzz-relay-workflow-owner-attribution \
  author_gate_tests::trusted_relay_workflow_uses_attributed_owner_for_author_gate \
  author_gate_tests::forged_workflow_marker_cannot_replace_actual_signer \
  author_gate_tests::relay_signed_non_workflow_event_cannot_replace_actual_signer \
  author_gate_tests::missing_trusted_relay_identity_fails_closed_to_actual_signer \
  author_gate_tests::invalid_signature_fails_closed_to_actual_signer \
  author_gate_tests::wrong_kind_fails_closed_to_actual_signer \
  author_gate_tests::duplicate_actor_or_workflow_tags_fail_closed_to_actual_signer \
  author_gate_tests::test_allowlist_accepts_explicit_external_pubkey \
  author_gate_tests::test_allowlist_rejects_non_sibling_not_in_allowlist \
  author_gate_tests::test_owner_only_rejects_stranger_so_no_steer \
  author_gate_tests::test_dm_accepts_explicit_allowlisted_external_pubkey \
  author_gate_tests::test_dm_rejects_allowlisted_external_pubkey_in_group \
  author_gate_tests::test_dm_rejects_external_pubkey_absent_from_allowlist \
  author_gate_tests::test_dm_rejects_stranger_under_anyone \
  author_gate_tests::test_author_gate_resolver_caches_verified_immutable_dm_metadata \
  author_gate_tests::test_author_gate_unknown_metadata_is_immediate_singleflight_and_backed_off \
  author_gate_tests::test_dynamic_dm_prefetch_accepts_first_replayed_allowlisted_message \
  relay::tests::nip11_identity_lookup_retries_boundedly_and_recovers \
  dm::tests::relay_channel_metadata_verifier_is_strict_and_fail_closed \
  handlers::side_effects::tests::immutable_dm_admin_routes_reject_in_place_membership_and_visibility_mutations \
  handlers::side_effects::tests::immutable_dm_discovery_tags_are_sorted_and_committed \
  handlers::side_effects::tests::immutable_dm_reconciliation_matcher_rejects_unmarked_metadata \
  nip11::tests::nip11_dev_fallback_identity_is_advertised_for_harness_verification \
  tests::channel_reconciliation_schedule_is_durable_beyond_legacy_startup_window \
  tests::reconcile_replacement_bumps_past_trusted_wrong_d_and_ignores_wrong_signer \
  dm::tests::immutable_dm_database_guards_reject_mutations_and_allow_create_dm \
  dm::tests::relay_group_role_discovery_verifier_is_strict_and_fail_closed \
  kind::tests::nip29_relay_authored_discovery_snapshots_are_relay_only \
  handlers::ingest::tests::relay_authored_discovery_and_membership_triggers_are_rejected_from_client_ingest \
  relay::tests::membership_discovery_rejects_forged_invalid_or_stale_snapshots \
  relay::tests::merge_discovered_channels_omits_missing_wrong_signer_and_malformed_metadata \
  dm::tests::relay_membership_notification_verifier_is_strict_and_target_bound \
  dm::tests::relay_channel_metadata_rejects_signed_nonempty_content \
  relay::tests::current_membership_state_is_tri_state_and_stale_notification_safe \
  relay::tests::merge_discovered_channels_newer_malformed_coordinate_shadows_older_valid_metadata \
  relay::tests::merge_discovered_channels_accepts_only_fully_verified_dm_metadata \
  relay::tests::membership_recheck_command_reopens_trigger_dedup_without_losing_replay_floor \
  setup_mode::tests::setup_membership_notifications_requery_current_signed_39002 \
  pool::tests::lazy_metadata_lookup_ignores_newer_wrong_signer_sibling \
  pool::tests::lazy_metadata_lookup_newer_malformed_trusted_head_shadows_older_valid \
  handlers::side_effects::tests::channel_reconciliation_matcher_rejects_wrong_signer_or_stale_regular_metadata \
  handlers::side_effects::tests::channel_reconciliation_repairs_missing_members_snapshot_with_valid_metadata \
  tests::reconcile_channels_repairs_missing_members_snapshot_with_valid_metadata \
  dm::tests::create_dm_rejects_duplicate_participants_before_opening_transaction \
  migration::tests::immutable_dm_migration_contract_is_embedded \
  setup_mode::tests::setup_membership_stale_add_cannot_override_current_removal_snapshot \
  setup_mode::tests::setup_membership_stale_remove_cannot_override_current_member_snapshot \
  relay::tests::verified_member_requires_ensure_subscribe_despite_stale_outer_tracking \
  relay::tests::membership_unknown_retry_is_bounded_and_distinct_readd_remains_processable \
  relay::tests::readd_ensure_subscribe_repairs_closed_drop_despite_stale_outer_tracking \
  relay::tests::exhausted_remove_fails_closed_but_add_waits_for_distinct_repair \
  membership_removal_cleanup_tests::authoritative_nonmember_and_exhausted_remove_share_full_cleanup_path \
  setup_mode::tests::setup_exhausted_remove_fails_closed_through_unsubscribe_path; do
  grep -Fq "$exact_source_command_id" "$gate1_workflow"
  grep -Fq "$exact_source_command_id" "$gate1_receipt"
  grep -Fq "$exact_source_command_id" "$release_runbook"
  grep -Fq "$exact_source_command_id" "$deploy_runbook"
done
grep -Fq 'cargo test --locked -p buzz-acp "$full_name" -- --exact' "$gate1_workflow"
if grep -Fq 'cargo test --locked -p buzz-acp author_gate_tests::' "$gate1_workflow"; then
  printf '%s\n' "Gate 1 must not use the broad ACP author_gate_tests filter" >&2
  exit 1
fi
attest_job=$(awk '/^  attest:$/ { keep=1 } keep { print }' "$gate1_workflow")
if grep -Eq 'cargo (run|test|build)|docker (pull|run)|runtime-contract-test\.sh' <<<"$attest_job"; then
  printf '%s\n' "OIDC-enabled Gate 1 attestation job must never execute candidate source or image code" >&2
  exit 1
fi

[[ $(grep -Fc '[[ ! -e trivyignores && ! -L trivyignores ]]' "$gate1_workflow") -eq 3 ]]
[[ $(grep -Fc 'install -m 600 /dev/null /tmp/personal-relay-trivy-config.yaml' "$gate1_workflow") -eq 3 ]]
[[ $(grep -Fc 'install -m 600 /dev/null /tmp/personal-relay-trivy-ignore' "$gate1_workflow") -eq 3 ]]
[[ $(grep -Fc 'install -m 600 /dev/null /tmp/personal-relay-trivy-secret.yaml' "$gate1_workflow") -eq 3 ]]
[[ $(grep -Fc "printf '{}\\n' > /tmp/personal-relay-trivy-config.yaml" "$gate1_workflow") -eq 3 ]]
[[ $(grep -Fc "printf '{}\\n' > /tmp/personal-relay-trivy-secret.yaml" "$gate1_workflow") -eq 3 ]]
validate_trivy_policy_inputs "$relay_workflow" "$gate1_workflow" "$desktop_workflow"

for field in \
  gate1_evidence_run_id gate1_evidence_run_attempt gate1_evidence_artifact_id \
  gate1_evidence_artifact_name gate1_evidence_artifact_digest \
  gate1_evidence_expires_at gate1_receipt_sha256 gate1_attestation_bundle_sha256; do
  grep -Fq "\"${field}\"" "$receipt"
  grep -Fq "$field" "$desktop_workflow"
done
grep -Fq '"authorized_by"' "$receipt"
grep -Fq '"authorized_at"' "$receipt"
grep -Fq 'STAGING_AUTHORIZED_BY' "$desktop_workflow"
grep -Fq 'download-exact-artifact.sh' "$desktop_workflow"
grep -Fq 'personal-relay-gate1/v1' "$desktop_workflow"
grep -Fq 'BUILD_PERSONAL_STAGING_DESKTOP' "$desktop_workflow"
grep -Fq '"$STAGING_BUILD_CONFIRMATION" == "BUILD_PERSONAL_STAGING_DESKTOP"' "$desktop_workflow"
grep -Fq 'personal-desktop-main-rulesets.json' "$desktop_workflow"
grep -Fq 'personal-relay-gate1-main-rulesets.json' "$desktop_workflow"
grep -Fq 'fromdateiso8601' "$desktop_workflow"
grep -Fq 'git merge-base --is-ancestor "$SOURCE_SHA" "$GITHUB_SHA"' "$desktop_workflow"
grep -Fq 'ref: ${{ inputs.source_sha }}' "$desktop_workflow"
if grep -Fq 'source_sha must exactly equal github.sha' "$desktop_workflow"; then
  printf '%s\n' "desktop verifier/source circularity was reintroduced" >&2
  exit 1
fi

desktop_build_job=$(awk '/^  build:$/ { keep=1 } /^  attest:$/ { exit } keep { print }' "$desktop_workflow")
desktop_attest_job=$(awk '/^  attest:$/ { keep=1 } /^  audit:$/ { exit } keep { print }' "$desktop_workflow")
desktop_audit_job=$(awk '/^  audit:$/ { keep=1 } keep { print }' "$desktop_workflow")
[[ -n "$desktop_build_job" && -n "$desktop_attest_job" && -n "$desktop_audit_job" ]]
[[ $(grep -Fc 'id-token: write' "$desktop_workflow") -eq 1 ]]
if grep -Eq 'ref:[[:space:]]+\$\{\{[[:space:]]*inputs\.source_sha' <<<"$desktop_attest_job" \
  || grep -Eq '(^|[;&|[:space:]])(cargo|pnpm|just|tauri)[[:space:]]|docker[[:space:]]+(run|pull)|(^|[[:space:]])(bash[[:space:]]+)?(\./)?[^[:space:]]*build[^[:space:]]*\.sh' \
    <<<"$desktop_attest_job"; then
  printf '%s\n' "OIDC-enabled desktop attestation must not checkout or execute candidate source" >&2
  exit 1
fi
[[ $(grep -Fc 'bash ./deploy/personal-relay/download-exact-artifact.sh' <<<"$desktop_attest_job") -eq 5 ]]
for exact_download_argument in \
  '--artifact-id "$ARTIFACT_ID"' \
  '--digest "$ARTIFACT_DIGEST"' \
  '--expires-at "$ARTIFACT_EXPIRES_AT"' \
  '--output-dir /tmp/personal-desktop-staging' \
  '--artifact-id "$AUTHORIZATION_ARTIFACT_ID"' \
  '--digest "$AUTHORIZATION_ARTIFACT_DIGEST"' \
  '--expires-at "$AUTHORIZATION_ARTIFACT_EXPIRES_AT"' \
  '--output-dir /tmp/personal-desktop-authorization' \
  '--artifact-id "$INSPECTION_ARTIFACT_ID"' \
  '--digest "$INSPECTION_ARTIFACT_DIGEST"' \
  '--expires-at "$INSPECTION_ARTIFACT_EXPIRES_AT"' \
  '--output-dir /tmp/personal-desktop-inspection' \
  '--artifact-id "$VOLUME_ARTIFACT_ID"' \
  '--digest "$VOLUME_ARTIFACT_DIGEST"' \
  '--expires-at "$VOLUME_ARTIFACT_EXPIRES_AT"' \
  '--output-dir /tmp/personal-desktop-mounted-volume' \
  '--artifact-id "$REMOUNT_ARTIFACT_ID"' \
  '--digest "$REMOUNT_ARTIFACT_DIGEST"' \
  '--expires-at "$REMOUNT_ARTIFACT_EXPIRES_AT"' \
  '--output-dir /tmp/personal-desktop-independent-remount'; do
  grep -Fq -- "$exact_download_argument" <<<"$desktop_attest_job"
done
[[ $(grep -Fc -- '--run-id "$GITHUB_RUN_ID"' <<<"$desktop_attest_job") -eq 5 ]]
[[ $(grep -Fc 'bash ./deploy/personal-relay/download-exact-artifact.sh' <<<"$desktop_audit_job") -eq 5 ]]
[[ $(grep -Fc -- '--run-id "$GITHUB_RUN_ID"' <<<"$desktop_audit_job") -eq 5 ]]
[[ $(grep -Fc -- '- name: Upload sealed pre-candidate authorization evidence' <<<"$desktop_build_job") -eq 1 ]]
[[ $(grep -Fc -- '- name: Checkout exact owner-authorized source for the desktop build' <<<"$desktop_build_job") -eq 1 ]]
authorization_upload_line=$(grep -nF -- '- name: Upload sealed pre-candidate authorization evidence' <<<"$desktop_build_job" | cut -d: -f1)
candidate_checkout_line=$(grep -nF -- '- name: Checkout exact owner-authorized source for the desktop build' <<<"$desktop_build_job" | cut -d: -f1)
[[ "$authorization_upload_line" -lt "$candidate_checkout_line" ]] || {
  printf '%s\n' "desktop authorization evidence must be uploaded before candidate checkout" >&2
  exit 1
}

grep -Fq 'canonical-json-sha256.sh' "$desktop_workflow"
grep -Fq 'canonical-json-sha256.sh approved-staging-deployment.json' "$release_runbook"
grep -Fq 'canonical-json-sha256.sh approved-staging-deployment.json' "$deploy_runbook"
for exact_acp_test in \
  test_allowlist_accepts_explicit_external_pubkey \
  test_allowlist_rejects_non_sibling_not_in_allowlist \
  test_owner_only_rejects_stranger_so_no_steer \
  test_dm_accepts_explicit_allowlisted_external_pubkey \
  test_dm_rejects_allowlisted_external_pubkey_in_group \
  test_dm_rejects_external_pubkey_absent_from_allowlist \
  test_dm_rejects_stranger_under_anyone; do
  grep -Fq "$exact_acp_test" "$release_runbook"
  grep -Fq "$exact_acp_test" "$deploy_runbook"
done
for mary_blocker in \
  'signed in as her own identity' \
  'respond_to=allowlist' \
  'exact 64-hex pubkey' \
  'same-thread' \
  'exact sole `p` tag' \
  'both root and parent' \
  'exact 1:1 DM' \
  'kind `41010` open event' \
  'lexicographically sorted two-key array' \
  'verified NIP-OA kind' \
  'owner binding to Justin' \
  'accepted owner-authored kind `30177`' \
  'allowed_explicit_allowlist' \
  'two kind `9` turns' \
  'Group or unknown' \
  '`anyone`' \
  'never sign in as Justin' \
  'provider-hosted' \
  'restarted' \
  'redeployed' \
  'unique kind `9` challenge' \
  "Justin's credentials" \
  'not advisory'; do
  grep -Fq "$mary_blocker" "$release_runbook"
  grep -Fq "$mary_blocker" "$deploy_runbook"
done
for desktop_acceptance_contract in \
  'pre-build staging' \
  'cannot prove' \
  'private evidence bundle' \
  '`personal-desktop-multi-user-acceptance/v3`' \
  '`personal-desktop-multi-user-acceptance-summary/v3`' \
  'exact DMG' \
  'attestation predicate' \
  'final v3 audit' \
  '`example_only: true`' \
  'public Actions artifact' \
  'independently retained' \
  'sealed private snapshot' \
  'does not authenticate' \
  'manifest_claimed_all_agents_passed: true' \
  'manifest_claimed_all_dm_conversations_passed: true' \
  'manifest_claimed_all_dm_channels_current_and_safe: true' \
  'manifest_claimed_all_dm_negative_probes_passed: true' \
  'eight DM conversations' \
  'metadata events' \
  'membership snapshots' \
  'DB invariant' \
  'sixteen DM turns' \
  'group-DM' \
  'unauthorized-third-party' \
  'kind `39000`' \
  'kind `39002`' \
  'lowercase hyphenated' \
  'dm_channel_sha256' \
  't=dm' \
  '["buzz:dm-participants","v1","<commitment>"]' \
  'one unsigned participant-count byte' \
  '32-byte x-only' \
  'immutable participant set' \
  'current membership' \
  '`channels.participant_hash`' \
  'concatenated sorted raw' \
  '`denied_group_dm`' \
  '`denied_not_allowlisted`' \
  '120-second' \
  'DB-invariant-failing' \
  'manifest_contract_passed: true' \
  'evidence_bundle_authenticated: false' \
  'cutover_authorized: false' \
  'unqualified summary `all_agents_passed`' \
  'validator summary alone never authorizes' \
  'own-identity' \
  'Any future production or promotion lane must exact-download'; do
  grep -Fq "$desktop_acceptance_contract" "$release_runbook"
  grep -Fq "$desktop_acceptance_contract" "$deploy_runbook"
done
for repository_writer_boundary in \
  'Same-repository write access is a trust boundary' \
  'limited to Justin' \
  'requires no collaborator, code' \
  'defend against the repository owner intentionally editing both a workflow'; do
  grep -Fq "$repository_writer_boundary" "$release_runbook"
done
[[ -f "$relay_env_example" && -r "$relay_env_example" && ! -L "$relay_env_example" ]]
[[ $(grep -Ec '^BUZZ_RECONCILE_CHANNELS=' "$relay_env_example") -eq 1 ]]
[[ $(grep -Fxc 'BUZZ_RECONCILE_CHANNELS=true' "$relay_env_example") -eq 1 ]]
[[ $(grep -Ec '^BUZZ_WEB_DESKTOP_SCHEME=' "$relay_env_example") -eq 1 ]]
[[ $(grep -Fxc 'BUZZ_WEB_DESKTOP_SCHEME=buzz' "$relay_env_example") -eq 1 ]]
[[ $(grep -Fxc '# Personal-staging override only: BUZZ_WEB_DESKTOP_SCHEME=buzz-personal-staging' "$relay_env_example") -eq 1 ]]
for channel_reconciliation_contract in \
  '`BUZZ_RECONCILE_CHANNELS=true`' \
  'personal staging and personal production' \
  "before Mary's acceptance" \
  'provider configuration receipt' \
  'startup reconciliation evidence' \
  'Gate 1 evidence'; do
  grep -Fq "$channel_reconciliation_contract" "$release_runbook"
  grep -Fq "$channel_reconciliation_contract" "$deploy_runbook"
done
for web_desktop_scheme_contract in \
  '`BUZZ_WEB_DESKTOP_SCHEME=buzz-personal-staging`' \
  'same-digest promotion' \
  '`buzz-personal-staging`' \
  'default `buzz`'; do
  grep -Fq "$web_desktop_scheme_contract" "$release_runbook"
  grep -Fq "$web_desktop_scheme_contract" "$deploy_runbook"
done
for desktop_release_contract in \
  'exact ten-file candidate' \
  'fresh `macos-15` runner' \
  '`personal-desktop-attestation-audit-expectations/v3`' \
  '`personal-desktop-attestation-audit-summary/v3`' \
  '`personal-desktop-staging-attestation-audit/v4`' \
  'uploads exactly seven' \
  'requires the entire Desktop workflow'; do
  grep -Fq "$desktop_release_contract" "$release_runbook"
done
grep -Fq '`terminal-verifier` after all scanners' "$deploy_runbook"
grep -Fq 'An attestation alone' "$deploy_runbook"
if grep -Eq 'nine-command contract|four-file candidate package|All six scans|build job secret-scans' "$release_runbook" "$deploy_runbook"; then
  printf '%s\n' "release documentation still describes the superseded Desktop or Gate 1 evidence graph" >&2
  exit 1
fi
grep -Fq -- '-p buzz-backend-kubernetes' "$desktop_workflow"
grep -Fq 'SIDECARS+=(buzz-backend-kubernetes)' "$bundle_script"
grep -Fq '"binaries/buzz-backend-kubernetes"' "$tauri_config"

grep -Fq 'RUN test -x /usr/bin/setpriv' "$relay_dockerfile"
for privilege_script in "$relay_entrypoint" "$relay_migrate"; do
  grep -Fq 'exec /usr/bin/setpriv' "$privilege_script"
  grep -Fq -- '--clear-groups' "$privilege_script"
  grep -Fq -- '--inh-caps=-all' "$privilege_script"
  grep -Fq -- '--ambient-caps=-all' "$privilege_script"
  grep -Fq -- '--bounding-set=-all' "$privilege_script"
  grep -Fq -- '--no-new-privs' "$privilege_script"
done
grep -Fq '! command -v gosu >/dev/null 2>&1' "$relay_runtime_contract"
grep -Fq "^Cap(Inh|Prm|Eff|Bnd|Amb):" "$relay_runtime_contract"
grep -Fq '^NoNewPrivs:' "$relay_runtime_contract"
grep -Fq '/usr/local/bin/personal-relay-migrate' "$relay_runtime_contract"
grep -Fq '.State.ExitCode' "$relay_runtime_contract"
grep -Fq 'BUZZ_WEB_DESKTOP_SCHEME=buzz' "$relay_runtime_contract"
grep -Fq 'data-buzz-runtime-config=' "$relay_runtime_contract"
grep -Fq 'buzz-personal-staging' "$relay_runtime_contract"
grep -Fq "personal-staging) expected_desktop_scheme=buzz-personal-staging" "$relay_smoke_test"
grep -Fq "personal-production) expected_desktop_scheme=buzz" "$relay_smoke_test"
grep -Fq '/invite/runtime-scheme-smoke' "$relay_smoke_test"
grep -Fq 'BUZZ_WEB_DESKTOP_SCHEME must be exactly' "$relay_config"
grep -Fq 'read_web_spa_index' "$relay_router"
grep -Fq 'data-buzz-runtime-config="desktop-scheme"' "$web_index"
grep -Fq 'buzz-personal-staging' "$web_desktop_deep_link"
grep -Fq 'desktopDeepLink("join"' "$web_invite_page"
grep -Fq 'desktopDeepLink(' "$web_connect_button"
if grep -Fq 'buzz://' "$web_invite_page" "$web_connect_button"; then
  printf '%s\n' "relay-served web deep links must use the validated runtime scheme helper" >&2
  exit 1
fi
[[ $(grep -Fc 'runtime-contract-test.sh "$IMAGE_REF"' "$relay_workflow") -eq 2 ]]
publish_job=$(awk '/^  publish:$/ { keep=1 } keep { print }' "$relay_workflow")
if grep -Eq '(^|[;&|[:space:]])(cargo|pnpm|just|tauri)[[:space:]]|docker[[:space:]]+(run|pull)|runtime-contract-test\.sh' \
  <<<"$publish_job"; then
  printf '%s\n' "OIDC-enabled personal relay publish job must not execute candidate source or images" >&2
  exit 1
fi
publish_script_calls=$(grep -Eo 'bash[[:space:]]+\./[^[:space:]\\]+' <<<"$publish_job" | sort -u)
[[ "$publish_script_calls" == $'bash ./deploy/personal-relay/download-exact-artifact.sh\nbash ./deploy/personal-relay/validate-main-protection.sh' ]] || {
  printf '%s\n' "OIDC-enabled publish may execute only the protected exact-artifact and main-protection verifiers" >&2
  exit 1
}
if grep -Eq '(^|[^[:alnum:]_])gosu([^[:alnum:]_]|$)' \
  "$relay_dockerfile" "$relay_entrypoint" "$relay_migrate"; then
  printf '%s\n' "personal relay runtime must not bundle or invoke gosu" >&2
  exit 1
fi

grep -Fq 'Fetch and bind the exact platform' "$relay_workflow"
grep -Fq 'oci-artifact=true' "$relay_workflow"
grep -Fq 'application/vnd.docker.attestation.manifest.v1+json' "$relay_workflow"
grep -Fq 'vnd.docker.reference.digest' "$relay_workflow"
grep -Fq 'personal-relay-sbom-attestation-${ARCH}.intoto.json' "$relay_workflow"
grep -Fq -- '--image-index "personal-relay-image-index-${ARCH}.json"' "$relay_workflow"
grep -Fq -- '--attestation-manifest "personal-relay-attestation-manifest-${ARCH}.json"' "$relay_workflow"
grep -Fq -- '--sbom-attestation "personal-relay-sbom-attestation-${ARCH}.intoto.json"' "$relay_workflow"
grep -Fq 'scan-type: sbom' "$relay_workflow"
grep -Fq 'TRIVY_PLATFORM: linux/${{ matrix.arch }}' "$relay_workflow"
[[ $(grep -Fc 'list-all-pkgs: true' "$relay_workflow") -eq 2 ]]
grep -Fq '[[ ! -e trivyignores && ! -L trivyignores ]]' "$relay_workflow"
grep -Fq "printf '{}\\n' > \"\$policy_root/trivy.yaml\"" "$relay_workflow"
grep -Fq ': > "$policy_root/trivy.ignore"' "$relay_workflow"
grep -Fq 'RUN_ATTEMPT: ${{ github.run_attempt }}' "$relay_workflow"
grep -Fq '"$RUN_ATTEMPT" == "1" && "$GITHUB_RUN_ATTEMPT" == "1"' "$relay_workflow"
grep -Fq -- '--argjson workflow_run_attempt "$GITHUB_RUN_ATTEMPT"' "$relay_workflow"
grep -Fq 'workflow_run_attempt: $workflow_run_attempt' "$relay_workflow"
grep -Fq 'trivy-report-policy.sh' "$relay_workflow"
grep -Fq 'personal-relay-trivy-policy-${ARCH}.json' "$relay_workflow"
grep -Fq 'VulnerabilityDBSHA256' "$relay_workflow"
grep -Fq 'JavaDBSHA256' "$relay_workflow"
grep -Fq 'deployment_eligible: false' "$relay_workflow"
grep -Fq 'pattern: personal-relay-scan-*' "$relay_workflow"
grep -Fq 'name: Reverify exact publication source' "$relay_workflow"
grep -Fq -- '--metadata-file /tmp/personal-relay-manifest-create.json' "$relay_workflow"
grep -Fq 'Verify the exact merged descriptor union by digest' "$relay_workflow"
grep -Fq 'personal-relay-expected-merged-descriptors.json' "$relay_workflow"
grep -Fq 'personal-relay-merged-index.json' "$relay_workflow"
grep -Fq 'exact union of the two scanned platform indexes' "$relay_workflow"
grep -Fq 'install -m 0644 "$evidence_file" "$evidence_root/$evidence_name"' "$relay_workflow"
grep -Fq 'personal-relay-final-evidence.sha256' "$relay_workflow"
grep -Fq 'chmod 0444 "$evidence_root"/*' "$relay_workflow"
grep -Fq 'chmod 0555 "$evidence_root"' "$relay_workflow"
grep -Fq 'sha256sum --check --strict personal-relay-final-evidence.sha256' "$relay_workflow"
grep -Fq '.ruleset_source_type == "Repository"' "$main_protection_validator"
grep -Fq '.ruleset_source == $expected_repository' "$main_protection_validator"
grep -Fq 'and .bypass_actors == []' "$main_protection_validator"
grep -Fq 'keys == ["classic_required_pull_request_reviews", "commit", "name", "protected"]' "$main_protection_validator"
grep -Fq '.classic_required_pull_request_reviews == false' "$main_protection_validator"
grep -Fq 'classic-review-protection' "$main_protection_validator_test"
grep -Fq '.parameters.require_code_owner_review == false' "$main_protection_validator"
grep -Fq 'code-owner-review' "$main_protection_validator_test"
grep -Fq 'as $applicable_ruleset_ids' "$main_protection_validator"
grep -Fq 'all($effective_rules[] | select(.type == "pull_request"); zero_review_pull_request)' "$main_protection_validator"
grep -Fq 'all($effective_rules[] | select(.type == "required_status_checks"); strict_status_checks)' "$main_protection_validator"
grep -Fq 'conflicting-pull-request-ruleset' "$main_protection_validator_test"
grep -Fq '.parameters.required_status_checks == [{' "$main_protection_validator"
grep -Fq 'context: "Gate 1 receipt contract"' "$main_protection_validator"
grep -Fq 'integration_id: 15368' "$main_protection_validator"
grep -Fq 'all(.[]; .type != "workflows" and .type != "required_deployments")' "$main_protection_validator"
for external_gate_fixture in extra-status-context added-status-rule added-workflow added-required-deployment; do
  grep -Fq "$external_gate_fixture" "$main_protection_validator_test"
done
if grep -Fq 'def required_workflows' "$main_protection_validator"; then
  printf '%s\n' "generic required-workflow rules must not replace the exact Gate 1 status contract" >&2
  exit 1
fi
for protection_fixture in wrong-context null-integration wrong-integration bypass-actor split-policy wrong-ruleset-source wrong-ruleset-id generic-workflow sha-workflow; do
  grep -Fq "$protection_fixture" "$main_protection_validator_test"
done
grep -Fq 'for enforcement in evaluate disabled' "$main_protection_validator_test"

upload_evidence_step=$(
  awk '
    /^      - name: Upload release evidence$/ { keep = 1 }
    keep && /^      - name: / && $0 !~ /Upload release evidence/ { exit }
    keep { print }
  ' "$relay_workflow"
)
[[ -n "$upload_evidence_step" ]] || {
  printf '%s\n' "could not locate the final release evidence upload step" >&2
  exit 1
}
[[ $(grep -Ec '^          path:' <<<"$upload_evidence_step") -eq 1 ]]
grep -Fxq '          path: /tmp/personal-relay-final-evidence/' <<<"$upload_evidence_step"
if grep -Fq 'imagetools inspect "$candidate_ref"' "$relay_workflow"; then
  printf '%s\n' "personal relay release must not derive its digest from a mutable candidate tag" >&2
  exit 1
fi
if grep -Fq 'ignore-unfixed: true' "$relay_workflow"; then
  printf '%s\n' "personal relay release must gate the exact retained Trivy JSON reports" >&2
  exit 1
fi
bash "$trivy_policy_test" >/dev/null

image_schema=$(
  awk '
    /"image":[[:space:]]*\{/ { in_image = 1 }
    in_image { print }
    in_image && /^[[:space:]]*},?[[:space:]]*$/ { exit }
  ' "$provider_config"
)
[[ -n "$image_schema" ]] || {
  printf '%s\n' "could not locate the Kubernetes provider image schema" >&2
  exit 1
}
if grep -Fq '"default"' <<<"$image_schema" \
  || grep -ERq 'DEFAULT_[A-Z0-9_]*IMAGE|IMAGE_[A-Z0-9_]*DEFAULT' "$provider_src" \
  || grep -ERq 'ghcr\.io/block/buzz-sprig(:[^@[:space:]"]+)?@sha256:[0-9a-f]{64}' "$provider_src"; then
  printf '%s\n' \
    "Kubernetes provider must not bake a ghcr.io/block/buzz-sprig default; require an explicit scanned and attested digest" >&2
  exit 1
fi

printf '%s\n' "personal relay release contracts passed"
