# frozen_string_literal: true

require "psych"

CANONICAL_PREFIX = "${{github.event_name!='pull_request'&&github.event_name!='pull_request_target'&&"
CANONICAL_SUFFIX = "||''}}"

def reject(path, node, message)
  warn "#{message}: #{path}:#{node.start_line + 1}"
  exit 1
end

def validate_item(path, node, item)
  normalized = item.gsub(/[[:space:]]/, "")
  return if normalized.empty?

  if normalized.include?("${{") || normalized.include?("}}")
    unless normalized.start_with?(CANONICAL_PREFIX) && normalized.end_with?(CANONICAL_SUFFIX)
      reject(path, node, "dynamic cache-to item must use the canonical whole-item non-PR guard")
    end

    guarded_body = normalized.delete_prefix(CANONICAL_PREFIX).delete_suffix(CANONICAL_SUFFIX)
    if guarded_body.include?("${{") || guarded_body.include?("}}") || guarded_body.include?("||")
      reject(path, node, "dynamic cache-to item must contain one outer non-PR expression and one empty fallback")
    end
    return
  end

  if normalized.include?("type=registry")
    reject(path, node, "registry cache-to item is not guarded against pull requests")
  end

  return if normalized.start_with?("type=")

  reject(path, node, "cache-to item is indirect or unsupported; use an explicit type or canonical non-PR guard")
end

def validate_cache_to(path, node)
  unless node.is_a?(Psych::Nodes::Scalar)
    reject(path, node, "cache-to must be a scalar, not an alias, sequence, or mapping")
  end

  if node.style == Psych::Nodes::Scalar::FOLDED
    reject(path, node, "cache-to folded scalars are unsupported; use one literal-block item per line")
  end

  items = if node.style == Psych::Nodes::Scalar::LITERAL
            node.value.lines(chomp: true).reject { |line| line.strip.empty? }
          else
            if node.value.include?("\n")
              reject(path, node, "multiline cache-to scalars must use literal block style")
            end
            [node.value]
          end

  reject(path, node, "cache-to must contain at least one explicit item") if items.empty?
  items.each { |item| validate_item(path, node, item) }
end

def walk(path, node)
  case node
  when Psych::Nodes::Mapping
    node.children.each_slice(2) do |key, value|
      unless key.is_a?(Psych::Nodes::Scalar)
        reject(path, key, "workflow mapping keys must be scalar; aliases and complex keys are unsupported")
      end
      unless key.tag.nil? || key.tag == "tag:yaml.org,2002:str"
        reject(path, key, "workflow mapping keys must be untagged strings")
      end
      if key.value.include?("${{") || key.value.include?("}}")
        reject(path, key, "workflow mapping keys must be static; expression keys can inject unchecked inputs")
      end

      normalized_key = key.value.tr("A-Z", "a-z")
      if normalized_key == "with" && !value.is_a?(Psych::Nodes::Mapping)
        reject(path, value, "workflow with values must be structural mappings, not expressions, aliases, or sequences")
      end
      validate_cache_to(path, value) if normalized_key == "cache-to"
      walk(path, value)
    end
  when Psych::Nodes::Stream, Psych::Nodes::Document, Psych::Nodes::Sequence
    node.children.each { |child| walk(path, child) }
  end
end

files = ARGV.flat_map do |argument|
  if File.directory?(argument)
    Dir.glob(File.join(argument, "**", "*.{yml,yaml}"), File::FNM_DOTMATCH)
  else
    argument
  end
end.uniq.sort

abort "usage: #{$PROGRAM_NAME} <workflow-file-or-directory> [...]" if files.empty?

files.each do |path|
  begin
    walk(path, Psych.parse_file(path))
  rescue Psych::SyntaxError => e
    warn "invalid workflow YAML: #{path}:#{e.line}: #{e.problem}"
    exit 1
  end
end
