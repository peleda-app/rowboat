#!/usr/bin/env bash
# Fails when unsafe code is allowed, expected or merely warned about in any .rs file outside the
# files listed in unsafe-allowlist.txt (attributes spread over several lines included), when a
# crate under a crates/ or apps/ directory at any depth does not inherit the workspace lints (which
# deny unsafe code), or when any other crate neither inherits them nor forbids unsafe code itself.
set -euo pipefail
cd "$(dirname "$0")/.."
allowed=""
if [ -f unsafe-allowlist.txt ]; then
  allowed="$(grep -v '^\s*#' unsafe-allowlist.txt | sed '/^\s*$/d' || true)"
fi
sources() {
  find . \( -name node_modules -o -name .git -o \( -name target -exec test -e '{}/../Cargo.toml' \; \) \) -prune -o -name "$1" -type f -print0
}
status=0
while IFS= read -r file; do
  if ! grep -qxF "$file" <<<"$allowed"; then
    echo "unsafe code allowed outside unsafe-allowlist.txt: $file" >&2
    status=1
  fi
done < <(sources '*.rs' \
  | xargs -0 -r perl -0777 -ne 'print "$ARGV\n" if /\b(allow|expect|warn)\s*\([^)]*\b(unsafe_code|clippy\s*::\s*undocumented_unsafe_blocks)\b/' \
  | sed 's|^\./||' | sort)
while IFS= read -r manifest; do
  verdict=$(awk '
    /^\[/ { section = $0; sub(/[[:space:]]*(#.*)?$/, "", section) }
    section == "[package]" { package = 1 }
    section == "[lints]" && /^workspace[[:space:]]*=[[:space:]]*true/ { inherits = 1 }
    section == "[lints.rust]" && /^unsafe_code[[:space:]]*=[[:space:]]*"forbid"/ { forbids = 1 }
    END { print (package ? "p" : "-") (inherits ? "i" : "-") (forbids ? "f" : "-") }
  ' "$manifest")
  case "$verdict" in
    -*|?i?) ;;
    *)
      if [[ "/$manifest" =~ /(crates|apps)/ ]]; then
        echo "crate does not inherit the workspace lints ([lints] workspace = true): $manifest" >&2
        status=1
      elif [ "$verdict" != "p-f" ]; then
        echo "crate neither inherits the workspace lints nor forbids unsafe code: $manifest" >&2
        status=1
      fi
      ;;
  esac
done < <(sources Cargo.toml | tr '\0' '\n' | sed 's|^\./||' | sort)
exit $status
