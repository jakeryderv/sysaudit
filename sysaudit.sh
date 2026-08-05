#!/usr/bin/env bash
#
# sysaudit.sh — read-only audit of every package manager on this machine.
#
# Detects which managers are present, reports their SCOPE (system / user /
# sandboxed / language-level), inventories only the ones that actually exist,
# then flags the classic failure modes: PATH shadowing, sudo-pip damage to
# distro Python, and duplicate version managers.
#
# Read-only. Installs nothing, changes nothing, needs no sudo.
#
# Usage:
#   ./sysaudit.sh              full audit
#   ./sysaudit.sh -q           quick (skip slow inventories, disk sizes + integrity scan)
#   ./sysaudit.sh -n           no color
#   ./sysaudit.sh -h           help
#
# Exit status: 0 = clean, 1 = flags raised, 2 = usage error.

set -uo pipefail

# Several checks parse English tool output (dpkg -S "no path found",
# apt "upgradable", rpm "not owned") — a localized system would silently
# pass every check without this.
export LC_ALL=C

QUICK=0
USE_COLOR=1

while [ $# -gt 0 ]; do
  case "$1" in
    -q|--quick)    QUICK=1 ;;
    -n|--no-color) USE_COLOR=0 ;;
    -h|--help)     awk 'NR>1 { if (!/^#/) exit; sub(/^# ?/,""); print }' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try -h)" >&2; exit 2 ;;
  esac
  shift
done

[ -t 1 ] || USE_COLOR=0
[ -n "${NO_COLOR:-}" ] && USE_COLOR=0
if [ "$USE_COLOR" -eq 1 ]; then
  B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'
  Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'
else
  B=''; DIM=''; R=''; G=''; Y=''; C=''; N=''
fi

FLAGS=()
flag() { FLAGS+=("$1"); }

section() { printf '\n%s┌─ %s %s\n' "$C$B" "$1" "$N"; }
item()    { printf '  %s\n' "$1"; }
note()    { printf '  %s%s%s\n' "$DIM" "$1" "$N"; }
good()    { printf '  %s✓%s %s\n' "$G" "$N" "$1"; }
warn()    { printf '  %s!%s %s\n' "$Y" "$N" "$1"; }
bad()     { printf '  %s✗%s %s\n' "$R" "$N" "$1"; }

has() { command -v "$1" >/dev/null 2>&1; }
where() { command -v "$1" 2>/dev/null; }

# Count lines on stdin, tolerating empty input.
count() { grep -c . 2>/dev/null || true; }

# Classify a binary path into a scope bucket.
scope_of() {
  case "$1" in
    /nix/store/*|*/.nix-profile/*|/run/current-system/*) echo "nix store" ;;
    /snap/*)                                            echo "snap" ;;
    */.local/share/flatpak/*|/var/lib/flatpak/*)         echo "flatpak" ;;
    /home/linuxbrew/*|/opt/homebrew/*)                   echo "homebrew" ;;
    "$HOME"/*)                                           echo "user" ;;
    /home/*/.*|/home/*/bin/*|/Users/*/.*)                echo "user" ;;
    /usr/local/*)                                        echo "local/manual" ;;
    /usr/bin/*|/bin/*|/usr/sbin/*|/sbin/*)               echo "system (distro)" ;;
    *)                                                   echo "other" ;;
  esac
}

# ── Manager registry: name|category ──────────────────────────────────────────
NATIVE="apt dnf yum pacman zypper apk emerge xbps-install eopkg slackpkg pkg"
UNIVERSAL="flatpak snap nix guix appimaged"
PREFIX="brew port pipx"
LANG_PM="pip pip3 npm pnpm yarn bun cargo gem go composer luarocks cpanm"
VERSION_MGR="asdf mise rustup nvm pyenv rbenv conda mamba uv volta sdk"

DETECTED=()   # "name|path|scope|category"

detect_group() {
  local category="$1"; shift
  local pm p
  # shellcheck disable=SC2048  # splitting the space-separated registry is the point
  for pm in $*; do
    p="$(where "$pm")" || continue
    [ -n "$p" ] && DETECTED+=("$pm|$p|$(scope_of "$p")|$category")
  done
}

have_pm() {
  local e
  for e in ${DETECTED[@]+"${DETECTED[@]}"}; do
    [ "${e%%|*}" = "$1" ] && return 0
  done
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
printf '%s%s\n' "$B" "PACKAGE MANAGER AUDIT$N"
note "$(uname -srm)  ·  $(date '+%Y-%m-%d %H:%M')  ·  read-only"

detect_group "system"    $NATIVE
detect_group "universal" $UNIVERSAL
detect_group "prefix"    $PREFIX
detect_group "language"  $LANG_PM
detect_group "versions"  $VERSION_MGR

section "DETECTED (${#DETECTED[@]} managers)"
if [ "${#DETECTED[@]}" -eq 0 ]; then
  bad "nothing found — is PATH set correctly?"
else
  printf '  %-14s %-16s %s\n' "MANAGER" "SCOPE" "PATH"
  printf '  %-14s %-16s %s\n' "-------" "-----" "----"
  for e in "${DETECTED[@]}"; do
    IFS='|' read -r nm pth scp _cat <<<"$e"
    printf '  %-14s %-16s %s%s%s\n' "$nm" "$scp" "$DIM" "$pth" "$N"
  done
fi

# ── Native / system ──────────────────────────────────────────────────────────
NATIVE_FOUND=0
for pm in $NATIVE; do have_pm "$pm" && NATIVE_FOUND=$((NATIVE_FOUND+1)); done

if [ "$NATIVE_FOUND" -gt 0 ]; then
  section "SYSTEM PACKAGES"
  if have_pm apt && has dpkg-query; then
    n=$(dpkg-query -f '${binary:Package}\n' -W 2>/dev/null | count)
    item "dpkg/apt        $n packages"
    if [ "$QUICK" -eq 0 ] && has apt; then
      m=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
      [ "$m" -gt 0 ] && warn "$m upgradable" || good "up to date"
    fi
  fi
  if have_pm dnf || have_pm yum; then
    has rpm && item "rpm/dnf         $(rpm -qa 2>/dev/null | count) packages"
  elif has rpm; then
    item "rpm             $(rpm -qa 2>/dev/null | count) packages"
  fi
  if have_pm pacman; then
    item "pacman          $(pacman -Qq 2>/dev/null | count) packages ($(pacman -Qqm 2>/dev/null | count) foreign/AUR)"
  fi
  have_pm zypper  && has rpm && item "zypper          $(rpm -qa 2>/dev/null | count) packages"
  have_pm apk     && item "apk             $(apk info 2>/dev/null | count) packages"
  have_pm emerge  && item "portage         $(ls -d /var/db/pkg/*/* 2>/dev/null | count) packages"
  have_pm xbps-install && item "xbps            $(xbps-query -l 2>/dev/null | count) packages"

  if [ "$NATIVE_FOUND" -gt 1 ]; then
    flag "More than one native manager on PATH — verify they aren't both writing to /usr."
  fi
fi

# ── Universal / sandboxed ────────────────────────────────────────────────────
if have_pm flatpak || have_pm snap || have_pm nix || have_pm guix; then
  section "UNIVERSAL / SANDBOXED"
  if have_pm flatpak; then
    n=$(flatpak list --app --columns=application 2>/dev/null | count)
    r=$(flatpak list --runtime --columns=application 2>/dev/null | count)
    item "flatpak         $n apps, $r runtimes"
    if [ "$QUICK" -eq 0 ]; then
      flatpak list --app --columns=application,origin,installation 2>/dev/null \
        | sed 's/^/      /' | head -20
      [ "$n" -gt 20 ] && note "    …and $((n-20)) more"
    fi
  fi
  if have_pm snap; then
    n=$(snap list 2>/dev/null | tail -n +2 | count)
    item "snap            $n snaps"
    if [ "$QUICK" -eq 0 ]; then
      snap list 2>/dev/null | tail -n +2 | awk '{printf "      %-24s %s\n",$1,$2}' | head -20
      [ "$n" -gt 20 ] && note "    …and $((n-20)) more"
    fi
  fi
  if have_pm nix; then
    out=$(nix profile list 2>/dev/null) || out=""
    [ -z "$out" ] && out=$(nix-env -q 2>/dev/null)
    # nix >= 2.20 prints a multi-line record per package (Name:/Flake:/...);
    # older versions print one line per package.
    n=$(printf '%s\n' "$out" | grep -c '^Name:')
    [ "$n" -eq 0 ] && n=$(printf '%s' "$out" | count)
    item "nix             $n in profile"
    if [ -d /nix/store ]; then
      paths=$(ls -1 /nix/store 2>/dev/null | count)
      sz=""
      [ "$QUICK" -eq 0 ] && sz=$(du -sh /nix/store 2>/dev/null | cut -f1)
      note "    store: $paths paths, ${sz:-?} — 'nix-collect-garbage -d' to reclaim"
    fi
  fi
  have_pm guix && item "guix            $(guix package -I 2>/dev/null | count) in profile"
fi

# ── User-prefix ──────────────────────────────────────────────────────────────
if have_pm brew || have_pm port || have_pm pipx || [ -d "$HOME/.local/bin" ]; then
  section "USER PREFIX"
  if have_pm brew && [ "$QUICK" -eq 0 ]; then
    f=$(brew list --formula 2>/dev/null | count)
    c=$(brew list --cask   2>/dev/null | count)
    item "homebrew        $f formulae, $c casks   (prefix: $(brew --prefix 2>/dev/null))"
  elif have_pm brew; then
    item "homebrew        present (skipped in quick mode)"
  fi
  have_pm port && item "macports        $(port installed 2>/dev/null | tail -n +2 | count) ports"
  if have_pm pipx; then
    item "pipx            $(pipx list --short 2>/dev/null | count) apps"
    [ "$QUICK" -eq 0 ] && pipx list --short 2>/dev/null | sed 's/^/      /'
  fi
  if [ -d "$HOME/.local/bin" ]; then
    # shellcheck disable=SC2088  # literal ~ is a display label, not a path
    item "~/.local/bin    $(ls -1 "$HOME/.local/bin" 2>/dev/null | count) executables"
  fi
fi

# ── Language-level ───────────────────────────────────────────────────────────
section "LANGUAGE-LEVEL (globals)"
LANG_ANY=0

if has pip || has pip3; then
  PIP=$(where pip3 || where pip)
  u=$("$PIP" list --user --format=freeze 2>/dev/null | count)
  item "pip --user      $u packages"
  [ "$u" -gt 25 ] && flag "pip --user has $u packages — consider pipx or venvs for tools."
  LANG_ANY=1
fi
if has npm; then
  g=$(npm ls -g --depth=0 --parseable 2>/dev/null | tail -n +2 | count)
  root=$(npm root -g 2>/dev/null)
  item "npm -g          $g packages   ${DIM}${root}${N}"
  case "$root" in
    /usr/lib/*|/usr/local/lib/*)
      [ -w "$root" ] || flag "npm global prefix is $root — root-owned; 'sudo npm -g' will fight your distro." ;;
  esac
  LANG_ANY=1
fi
if has pnpm; then
  # grep for /node_modules/ rather than tail -n +2: pnpm's parseable output
  # omits the root line entirely when no globals are installed.
  item "pnpm -g         $(pnpm ls -g --parseable --depth=0 2>/dev/null | grep -c '/node_modules/') packages"
  LANG_ANY=1
fi
if has yarn; then
  item "yarn global     $(yarn global list --silent 2>/dev/null | grep -c '^info "') packages"
  LANG_ANY=1
fi
if has bun; then
  item "bun -g          $(bun pm ls -g 2>/dev/null | grep -c '── ') packages"
  LANG_ANY=1
fi
if has cargo; then
  item "cargo install   $(cargo install --list 2>/dev/null | grep -c ':$') crates"
  LANG_ANY=1
fi
if has gem; then
  item "gem             $(gem list --local 2>/dev/null | count) gems"
  LANG_ANY=1
fi
if has go; then
  # An empty GOPATH would collapse the path below to /bin and count
  # system binaries as go installs.
  gp=$(go env GOPATH 2>/dev/null)
  [ -n "$gp" ] && item "go install      $(ls -1 "$gp/bin" 2>/dev/null | count) binaries"
  LANG_ANY=1
fi
has composer && { item "composer -g     $(composer global show 2>/dev/null | count) packages"; LANG_ANY=1; }
if has luarocks; then
  item "luarocks        $(luarocks list --porcelain 2>/dev/null | cut -f1 | sort -u | count) rocks"
  LANG_ANY=1
fi
if has uv; then
  # tool lines start at column 0; their entrypoints are indented "- " lines
  t=$(uv tool list 2>/dev/null | grep -c '^[^-]')
  p=$(uv python list --only-installed 2>/dev/null | awk '{print $1}' | sort -u | count)
  item "uv              $t tools, $p managed pythons"
  LANG_ANY=1
fi
[ "$LANG_ANY" -eq 0 ] && note "none present"

# ── Version managers ─────────────────────────────────────────────────────────
VM_LIST=()
for pm in $VERSION_MGR; do have_pm "$pm" && VM_LIST+=("$pm"); done
# nvm and sdkman are shell functions, invisible to command -v — detect by dir.
[ -d "$HOME/.nvm" ] && ! printf '%s\n' ${VM_LIST[@]+"${VM_LIST[@]}"} | grep -qx nvm && VM_LIST+=("nvm(dir)")
[ -d "$HOME/.sdkman" ] && ! printf '%s\n' ${VM_LIST[@]+"${VM_LIST[@]}"} | grep -qx sdk && VM_LIST+=("sdkman(dir)")

if [ "${#VM_LIST[@]}" -gt 0 ]; then
  section "VERSION MANAGERS"
  item "${VM_LIST[*]}"
  if [ "${#VM_LIST[@]}" -gt 2 ]; then
    flag "${#VM_LIST[@]} version managers present (${VM_LIST[*]}) — overlapping ones fight over PATH shims."
  fi
fi

# ── PATH shadowing ───────────────────────────────────────────────────────────
section "PATH SHADOWING"
note "which copy wins when two managers ship the same command"
SHADOW=0
for cmd in python3 pip3 node npm git curl openssl ruby perl go make gcc; do
  # Dedupe by RESOLVED target: on modern distros /bin is a symlink to /usr/bin,
  # so the same binary appears twice in PATH without being a real conflict.
  hits=$(IFS=:; for d in $PATH; do
      f="$d/$cmd"
      [ -f "$f" ] && [ -x "$f" ] || continue
      rp=$(readlink -f "$f" 2>/dev/null) || rp="$f"
      printf '%s\t%s\n' "${rp:-$f}" "$f"
    done | awk -F'\t' '!seen[$1]++ {print $2}')
  n=$(printf '%s' "$hits" | count)
  [ "$n" -le 1 ] && continue
  SHADOW=1
  winner=$(printf '%s\n' "$hits" | head -1)
  printf '  %-10s %s%s%s  (wins)\n' "$cmd" "$B" "$winner" "$N"
  printf '%s\n' "$hits" | tail -n +2 | sed "s/^/             ${DIM}shadowed: /;s/\$/${N}/"
  case "$(scope_of "$winner")" in
    system\ \(distro\)) ;;
    *) flag "'$cmd' resolves to $(scope_of "$winner") ($winner), not the distro copy — cron/systemd use a minimal PATH and will get a different one." ;;
  esac
done
[ "$SHADOW" -eq 0 ] && good "no duplicates among common commands"

# ── Distro Python integrity ──────────────────────────────────────────────────
if [ "$QUICK" -eq 0 ]; then
  section "DISTRO PYTHON INTEGRITY"
  note "files under distro dirs that no package owns = installed by 'sudo pip'"
  CHECKED=0
  if has dpkg-query; then
    DIRS=$(for d in /usr/lib/python3/dist-packages /usr/lib/python3*/dist-packages \
                    /usr/lib/python3*/site-packages; do
             [ -d "$d" ] && (readlink -f "$d" 2>/dev/null || echo "$d")
           done | sort -u)
    for d in $DIRS; do
      CHECKED=1
      # __pycache__ and .pyc are generated at runtime and never dpkg-owned:
      # counting them as "unowned" would flag every healthy system.
      unowned=$(dpkg -S "$d"/* 2>&1 >/dev/null \
        | sed -n 's/.*no path found matching pattern //p' \
        | xargs -r -n1 basename 2>/dev/null \
        | grep -Ev '^(__pycache__|.*\.pyc|.*\.pyo)$' | sort -u)
      n=$(printf '%s' "$unowned" | count)
      if [ "$n" -gt 0 ]; then
        bad "$d — $n unowned entries"
        printf '%s\n' "$unowned" | head -12 | sed 's/^/      /'
        [ "$n" -gt 12 ] && note "    …and $((n-12)) more"
        flag "$n unowned files in $d — legacy 'sudo pip install'; apt can't manage or patch these."
      else
        good "$d clean"
      fi
    done
  elif has rpm; then
    for d in /usr/lib/python3*/site-packages /usr/lib64/python3*/site-packages; do
      [ -d "$d" ] || continue
      CHECKED=1
      # One batched rpm -qf; the "not owned" message lands on stdout or
      # stderr depending on rpm version, so merge and pattern-match.
      unowned=$(rpm -qf "$d"/* 2>&1 \
        | sed -n 's/^file \(.*\) is not owned by any package$/\1/p' \
        | xargs -r -n1 basename 2>/dev/null \
        | grep -Ev '^(__pycache__|.*\.pyc|.*\.pyo)$' | sort -u)
      n=$(printf '%s' "$unowned" | count)
      if [ "$n" -gt 0 ]; then
        bad "$d — $n unowned entries"
        printf '%s\n' "$unowned" | head -12 | sed 's/^/      /'
        [ "$n" -gt 12 ] && note "    …and $((n-12)) more"
        flag "$n unowned files in $d — legacy 'sudo pip install'; rpm can't manage or patch these."
      else
        good "$d clean"
      fi
    done
  fi
  [ "$CHECKED" -eq 0 ] && note "not applicable on this system"
fi

# ── Off-PATH footprints ──────────────────────────────────────────────────────
section "OFF-PATH FOOTPRINTS"
note "installed or leftover but not currently in PATH"
OFF=0
for d in /nix /var/lib/flatpak "$HOME/.local/share/flatpak" /snap /var/lib/snapd \
         "$HOME/.nix-profile" "$HOME/.cargo" "$HOME/.rustup" "$HOME/.asdf" \
         "$HOME/.local/share/mise" "$HOME/.nvm" "$HOME/.pyenv" "$HOME/.rbenv" \
         "$HOME/.sdkman" "$HOME/.bun" /home/linuxbrew /opt/homebrew \
         "$HOME/miniconda3" "$HOME/anaconda3" "$HOME/.gem" "$HOME/go"; do
  [ -e "$d" ] || continue
  OFF=1
  sz=""
  [ "$QUICK" -eq 0 ] && sz=$(du -sh "$d" 2>/dev/null | cut -f1)
  printf '  %-40s %s\n' "$d" "${sz:-?}"
done
[ "$OFF" -eq 0 ] && note "none"

# ── Summary ──────────────────────────────────────────────────────────────────
section "SUMMARY"
if [ "${#FLAGS[@]}" -eq 0 ]; then
  good "No red flags. Layers look cleanly separated."
else
  printf '  %s%d thing(s) worth a look:%s\n\n' "$Y" "${#FLAGS[@]}" "$N"
  i=1
  for f in "${FLAGS[@]}"; do
    printf '  %s%d.%s %s\n' "$B" "$i" "$N" "$f"
    i=$((i+1))
  done
fi
echo
[ "${#FLAGS[@]}" -eq 0 ] || exit 1
