#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""A pull request from a fork never runs on this repository's own runners.

  scripts/check-fork-guard.py              check .github/workflows (exit 1 on a refusal)
  scripts/check-fork-guard.py --self-test  paired controls, then the real tree
  scripts/check-fork-guard.py --public     require read-only standard hosted jobs

The explicit public mode retains the private fixture controls and adds hosted
runner, permission, checkout, reusable witness and failure-propagation checks.
Without --public the private guard rules below remain unchanged.
The public reader accepts a narrow canonical YAML subset and rejects unknown
representations. It is a static check of committed files, not the runner access
boundary: a fork can edit its own guard. Repository and runner-group settings
must independently deny the private fleet access to public contribution jobs.

Four rules over every workflow file:

  1. A job whose runner is not a literal GitHub-hosted image label carries
     GUARD, verbatim and alone on its line, as its one job-level `if:`. "Not a
     literal hosted label" rather than "names self-hosted": runners are chosen
     by label, so `runs-on: [granary]` reaches the fleet without the word, and
     an expression or a missing `runs-on` (a reusable-workflow call) cannot be
     read as hosted. "Alone on its line": a more-indented line below it, or a
     block scalar, folds into the condition (`GUARD || true`), so either is
     refused. The one exception is `ci-green`, which a fork must fail rather
     than skip, since a skipped required check reads as a pass. It carries
     `if: always()` alone, its `runs-on` sends a fork to a hosted image through
     GUARD itself, and its first step is exactly REFUSAL_STEP, failing a fork
     with "needs maintainer import"; nothing in it or its workflow may let
     that step fail softly (`continue-on-error`, `defaults`).
  2. No workflow names `pull_request_target`, on any line that is not a
     comment.
  3. A workflow that names a pull request's head anywhere
     (`github.event.pull_request.head.` outside GUARD and FORK,
     `github.head_ref`, `refs/pull/`) names no secret anywhere, in any key
     order: a head named in an `env:` reaches a checkout through `env.X`. A
     form this reader cannot resolve is refused wherever it appears: a block
     scalar on `ref:` or `repository:`, an indexed context (`github[...]`,
     `x['y']`), or an expression that does not close on its own line.
  4. A workflow with a job on its own runners triggers only on TRIGGERS. GUARD
     reads `pull_request` alone, so another event carrying a fork's code (a
     review, a comment, `workflow_run`, a merge queue) would pass it.

The parser reads the small schema these workflows use and refuses a shape it
does not recognise rather than assuming it is safe.

WHAT THIS IS NOT: a boundary against a hostile fork. A `pull_request` run
executes the workflow file from the pull request's merge commit, so a fork can
delete the guard in its own copy. The guard stops this repository's own
workflows from scheduling fork code on its runners by accident; the boundary
against a hostile fork is the owner's fork-approval setting, which no file in
the tree can hold.
"""
import argparse
import json
from pathlib import Path
import re
import sys

GUARD = ("github.event_name != 'pull_request'"
         " || github.event.pull_request.head.repo.full_name == github.repository")
FORK = ("github.event_name == 'pull_request'"
        " && github.event.pull_request.head.repo.full_name != github.repository")
HOSTED = re.compile(r"(ubuntu|macos|windows)-[0-9a-z.-]+")
TRIGGERS = {"push", "pull_request", "schedule", "workflow_dispatch"}
ROUTED = re.compile(r"\(" + re.escape(GUARD)
                    + r"\) && (?:\(vars\.CI_GREEN_SELF_HOSTED == 'true'"
                    + r" \|\| github\.event_name != 'pull_request'\) && )?"
                    + r"fromJSON\('(\[[^']*\])'\) \|\| '([^']+)'")
HEAD_REF = re.compile(r"github\.event\.pull_request\.head\b|github\.head_ref|refs/pull/")
QUOTED_KEY = re.compile(r"^\s*(-\s*)?([\"'][^\"']*[\"']\s*:|\?(\s|$))")
SECRET = re.compile(r"\bsecrets\b")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}")
INDEXED = re.compile(r"[\w\])]\s*\[")
BLOCK_CHECKOUT = re.compile(r"\b(ref|repository)\s*:\s*[|>]")
JOB = re.compile(r"  ([A-Za-z0-9_-]+):\s*(#.*)?")
# ci-green's first step, line for line; NOTICE stands for its message line.
NOTICE = re.compile(r'            echo "::error::needs maintainer import[^"$`\\]*"')
REFUSAL_STEP = (
    "      - name: fork pull request needs maintainer import",
    "        env:",
    f"          FORK: ${{{{ {FORK} }}}}",
    "        run: |",
    '          if [ "$FORK" != false ]; then',
    NOTICE,
    "            exit 1",
    "          fi",
)


def uncommented(text):
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def value(line):
    """The scalar after `key:`, without a trailing comment or `${{ }}` wrapper."""
    text = re.sub(r"\s+#.*$", "", line.split(":", 1)[1]).strip()
    inner = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", text)
    return inner[1] if inner and "${{" not in inner[1] else text


def triggers(lines, name):
    start = [i for i, line in enumerate(lines) if re.match(r"on:", line)]
    if len(start) != 1:
        raise ValueError(f"{name}: no single readable `on:` trigger list")
    inline = lines[start[0]][3:].strip()
    if inline:
        listed = re.fullmatch(r"\[([a-z_, ]+)\]|([a-z_]+)", inline)
        if listed is None:
            raise ValueError(f"{name}: unreadable `on:` trigger list")
        return {item.strip() for item in (listed[1] or listed[2]).split(",")}
    found = set()
    for line in lines[start[0] + 1:]:
        if not line.startswith(" "):
            break
        key = re.fullmatch(r"  ([a-z_]+):.*", line)
        if key:
            found.add(key[1])
        elif not line.startswith("   "):
            raise ValueError(f"{name}: unreadable `on:` trigger list")
    if not found:
        raise ValueError(f"{name}: no single readable `on:` trigger list")
    return found


def jobs(lines, name):
    start = [i for i, line in enumerate(lines) if line == "jobs:"]
    if len(start) != 1:
        raise ValueError(f"{name}: no single `jobs:` block")
    blocks, current = {}, None
    for line in lines[start[0] + 1:]:
        if not line.startswith(" "):
            break
        header = JOB.fullmatch(line)
        if header:
            if header[1] in blocks:
                raise ValueError(f"{name}: job {header[1]} is declared twice")
            current = header[1]
            blocks[current] = []
        elif current is None or not line.startswith("    "):
            raise ValueError(f"{name}: unreadable job declaration: {line.strip()}")
        else:
            blocks[current].append(line)
    if not blocks:
        raise ValueError(f"{name}: no jobs")
    return blocks


def runs_on(body):
    keys = [i for i, line in enumerate(body) if re.match(r"    runs-on:", line)]
    if len(keys) > 1:
        raise ValueError("runs-on is declared twice")
    if not keys:
        return None
    text = value(body[keys[0]])
    for line in body[keys[0] + 1:]:
        if not line.startswith("     "):
            break
        text += " " + line.strip()
    return text


def first_step(body):
    try:
        steps = body.index("    steps:")
    except ValueError:
        return []
    step = []
    for line in body[steps + 1:]:
        if line.startswith("      - ") and step:
            break
        if not line.startswith("      "):
            break
        step.append(line)
    return step


def conditions(body):
    """The job-level `if:` values, each refused unless it stands alone on its line."""
    found = []
    for i, line in enumerate(body):
        if re.match(r"    if:", line):
            text = value(line)
            if not text or text[0] in "|>" or body[i + 1:i + 2] and body[i + 1].startswith("     "):
                raise ValueError("its job-level `if:` does not stand alone on its line,"
                                 " so this reader cannot equate it with a known condition")
            found.append(text)
    return found


def check_ci_green(body, runner, name):
    """`ci-green` fails a fork instead of being skipped (rule 1's exception)."""
    if conditions(body) != ["always()"]:
        raise ValueError(f"{name}: job ci-green must carry `if: always()` alone,"
                         " or a fork skips it and a skipped required check reads as a pass")
    routed = ROUTED.fullmatch(runner or "")
    if not (routed and HOSTED.fullmatch(routed[2])):
        raise ValueError(f"{name}: job ci-green must route a fork to a GitHub-hosted runner"
                         f" through the fork guard ({runner or 'no runs-on'})")
    step = first_step(body)
    if (len(step) != len(REFUSAL_STEP)
            or any(not (want.fullmatch(got) if want is NOTICE else want == got)
                   for want, got in zip(REFUSAL_STEP, step))
            or any(re.match(r"    (continue-on-error|defaults):", line) for line in body)):
        raise ValueError(f"{name}: job ci-green routes a fork to a hosted runner"
                         " but its first step does not fail it with \"needs maintainer import\"")
    return True


def check_job(job, body, name):
    """Return True when the job runs on this repository's own runners."""
    runner = runs_on(body)
    if job == "ci-green":
        return check_ci_green(body, runner, name)
    if runner is not None and HOSTED.fullmatch(runner):
        return False
    if conditions(body) == [GUARD]:
        return True
    raise ValueError(f"{name}: job {job} may run on this repository's runners"
                     f" ({runner or 'no runs-on'}) without the fork guard `if: {GUARD}`")


def check_workflow(name, text, public=False):
    """Refuse a rule breach with ValueError; return (jobs, own-runner jobs)."""
    lines = uncommented(text)
    if any("pull_request_target" in line for line in lines):
        raise ValueError(f"{name}: names pull_request_target")
    for line in lines:
        expressions = EXPRESSION.findall(line)
        if line.count("${{") != len(expressions):
            raise ValueError(f"{name}: an expression does not close on its own line: {line.strip()}")
        if re.search(r"\bgithub\s*\[", line) or any(INDEXED.search(inner) for inner in expressions):
            raise ValueError(f"{name}: indexes a context, which this reader cannot judge: {line.strip()}")
        if QUOTED_KEY.search(line):
            raise ValueError(f"{name}: a quoted or explicit key, which this reader cannot judge: {line.strip()}")
        if BLOCK_CHECKOUT.search(line):
            raise ValueError(f"{name}: a block scalar on `ref:` or `repository:`,"
                             f" which this reader cannot judge: {line.strip()}")
    # GUARD and FORK read the head repository's name only to compare it.
    if (any(HEAD_REF.search(line.replace(GUARD, "").replace(FORK, "")) for line in lines)
            and any(SECRET.search(line) for line in lines)):
        raise ValueError(f"{name}: checks out a pull request head with secrets")
    preamble = lines[:lines.index("jobs:")] if "jobs:" in lines else lines
    on = triggers(preamble, name)
    blocks = jobs(lines, name)
    if "ci-green" in blocks and any(re.match(r"defaults:", line) for line in lines):
        raise ValueError(f"{name}: a workflow-level `defaults:` could let ci-green's refusal step fail softly")
    if public:
        check_public(name, preamble, on, blocks, lines)
        return len(blocks), 0
    own = 0
    for job, body in blocks.items():
        try:
            own += check_job(job, body, name)
        except ValueError as exc:
            if str(exc).startswith(name):
                raise
            raise ValueError(f"{name}: job {job}: {exc}") from exc
    if own and not on <= TRIGGERS:
        raise ValueError(f"{name}: a workflow with jobs on this repository's runners"
                         f" triggers on {sorted(on - TRIGGERS)}, which the fork guard does not read")
    return len(blocks), own


PUBLIC_HOSTED = {"ubuntu-24.04", "macos-26", "macos-15"}
CANDIDATE_WORKFLOW = "./.github/workflows/public-ci-candidate.yml"


def public_permissions(body, indent):
    declarations = [i for i, line in enumerate(body) if re.match(" " * indent + r"permissions:", line)]
    if len(declarations) != 1:
        raise ValueError("public permissions must be explicit and read-only")
    index, = declarations
    raw = value(body[index])
    if raw == "{}":
        return
    if raw.startswith("{") and raw.endswith("}"):
        fields = [field.strip() for field in raw[1:-1].split(",")]
    elif not raw:
        fields = []
        for line in body[index + 1:]:
            if not line.startswith(" " * (indent + 1)):
                break
            fields.append(line.strip())
    else:
        fields = []
    if (not fields or len(fields) != len(set(fields))
            or any(not re.fullmatch(r"(?:actions|contents): read", field) for field in fields)):
        raise ValueError("public permissions must be explicit and read-only")


def public_flow_fields(text):
    """Split the supported flat flow maps/lists without treating quoted data as YAML."""
    fields, start, index = [], 0, 0
    quote = None
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                if quote == "'" and text[index:index + 2] == "''":
                    index += 2
                    continue
                quote = None
        elif text[index:index + 3] == "${{":
            end = text.find("}}", index + 3)
            if end < 0:
                raise ValueError("public YAML has an unreadable expression")
            index = end + 2
            continue
        elif char in "\"'":
            quote = char
        elif char in "{}[]":
            raise ValueError("public YAML does not support nested flow nodes")
        elif char == ",":
            fields.append(text[start:index].strip())
            start = index + 1
        index += 1
    if quote:
        raise ValueError("public YAML has an unreadable quoted scalar")
    fields.append(text[start:].strip())
    return fields


PUBLIC_KEY = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*):(?: (.*))?$")


def public_scalar(raw):
    if raw.startswith(("&", "*", "!")):
        raise ValueError("public YAML does not support anchors, aliases or tags")
    if raw.startswith(("{", "[")):
        if not raw.endswith("}" if raw[0] == "{" else "]"):
            raise ValueError("public YAML has an unreadable flow node")
        fields = public_flow_fields(raw[1:-1]) if raw[1:-1].strip() else []
        if raw[0] == "[":
            return [public_scalar(field) for field in fields]
        result = {}
        for field in fields:
            match = PUBLIC_KEY.fullmatch(field)
            if match is None or match[1] in result or not match[2]:
                raise ValueError("public YAML requires distinct canonical mapping keys")
            result[match[1]] = public_scalar(match[2])
        return result
    return raw


def public_mapping(lines, indent):
    """Read only canonical block mappings, mapping sequences and flat flow values.

    Literal/folded scalar payloads remain data: shell case arms, heredocs and
    strings naming YAML fields must never become workflow properties.
    """
    result, index = {}, 0
    while index < len(lines):
        line = lines[index]
        if len(line) - len(line.lstrip(" ")) != indent:
            raise ValueError("public YAML requires canonical mapping indentation")
        match = PUBLIC_KEY.fullmatch(line[indent:])
        if match is None or match[1] in result:
            raise ValueError("public YAML requires distinct canonical mapping keys")
        key, raw = match[1], re.sub(r"\s+#.*$", "", match[2] or "").strip()
        end = index + 1
        while end < len(lines) and len(lines[end]) - len(lines[end].lstrip(" ")) > indent:
            end += 1
        nested = lines[index + 1:end]
        if re.fullmatch(r"[|>](?:[-+]?[1-9]?|[1-9][-+]?)", raw):
            result[key] = raw + "\n" + "\n".join(nested)
        elif raw:
            if nested:
                raise ValueError("public YAML does not support continued scalar properties")
            result[key] = public_scalar(raw)
        elif nested and nested[0].startswith(" " * (indent + 2) + "- "):
            result[key] = public_sequence(nested, indent + 2)
        else:
            result[key] = public_mapping(nested, indent + 2) if nested else ""
        index = end
    return result


def public_sequence(lines, indent):
    result, index = [], 0
    prefix = " " * indent + "- "
    while index < len(lines):
        line = lines[index]
        if not line.startswith(prefix) or PUBLIC_KEY.fullmatch(line[len(prefix):]) is None:
            raise ValueError("public YAML requires canonical mapping sequence entries")
        end = index + 1
        while end < len(lines) and len(lines[end]) - len(lines[end].lstrip(" ")) > indent:
            end += 1
        result.append(public_mapping([" " * (indent + 2) + line[len(prefix):], *lines[index + 1:end]], indent + 2))
        index = end
    return result


def public_expression(expression):
    """Recognize context roots lexically; do not evaluate GitHub expressions."""
    if "\\" in expression:
        raise ValueError("public expressions do not support escapes")
    # Single-quoted expression literals use doubled apostrophes. Their contents
    # are data, while a bare context root can carry the token even through toJSON.
    pieces, index = [], 0
    while index < len(expression):
        if expression[index] == "'":
            match = re.match(r"'(?:[^']|'')*'", expression[index:])
            if match is None:
                raise ValueError("public expressions require closed string literals")
            pieces.append(" ")
            index += len(match[0])
        else:
            pieces.append(expression[index])
            index += 1
    code = "".join(pieces)
    if not code.isascii():
        raise ValueError("public expressions require ASCII identifiers")
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_-]*|[^\s]", code)
    for index, token in enumerate(tokens):
        if token.casefold() != "github" or index > 0 and tokens[index - 1] == ".":
            continue
        following = tokens[index + 1:index + 3]
        if (len(following) == 2 and following[0] == "."
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", following[1])
                and following[1].casefold() != "token"):
            continue
        raise ValueError("public PR and reusable code cannot receive an explicit token or whole github context")


def public_context_scalars(node):
    # YAML double-quoted escapes could create an expression marker or context
    # name only after this static reader ran. Decline that representation.
    if isinstance(node, dict):
        for value_ in node.values():
            public_context_scalars(value_)
    elif isinstance(node, list):
        for value_ in node:
            public_context_scalars(value_)
    elif isinstance(node, str) and node.startswith('"') and "\\" in node:
        raise ValueError("public expressions do not support escaped YAML scalars")


def public_bare_if(raw):
    if raw is None:
        return
    if not isinstance(raw, str):
        raise ValueError("public if conditions require a scalar expression")
    if "${{" in raw:
        return  # Every explicit expression was inspected independently.
    if raw.startswith(("|", ">")):
        raw = " ".join(raw.splitlines()[1:]).strip()
    if raw.startswith(("'", '"')):
        if len(raw) < 2 or raw[-1] != raw[0]:
            raise ValueError("public if conditions require a closed YAML scalar")
        raw = raw[1:-1].replace("''", "'") if raw[0] == "'" else raw[1:-1]
    public_expression(raw)


def check_public(name, preamble, on, blocks, lines):
    header = public_mapping(preamble, 0)
    sensitive = bool(on & {"pull_request", "workflow_call"})
    if sensitive:
        public_context_scalars(header)
        for line in lines:
            for expression in EXPRESSION.findall(line):
                public_expression(expression)
    if not on <= TRIGGERS | {"workflow_call"}:
        raise ValueError("unsupported public workflow trigger")
    if [line for line in preamble if line.startswith("permissions:")] != ["permissions: {}"]:
        raise ValueError("public workflow permissions must be empty")
    if any(line.startswith("defaults:") for line in preamble):
        raise ValueError("public workflows cannot override the shell")
    if any(re.search(r"\bsecrets\b", line, re.IGNORECASE)
           or re.match(r" *[^#]*\b(?:environment|container|services):", line) for line in lines):
        raise ValueError("public workflows cannot use secrets, environments, containers or services")
    for job, body in blocks.items():
        parsed = public_mapping(body, 4)
        if sensitive:
            public_context_scalars(parsed)
            public_bare_if(parsed.get("if"))
        public_permissions(body, 4)
        if any(re.match(r"    (?:continue-on-error|defaults):", line) for line in body):
            raise ValueError("public jobs cannot soften failures or override the shell")
        if job == "candidate-identity":
            if body != ["    permissions: {}", "    uses: " + CANDIDATE_WORKFLOW]:
                raise ValueError("candidate-identity must use the exact relative witness without overrides")
            continue
        runner = runs_on(body)
        if runner not in PUBLIC_HOSTED:
            raise ValueError("public jobs require a literal standard hosted runner")
        expected_conditions = ["always()"] if job == "ci-green" else []
        if conditions(body) != expected_conditions:
            raise ValueError("public workers must be unconditional and ci-green must always run")
        if len([line for line in body if line.startswith("    timeout-minutes:")]) != 1:
            raise ValueError("public jobs require an explicit timeout")
        steps = parsed.get("steps")
        if not isinstance(steps, list) or not steps or any(not isinstance(step, dict) for step in steps):
            raise ValueError("public jobs require a nonempty canonical steps sequence")
        if "uses" in parsed:
            raise ValueError("only candidate-identity may call a reusable workflow")
        for step in steps:
            if sensitive:
                public_bare_if(step.get("if"))
            if ("uses" in step) == ("run" in step):
                raise ValueError("public steps require exactly one action or run command")
            if "uses" in step and (not isinstance(step["uses"], str) or not re.fullmatch(
                    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}", step["uses"])):
                raise ValueError("public actions require a full commit pin")
            if "continue-on-error" in step and not (
                    name == "macos-weekly.yml" and step.get("name") == "report test binary unwind sizes"
                    and step["continue-on-error"] == "true" and isinstance(step.get("run"), str)
                    and "scripts/report-macos-unwind.py" in step["run"]):
                raise ValueError("required public steps cannot soften failures")
            if (isinstance(step.get("uses"), str)
                    and step["uses"].split("@", 1)[0].casefold().split("/")[:2] == ["actions", "checkout"]):
                inputs = step.get("with")
                if isinstance(inputs, dict) and any(key != key.casefold() for key in inputs):
                    raise ValueError("public checkout requires canonical lowercase input keys")
                if not isinstance(inputs, dict) or inputs.get("persist-credentials") != "false":
                    raise ValueError("public checkout must disable persisted credentials")
    if name == "public-ci-candidate.yml":
        body = blocks.get("verify", [])
        if (on != {"workflow_call"} or set(blocks) != {"verify"}
                or "    permissions: {}" not in body
                or any(re.match(r" +(?:- )?uses:", line) or "github.token" in line for line in lines)):
            raise ValueError("candidate witness must be a token-free no-checkout reusable job")


def public_self_test():
    fixture = """name: fixture
on: [pull_request]
permissions: {}
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with: { persist-credentials: false }
  ci-green:
    needs: [build]
    if: always()
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions: { contents: read }
    steps:
      - run: true
"""
    cases = 0
    def case(label, text, diagnostic=None, name="ci.yml"):
        nonlocal cases
        try:
            check_workflow(name, text, public=True)
        except ValueError as exc:
            if diagnostic is None or diagnostic not in str(exc):
                raise RuntimeError(f"{label}: unexpected refusal {exc}") from exc
        else:
            if diagnostic is not None:
                raise RuntimeError(f"{label}: accepted invalid public workflow")
        cases += 1
        print(f"public fork guard self-test: {label} PASS")
    case("read-only hosted", fixture)
    for runner in ("macos-15", "macos-26"):
        case(runner, fixture.replace("runs-on: ubuntu-24.04", "runs-on: " + runner))
    for runner in ("[self-hosted, linux]", "[granary]", "${{ matrix.os }}", "ubuntu-24.04-8-cores", "ubuntu-latest"):
        case("runner " + runner, fixture.replace("runs-on: ubuntu-24.04", "runs-on: " + runner), "literal standard hosted")
    for permission in ("write-all", "{ contents: write }", "{ contents: read, id-token: write }"):
        case("permissions " + permission, fixture.replace("{ contents: read }", permission), "explicit and read-only")
    case("missing job permissions", fixture.replace("    permissions: { contents: read }\n", ""), "explicit and read-only")
    case("workflow write permission", fixture.replace("permissions: {}", "permissions: write-all"), "workflow permissions must be empty")
    case("persist credentials", fixture.replace("persist-credentials: false", "persist-credentials: true"), "disable persisted")
    case("default credentials", fixture.replace("        with: { persist-credentials: false }\n", ""), "disable persisted")
    case("action tag", fixture.replace("@" + "0" * 40, "@v7"), "full commit pin")
    case("missing timeout", fixture.replace("    timeout-minutes: 5\n", ""), "explicit timeout")
    case("conditional worker", fixture.replace("  build:\n", "  build:\n    if: false\n"), "unconditional")
    case("skipped summary", fixture.replace("if: always()", "if: success()"), "unconditional")
    case("soft job", fixture.replace("  build:\n", "  build:\n    continue-on-error: true\n"), "soften failures")
    case("soft step", fixture.replace("      - run: true", "      - run: true\n        continue-on-error: true"), "soften failures")
    case("weekly suite soft failure", fixture.replace("      - run: true", "      - run: true\n        continue-on-error: true"), "soften failures", name="macos-weekly.yml")
    diagnostic = "      - name: report test binary unwind sizes\n        continue-on-error: true\n        run: python3 scripts/report-macos-unwind.py inventory\n"
    case("weekly diagnostic", fixture.replace("      - run: true\n", diagnostic), name="macos-weekly.yml")
    case("workflow shell override", fixture.replace("jobs:\n", "defaults: { run: { shell: sh } }\njobs:\n"), "workflow-level `defaults:`")
    for key in ("environment: private", "container: private", "services: {}", "env: { TOKEN: '${{ secrets.DEPLOY }}' }"):
        case(key, fixture.replace("  build:\n", "  build:\n    " + key + "\n"), "cannot use secrets")
    case("explicit PR token", fixture.replace("      - run: true", "      - run: echo '${{ github.token }}'"), "explicit token")
    relative = fixture + "  candidate-identity:\n    permissions: {}\n    uses: " + CANDIDATE_WORKFLOW + "\n"
    case("exact relative witness", relative)
    for suffix in ("@main", "@" + "0" * 40):
        case("lookalike witness " + suffix, relative.replace(CANDIDATE_WORKFLOW, CANDIDATE_WORKFLOW + suffix), "exact relative witness")
    case("witness conditional", relative.replace("  candidate-identity:\n", "  candidate-identity:\n    if: false\n"), "exact relative witness")
    checkout = ("      - uses: actions/checkout@" + "0" * 40 + "\n"
                "        with: { persist-credentials: false }\n")
    case("flow action tag and default credentials", fixture.replace(checkout,
         "      - { uses: actions/checkout@v7 }\n"), "canonical mapping sequence")
    case("flow pinned checkout default credentials", fixture.replace(checkout,
         "      - { uses: actions/checkout@" + "0" * 40 + " }\n"), "canonical mapping sequence")
    case("flow soft step", fixture.replace("      - run: true\n",
         "      - { run: false, continue-on-error: true }\n"), "canonical mapping sequence")
    case("flow steps list", fixture.replace("    steps:\n      - run: true\n",
         "    steps: [{ run: false, continue-on-error: true }]\n"), "nested flow")
    case("indentless soft step", fixture.replace("    steps:\n      - run: true\n",
         "    steps:\n    - run: false\n      continue-on-error: true\n"), "canonical mapping")
    case("indentless checkout", fixture.replace(checkout,
         "    - uses: actions/checkout@v7\n"), "canonical mapping")
    case("extra sequence indentation", fixture.replace("      - run: true\n",
         "        - run: true\n"), "canonical mapping")
    anchored = fixture.replace("permissions: {}\n", "permissions: {}\nenv:\n  fixture: &danger {run: false, continue-on-error: true}\n", 1)
    case("aliased step", anchored.replace("      - run: true\n", "      - *danger\n"), "anchors, aliases or tags")
    case("merged step", anchored.replace("      - run: true\n", "      - <<: *danger\n"), "anchors, aliases or tags")
    case("anchored steps", fixture.replace("    steps:\n", "    steps: &steps\n", 1), "continued scalar")
    case("anchored flow step and alias", fixture.replace("      - run: true\n",
         "      - &danger { run: false, continue-on-error: true }\n      - *danger\n"), "canonical mapping sequence")
    case("alias sequence entry", fixture.replace("      - run: true\n", "      - *danger\n"), "canonical mapping sequence")
    case("anchored action", fixture.replace("uses: actions/checkout@", "uses: &action actions/checkout@"), "anchors, aliases or tags")
    case("tagged action", fixture.replace("uses: actions/checkout@", "uses: !!str actions/checkout@"), "anchors, aliases or tags")
    case("tagged sequence entry", fixture.replace("      - run: true\n", "      - !!map { run: true }\n"), "canonical mapping sequence")
    case("root merge key", fixture.replace("jobs:\n", "<<: *defaults\njobs:\n"), "canonical mapping keys")
    case("flow merge key", fixture.replace("{ persist-credentials: false }", "{ <<: *defaults, persist-credentials: false }"), "canonical mapping keys")
    case("flow alias input", fixture.replace("{ persist-credentials: false }", "{ persist-credentials: *disabled }"), "anchors, aliases or tags")
    case("flow anchored input", fixture.replace("{ persist-credentials: false }", "{ persist-credentials: &disabled false }"), "anchors, aliases or tags")
    case("flow quoted input key", fixture.replace("{ persist-credentials: false }", "{ 'persist-credentials': false }"), "canonical mapping keys")
    case("duplicate action", fixture.replace("        with: { persist-credentials: false }\n",
         "        uses: other/action@" + "0" * 40 + "\n        with: { persist-credentials: false }\n"), "canonical mapping keys")
    case("duplicate credentials input", fixture.replace("{ persist-credentials: false }",
         "{ persist-credentials: false, persist-credentials: true }"), "canonical mapping keys")
    case("credential text in unrelated input", fixture.replace("{ persist-credentials: false }",
         '{ persist-credentials: true, path: "persist-credentials: false bogus" }'), "disable persisted")
    case("credential text in block input", fixture.replace("        with: { persist-credentials: false }\n",
         '        with:\n          path: "persist-credentials: false bogus"\n          persist-credentials: true\n'), "disable persisted")
    case("flow job", fixture.replace("  build:\n", "  build: { runs-on: ubuntu-24.04 }\n"), "unreadable job declaration")
    case("mapping steps", fixture.replace("    steps:\n      - run: true\n", "    steps: {}\n"), "canonical steps sequence")
    case("scalar steps", fixture.replace("    steps:\n      - run: true\n", "    steps: [echo]\n"), "canonical steps sequence")
    case("continued action", fixture.replace("uses: actions/checkout@", "uses: >-\n          actions/checkout@"), "full commit pin")
    named = fixture.replace(checkout, "      - name: checkout\n        uses: actions/checkout@" + "0" * 40 + "\n        with:\n          persist-credentials: false\n")
    case("named checkout with block inputs", named)
    case("quoted commas in flat inputs", fixture.replace("{ persist-credentials: false }",
         '{ persist-credentials: false, path: "comma, colon: *literal &data !tag" }'))
    case("literal YAML-shaped run data", fixture.replace("      - run: true\n",
         "      - run: |\n          uses: actions/checkout@v7\n          <<: *literal\n          continue-on-error: true\n"))
    for spelling in ("Actions/Checkout", "ACTIONS/CHECKOUT", "actions/CHECKOUT"):
        mixed = fixture.replace("actions/checkout@", spelling + "@")
        case("case-variant checkout with disabled credentials " + spelling, mixed)
        case("case-variant checkout with default credentials " + spelling,
             mixed.replace("        with: { persist-credentials: false }\n", ""), "disable persisted")
    for path in ("Actions/Checkout/action", "Actions/Checkout/."):
        case("checkout repository subpath " + path,
             fixture.replace("actions/checkout@", path + "@").replace("        with: { persist-credentials: false }\n", ""), "disable persisted")
    case("case-variant checkout input override", fixture.replace("{ persist-credentials: false }",
         "{ persist-credentials: false, PERSIST-CREDENTIALS: true }"), "canonical lowercase input")

    def context_env(expression):
        return fixture.replace("      - run: true\n",
            "      - run: true\n        env:\n          CONTEXT: " + expression + "\n")
    for expression in ("github", "toJSON(github)", "toJSON(GitHub)", "format('{0}', GITHUB)",
                       "GitHub.Token", "GITHUB.TOKEN", "github . token", "(github).token",
                       "github.*", "fromJSON(toJSON(github)).token"):
        case("sensitive context " + expression, context_env("${{ " + expression + " }}"), "explicit token")
    for expression in ("github['token']", "GitHub['Token']"):
        case("indexed context " + expression, context_env("${{ " + expression + " }}"), "indexes a context")
    for expression in ("contains(toJSON(github), 'token')", "GitHub.Token != ''", "github . token != null",
                       '"GitHub.Token"', "'GitHub.Token'", "GitHub['token']",
                       ">-\n          contains(toJSON(github), 'token')"):
        case("bare if context " + expression, fixture.replace("      - run: true\n",
             "      - run: true\n        if: " + expression + "\n"), "explicit token")
    case("bare indexed lowercase context", fixture.replace("      - run: true\n",
         "      - run: true\n        if: github['token'] != ''\n"), "indexes a context")
    for expression in ("runner.os == 'Linux'", "github.ref == 'refs/heads/main'",
                       '"github.ref == \'refs/heads/main\'"', "'contains(''github.token'', ''github'')'"):
        case("ordinary bare if " + expression, fixture.replace("      - run: true\n",
             "      - run: true\n        if: " + expression + "\n"))
    case("escaped YAML expression marker", context_env('"' + chr(92) + 'u0024{{ toJSON(github) }}"'), "escaped YAML scalars")
    case("escaped YAML context name", context_env('"${{ ' + chr(92) + 'u0067ithub.token }}"'), "do not support escapes")
    for spelling in ("Secrets.DEPLOY", "SECRETS.DEPLOY", "toJSON(SeCrEtS)"):
        case("case-variant secret context " + spelling, context_env("${{ " + spelling + " }}"), "cannot use secrets")
    witness = (Path(__file__).resolve().parent.parent / ".github/workflows/public-ci-candidate.yml").read_text()
    for expression in ("toJSON(github)", "GitHub.Token"):
        case("reusable witness context " + expression,
             witness.replace("${{ github.event.number }}", "${{ " + expression + " }}"),
             "explicit token", name="public-ci-candidate.yml")
    freshness = (Path(__file__).resolve().parent.parent / ".github/workflows/ci-freshness.yml").read_text()
    case("scheduled scoped read token", freshness, name="ci-freshness.yml")
    case("quoted context names are data", context_env("${{ format('github.token', 'github') }}"))
    if cases != 106:
        raise RuntimeError(f"public guard controls missing: {cases}")
    print(f"public fork guard self-test: {cases}/{cases} fixture controls passed")
    witness_self_test()



def witness_self_test():
    import os
    import subprocess
    import textwrap
    workflow = Path(__file__).resolve().parent.parent / ".github/workflows/public-ci-candidate.yml"
    text = workflow.read_text()
    check_workflow(workflow.name, text, public=True)
    script = textwrap.dedent(text.split("        run: |\n", 1)[1])
    good = dict(GITHUB_EVENT_NAME="pull_request", GITHUB_SHA="a" * 40,
                GITHUB_REF="refs/pull/17/merge", PR_NUMBER="17")
    cases = 0
    for label, changed, diagnostic in (
            ("PR merge identity", {}, None),
            ("PR head ref", {"GITHUB_REF": "refs/pull/17/head"}, "PR merge ref required"),
            ("wrong PR number", {"PR_NUMBER": "18"}, "PR merge ref required"),
            ("missing PR number", {"PR_NUMBER": ""}, "invalid PR number"),
            ("invalid PR number", {"PR_NUMBER": "17;true"}, "invalid PR number"),
            ("zero PR number", {"PR_NUMBER": "0"}, "invalid PR number"),
            ("short SHA", {"GITHUB_SHA": "a" * 39}, "invalid candidate SHA"),
            ("main push", {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"}, None),
            ("other branch push", {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/topic"}, "main ref required"),
            ("main schedule", {"GITHUB_EVENT_NAME": "schedule", "GITHUB_REF": "refs/heads/main"}, None),
            ("branch dispatch", {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/topic"}, None),
            ("tag dispatch", {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/tags/v1"}, "branch ref required"),
            ("unknown event", {"GITHUB_EVENT_NAME": "issue_comment"}, "unsupported candidate event")):
        result = subprocess.run(["bash", "-c", script], env={**os.environ, **good, **changed},
                                capture_output=True, text=True)
        if (result.returncode != (1 if diagnostic else 0)
                or diagnostic is not None and diagnostic not in result.stderr):
            raise RuntimeError(f"{label}: unexpected witness result {result}")
        cases += 1
        print(f"candidate witness self-test: {label} PASS")
    print(f"candidate witness self-test: {cases}/{cases} controls passed")


def check_tree(root, public=False):
    files = sorted([*root.glob("*.yml"), *root.glob("*.yaml")])
    if not files:
        raise ValueError(f"no workflow files under {root}")
    total = own = 0
    for path in files:
        jobs_, own_ = check_workflow(path.name, path.read_text(), public)
        total += jobs_
        own += own_
    if not public and not own:
        raise ValueError("no job on this repository's runners was found; the reader has gone blind")
    print(f"fork guard: {len(files)} workflows, {total} jobs, {own} on this repository's runners, every one guarded")
    return own


GOOD = f"""\
name: fixture
on:
  push:
    branches: [main]
  pull_request:
jobs:
  build:
    if: {GUARD}
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v0
        with: {{ persist-credentials: false }}
  hosted:
    runs-on: ubuntu-24.04
    steps:
      - run: true
  ci-green:
    needs: [build, hosted]
    if: always()
    runs-on: ${{{{ ({GUARD}) && fromJSON('["self-hosted","linux"]') || 'ubuntu-24.04' }}}}
    steps:
      - name: fork pull request needs maintainer import
        env:
          FORK: ${{{{ {FORK} }}}}
        run: |
          if [ "$FORK" != false ]; then
            echo "::error::needs maintainer import"
            exit 1
          fi
      - run: true
"""
GUARD_LINE = f"    if: {GUARD}\n"


def self_test(public=False):
    cases = 0

    def case(label, text, refusal):
        nonlocal cases
        cases += 1
        try:
            check_workflow("fixture.yml", text)
        except ValueError as exc:
            if refusal is None or refusal not in str(exc):
                raise RuntimeError(f"{label}: wanted {refusal!r}, got refusal {exc}") from exc
        else:
            if refusal is not None:
                raise RuntimeError(f"{label}: wanted refusal {refusal!r}, got acceptance")
        print(f"fork guard self-test: {label} {'refused' if refusal else 'accepted'} PASS")

    unguarded = "may run on this repository's runners"
    case("guarded, hosted and fork-routed jobs", GOOD, None)
    routed = f"({GUARD}) && "
    switch = "(vars.CI_GREEN_SELF_HOSTED == 'true' || github.event_name != 'pull_request') && "
    switched = routed + switch
    switched_good = GOOD.replace(routed, switched)
    routing_refusal = "must route a fork to a GitHub-hosted runner"
    case("fork-routed job with PR-only hosted switch", switched_good, None)
    # Fixed fixture only: Python has the same &&/|| precedence and truthiness
    # for this nonempty array. Exercise routing separately from the whitelist.
    expression = runs_on(jobs(uncommented(switched_good), "fixture.yml")["ci-green"])
    for event in ("pull_request", "push", "schedule", "workflow_dispatch"):
        for variable in ("", "true"):
            for same_repo in ((False, True) if event == "pull_request" else (True,)):
                resolved = expression
                for context, literal in (
                    ("github.event.pull_request.head.repo.full_name", "own/repo" if same_repo else "fork/repo"),
                    ("github.repository", "own/repo"),
                    ("github.event_name", event),
                    ("vars.CI_GREEN_SELF_HOSTED", variable),
                ):
                    resolved = resolved.replace(context, repr(literal))
                runner = eval(resolved.replace("&&", " and ").replace("||", " or "),
                              {"__builtins__": {}, "fromJSON": json.loads})
                expected = ("ubuntu-24.04" if event == "pull_request" and (not same_repo or variable != "true")
                            else ["self-hosted", "linux"])
                if runner != expected:
                    raise RuntimeError(f"routing {event} same_repo={same_repo} variable={variable!r}: {runner!r}")
                cases += 1
                print(f"fork guard self-test: routing {event} same_repo={same_repo} variable={variable!r} PASS")
    case("PR-only switch with self-hosted fork fallback",
         switched_good.replace("|| 'ubuntu-24.04' }}", "|| 'self-hosted' }}"), routing_refusal)
    case("old bare-variable switch",
         GOOD.replace(routed, routed + "vars.CI_GREEN_SELF_HOSTED == 'true' && "), routing_refusal)
    case("routing OR outside parentheses",
         GOOD.replace(routed, routed + "vars.CI_GREEN_SELF_HOSTED == 'true' || github.event_name != 'pull_request' && "),
         routing_refusal)
    case("variable inside guard can route a fork to self-hosted",
         GOOD.replace(routed, f"({GUARD} || vars.CI_GREEN_SELF_HOSTED == 'true') && "), routing_refusal)
    case("variable before guard",
         GOOD.replace(routed, switch + routed), routing_refusal)
    case("another routing variable",
         switched_good.replace("vars.CI_GREEN_SELF_HOSTED", "vars.X"), routing_refusal)
    case("another routing event",
         switched_good.replace(switch, switch.replace("'pull_request'", "'push'")), routing_refusal)
    case("another routing event operator",
         switched_good.replace(switch, switch.replace("!=", "==")), routing_refusal)
    case("repeated self-hosted switch",
         GOOD.replace(routed, switched + switch), routing_refusal)
    case("changes with bare guard", GOOD.replace("  build:\n", "  changes:\n"), None)
    case("changes without bare guard", GOOD.replace("  build:\n" + GUARD_LINE, "  changes:\n"), unguarded)
    case("self-hosted job without the guard", GOOD.replace(GUARD_LINE, "", 1), unguarded)
    case("label-only runner without the guard",
         GOOD.replace(GUARD_LINE, "", 1).replace("[self-hosted, linux]", "[granary]"), unguarded)
    case("matrix expression runner with the guard",
         GOOD.replace("[self-hosted, linux]", "${{ matrix.os == 'a' && fromJSON('[\"self-hosted\"]') || matrix.os }}"), None)
    case("matrix expression runner without the guard",
         GOOD.replace(GUARD_LINE, "", 1).replace("[self-hosted, linux]", "${{ matrix.os }}"), unguarded)
    case("block-list runner without the guard",
         GOOD.replace(GUARD_LINE, "", 1).replace("runs-on: [self-hosted, linux]", "runs-on:\n      - self-hosted\n      - linux"),
         unguarded)
    case("reusable-workflow call without the guard",
         GOOD.replace(GUARD_LINE, "", 1).replace("    runs-on: [self-hosted, linux]\n", "    uses: ./.github/workflows/x.yml\n"),
         "no runs-on")
    case("guard in ${{ }} form", GOOD.replace(GUARD_LINE, f"    if: ${{{{ {GUARD} }}}}\n", 1), None)
    case("weakened guard", GOOD.replace(GUARD_LINE, "    if: github.event_name != 'pull_request' || true\n", 1), unguarded)
    case("guard joined to another condition",
         GOOD.replace(GUARD_LINE, f"    if: always() && ({GUARD})\n", 1), unguarded)
    case("guard declared twice", GOOD.replace(GUARD_LINE, GUARD_LINE + "    if: always()\n", 1), unguarded)
    case("guard only on a step",
         GOOD.replace(GUARD_LINE, "", 1).replace("      - uses: actions/checkout", f"      - if: {GUARD}\n        uses: actions/checkout", 1),
         unguarded)
    case("guard only in a comment", GOOD.replace(GUARD_LINE, f"    # if: {GUARD}\n", 1), unguarded)
    routed_refusal = "does not fail it with \"needs maintainer import\""
    case("fork-routed job without its refusal step",
         GOOD.replace('            exit 1\n', '            true\n'), routed_refusal)
    case("fork-routed refusal step behind a step if",
         GOOD.replace("        env:\n          FORK:", f"        if: {FORK}\n        env:\n          FORK:"), routed_refusal)
    case("fork-routed job whose hosted branch is self-hosted",
         GOOD.replace("|| 'ubuntu-24.04' }}", "|| 'self-hosted' }}"), "must route a fork to a GitHub-hosted runner")
    alone = "does not stand alone on its line"
    case("guard continued on the next line", GOOD.replace(GUARD_LINE, GUARD_LINE + "      || true\n", 1), alone)
    case("guard as a block scalar", GOOD.replace(GUARD_LINE, f"    if: >-\n      {GUARD}\n", 1), alone)
    skipped = "must carry `if: always()` alone"
    case("ci-green skipped for a fork",
         GOOD.replace("    if: always()\n", "    if: github.event_name != 'pull_request'\n"), skipped)
    case("ci-green carrying the guard", GOOD.replace("    if: always()\n", GUARD_LINE), skipped)
    case("ci-green always() continued", GOOD.replace("    if: always()\n", "    if: always()\n      && false\n"), alone)
    case("ci-green refusal step allowed to fail",
         GOOD.replace("        env:\n          FORK:", "        continue-on-error: true\n        env:\n          FORK:"), routed_refusal)
    case("ci-green allowed to fail", GOOD.replace("    if: always()\n", "    if: always()\n    continue-on-error: true\n"),
         routed_refusal)
    case("ci-green under a workflow default shell", GOOD.replace("jobs:\n", "defaults:\n  run:\n    shell: sh\njobs:\n", 1),
         "workflow-level `defaults:`")
    case("pull_request_target trigger", GOOD.replace("  pull_request:\n", "  pull_request_target:\n"), "names pull_request_target")
    case("pull_request_target in a list", GOOD.replace("on:\n  push:\n    branches: [main]\n  pull_request:\n", "on: [push, pull_request_target]\n"),
         "names pull_request_target")
    case("pull_request_target only in a comment", GOOD.replace("on:\n", "# no pull_request_target here\non:\n"), None)
    head = "        with: { persist-credentials: false, ref: ${{ github.event.pull_request.head.sha }} }\n"
    headed = GOOD.replace("        with: { persist-credentials: false }\n", head)
    case("pull request head checkout without secrets", headed, None)
    case("pull request head checkout with a job secret",
         headed.replace(head, head + "        env:\n          TOKEN: ${{ secrets.DEPLOY }}\n"),
         "checks out a pull request head with secrets")
    case("pull request head checkout with a workflow secret",
         headed.replace("jobs:\n", "env:\n  TOKEN: ${{ secrets.DEPLOY }}\njobs:\n", 1),
         "checks out a pull request head with secrets")
    case("head_ref checkout with secrets inherited",
         GOOD.replace("        with: { persist-credentials: false }\n",
                      "        with:\n          ref: ${{ github.head_ref }}\n    secrets: inherit\n"),
         "checks out a pull request head with secrets")
    case("pull request head checkout with a workflow secret after jobs",
         headed + "env:\n  TOKEN: ${{ secrets.DEPLOY }}\n", "checks out a pull request head with secrets")
    case("pull request head checkout with every secret as JSON",
         headed.replace(head, head + "        env:\n          ALL: ${{ toJSON(secrets) }}\n"),
         "checks out a pull request head with secrets")
    case("pull request head through an env value with secrets",
         GOOD.replace("        with: { persist-credentials: false }\n",
                      "        with: { persist-credentials: false, ref: ${{ env.HEAD }} }\n"
                      "        env:\n          HEAD: ${{ github.event.pull_request.head.sha }}\n"
                      "          TOKEN: ${{ secrets.DEPLOY }}\n"),
         "checks out a pull request head with secrets")
    case("pull request head ref in a block scalar",
         GOOD.replace("        with: { persist-credentials: false }\n",
                      "        with:\n          persist-credentials: false\n          ref: >-\n"
                      "            ${{ github.event.pull_request.head.sha }}\n"),
         "a block scalar on `ref:` or `repository:`")
    case("pull request head by indexed github context",
         headed.replace("github.event.pull_request.head.sha", "github['event']['pull_request']['head']['sha']"),
         "indexes a context")
    case("pull request head by indexed event property",
         headed.replace("github.event.pull_request.head.sha", "github.event['pull_request'].head.sha"),
         "indexes a context")
    case("pull request head read as a whole object with secrets",
         headed.replace(head, head + "        env:\n          TOKEN: ${{ secrets.DEPLOY }}\n")
         .replace("github.event.pull_request.head.sha", "fromJSON(toJSON(github.event.pull_request.head)).sha"),
         "checks out a pull request head with secrets")
    case("a quoted defaults key",
         GOOD.replace("jobs:\n", '"defaults":\n  run:\n    shell: bash\njobs:\n', 1),
         "a quoted or explicit key")
    case("an explicit defaults key",
         GOOD.replace("jobs:\n", '? "defaults"\n: {run: {shell: bash}}\njobs:\n', 1),
         "a quoted or explicit key")
    case("indexed github context in a bare step condition",
         GOOD.replace("      - uses: actions/checkout", "      - if: github['event_name'] == 'push'\n        uses: actions/checkout", 1),
         "indexes a context")
    case("pull request head in an expression split across lines",
         GOOD.replace("        with: { persist-credentials: false }\n",
                      "        with:\n          ref: ${{ github.event.pull_request\n            .head.sha }}\n"),
         "does not close on its own line")
    case("own-runner workflow on a review trigger",
         GOOD.replace("  pull_request:\n", "  pull_request:\n  pull_request_review:\n"), "which the fork guard does not read")
    case("own-runner workflow on workflow_run",
         GOOD.replace("on:\n  push:\n    branches: [main]\n  pull_request:\n", "on: [push, workflow_run]\n"),
         "which the fork guard does not read")
    hosted_only = "name: fixture\non:\n  issue_comment:\njobs:\n  hosted:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n"
    case("hosted-only workflow on another trigger", hosted_only, None)
    case("no jobs", "name: fixture\non: [push]\njobs:\n", "no jobs")
    case("no trigger list", GOOD.replace("on:\n  push:\n    branches: [main]\n  pull_request:\n", ""), "no single readable `on:`")
    case("unreadable job declaration", GOOD.replace("  hosted:\n", "  hosted: { runs-on: ubuntu-24.04 }\n"),
         "unreadable job declaration")
    case("job declared twice", GOOD + "  build:\n    runs-on: ubuntu-24.04\n", "declared twice")
    if cases != 71:
        raise RuntimeError(f"wrong fixture case count {cases}")

    if public:
        print(f"fork guard self-test: {cases} private fixture controls passed")
        public_self_test()
        return

    # The real tree, each guard removed in turn: every one must refuse, naming its job.
    root = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    removed = 0
    for path in sorted(root.glob("*.yml")):
        text = path.read_text()
        for match in re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):[^\n]*\n((?:    #[^\n]*\n)*)" + re.escape(GUARD_LINE), text):
            removed += 1
            stripped = text[:match.end() - len(GUARD_LINE)] + text[match.end():]
            try:
                check_workflow(path.name, stripped)
            except ValueError as exc:
                if f"job {match[1]} may run on this repository's runners" not in str(exc):
                    raise RuntimeError(f"{path.name} {match[1]}: wrong refusal {exc}") from exc
            else:
                raise RuntimeError(f"{path.name} {match[1]}: guard removed and accepted")
    if removed == 0:
        raise RuntimeError("no guard found to remove in the real workflows")
    print(f"fork guard self-test: {removed} real guards each removed and refused PASS")
    own = check_tree(root)
    routed = own - removed
    if routed < 1:
        raise RuntimeError("ci-green is not fork-routed")
    print(f"fork guard self-test: {cases} fixture controls + {removed} removed-guard controls passed;"
          f" {routed} fork-routed job(s)")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--public", action="store_true", help="require read-only standard hosted workflows")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test(args.public)
        else:
            check_tree(Path(__file__).resolve().parent.parent / ".github" / "workflows", args.public)
    except (ValueError, OSError) as exc:
        print(f"fork guard: refused — {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
