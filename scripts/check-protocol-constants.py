#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Compare the server's wire spellings, response assignments and limits with
scripts/protocol-constants.tsv. Values in that file are reviewed independently
of the implementation. A changed contract requires review of the affected rows.

Exit 0 on agreement, 1 on a difference and 2 on missing or unreadable evidence.
The Rust extraction accepts the literal match tables, cache assignments and
typed integer declarations used here. Runtime tests exercise emitted responses.
"""

import re
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "scripts/protocol-constants.tsv"
WIRE = ROOT / "crates/granary-server/src/wire.rs"
ADMISSION = ROOT / "crates/granary-server/src/admission.rs"
ACCEPT = ROOT / "crates/granary-net/src/accept.rs"
LIMITS = {
    "DECLARED_MAX_EXTENT": (ADMISSION, "u32"),
    "INGEST_UNPACKED_SUM_MAX": (ADMISSION, "u64"),
    "MAX_CONNECTIONS": (ACCEPT, "usize"),
    "H2_MAX_CONCURRENT_STREAMS": (ACCEPT, "u32"),
}
RENDERERS = ("ErrorToken", "ContentType", "Allow", "CacheControl")
GROUPS = (*RENDERERS, "Resource", "Outcome", "RefusalCache", "Limit")


class Unreadable(ValueError):
    pass


def read_expected():
    groups = {group: {} for group in GROUPS}
    for line_no, line in enumerate(
        EXPECTED.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise Unreadable(
                f"{EXPECTED}:{line_no}: expected three tab-separated fields"
            )
        group, key, value = fields
        if (
            group not in groups
            or not re.fullmatch(r"[A-Za-z_]\w*", key, re.ASCII)
            or not value
            or value.strip() != value
            or not value.isascii()
            or not value.isprintable()
        ):
            raise Unreadable(f"{EXPECTED}:{line_no}: invalid contract row {line!r}")
        if key in groups[group]:
            raise Unreadable(f"{EXPECTED}:{line_no}: duplicate {group}.{key}")
        if group == "Limit" and not re.fullmatch(r"0|[1-9][0-9]*", value):
            raise Unreadable(
                f"{EXPECTED}:{line_no}: {key} needs an unsigned decimal value"
            )
        groups[group][key] = value
    for group, rows in groups.items():
        if not rows:
            raise Unreadable(f"{EXPECTED}: missing {group} rows")
    return groups


class Rust:
    """Keep original and masked slices aligned, including nested comments and raw strings."""

    def __init__(self, raw, code, lexer, where):
        self.raw = raw
        self.code = code
        self.lexer = lexer
        self.where = where
        self.spans = lexer["delim_spans"](code)
        for attr in re.finditer(r"#\s*!\s*\[\s*cfg(?:_attr)?\b", code):
            if self.top(attr.start()):
                raise Unreadable(f"{where}: conditional declaration on enclosing scope")

    @classmethod
    def read(cls, path, lexer):
        raw = path.read_text(encoding="utf-8")
        return cls(raw, lexer["strip_comments_and_strings"](raw), lexer, path)

    def top(self, position):
        return not any(start < position < end for start, end in self.spans)

    def unconditional(self, start):
        # Only a top-level item boundary terminates the attribute list.
        # Braces and semicolons inside another attribute belong to that attribute.
        for attr in re.finditer(r"#\s*\[\s*cfg(?:_attr)?\b", self.code[:start]):
            if not self.top(attr.start()):
                continue
            boundaries = re.compile(r"[};]").finditer(self.code, attr.end(), start)
            if not any(self.top(boundary.start()) for boundary in boundaries):
                raise Unreadable(f"{self.where}: conditional declaration at {start}")

    def bodies(self, pattern):
        result = {}
        for match in re.finditer(pattern, self.code):
            if not self.top(match.start()):
                continue
            name = match[1]
            self.unconditional(match.start())
            if name in result:
                raise Unreadable(f"{self.where}: multiple definitions of {name}")
            opening = match.end() - 1
            closing = self.lexer["find_matching"](self.code, opening, "{", "}")
            if closing is None:
                raise Unreadable(f"{self.where}: unclosed {name}")
            result[name] = Rust(
                self.raw[opening + 1 : closing],
                self.code[opening + 1 : closing],
                self.lexer,
                f"{self.where}::{name}",
            )
        return result

    def required_body(self, pattern, name):
        bodies = self.bodies(pattern)
        if name not in bodies:
            raise Unreadable(f"{self.where}: missing definition of {name}")
        return bodies[name]


def methods(wire, name):
    block = wire.required_body(rf"\bimpl\s+({name})\s*\{{", name)
    return block.bodies(r"\bfn\s+(\w+)\b[^;{]*\{")


def literal_string(body, start, end):
    # Braces, comments, strings and literal commas are already masked in the
    # structural match. Read this arm's actual literal at its original offset.
    raw = body.raw[start:end]
    skip = body.lexer["skip_ws_and_comments"]
    match = re.compile(r'"([\x20-\x21\x23-\x5b\x5d-\x7e]+)"').match(raw, skip(raw, 0))
    if not match or skip(raw, match.end()) != len(raw):
        raise Unreadable(
            f"{body.where}: expected one plain wire string, found {raw.strip()!r}"
        )
    return match[1]


def arms(wire, name, function, rhs_type=None):
    body = methods(wire, name).get(function)
    if body is None:
        raise Unreadable(f"{wire.where}: missing {name}::{function}")
    table = re.fullmatch(r"\s*match\s+self\s*\{(.*)\}\s*", body.code, re.DOTALL)
    if not table:
        raise Unreadable(f"{body.where}: expected a literal match on self")

    # Consume the whole match body. Skipping an unrecognized arm can leave a
    # complete-looking set of spellings while another variant emits a new one.
    arm = re.compile(r"\s*(Self::\w+(?:\s*\|\s*Self::\w+)*)\s*=>([^,]*),")
    rows = {}
    position = table.start(1)
    while body.code[position : table.end(1)].strip():
        match = arm.match(body.code, position, table.end(1))
        if not match:
            raise Unreadable(f"{body.where}: unreadable match arm at {position}")
        if rhs_type is None:
            value = literal_string(body, match.start(2), match.end(2))
        elif rhs_type == "Option<CacheControl>":
            optional = re.fullmatch(
                r"\s*(?:None|Some\(CacheControl::(\w+)\))\s*", match[2]
            )
            if not optional:
                raise Unreadable(
                    f"{body.where}: expected None or Some(CacheControl::variant)"
                )
            value = optional[1]
        else:
            variant = re.fullmatch(rf"\s*{rhs_type}::(\w+)\s*", match[2])
            if not variant:
                raise Unreadable(f"{body.where}: expected a {rhs_type} variant")
            value = variant[1]
        for key in re.findall(r"Self::(\w+)", match[1]):
            if key in rows:
                raise Unreadable(f"{body.where}: duplicate match arm for {key}")
            rows[key] = value
        position = match.end()

    enum = wire.required_body(rf"\benum\s+({name})\s*\{{", name)
    keys = [key.strip() for key in enum.code.strip().rstrip(",").split(",")]
    if len(keys) != len(set(keys)) or set(keys) != rows.keys():
        raise Unreadable(
            f"{body.where}: expected exactly one arm for each {name} variant; "
            f"unmatched {sorted(set(keys) ^ rows.keys())}"
        )
    return rows


def spelling(renderer, variant, where):
    if variant not in renderer:
        raise Unreadable(f"{where}: no spelling for {variant}")
    return renderer[variant]


def check_cache_field_scope(wire):
    # Rust children can write a parent's private field. Inline children are
    # scanned below. An out-of-line child must be excluded from production.
    # Use the existing lexer patterns for Rust source included by a macro.
    ws = wire.lexer["WS"]
    test_module = re.compile(
        rf"#{ws}*\[{ws}*cfg{ws}*\({ws}*test{ws}*\){ws}*\]{ws}*"
        rf"(mod){ws}+(?:r#)?\w+{ws}*;"
    )
    test_sites = {match.start(1) for match in test_module.finditer(wire.code)}
    inline = re.compile(rf"{ws}+(?:r#)?\w+{ws}*\{{")
    for keyword in re.finditer(r"\bmod\b", wire.code):
        if keyword.start() not in test_sites and not inline.match(
            wire.code, keyword.end()
        ):
            raise Unreadable(
                f"{wire.where}: unverified out-of-line module or module declaration"
            )

    for pattern in (
        "INCLUDE_RE",
        "INCLUDE_PATH_RE",
        "INCLUDE_IMPORT_RE",
        "INCLUDE_ALIAS_RE",
    ):
        if wire.lexer[pattern].search(wire.code):
            raise Unreadable(
                f"{wire.where}: included Rust source is outside the cache field check"
            )


def outcome_cache(wire, renderer):
    field = re.compile(r"\bcache_control\b")
    declaration = wire.required_body(r"\bstruct\s+(Outcome)\s*\{", "Outcome")
    check_cache_field_scope(wire)
    fields = re.finditer(
        r"(?:^|,)\s*(cache_control)\s*:\s*Option<CacheControl>\s*,", declaration.code
    )
    if sum(declaration.top(match.start(1)) for match in fields) != 1:
        raise Unreadable(
            f"{declaration.where}: expected one private cache_control field"
        )
    # Account for the struct field and the getter's function name. Every
    # remaining field token must occur at a checked site in a method body.
    accounted = 2
    functions = methods(wire, "Outcome")
    special = {
        "from_answer": "None",
        "method_not_allowed": "resource.refusal_cache_control()",
    }
    for required in (*special, "cache_control"):
        if required not in functions:
            raise Unreadable(f"{wire.where}: missing Outcome::{required}")
    rows = {}
    for name, body in functions.items():
        accesses = list(field.finditer(body.code))
        mentions = list(re.finditer(r"\bCacheControl\s*::", body.code))
        accounted += len(accesses)
        if name == "cache_control":
            if not re.fullmatch(r"\s*self\s*\.\s*cache_control\s*", body.code):
                raise Unreadable(
                    f"{body.where}: expected the cache_control field getter"
                )
            continue
        if not accesses and not mentions and name not in special:
            continue
        if re.search(r"#\s*!?\s*\[\s*cfg(?:_attr)?\b", body.code):
            raise Unreadable(
                f"{body.where}: conditional declaration in cache assignment method"
            )
        # Accept a struct field initializer or an assignment to a field.
        # A local binding, a borrow, a method call or a second field access
        # cannot stand in for the constructor's single checked write.
        writes = list(
            re.finditer(
                r"(?:[,{]\s*(cache_control)\s*:(?!:)|\.\s*(cache_control)\s*=(?!=))\s*([^,;]+)[,;]",
                body.code,
            )
        )
        if len(accesses) != 1 or len(writes) != 1:
            raise Unreadable(
                f"{body.where}: expected one cache_control field write; "
                f"observed {len(accesses)} access(es), {len(writes)} write(s)"
            )
        rhs = re.sub(r"\s+", "", writes[0][3])
        if name in special:
            if rhs != special[name] or mentions:
                raise Unreadable(
                    f"{body.where}: expected cache_control = {special[name]}, observed {rhs}"
                )
            continue
        variant = re.fullmatch(r"Some\(CacheControl::(\w+)\)", rhs)
        if not variant or len(mentions) != 1:
            raise Unreadable(
                f"{body.where}: expected one explicit cache directive, observed {rhs!r}"
            )
        rows[name] = spelling(renderer, variant[1], body.where)
    if len(field.findall(wire.code)) != accounted:
        raise Unreadable(
            f"{wire.where}: unrecognized cache_control site outside Outcome methods"
        )
    return rows


def limit(source, name, ty):
    declarations = list(re.finditer(rf"\bconst\s+{name}\b([^;]*);", source.code))
    if len(declarations) != 1 or not source.top(declarations[0].start()):
        raise Unreadable(
            f"{source.where}: expected one top-level {name} declaration, "
            f"observed {len(declarations)} declaration(s)"
        )
    declaration = declarations[0]
    source.unconditional(declaration.start())
    match = re.fullmatch(r"\s*:\s*(\w+)\s*=\s*(.*?)\s*", declaration[1], re.DOTALL)
    if not match or match[1] != ty:
        raise Unreadable(
            f"{source.where}: expected {name}: {ty}, observed {declaration[0].strip()}"
        )
    literal = re.fullmatch(
        r"(0x[\da-fA-F_]+|0o[0-7_]+|0b[01_]+|[0-9][0-9_]*)([iu](?:8|16|32|64|128|size))?",
        match[2],
        re.ASCII,
    )
    if not literal or literal[2] not in (None, ty):
        raise Unreadable(
            f"{source.where}: expected one {ty} integer literal for {name}, observed {match[2]!r}"
        )
    digits = literal[1].replace("_", "")
    base = 0 if digits.startswith(("0x", "0o", "0b")) else 10
    return str(int(digits, base))


def main():
    if not __debug__ or len(sys.argv) != 1:
        raise Unreadable(
            "run python3 scripts/check-protocol-constants.py without options"
        )
    expected = read_expected()
    lexer = runpy.run_path(str(ROOT / "scripts/fsguard-scan.py"))
    wire = Rust.read(WIRE, lexer)
    actual = {name: arms(wire, name, "as_str") for name in RENDERERS}
    actual["Resource"] = {
        key: spelling(actual["Allow"], variant, f"{WIRE}: Resource::{key}")
        for key, variant in arms(wire, "Resource", "allow", "Allow").items()
    }
    actual["Outcome"] = outcome_cache(wire, actual["CacheControl"])
    actual["RefusalCache"] = {
        key: "None"
        if variant is None
        else spelling(actual["CacheControl"], variant, f"{WIRE}: Resource::{key}")
        for key, variant in arms(
            wire, "Resource", "refusal_cache_control", "Option<CacheControl>"
        ).items()
    }
    sources = {path: Rust.read(path, lexer) for path in (ADMISSION, ACCEPT)}
    actual["Limit"] = {
        key: limit(sources[path], key, ty) for key, (path, ty) in LIMITS.items()
    }

    drift = False
    for group in GROUPS:
        for key in sorted(expected[group].keys() | actual[group].keys()):
            want, got = expected[group].get(key), actual[group].get(key)
            if want != got:
                print(
                    f"{group}.{key}: expected {want!r}, observed {got!r}",
                    file=sys.stderr,
                )
                drift = True
    if drift:
        return 1
    print(
        "Protocol constants agree: "
        + ", ".join(f"{len(rows)} {key}" for key, rows in expected.items())
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as problem:
        print(f"Cannot check protocol constants: {problem}", file=sys.stderr)
        sys.exit(2)
