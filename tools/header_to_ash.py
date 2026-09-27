#!/usr/bin/env python3
# Copyright (c) 2026 StackAndPointer
# SPDX-License-Identifier: MIT
"""Convert a conservative Windows C ABI header into a SigilHook .ash binding.

The parser intentionally rejects syntax whose native ABI cannot be proven.  It
is not a C or C++ compiler; it is a small, deterministic declaration parser
for headers that expose exported C-style functions.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


class ParseError(Exception):
    def __init__(self, path: Path, line: int, column: int, message: str):
        super().__init__(f"{path}:{line}:{column}: {message}")
        self.path = path
        self.line = line
        self.column = column
        self.message = message


@dataclass
class TypeRef:
    kind: str  # void, scalar, enum, pointer, reference, string, wstring, record
    name: str = ""
    signed: bool = True
    width: int = 0
    align: int = 1
    record: Optional[str] = None
    pointee: Optional["TypeRef"] = None

    @property
    def is_record(self) -> bool:
        return self.kind == "record"

    @property
    def is_pointer_like(self) -> bool:
        return self.kind in {"pointer", "reference", "string", "wstring"}


@dataclass
class Field:
    name: str
    type: TypeRef
    array_count: int = 0
    line: int = 1


@dataclass
class Record:
    name: str
    fields: List[Field] = field(default_factory=list)
    size: int = 0
    align: int = 1
    line: int = 1
    source: Path = Path()


@dataclass
class EnumValue:
    name: str
    value: int
    line: int = 1


@dataclass
class Enum:
    name: str
    values: List[EnumValue] = field(default_factory=list)
    line: int = 1


@dataclass
class Param:
    name: str
    type: TypeRef
    line: int = 1


@dataclass
class Function:
    name: str
    export_name: str
    return_type: TypeRef
    params: List[Param]
    convention: str
    dll: str
    line: int = 1
    source: Path = Path()
    annotation: str = ""


@dataclass
class HeaderModel:
    source: Path
    dll: str
    arch: str
    aliases: Dict[str, TypeRef] = field(default_factory=dict)
    records: Dict[str, Record] = field(default_factory=dict)
    enums: Dict[str, Enum] = field(default_factory=dict)
    functions: List[Function] = field(default_factory=list)
    notices: List[str] = field(default_factory=list)
    macros: Dict[str, str] = field(default_factory=dict)
    defines: Dict[str, str] = field(default_factory=dict)


_BUILTIN_SCALARS = {
    "void": ("void", False, 0, 1),
    "bool": ("scalar", False, 1, 1),
    "char": ("scalar", True, 1, 1),
    "signed char": ("scalar", True, 1, 1),
    "unsigned char": ("scalar", False, 1, 1),
    "short": ("scalar", True, 2, 2),
    "short int": ("scalar", True, 2, 2),
    "unsigned short": ("scalar", False, 2, 2),
    "unsigned short int": ("scalar", False, 2, 2),
    "int": ("scalar", True, 4, 4),
    "signed int": ("scalar", True, 4, 4),
    "unsigned int": ("scalar", False, 4, 4),
    "long": ("scalar", True, 4, 4),  # Windows LLP64
    "long int": ("scalar", True, 4, 4),
    "unsigned long": ("scalar", False, 4, 4),
    "unsigned long int": ("scalar", False, 4, 4),
    "long long": ("scalar", True, 8, 8),
    "long long int": ("scalar", True, 8, 8),
    "unsigned long long": ("scalar", False, 8, 8),
    "unsigned long long int": ("scalar", False, 8, 8),
    "float": ("scalar", True, 4, 4),
    "double": ("scalar", True, 8, 8),
    "int8_t": ("scalar", True, 1, 1),
    "uint8_t": ("scalar", False, 1, 1),
    "int16_t": ("scalar", True, 2, 2),
    "uint16_t": ("scalar", False, 2, 2),
    "int32_t": ("scalar", True, 4, 4),
    "uint32_t": ("scalar", False, 4, 4),
    "int64_t": ("scalar", True, 8, 8),
    "uint64_t": ("scalar", False, 8, 8),
    "intptr_t": ("scalar", True, 0, 0),
    "uintptr_t": ("scalar", False, 0, 0),
    "ptrdiff_t": ("scalar", True, 0, 0),
    "size_t": ("scalar", False, 0, 0),
    "wchar_t": ("scalar", True, 2, 2),
    "char16_t": ("scalar", False, 2, 2),
    "char32_t": ("scalar", False, 4, 4),
}

_CALLING_CONVENTIONS = {
    "", "cdecl", "__cdecl", "stdcall", "__stdcall", "fastcall", "__fastcall",
    "thiscall", "__thiscall", "vectorcall", "__vectorcall",
}

_EXPORT_WORDS = {
    "extern", "static", "inline", "__inline", "__forceinline", "virtual",
    "constexpr", "consteval", "__declspec", "__attribute__", "SIGILHOOK_API",
    "SH_API", "APIENTRY", "WINAPI", "NTAPI", "CALLBACK", "PASCAL",
}


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def strip_comments(text: str) -> Tuple[str, List[str]]:
    """Remove comments while preserving line breaks and collect notices."""
    notices: List[str] = []
    out: List[str] = []
    index = 0
    line = 1
    while index < len(text):
        char = text[index]
        if char == "\n":
            out.append(char)
            line += 1
            index += 1
            continue
        if text.startswith("//", index):
            start = index
            end = text.find("\n", index)
            if end < 0:
                end = len(text)
            comment = text[start:end]
            if re.search(r"copyright|license|spdx", comment, re.I):
                notices.append(comment.rstrip())
            out.append("\n" * comment.count("\n"))
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                end = len(text) - 2
            comment = text[index:end + 2]
            if re.search(r"copyright|license|spdx", comment, re.I):
                notices.append(comment.rstrip())
            out.append("\n" * comment.count("\n"))
            index = end + 2
            continue
        if char in "\"'":
            quote = char
            out.append(char)
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    out.append(text[index:index + 2])
                    index += 2
                    continue
                out.append(text[index])
                if text[index] == quote:
                    index += 1
                    break
                if text[index] == "\n":
                    line += 1
                index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out), notices


def expand_simple_macros(text: str, macros: Dict[str, str]) -> str:
    """Expand object-like and simple function-like macros without a compiler."""
    # Handle invocations first so a replacement containing another macro works.
    for _ in range(16):
        changed = False
        for name in sorted(macros, key=len, reverse=True):
            replacement = macros[name]
            pattern = re.compile(rf"\b{re.escape(name)}\b")
            if pattern.search(text):
                text = pattern.sub(lambda _match, value=replacement: value, text)
                changed = True
            if "(" not in replacement:
                continue
            # Function-like macro invocation with balanced arguments.
            cursor = 0
            while True:
                match = re.search(rf"\b{re.escape(name)}\s*\(", text[cursor:])
                if not match:
                    break
                start = cursor + match.start()
                open_pos = cursor + match.end() - 1
                depth = 0
                close_pos = -1
                for pos in range(open_pos, len(text)):
                    if text[pos] == "(":
                        depth += 1
                    elif text[pos] == ")":
                        depth -= 1
                        if depth == 0:
                            close_pos = pos
                            break
                if close_pos < 0:
                    break
                arguments = text[open_pos + 1:close_pos]
                # This conservative parser only supports the common one-argument
                # macro shape used by export headers.
                value = replacement
                if "(" in value:
                    value = re.sub(r"\([A-Za-z_]\w*\)", f"({arguments})", value, count=1)
                text = text[:start] + value + text[close_pos + 1:]
                cursor = start + len(value)
                changed = True
                break
        if not changed:
            break
    return text


class Preprocessor:
    def __init__(self, defines: Dict[str, str], include_dirs: Sequence[Path], arch: str):
        self.macros = dict(defines)
        self.include_dirs = list(include_dirs)
        self.arch = arch
        self.include_stack: List[Path] = []
        self.once: set[Path] = set()
        self.notices: List[str] = []

    def process(self, path: Path) -> str:
        path = path.resolve()
        if path in self.include_stack:
            chain = " -> ".join(str(item) for item in self.include_stack + [path])
            raise ParseError(path, 1, 1, f"include cycle: {chain}")
        if path in self.once:
            return ""
        if not path.is_file():
            raise ParseError(path, 1, 1, "header file not found")
        self.include_stack.append(path)
        try:
            raw = path.read_text(encoding="utf-8-sig", errors="strict")
        except UnicodeDecodeError as error:
            raise ParseError(path, 1, 1, f"header is not valid UTF-8: {error}") from error
        except OSError as error:
            raise ParseError(path, 1, 1, str(error)) from error
        stripped, notices = strip_comments(raw)
        self.notices.extend(notices)
        output: List[str] = []
        conditionals: List[Tuple[bool, bool]] = []  # parent_active, branch_taken
        active = True
        pack_stack: List[int] = []
        for line_number, original in enumerate(stripped.splitlines(), 1):
            line = original.rstrip()
            directive = line.lstrip()
            if directive.startswith("#"):
                body = directive[1:].strip()
                keyword = body.split(None, 1)[0] if body else ""
                if keyword == "pragma":
                    if "once" in body:
                        continue
                    pack = re.search(r"pack\s*\(\s*(?:push\s*,\s*)?(\d+)\s*\)", body, re.I)
                    if pack and int(pack.group(1)) not in {1, 2, 4, 8, 16}:
                        raise ParseError(path, line_number, 1, "unsupported #pragma pack alignment")
                    if pack:
                        pack_stack.append(int(pack.group(1)))
                        output.append(f"#pragma pack({pack.group(1)})")
                        continue
                    if re.search(r"pack\s*\(\s*pop\s*\)", body, re.I):
                        if pack_stack:
                            pack_stack.pop()
                        output.append("#pragma pack(pop)")
                        continue
                    if re.search(r"pack", body, re.I):
                        raise ParseError(path, line_number, 1, "unsupported #pragma pack form")
                    continue
                if keyword == "include":
                    if not active:
                        continue
                    target = re.match(r'include\s+([<"])([^>"]+)[>"]', body)
                    if not target:
                        raise ParseError(path, line_number, 1, "malformed #include")
                    include_name = target.group(2)
                    candidate = (path.parent / include_name).resolve()
                    if not candidate.is_file():
                        for directory in self.include_dirs:
                            candidate = (directory / include_name).resolve()
                            if candidate.is_file():
                                break
                        else:
                            # System headers are intentionally skipped; aliases
                            # for the standard integer types are built in.
                            if "<" in target.group(1) or include_name.startswith(("sys/", "std", "windows", "c")):
                                continue
                            raise ParseError(path, line_number, 1, f"missing include {include_name}")
                    output.append(self.process(candidate))
                    continue
                if keyword in {"define", "undef"}:
                    if active:
                        self._directive_define(body, path, line_number)
                    continue
                if keyword in {"if", "ifdef", "ifndef", "elif", "else", "endif"}:
                    if keyword == "if":
                        parent = active
                        value = self._eval_condition(body[2:].strip(), path, line_number)
                        conditionals.append((parent, value))
                        active = parent and value
                    elif keyword == "ifdef":
                        parent = active
                        value = body[6:].strip() in self.macros
                        conditionals.append((parent, value))
                        active = parent and value
                    elif keyword == "ifndef":
                        parent = active
                        value = body[7:].strip() not in self.macros
                        conditionals.append((parent, value))
                        active = parent and value
                    elif keyword == "elif":
                        if not conditionals:
                            raise ParseError(path, line_number, 1, "#elif without #if")
                        parent, taken = conditionals[-1]
                        value = self._eval_condition(body[4:].strip(), path, line_number)
                        branch = parent and not taken and value
                        conditionals[-1] = (parent, taken or branch)
                        active = branch
                    elif keyword == "else":
                        if not conditionals:
                            raise ParseError(path, line_number, 1, "#else without #if")
                        parent, taken = conditionals[-1]
                        conditionals[-1] = (parent, True)
                        active = parent and not taken
                    else:
                        if not conditionals:
                            raise ParseError(path, line_number, 1, "#endif without #if")
                        _, _ = conditionals.pop()
                        active = conditionals[-1][0] if conditionals else True
                    continue
                if active:
                    raise ParseError(path, line_number, 1, f"unsupported preprocessor directive #{keyword}")
                continue
            if active:
                output.append(line)
        if conditionals:
            raise ParseError(path, len(stripped.splitlines()), 1, "unterminated conditional block")
        self.once.add(path)
        self.include_stack.pop()
        expanded = expand_simple_macros("\n".join(output), self.macros)
        return expanded + "\n"

    def _directive_define(self, body: str, path: Path, line: int) -> None:
        match = re.match(r"define\s+([A-Za-z_]\w*)(\([^)]*\))?\s*(.*)$", body)
        if not match:
            raise ParseError(path, line, 1, "malformed #define")
        name, arguments, value = match.groups()
        if arguments:
            # Function-like macro definitions are retained only when their body
            # is a simple identifier substitution; otherwise expansion fails
            # later as an unsupported declaration.
            self.macros[name] = value.strip()
        else:
            self.macros[name] = value.strip()

    def _eval_condition(self, expression: str, path: Path, line: int) -> bool:
        if not expression:
            return False
        expression = re.sub(
            r"\bdefined\s*\(\s*([A-Za-z_]\w*)\s*\)",
            lambda match: "1" if match.group(1) in self.macros else "0",
            expression,
        )
        expression = re.sub(
            r"\bdefined\s+([A-Za-z_]\w*)",
            lambda match: "1" if match.group(1) in self.macros else "0",
            expression,
        )

        def replace_identifier(match: re.Match[str]) -> str:
            name = match.group(0)
            if name in {"and", "or", "not"}:
                return {"and": "and", "or": "or", "not": "not"}[name]
            if name in self.macros:
                value = self.macros[name]
                if re.fullmatch(r"[-+]?\d+(?:[uUlL]+)?", value):
                    return re.sub(r"[uUlL]+$", "", value)
                return "0"
            return "0"

        expression = re.sub(r"\b[A-Za-z_]\w*\b", replace_identifier, expression)
        expression = expression.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
        try:
            return bool(eval(expression, {"__builtins__": {}}, {}))
        except Exception as error:
            raise ParseError(path, line, 1, f"unsupported #if expression: {error}") from error


def balanced_end(text: str, start: int, opening: str = "(", closing: str = ")") -> int:
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def find_matching_brace(text: str, start: int) -> int:
    return balanced_end(text, start, "{", "}")


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def split_top_level(text: str, delimiter: str = ",") -> List[str]:
    parts: List[str] = []
    start = 0
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == delimiter and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def strip_declaration_noise(value: str) -> str:
    value = re.sub(r"__declspec\s*\([^)]*\)", " ", value)
    value = re.sub(r'extern\s+"C"\s+', " ", value)
    value = re.sub(r"__attribute__\s*\(\([^)]*\)\)", " ", value)
    value = re.sub(r"\b(?:extern|static|inline|__inline|__forceinline|virtual|constexpr|consteval)\b", " ", value)
    value = re.sub(r"\b(?:SIGILHOOK_API|SH_API|APIENTRY|WINAPI|NTAPI|CALLBACK|PASCAL)\b", " ", value)
    return normalize_space(value)


def parse_numeric(value: str, previous: int = 0) -> int:
    text = normalize_space(value).replace("'", "")
    text = re.sub(r"\b(0x[0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", text)
    if re.fullmatch(r"0x[0-9a-fA-F]+", text, re.I):
        return int(text, 16)
    if re.fullmatch(r"0[0-7]+", text):
        return int(text, 8)
    if re.fullmatch(r"-?\d+", text):
        return int(text, 10)
    # Keep the common enum forms understandable without a full expression parser.
    text = re.sub(r"\b([A-Za-z_]\w*)\b", lambda match: str(previous) if match.group(1) else "0", text)
    if re.fullmatch(r"[-+*/%() \d]+", text):
        try:
            return int(eval(text, {"__builtins__": {}}, {}))
        except Exception:
            pass
    raise ValueError(value)


class HeaderParser:
    def __init__(
        self,
        source: Path,
        text: str,
        dll: str,
        arch: str,
        macros: Dict[str, str],
        notices: Sequence[str],
    ):
        self.source = source
        self.text = text
        self.dll = dll
        self.arch = arch
        self.macros = dict(macros)
        self.model = HeaderModel(source=source, dll=dll, arch=arch, defines=dict(macros))
        self.model.notices.extend(dict.fromkeys(strip.strip() for strip in notices if strip.strip()))
        self.pointer_size = 8 if arch == "x64" else 4

    def parse(self) -> HeaderModel:
        cleaned, _ = strip_comments(self.text)
        self._reject_unsupported(cleaned)
        self._parse_records(cleaned)
        self._parse_enums(cleaned)
        self._parse_aliases(cleaned)
        self._parse_functions(cleaned)
        self._resolve_model()
        if not self.model.functions and not self.model.records and not self.model.enums:
            raise ParseError(self.source, 1, 1, "no supported declarations found")
        return self.model

    @staticmethod
    def _mask_pack_directives(text: str) -> str:
        chars = list(text)
        for match in re.finditer(r"^\s*#pragma\s+pack\([^\n]*\)\s*$", text, re.M):
            for index in range(match.start(), match.end()):
                if chars[index] != "\n": chars[index] = " "
        return "".join(chars)

    @staticmethod
    def _pack_state_at(text: str, end: int) -> int:
        value = 16
        stack: List[int] = []
        for match in re.finditer(r"^\s*#pragma\s+pack\(([^\n)]*)\)\s*$", text[:end], re.M):
            argument = match.group(1).strip()
            parts = [part.strip() for part in argument.split(",")]
            if len(parts) > 1 and parts[-1].isdigit():
                stack.append(value)
                value = int(parts[-1])
            elif len(parts) == 1 and parts[0].isdigit():
                value = int(parts[0])
            elif "pop" in argument and stack:
                value = stack.pop()
        return max(1, min(16, value))

    def _reject_unsupported(self, text: str) -> None:
        checks = [
            (r"\btemplate\s*<", "templates are not supported"),
            (r"\bclass\s+[A-Za-z_]\w*\s*(?:final\s*)?\{", "C++ classes are not supported"),
            (r"\bvirtual\b", "virtual methods are not supported"),
            (r"\boperator\b", "operator functions are not supported"),
            (r"\bunion\b", "unions are not supported"),
            (r"\.\.\.", "variadic functions are not supported"),
            (r"\bnamespace\s+[A-Za-z_]\w*\s*\{", "namespaces are not supported"),
            (r"\bnew\b|\bdelete\b", "C++ object declarations are not supported"),
        ]
        for pattern, message in checks:
            match = re.search(pattern, text)
            if match:
                raise ParseError(self.source, line_of(text, match.start()), match.start() - text.rfind("\n", 0, match.start()), message)

    def _parse_records(self, text: str) -> None:
        consumed: List[Tuple[int, int]] = []
        pending: List[Tuple[str, str, int, int, str, int]] = []
        pattern = re.compile(r"\b(?:typedef\s+)?struct\s*(?:[A-Za-z_]\w*)?\s*\{")
        for match in pattern.finditer(text):
            body_start = match.end() - 1
            body_end = find_matching_brace(text, body_start)
            if body_end < 0:
                raise ParseError(self.source, line_of(text, match.start()), 1, "unterminated struct body")
            prefix = text[match.start():body_start]
            suffix_start = body_end + 1
            suffix_end = text.find(";", suffix_start)
            if suffix_end < 0:
                suffix_end = len(text)
            suffix = text[suffix_start:suffix_end]
            typedef_match = re.search(r"\b([A-Za-z_]\w*)\s*;", suffix)
            name_match = re.search(r"struct\s+([A-Za-z_]\w*)", prefix)
            name = name_match.group(1) if name_match else ""
            alias = typedef_match.group(1) if typedef_match else ""
            if not name and alias:
                name = alias
            if not name:
                raise ParseError(self.source, line_of(text, match.start()), 1, "anonymous struct without typedef is unsupported")
            if name in self.model.records:
                raise ParseError(self.source, line_of(text, match.start()), 1, f"duplicate type {name}")
            body = text[body_start + 1:body_end]
            self.model.records[name] = Record(name=name, line=line_of(text, match.start()), source=self.source)
            pending.append((name, body, line_of(text, body_start + 1), match.start(), alias, self._pack_state_at(text, match.start())))
            consumed.append((match.start(), suffix_end + 1))
        for name, body, body_line, _start, alias, initial_pack in pending:
            record = self.model.records[name]
            self._parse_record_fields(body, record, body_line, initial_pack)
            if alias and alias != name:
                if alias in self.model.aliases:
                    raise ParseError(self.source, record.line, 1, f"duplicate type {alias}")
                self.model.aliases[alias] = TypeRef(kind="record", record=name)
        # Keep struct bodies out of function/alias scans.
        self._masked_records = consumed

    def _parse_record_fields(self, body: str, record: Record, base_line: int, initial_pack: int = 16) -> None:
        pack = initial_pack
        offset = 0
        max_align = 1
        statements = self._split_statements(body)
        for statement, relative_line in statements:
            statement = statement.strip()
            if not statement:
                continue
            if statement.startswith("#pragma"):
                pack_match = re.search(r"pack\s*\(\s*(\d+)\s*\)", statement)
                if pack_match:
                    pack = int(pack_match.group(1))
                    continue
                if re.search(r"pack\s*\(\s*pop\s*\)", statement):
                    pack = 16
                    continue
                raise ParseError(self.source, base_line + relative_line, 1, "unsupported struct pragma")
            if re.search(r"\b(?:virtual|operator|template|class)\b", statement):
                raise ParseError(self.source, base_line + relative_line, 1, "non-POD struct member is unsupported")
            if ":" in statement and not statement.startswith(":"):
                # Bitfields are deliberately rejected; their allocation rules
                # are compiler-specific.
                if re.search(r"[A-Za-z_]\w*\s*:\s*\d+", statement):
                    raise ParseError(self.source, base_line + relative_line, 1, "bitfields are unsupported")
            declarators = split_top_level(statement)
            # A field declaration can be split at commas after the type.
            if len(declarators) == 1:
                pieces = [statement]
            else:
                # Reattach the type prefix to the first declarator.
                pieces = declarators
            type_text = pieces[0]
            # Extract the type and each declarator from the original statement.
            field_decls = self._split_field_declarations(statement)
            for declarator, field_line in field_decls:
                name, type_text_field, array_count = self._split_declarator(declarator)
                if not name:
                    raise ParseError(self.source, base_line + field_line, 1, "invalid struct field")
                if array_count < 0:
                    raise ParseError(self.source, base_line + field_line, 1, "unsized struct array is unsupported")
                field_type = self._resolve_type(type_text_field, base_line + field_line)
                natural_align = field_type.align
                if array_count:
                    natural_align = field_type.align
                field_align = min(pack, natural_align) if natural_align else 1
                if field_align <= 0:
                    field_align = 1
                offset = align_up(offset, field_align)
                record.fields.append(Field(name=name, type=field_type, array_count=array_count, line=base_line + field_line))
                max_align = max(max_align, field_align)
                if array_count:
                    offset += field_type.width * array_count
                else:
                    offset += field_type.width
        record.align = min(pack, max_align) if max_align else 1
        record.size = align_up(offset, record.align)
        if record.size <= 0:
            raise ParseError(self.source, record.line, 1, f"struct {record.name} has no representable size")

    def _split_field_declarations(self, statement: str) -> List[Tuple[str, int]]:
        # The first comma at depth zero separates declarators only when a type
        # prefix has already appeared. This is enough for `int a, b;` while
        # preserving template-free C declarations.
        result: List[Tuple[str, int]] = []
        depth = 0
        start = 0
        commas: List[int] = []
        for index, char in enumerate(statement):
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == "," and depth == 0:
                commas.append(index)
        if not commas:
            return [(statement, 0)]
        first = statement[:commas[0]]
        type_match = re.match(r"^(.*?)([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$", first, re.S)
        if not type_match:
            return [(statement, 0)]
        type_prefix = type_match.group(1)
        name_part = type_match.group(2)
        array_part = type_match.group(3) or ""
        result.append((type_prefix + " " + name_part + array_part, 0))
        for comma in commas:
            end = statement.find(";", comma)
            if end < 0:
                end = len(statement)
            result.append((type_prefix + " " + statement[comma + 1:end], 0))
        return result

    def _parse_enums(self, text: str) -> None:
        pattern = re.compile(r"\benum\s+(?:class\s+)?([A-Za-z_]\w*)?\s*\{")
        for match in pattern.finditer(text):
            body_start = match.end() - 1
            body_end = find_matching_brace(text, body_start)
            if body_end < 0:
                raise ParseError(self.source, line_of(text, match.start()), 1, "unterminated enum body")
            name_match = re.search(r"enum\s+(?:class\s+)?([A-Za-z_]\w*)", text[match.start():body_start])
            name = name_match.group(1) if name_match else ""
            suffix_end = text.find(";", body_end + 1)
            suffix = text[body_end + 1:suffix_end if suffix_end >= 0 else len(text)]
            typedef_match = re.search(r"\b([A-Za-z_]\w*)\s*;", suffix)
            if not name and typedef_match:
                name = typedef_match.group(1)
            if not name:
                raise ParseError(self.source, line_of(text, match.start()), 1, "anonymous enum without typedef is unsupported")
            body = text[body_start + 1:body_end]
            enum = Enum(name=name, line=line_of(text, match.start()))
            previous = 0
            for entry in split_top_level(body):
                if not entry or entry.startswith("#"):
                    continue
                if "=" in entry:
                    entry_name, expression = entry.split("=", 1)
                else:
                    entry_name, expression = entry, str(previous)
                entry_name = entry_name.strip()
                if not re.fullmatch(r"[A-Za-z_]\w*", entry_name):
                    raise ParseError(self.source, enum.line, 1, f"invalid enum value {entry_name}")
                try:
                    value = parse_numeric(expression, previous)
                except ValueError as error:
                    raise ParseError(self.source, enum.line, 1, f"unsupported enum expression {expression}") from error
                enum.values.append(EnumValue(entry_name, value, enum.line))
                previous = value
            self.model.enums[name] = enum

    def _parse_aliases(self, text: str) -> None:
        masked = self._mask_ranges(text, getattr(self, "_masked_records", []))
        for match in re.finditer(r"\btypedef\s+([^;]+);", masked):
            declaration = normalize_space(match.group(1))
            alias_match = re.match(r"^(.*?)\s+([A-Za-z_]\w*)$", declaration)
            if not alias_match or "(" in declaration:
                raise ParseError(self.source, line_of(text, match.start()), 1, "unsupported typedef")
            source_type, alias = alias_match.groups()
            try:
                self.model.aliases[alias] = self._resolve_type(source_type, line_of(text, match.start()))
            except ParseError:
                # A struct typedef is handled by _parse_records; defer unknown
                # aliases until record names are known.
                self.model.aliases[alias] = TypeRef(kind="record", record=alias)
        for match in re.finditer(r"\busing\s+([A-Za-z_]\w*)\s*=\s*([^;]+);", masked):
            try:
                self.model.aliases[match.group(1)] = self._resolve_type(match.group(2), line_of(text, match.start()))
            except ParseError:
                self.model.aliases[match.group(1)] = TypeRef(kind="record", record=match.group(1))

    def _parse_functions(self, text: str) -> None:
        text = self._mask_pack_directives(text)
        ranges = list(getattr(self, "_masked_records", []))
        ranges.extend(self._enum_ranges(text))
        ranges.extend(self._typedef_ranges(text))
        masked = self._mask_ranges(text, ranges)
        masked = self._remove_extern_c_wrappers(masked)

        depth = 0
        start = 0
        declarations: List[Tuple[str, int]] = []
        for index, char in enumerate(masked):
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == ";" and depth == 0:
                declaration = masked[start:index].strip()
                if declaration:
                    declarations.append((declaration, line_of(masked, start)))
                start = index + 1
        for declaration, line in declarations:
            if not self._looks_like_function(declaration):
                continue
            function = self._parse_function(declaration, line, text)
            if any(existing.name == function.name and existing.params == function.params for existing in self.model.functions):
                raise ParseError(self.source, line, 1, f"duplicate function {function.name}")
            self.model.functions.append(function)
    @staticmethod
    def _typedef_ranges(text: str) -> List[Tuple[int, int]]:
        return [(match.start(), match.end()) for match in re.finditer(r"\btypedef\s+[^;]+;", text)]

    @staticmethod
    def _remove_extern_c_wrappers(text: str) -> str:
        result = list(text)
        for match in re.finditer(r'\bextern\s+"C"\s*\{', text):
            if match.start() < 0 or result[match.start()] == " ":
                continue
            depth = 0
            close = -1
            for index in range(match.end() - 1, len(text)):
                char = text[index]
                if char == "{" and not HeaderParser._inside_quoted_span(text, index):
                    depth += 1
                elif char == "}" and not HeaderParser._inside_quoted_span(text, index):
                    depth -= 1
                    if depth == 0:
                        close = index
                        break
            if close < 0:
                raise ValueError("unterminated extern \"C\" block")
            for index in range(match.start(), match.end()):
                result[index] = "\n" if text[index] == "\n" else " "
            if text[close] == "\n":
                result[close] = "\n"
            else:
                result[close] = " "
        return "".join(result)

    @staticmethod
    def _inside_quoted_span(text: str, index: int) -> bool:
        quoted = False
        escaped = False
        for char in text[:index]:
            if escaped:
                escaped = False
                continue
            if char == "\\" and quoted:
                escaped = True
            elif char == '"':
                quoted = not quoted
        return quoted

    @staticmethod
    def _looks_like_function(declaration: str) -> bool:
        if "(" not in declaration or ")" not in declaration:
            return False
        if declaration.startswith(("typedef", "struct", "enum", "static_assert")):
            return False
        if re.search(r"\b(?:if|for|while|switch|return)\s*\(", declaration):
            return False
        return True

    def _parse_function(self, declaration: str, line: int, full_text: str) -> Function:
        clean = strip_declaration_noise(declaration)
        if "{" in clean or "}" in clean:
            raise ParseError(self.source, line, 1, "function bodies are unsupported")
        close = clean.rfind(")")
        if close < 0:
            raise ParseError(self.source, line, 1, "malformed function declaration")
        open_pos = clean.find("(", close)
        # Find the opening parenthesis matching the final close parenthesis.
        depth = 0
        open_pos = -1
        for index in range(close, -1, -1):
            if clean[index] == ")":
                depth += 1
            elif clean[index] == "(":
                depth -= 1
                if depth == 0:
                    open_pos = index
                    break
        if open_pos < 0:
            raise ParseError(self.source, line, 1, "malformed parameter list")
        prefix = clean[:open_pos].strip()
        params_text = clean[open_pos + 1:close].strip()
        if re.search(r"(?:^|,)\s*[^,=]+\=", params_text):
            raise ParseError(self.source, line, 1, "default arguments are unsupported")
        suffix = clean[close + 1:].strip()
        if suffix and not re.fullmatch(r"(?:const|noexcept|final|override|\s)+", suffix):
            raise ParseError(self.source, line, 1, "unsupported function suffix")
        name_match = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
        if not name_match:
            raise ParseError(self.source, line, 1, "function name not found")
        name = name_match.group(1)
        return_prefix = prefix[:name_match.start()].strip()
        convention = "cdecl"
        for token in ("__vectorcall", "vectorcall", "__fastcall", "fastcall", "__thiscall", "thiscall", "__stdcall", "stdcall", "__cdecl", "cdecl"):
            if re.search(rf"\b{re.escape(token)}\b", return_prefix):
                convention = token.lstrip("_")
                break
        return_type_text = re.sub(r"\b(?:__vectorcall|vectorcall|__fastcall|fastcall|__thiscall|thiscall|__stdcall|stdcall|__cdecl|cdecl)\b", " ", return_prefix)
        return_type = self._resolve_type(return_type_text, line)
        params: List[Param] = []
        if params_text and params_text != "void":
            for index, raw_param in enumerate(split_top_level(params_text), 1):
                if not raw_param:
                    raise ParseError(self.source, line, 1, "empty function parameter")
                param_name, param_type_text, array_count = self._split_declarator(raw_param)
                if not param_name:
                    param_name = f"arg{index}"
                param_type = self._resolve_type(param_type_text, line)
                if array_count:
                    param_type = TypeRef(
                        kind="pointer",
                        width=self.pointer_size,
                        align=self.pointer_size,
                        pointee=param_type,
                    )
                params.append(Param(name=param_name, type=param_type, line=line))
        annotation = self._annotation_for(name, full_text)
        export_match = re.search(r"\bexport\s*=\s*([A-Za-z0-9_@$?.]+)", annotation)
        dll_match = re.search(r"\bdll\s*=\s*([^\s]+)", annotation)
        export_name = export_match.group(1) if export_match else name
        dll = dll_match.group(1) if dll_match else self.dll
        convention_match = re.search(r"\bconvention\s*=\s*([^\s]+)", annotation)
        if convention_match:
            convention = convention_match.group(1)
        return Function(
            name=name,
            export_name=export_name,
            return_type=return_type,
            params=params,
            convention=convention,
            dll=dll,
            line=line,
            source=self.source,
            annotation=annotation,
        )

    def _annotation_for(self, name: str, text: str) -> str:
        # Look for a SigilHook annotation immediately preceding the declaration.
        try:
            source_text = self.source.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            source_text = self.text if "@sigilhook" in self.text else text
        matches = list(re.finditer(r"@sigilhook\s+([^\n]*)", source_text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(source_text)
            segment = source_text[match.start():end]
            declarations = list(re.finditer(r"\b([A-Za-z_]\w*)\s*\(", segment))
            if not declarations or declarations[0].group(1) != name:
                continue
            if re.search(rf"\b{re.escape(name)}\s*\(", segment):
                return match.group(1).strip()
        return ""

    @staticmethod
    def _mask_ranges(text: str, ranges: Sequence[Tuple[int, int]]) -> str:
        chars = list(text)
        for start, end in ranges:
            for index in range(max(0, start), min(len(chars), end)):
                if chars[index] != "\n":
                    chars[index] = " "
        return "".join(chars)

    @staticmethod
    def _enum_ranges(text: str) -> List[Tuple[int, int]]:
        ranges: List[Tuple[int, int]] = []
        for match in re.finditer(r"\benum\s+(?:class\s+)?[A-Za-z_]\w*\s*\{", text):
            body_start = match.end() - 1
            body_end = find_matching_brace(text, body_start)
            if body_end >= 0:
                suffix_end = text.find(";", body_end + 1)
                ranges.append((match.start(), suffix_end + 1 if suffix_end >= 0 else body_end + 1))
        return ranges

    @staticmethod
    def _split_statements(text: str) -> List[Tuple[str, int]]:
        result: List[Tuple[str, int]] = []
        start = 0
        depth = 0
        for index, char in enumerate(text):
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == ";" and depth == 0:
                result.append((text[start:index], text.count("\n", 0, start)))
                start = index + 1
        if text[start:].strip():
            result.append((text[start:], text.count("\n", 0, start)))
        return result

    @staticmethod
    def _split_declarator(value: str) -> Tuple[str, str, int]:
        value = normalize_space(value)
        array_match = re.search(r"\[(\d*)\]\s*$", value)
        array_count = 0
        if array_match:
            array_count = int(array_match.group(1)) if array_match.group(1) else -1
            value = value[:array_match.start()].strip()
        name_match = re.search(r"([A-Za-z_]\w*)\s*$", value)
        if not name_match:
            return "", value, array_count
        name = name_match.group(1)
        type_text = value[:name_match.start()].strip()
        if not type_text:
            type_text = name
            name = ""
        return name, type_text, array_count

    def _resolve_type(self, value: str, line: int) -> TypeRef:
        text = strip_declaration_noise(value)
        text = normalize_space(text)
        if not text:
            raise ParseError(self.source, line, 1, "missing type")
        # References and pointers are represented by their suffix operators.
        pointer_count = text.count("*")
        reference = "&" in text
        text = text.replace("*", " ").replace("&", " ").strip()
        text = re.sub(r"^(?:const|volatile|restrict|__restrict)\s+", "", text)
        text = re.sub(r"\s+(?:const|volatile|restrict|__restrict)$", "", text)
        text = re.sub(r"^struct\s+", "", text)
        text = re.sub(r"^enum\s+(?:class\s+)?", "", text)
        text = normalize_space(text)
        if text in {"char", "wchar_t", "char16_t"} and (pointer_count or reference):
            return TypeRef(kind="string" if text == "char" else "wstring", width=self.pointer_size, align=self.pointer_size)
        # String pointer normalization is handled after const qualifier removal.
        if text in {"const char", "char const"} and (pointer_count or reference):
            return TypeRef(kind="string", width=self.pointer_size, align=self.pointer_size)
        if text in {"const wchar_t", "wchar_t const", "const char16_t", "char16_t const"} and (pointer_count or reference):
            return TypeRef(kind="wstring", width=self.pointer_size, align=self.pointer_size)
        if text == "void" and not pointer_count and not reference:
            return TypeRef(kind="void", width=0, align=1)
        if text in self.model.records:
            base = TypeRef(kind="record", record=text, width=self.model.records[text].size, align=self.model.records[text].align)
        elif text in self.model.enums:
            base = TypeRef(kind="enum", name=text, signed=True, width=4, align=4)
        elif text in self.model.aliases:
            base = self.model.aliases[text]
        elif text in _BUILTIN_SCALARS:
            kind, signed, width, align = _BUILTIN_SCALARS[text]
            base = TypeRef(kind=kind, name=text, signed=signed, width=width, align=align)
            if width == 0:
                base.width = self.pointer_size
                base.align = self.pointer_size
        else:
            # Deferred record aliases are resolved after all declarations exist.
            if text in self.model.records:
                record = self.model.records[text]
                base = TypeRef(kind="record", record=text, width=record.size, align=record.align)
            else:
                raise ParseError(self.source, line, 1, f"unsupported type {text}")
        if pointer_count or reference:
            if base.kind == "void":
                return TypeRef(kind="pointer", width=self.pointer_size, align=self.pointer_size, pointee=base)
            return TypeRef(kind="pointer", width=self.pointer_size, align=self.pointer_size, pointee=base)
        return base

    def _resolve_model(self) -> None:
        # Resolve aliases and record references after every struct has a size.
        for name, record in self.model.records.items():
            for field in record.fields:
                field.type = self._resolve_existing(field.type, record.line)
        for alias, type_ref in list(self.model.aliases.items()):
            if type_ref.kind == "record" and type_ref.record == alias and alias in self.model.records:
                record = self.model.records[alias]
                self.model.aliases[alias] = TypeRef(kind="record", record=alias, width=record.size, align=record.align)
        for function in self.model.functions:
            function.return_type = self._resolve_existing(function.return_type, function.line)
            for param in function.params:
                param.type = self._resolve_existing(param.type, param.line)

    def _resolve_existing(self, type_ref: TypeRef, line: int) -> TypeRef:
        if type_ref.kind == "pointer" and type_ref.pointee is not None:
            pointee = self._resolve_existing(type_ref.pointee, line)
            return TypeRef(kind="pointer", width=self.pointer_size, align=self.pointer_size, pointee=pointee)
        if type_ref.kind == "record" and type_ref.record in self.model.records:
            record = self.model.records[type_ref.record]
            return TypeRef(kind="record", record=record.name, width=record.size, align=record.align)
        return type_ref


def canonical_type(type_ref: TypeRef, arch: str) -> str:
    if type_ref.kind == "void":
        return "v"
    if type_ref.kind in {"pointer", "reference", "string", "wstring"}:
        return "p"
    if type_ref.kind == "record":
        return "r"
    if type_ref.kind == "enum":
        return "i"
    if type_ref.name == "float":
        return "f"
    if type_ref.name == "double":
        return "d"
    return "i" if type_ref.signed else "u"


def type_width(type_ref: TypeRef, arch: str) -> int:
    pointer_size = 8 if arch == "x64" else 4
    if type_ref.kind in {"pointer", "reference", "string", "wstring"}:
        return pointer_size
    if type_ref.kind == "record":
        return type_ref.width
    if type_ref.width == 0:
        return pointer_size
    return type_ref.width


def type_align(type_ref: TypeRef, arch: str) -> int:
    pointer_size = 8 if arch == "x64" else 4
    if type_ref.kind in {"pointer", "reference", "string", "wstring"}:
        return pointer_size
    if type_ref.kind == "record":
        return type_ref.align
    if type_ref.align == 0:
        return pointer_size
    return type_ref.align


def escape_as(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def as_type_name(type_ref: TypeRef, model: HeaderModel) -> str:
    if type_ref.kind == "void":
        return "void"
    if type_ref.kind in {"pointer", "reference", "string", "wstring"}:
        return "uint64"

    if type_ref.kind == "record":
        return type_ref.record or "uint64"
    if type_ref.kind == "enum":
        return type_ref.name or "int"
    if type_ref.name == "bool":
        return "bool"
    if type_ref.name == "float":
        return "float"
    if type_ref.name == "double":
        return "double"
    if type_ref.name in {"char", "signed char", "int8_t"}:
        return "int8"
    if type_ref.name in {"unsigned char", "uint8_t"}:
        return "uint8"
    if type_ref.name in {"short", "short int", "signed short", "int16_t"}:
        return "int16"
    if type_ref.name in {"unsigned short", "unsigned short int", "uint16_t"}:
        return "uint16"
    if type_ref.name in {"long long", "long long int", "int64_t", "intptr_t", "ptrdiff_t"}:
        return "int64"
    if type_ref.name in {"unsigned long long", "unsigned long long int", "uint64_t", "uintptr_t", "size_t"}:
        return "uint64"
    if type_ref.name in {"wchar_t", "char16_t", "char32_t"}:
        return "uint16" if type_ref.width == 2 else "uint32"
    if type_ref.signed:
        return "int32"
    return "uint32"


def as_parameter_type(type_ref: TypeRef, model: HeaderModel) -> str:
    if type_ref.kind in {"string", "wstring"}:
        return "const string &in"
    return as_type_name(type_ref, model)


def is_string_type(type_ref: TypeRef) -> bool:
    return type_ref.kind in {"string", "wstring"}


def is_wide_string(type_ref: TypeRef) -> bool:
    return type_ref.kind == "wstring"




def flat_fields(record: Record) -> List[Tuple[str, TypeRef, int, int, int]]:
    entries: List[Tuple[str, TypeRef, int, int, int]] = []
    offset = 0
    for field in record.fields:
        align = max(1, min(record.align, field.type.align or 1))
        offset = align_up(offset, align)
        count = max(1, field.array_count)
        for index in range(count):
            name = field.name if count == 1 else f"{field.name}[{index}]"
            entries.append((name, field.type, offset, field.type.width, field.line))
            offset += field.type.width
    return entries


def descriptor_for(type_ref: TypeRef, offset: int, arch: str) -> str:
    return ",".join([
        canonical_type(type_ref, arch),
        str(type_width(type_ref, arch)),
        str(type_align(type_ref, arch)),
        str(offset),
        str(type_width(type_ref, arch)),
    ])


def build_signature(model: HeaderModel, function: Function, arch: str) -> str:
    offset = 0
    params: List[str] = []
    for param in function.params:
        align = type_align(param.type, arch)
        offset = align_up(offset, align)
        params.append(descriptor_for(param.type, offset, arch))
        offset += type_width(param.type, arch)
    return "ret=" + descriptor_for(function.return_type, 0, arch) + ";args=" + "|".join(params)


def argument_layout(model: HeaderModel, function: Function, arch: str) -> Tuple[List[Tuple[Param, int]], int]:
    offset = 0
    result: List[Tuple[Param, int]] = []
    for param in function.params:
        align = type_align(param.type, arch)
        offset = align_up(offset, align)
        result.append((param, offset))
        offset += type_width(param.type, arch)
    return result, align_up(offset, 1)


def write_field(source: str, offset: int, type_ref: TypeRef, model: HeaderModel, indent: str) -> List[str]:
    width = type_width(type_ref, model.arch)
    if type_ref.kind == "record":
        record = model.records[type_ref.record or ""]
        lines: List[str] = []
        for name, field_type, field_offset, _field_width, _line in flat_fields(record):
            # Recurse so nested POD records preserve their declared layout.
            lines.extend(write_field(f"{source}.{name}", offset + field_offset, field_type, model, indent))
        return lines
    if type_ref.kind == "float":
        # Floating-point payloads are copied as IEEE bit patterns.
        return [f"{indent}shWriteBlob(args, {offset}, 4, shFloatBits({source}));"]
    if type_ref.name == "double":
        return [f"{indent}shWriteBlob(args, {offset}, 8, shDoubleBits({source}));"]
    if type_ref.kind in {"string", "wstring"}:
        return []
    return [f"{indent}shWriteBlob(args, {offset}, {width}, uint64({source}));"]


def read_record(record: Record, model: HeaderModel, source: str, offset: int, indent: str) -> List[str]:
    lines: List[str] = []
    for name, field_type, field_offset, width, _line in flat_fields(record):
        target = f"{source}.{name}"
        if field_type.kind == "record":
            nested = model.records[field_type.record or ""]
            lines.extend(read_record(nested, model, target, offset + field_offset, indent))
        elif field_type.kind == "float":
            lines.append(f"{indent}{target} = shBitsFloat(shReadBlob(ret, {offset + field_offset}, 4));")
        elif field_type.name == "double":
            lines.append(f"{indent}{target} = shBitsDouble(shReadBlob(ret, {offset + field_offset}, 8));")
        else:
            as_name = as_type_name(field_type, model)
            lines.append(f"{indent}{target} = {as_name}(shReadBlob(ret, {offset + field_offset}, {width}));")
    return lines


def generate_ash(model: HeaderModel, input_path: Path, dll: str, arch: str) -> str:
    if not model.functions:
        raise ParseError(model.source, 1, 1, "no functions to generate")
    lines: List[str] = [
        "// Copyright (c) 2026 StackAndPointer",
        "// SPDX-License-Identifier: MIT",
        "// Generated by tools/header_to_ash.py. Do not edit manually.",
        f"// Source: {input_path.as_posix()}",
        "#pragma once",
        '#include "SigilHook.ash"',
        "",
    ]
    for notice in model.notices:
        lines.append(notice)
        lines.append("")
    # Deduplicate notices while preserving source order.
    seen_notices: set[str] = set()
    notice_lines: List[str] = []
    for notice in model.notices:
        if notice not in seen_notices:
            seen_notices.add(notice)
            notice_lines.append(notice)
    lines = lines[:7] + notice_lines + [""]

    for enum in model.enums.values():
        lines.append(f"enum {enum.name} {{")
        for value in enum.values:
            lines.append(f"    {value.name} = {value.value},")
        lines.append("};")
        lines.append("")
    for record in model.records.values():
        lines.append(f"class {record.name} {{")
        for field in record.fields:
            if field.array_count:
                lines.append(f"    array<{as_type_name(field.type, model)}> {field.name}[{field.array_count}];")
            else:
                lines.append(f"    {as_type_name(field.type, model)} {field.name};")
        lines.append("};")
        lines.append("")

    for function in model.functions:
        params_text = ", ".join(
            f"{as_parameter_type(param.type, model)} {param.name}" for param in function.params
        )
        return_text = as_type_name(function.return_type, model)
        signature = build_signature(model, function, arch)
        layout, arg_size = argument_layout(model, function, arch)
        lines.append(f"// {function.source.as_posix()}:{function.line}")
        lines.append(f"{return_text} {function.name}({params_text}) {{")
        lines.append(f'    array<uint8> args;')
        lines.append(f"    args.resize({arg_size});")
        for param, offset in layout:
            if param.type.kind == "string":
                lines.append(f"    array<uint8> bytes_{param.name} = nativeStringBytes({param.name}, false);")
                lines.append(f"    shWriteBlob(args, {offset}, {type_width(param.type, arch)}, bufferAddress(bytes_{param.name}));")
                lines[-2] = f"    array<uint8> bytes_{param.name} = shNativeStringBytes({param.name}, false);"
                lines[-1] = f"    shWriteBlob(args, {offset}, {type_width(param.type, arch)}, shBufferAddress(bytes_{param.name}));"
            elif param.type.kind == "wstring":
                lines.append(f"    array<uint8> bytes_{param.name} = nativeStringBytes({param.name}, true);")
                lines.append(f"    shWriteBlob(args, {offset}, {type_width(param.type, arch)}, bufferAddress(bytes_{param.name}));")
                lines[-2] = f"    array<uint8> bytes_{param.name} = shNativeStringBytes({param.name}, true);"
                lines[-1] = f"    shWriteBlob(args, {offset}, {type_width(param.type, arch)}, shBufferAddress(bytes_{param.name}));"
            elif param.type.kind == "record":
                lines.extend(write_field(param.name, offset, param.type, model, "    "))
            elif param.type.name == "float":
                lines.append(f"    shWriteBlob(args, {offset}, 4, shFloatBits({param.name}));")
            elif param.type.name == "double":
                lines.append(f"    shWriteBlob(args, {offset}, 8, shDoubleBits({param.name}));")
            else:
                lines.append(f"    shWriteBlob(args, {offset}, {type_width(param.type, arch)}, uint64({param.name}));")
        return_size = type_width(function.return_type, arch)
        lines.append(f"    array<uint8> ret;")
        lines.append(f"    ret.resize({max(1, return_size)});")
        lines.append(f'    uint64 target = shNativeAddress("{escape_as(function.dll)}", "{escape_as(function.export_name)}", "{escape_as(function.convention)}");')
        lines.append(f'    uint8 status = shInvokeNativeBlob(target, "{escape_as(signature)}", "{escape_as(function.convention)}", args, ret);')
        lines.append("    if (status != SH_OK) {")
        lines.append("        shNativeThrow(status);")
        if function.return_type.kind != "void":
            if function.return_type.kind == "record":
                lines.append(f"        {return_text} result;")
                lines.append("        return result;")
            else:
                lines.append(f"        return {default_value(function.return_type, model)};")
        lines.append("    }")
        if function.return_type.kind == "void":
            lines.append("}")
        elif function.return_type.kind == "record":
            lines.append(f"    {return_text} result;")
            lines.extend(read_record(model.records[function.return_type.record or ""], model, "result", 0, "    "))
            lines.append("    return result;")
            lines.append("}")
        elif function.return_type.kind in {"string", "wstring"}:
            lines.append(f"    return uint64(shReadBlob(ret, 0, {return_size}));")
            lines.append("}")
        elif function.return_type.kind == "float":
            lines.append("    return shBitsFloat(shReadBlob(ret, 0, 4));")
            lines.append("}")
        elif function.return_type.name == "double":
            lines.append("    return shBitsDouble(shReadBlob(ret, 0, 8));")
            lines.append("}")
        elif function.return_type.kind == "record":
            lines.append("}")
        else:
            as_name = as_type_name(function.return_type, model)
            lines.append(f"    return {as_name}(shReadBlob(ret, 0, {return_size}));")
            lines.append("}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def default_value(type_ref: TypeRef, model: HeaderModel) -> str:
    if type_ref.kind == "record":
        return f"{type_ref.record}()"
    if type_ref.kind in {"pointer", "reference", "string", "wstring"}:
        return "uint64(0)"
    if type_ref.name == "bool":
        return "false"
    if type_ref.kind == "float":
        return "0.0f"
    if type_ref.kind == "double":
        return "0.0"
    return as_type_name(type_ref, model) + "(0)"


def source_notice_text(model: HeaderModel, input_path: Path, arch: str) -> str:
    notices = []
    for notice in model.notices:
        if notice and notice not in notices:
            notices.append(notice)
    return "\n".join(notices)


def parse_header(path: Path, dll: str, arch: str, include_dirs: Sequence[Path], defines: Dict[str, str]) -> HeaderModel:
    if arch not in {"x86", "x64"}:
        raise ValueError("arch must be x86 or x64")
    if not dll:
        raise ValueError("--dll or an @sigilhook dll annotation is required")
    defaults = {
        "_WIN32": "1",
        "WIN32": "1",
        "_MSC_VER": "1930",
        "__cplusplus": "199711L",
    }
    if arch == "x64":
        defaults["_WIN64"] = "1"
        defaults["_M_X64"] = "100"
    else:
        defaults["_M_IX86"] = "600"
    merged = dict(defaults)
    merged.update(defines)
    preprocessor = Preprocessor(merged, include_dirs, arch)
    text = preprocessor.process(path)
    parser = HeaderParser(path, text, dll, arch, preprocessor.macros, preprocessor.notices)
    return parser.parse()


def render(model: HeaderModel, input_path: Path, dll: str, arch: str) -> str:
    return generate_ash(model, input_path, dll, arch)


def check_output(path: Path, expected: str) -> bool:
    try:
        actual = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return actual == expected


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="C/C++ header to convert")
    parser.add_argument("--dll", default="", help="DLL name used by generated wrappers")
    parser.add_argument("--output", type=Path, required=True, help="destination .ash file")
    parser.add_argument("--arch", choices=("x86", "x64"), required=True)
    parser.add_argument("--include-dir", action="append", type=Path, default=[], help="additional include directory")
    parser.add_argument("--define", action="append", default=[], help="NAME or NAME=VALUE preprocessor definition")
    parser.add_argument("--check", action="store_true", help="fail if output is missing or stale")
    return parser


def parse_defines(values: Sequence[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for value in values:
        if "=" in value:
            name, definition = value.split("=", 1)
        else:
            name, definition = value, "1"
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            raise ValueError(f"invalid --define name {name}")
        result[name] = definition
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        defines = parse_defines(args.define)
        model = parse_header(args.input, args.dll, args.arch, args.include_dir, defines)
        # A header-level annotation can provide the DLL when --dll is omitted.
        if not args.dll:
            annotated = next((fn.dll for fn in model.functions if fn.dll), "")
            if annotated:
                model.dll = annotated
                for function in model.functions:
                    function.dll = annotated
            else:
                raise ValueError("--dll or an @sigilhook dll annotation is required")
        output = render(model, args.input, model.dll, args.arch)
        if args.check:
            if not check_output(args.output, output):
                print(f"{args.output}: generated binding is missing or stale", file=sys.stderr)
                return 1
            return 0
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8", newline="\n")
        return 0
    except (ParseError, ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
