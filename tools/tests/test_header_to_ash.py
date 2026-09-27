# Copyright (c) 2026 StackAndPointer
# SPDX-License-Identifier: MIT
import importlib.util
import sys
import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("header_to_ash", ROOT / "tools" / "header_to_ash.py")
assert SPEC and SPEC.loader
header_to_ash = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = header_to_ash
SPEC.loader.exec_module(header_to_ash)


class HeaderToAshTests(unittest.TestCase):
    def parse(self, name: str = "basic.h"):
        return header_to_ash.parse_header(
            ROOT / "tools" / "tests" / "fixtures" / name,
            "GameApi.dll",
            "x64",
            [],
            {},
        )

    def test_parses_scalars_strings_enums_and_records(self):
        model = self.parse()
        self.assertEqual([fn.name for fn in model.functions], [
            "Add", "Scale", "Name", "Move", "PackValue", "UsercallAdd",
        ])
        self.assertEqual(model.records["Point"].size, 8)
        self.assertEqual(model.records["Packed"].size, 8)
        self.assertEqual(model.enums["Mode"].values[1].value, 1)
        self.assertEqual(model.functions[5].convention, "usercall:ret=eax;arg0=ecx;cleanup=4")

    def test_generation_is_deterministic_and_checkable(self):
        model = self.parse()
        source = ROOT / "tools" / "tests" / "fixtures" / "basic.h"
        first = header_to_ash.render(model, source, "GameApi.dll", "x64")
        second = header_to_ash.render(model, source, "GameApi.dll", "x64")
        self.assertEqual(first, second)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "basic.ash"
            output.write_text(first, encoding="utf-8", newline="\n")
            self.assertTrue(header_to_ash.check_output(output, first))
            output.write_text(first + "\n", encoding="utf-8", newline="\n")
            self.assertFalse(header_to_ash.check_output(output, first))

    def test_rejects_cpp_classes_and_unions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.hpp"
            path.write_text("class Thing { virtual void f(); };", encoding="utf-8")
            with self.assertRaises(header_to_ash.ParseError):
                header_to_ash.parse_header(path, "Bad.dll", "x64", [], {})
            path.write_text("union Value { int i; float f; };", encoding="utf-8")
            with self.assertRaises(header_to_ash.ParseError):
                header_to_ash.parse_header(path, "Bad.dll", "x64", [], {})

    def test_reports_missing_include_and_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.h"
            second = root / "second.h"
            first.write_text('#include "second.h"\nint first(void);\n', encoding="utf-8")
            second.write_text('#include "first.h"\nint second(void);\n', encoding="utf-8")
            with self.assertRaises(header_to_ash.ParseError):
                header_to_ash.parse_header(first, "Bad.dll", "x64", [], {})

    def test_requires_dll_when_no_annotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plain.h"
            path.write_text("int Answer(void);\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                header_to_ash.parse_header(path, "", "x64", [], {})


    def test_nested_include_macro_and_pack_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            include = root / "include"
            include.mkdir()
            (include / "api.h").write_text("SH_API int32_t Included(void);\n", encoding="utf-8")
            path = root / "nested.h"
            path.write_text(
                "#define SH_API __declspec(dllexport)\n"
                "#define SH_VALUE 7\n"
                '#include "include/api.h"\n'
                '#include "include/api.h"\n'
                "#pragma pack(push, 1)\n"
                "typedef struct Packed { uint8_t tag; uint32_t value; } Packed;\n"
                "#pragma pack(pop)\n"
                "typedef struct Inner { int32_t value; } Inner;\n"
                "typedef struct Outer { Inner inner; int32_t tail; } Outer;\n"
                "SH_API Outer Echo(Outer value);\n",
                encoding="utf-8")
            model = header_to_ash.parse_header(path, "GameApi.dll", "x64", [], {})
            self.assertEqual([fn.name for fn in model.functions], ["Included", "Echo"])
            self.assertEqual(model.records["Packed"].size, 5)
            self.assertEqual(model.records["Packed"].align, 1)
            self.assertEqual(model.records["Outer"].size, 8)
            output = header_to_ash.render(model, path, "GameApi.dll", "x64")
            self.assertIn("shWriteBlob(args, 0, 4, uint64(value.inner.value));", output)
            self.assertIn("shWriteBlob(args, 4, 4, uint64(value.tail));", output)
    def test_decorated_export_annotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exports.h"
            path.write_text(
                "#define SH_API __declspec(dllexport)\n"
                "extern \"C\" SH_API int32_t __stdcall Legacy(int32_t value);\n"
                "// @sigilhook export=_Legacy@4 convention=stdcall\n"
                "extern \"C\" SH_API int32_t Named(int32_t value);\n"
                "// @sigilhook export=Named@@8 convention=vectorcall\n"
                "extern \"C\" SH_API int32_t Vector(int32_t value, int32_t other);\n",
                encoding="utf-8")
            model = header_to_ash.parse_header(path, "GameApi.dll", "x86", [], {})
            functions = {fn.name: fn for fn in model.functions}
            self.assertEqual(functions["Legacy"].export_name, "Legacy")
            self.assertEqual(functions["Named"].export_name, "_Legacy@4")
            self.assertEqual(functions["Named"].convention, "stdcall")
            self.assertEqual(functions["Vector"].export_name, "Named@@8")
            self.assertEqual(functions["Vector"].convention, "vectorcall")

    def test_rejects_bodies_defaults_duplicates_and_bad_packing(self):
        cases = {
            "body.hpp": "int Body(void) { return 1; }\n",
            "default.h": "int Default(int value = 3);\n",
            "duplicate.h": "int Same(int value);\nint Same(int value);\n",
            "pack.h": "#pragma pack(3)\nstruct P { int value; };\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in cases.items():
                path = root / name
                path.write_text(text, encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(header_to_ash.ParseError) as raised:
                    header_to_ash.parse_header(path, "Bad.dll", "x64", [], {})
                self.assertRegex(str(raised.exception), rf"{re.escape(path.name)}:1:\d+:")

if __name__ == "__main__":
    unittest.main()
