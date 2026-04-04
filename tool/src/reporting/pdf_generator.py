"""PDF report export for security analysis results.

This module intentionally uses a tiny built-in PDF writer to avoid external
dependencies while still producing valid .pdf artifacts.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from reporting.cli_formatter import render_cli_report


def generate_pdf_report(report: Mapping[str, Any], output_path: str) -> Path:
	"""Render analysis report into a PDF artifact and return the file path."""
	path = Path(output_path)
	if path.parent and path.parent != Path("."):
		path.parent.mkdir(parents=True, exist_ok=True)

	text = render_cli_report(report)
	lines = [line.rstrip() for line in text.splitlines()]
	pages = _paginate_lines(lines, lines_per_page=45)
	pdf_bytes = _build_pdf_bytes(pages)
	path.write_bytes(pdf_bytes)
	return path


def _paginate_lines(lines: list[str], lines_per_page: int) -> list[list[str]]:
	if not lines:
		return [[""]]
	pages: list[list[str]] = []
	for idx in range(0, len(lines), lines_per_page):
		pages.append(lines[idx:idx + lines_per_page])
	return pages


def _build_pdf_bytes(pages: list[list[str]]) -> bytes:
	objects: dict[int, bytes] = {}
	objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
	objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

	page_ids: list[int] = []
	next_id = 4
	for page_lines in pages:
		page_obj_id = next_id
		content_obj_id = next_id + 1
		next_id += 2

		page_ids.append(page_obj_id)
		stream = _page_stream(page_lines)
		objects[content_obj_id] = (
			f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
			+ stream
			+ b"\nendstream"
		)
		objects[page_obj_id] = (
			f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] ".encode("latin-1")
			+ f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj_id} 0 R >>".encode("latin-1")
		)

	kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
	objects[2] = f"<< /Type /Pages /Count {len(page_ids)} /Kids [ {kids} ] >>".encode("latin-1")

	return _serialize_pdf_objects(objects)


def _page_stream(lines: list[str]) -> bytes:
	commands: list[str] = ["BT", "/F1 11 Tf", "14 TL", "48 794 Td"]
	for idx, line in enumerate(lines):
		escaped = _pdf_escape(line)
		commands.append(f"({escaped}) Tj")
		if idx != len(lines) - 1:
			commands.append("T*")
	commands.append("ET")
	return ("\n".join(commands) + "\n").encode("latin-1", errors="replace")


def _pdf_escape(value: str) -> str:
	return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _serialize_pdf_objects(objects: dict[int, bytes]) -> bytes:
	max_id = max(objects)
	header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
	output = bytearray(header)
	offsets = [0] * (max_id + 1)

	for obj_id in sorted(objects):
		offsets[obj_id] = len(output)
		output.extend(f"{obj_id} 0 obj\n".encode("latin-1"))
		output.extend(objects[obj_id])
		output.extend(b"\nendobj\n")

	xref_pos = len(output)
	output.extend(f"xref\n0 {max_id + 1}\n".encode("latin-1"))
	output.extend(b"0000000000 65535 f \n")
	for obj_id in range(1, max_id + 1):
		offset = offsets[obj_id]
		output.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))

	output.extend(f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\n".encode("latin-1"))
	output.extend(f"startxref\n{xref_pos}\n%%EOF\n".encode("latin-1"))
	return bytes(output)