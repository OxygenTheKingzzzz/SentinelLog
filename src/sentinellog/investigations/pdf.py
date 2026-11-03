"""Render an investigation report as a PDF. Text is drawn; nothing is executed."""

from collections.abc import Iterable

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
MARGIN = 48
LEADING = 13
FONT_SIZE = 10
LINE_WIDTH = 92


def _escape(text: str) -> str:
    cleaned = (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )
    return cleaned.encode("latin-1", errors="replace").decode("latin-1")


def wrap_text(text: str, width: int = LINE_WIDTH) -> list[str]:
    words = text.split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        while len(word) > width:
            if current:
                lines.append(current)
                current = ""
            lines.append(word[:width])
            word = word[width:]
        candidate = word if not current else f"{current} {word}"
        if len(candidate) <= width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines or [""]


def _pages(lines: Iterable[str]) -> list[bytes]:
    capacity = (PAGE_HEIGHT - (MARGIN * 2)) // LEADING
    chunks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        current.append(line)
        if len(current) >= capacity:
            chunks.append(current)
            current = []
    if current or not chunks:
        chunks.append(current)
    streams: list[bytes] = []
    for chunk in chunks:
        commands = [
            "BT",
            f"/F1 {FONT_SIZE} Tf",
            f"{LEADING} TL",
            f"1 0 0 1 {MARGIN} {PAGE_HEIGHT - MARGIN - FONT_SIZE} Tm",
        ]
        for line in chunk:
            commands.append(f"({_escape(line)}) Tj")
            commands.append("T*")
        commands.append("ET")
        streams.append("\n".join(commands).encode("latin-1") + b"\n")
    return streams


def _stream_object(payload: bytes) -> bytes:
    header = b"<< /Length " + str(len(payload)).encode("ascii") + b" >>\nstream\n"
    return header + payload + b"endstream"


def render_lines(lines: list[str]) -> bytes:
    """Return a PDF 1.4 document whose page text is `lines`."""
    pages = _pages(lines)
    page_ids = [4 + (index * 2) for index in range(len(pages))]
    content_ids = [page_id + 1 for page_id in page_ids]
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: f"<< /Type /Pages /Count {len(pages)} /Kids [{kids}] >>".encode("ascii"),
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    for page_id, content_id, stream in zip(page_ids, content_ids, pages, strict=True):
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Contents {content_id} 0 R /Resources << /Font << /F1 3 0 R >> >> >>"
        ).encode("ascii")
        objects[content_id] = _stream_object(stream)

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number in range(1, max(objects) + 1):
        offsets.append(len(out))
        out.extend(f"{number} 0 obj\n".encode("ascii"))
        out.extend(objects[number])
        out.extend(b"\nendobj\n")
    xref_at = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(out)
