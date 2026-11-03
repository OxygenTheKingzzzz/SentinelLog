import pytest

from sentinellog.ingestion.validation import (
    CSV_SUFFIXES,
    RAW_SUFFIXES,
    FileRejected,
    ensure_text_bytes,
    validate_filename,
)


def test_filename_rejects_traversal_and_bad_extension():
    with pytest.raises(FileRejected):
        validate_filename("../etc/passwd", RAW_SUFFIXES)
    with pytest.raises(FileRejected):
        validate_filename("..\\windows.log", RAW_SUFFIXES)
    with pytest.raises(FileRejected):
        validate_filename("nested/Linux_2k.log", RAW_SUFFIXES)
    with pytest.raises(FileRejected):
        validate_filename("payload.exe", RAW_SUFFIXES)
    with pytest.raises(FileRejected):
        validate_filename("notes.csv", RAW_SUFFIXES)
    assert validate_filename("Linux_2k.log", RAW_SUFFIXES) == "Linux_2k.log"
    assert validate_filename("Linux_2k.log_templates.csv", CSV_SUFFIXES).endswith(".csv")


def test_bytes_reject_nul_oversize_and_binary():
    with pytest.raises(FileRejected):
        ensure_text_bytes(b"ok\x00hidden", max_bytes=100)
    with pytest.raises(FileRejected):
        ensure_text_bytes(b"abcdef", max_bytes=3)
    with pytest.raises(FileRejected):
        ensure_text_bytes(b"\xff\xfe", max_bytes=100)
    ensure_text_bytes(b"Jun 14 15:16:01 combo sshd: hello\n", max_bytes=1000)
