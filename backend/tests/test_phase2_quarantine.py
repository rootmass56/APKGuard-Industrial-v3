import hashlib
import zipfile
from pathlib import Path

from app.core.config import Settings
from app.services.quarantine import QuarantineStorage
from app.services.upload_service import UploadArtifact


def _apk(path: Path) -> UploadArtifact:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
    payload = path.read_bytes()
    return UploadArtifact(
        original_filename="sample.apk",
        temporary_path=path,
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        zip_entry_count=2,
        total_uncompressed_bytes=11,
    )


def test_quarantine_is_content_addressed_and_deduplicated(tmp_path: Path):
    settings = Settings(quarantine_dir=tmp_path / "quarantine")
    storage = QuarantineStorage(settings)
    artifact = _apk(tmp_path / "sample.apk")
    first = storage.store(artifact)
    second = storage.store(artifact)
    assert first.quarantine_path == storage.path_for(artifact.sha256)
    assert first.quarantine_path.exists()
    assert not first.deduplicated
    assert second.deduplicated
    assert first.quarantine_path.name == f"{artifact.sha256}.apk"
