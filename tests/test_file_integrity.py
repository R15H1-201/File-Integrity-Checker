import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import baseline
from hasher import calculate_file_hash
from scanner import scan_log_files
from checker import check_file_integrity, check_directory_integrity
from baseline import save_baseline, load_baseline, BaselineIntegrityError


class FileIntegrityTests(unittest.TestCase):

    def setUp(self):
        """Create an isolated temporary project for each test."""

        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        self.storage = self.root / "storage"
        self.storage.mkdir()

        self.logs = self.root / "test_logs"
        self.logs.mkdir()

        self.baseline_path = self.storage / "baseline.json"
        self.key_path = self.storage / "baseline.key"

        self.baseline_patch = patch.object(
            baseline, "BASELINE_PATH", self.baseline_path
        )
        self.key_patch = patch.object(
            baseline, "KEY_PATH", self.key_path
        )

        self.baseline_patch.start()
        self.key_patch.start()

        self.log_file = self.logs / "application.log"
        self.log_file.write_text("Original log content", encoding="utf-8")

    def tearDown(self):
        """Clean up temporary files after each test."""

        self.baseline_patch.stop()
        self.key_patch.stop()
        self.temp_dir.cleanup()

    def test_sha256_hash(self):
        """Verify SHA-256 hashing."""

        expected = hashlib.sha256(
            b"Original log content"
        ).hexdigest()

        actual = calculate_file_hash(self.log_file)

        self.assertEqual(actual, expected)

    def test_scanner_finds_log_files(self):
        """Verify that directory scanning finds log files."""

        another_log = self.logs / "system.log"
        another_log.write_text("System log", encoding="utf-8")

        text_file = self.logs / "notes.txt"
        text_file.write_text("Not a log", encoding="utf-8")

        result = scan_log_files(self.logs)

        self.assertEqual(len(result), 2)
        self.assertTrue(all(path.suffix.lower() == ".log" for path in result))

    def test_baseline_save_and_load(self):
        """Verify that the authenticated baseline can be saved and loaded."""

        file_hash = calculate_file_hash(self.log_file)

        save_baseline(self.log_file, file_hash)

        data = load_baseline()

        self.assertIn(str(self.log_file.resolve()), data["files"])
        self.assertTrue(self.key_path.exists())
        self.assertIn("hmac", data)

    def test_baseline_tampering_detection(self):
        """Verify that modified baseline data is rejected."""

        file_hash = calculate_file_hash(self.log_file)
        save_baseline(self.log_file, file_hash)

        with open(self.baseline_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        data["files"][str(self.log_file.resolve())] = "0" * 64

        with open(self.baseline_path, "w", encoding="utf-8") as file:
            json.dump(data, file)

        with self.assertRaises(BaselineIntegrityError):
            load_baseline()

    def test_missing_key_detection(self):
        """Verify that a missing authentication key is detected."""

        file_hash = calculate_file_hash(self.log_file)
        save_baseline(self.log_file, file_hash)

        self.key_path.unlink()

        with self.assertRaises(BaselineIntegrityError):
            load_baseline()

    def test_unmodified_file(self):
        """Verify that an unchanged file is reported correctly."""

        file_hash = calculate_file_hash(self.log_file)
        save_baseline(self.log_file, file_hash)

        result = check_file_integrity(self.log_file)

        self.assertEqual(result, "UNMODIFIED")

    def test_modified_file(self):
        """Verify that changes to a monitored file are detected."""

        file_hash = calculate_file_hash(self.log_file)
        save_baseline(self.log_file, file_hash)

        self.log_file.write_text("Modified content", encoding="utf-8")

        result = check_file_integrity(self.log_file)

        self.assertEqual(result, "MODIFIED")

    def test_directory_detects_new_file(self):
        """Verify that newly added log files are detected."""

        save_baseline(
            self.log_file,
            calculate_file_hash(self.log_file)
        )

        new_log = self.logs / "new.log"
        new_log.write_text("New log entry", encoding="utf-8")

        results = check_directory_integrity(self.logs)

        statuses = [item["status"] for item in results]

        self.assertIn("NEW", statuses)

    def test_directory_detects_missing_file(self):
        """Verify that deleted monitored files are detected."""

        save_baseline(
            self.log_file,
            calculate_file_hash(self.log_file)
        )

        self.log_file.unlink()

        results = check_directory_integrity(self.logs)

        statuses = [item["status"] for item in results]

        self.assertIn("MISSING", statuses)


if __name__ == "__main__":
    unittest.main()
