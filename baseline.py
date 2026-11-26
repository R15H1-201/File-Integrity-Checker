import os
import json
import hmac
import hashlib
import secrets
import tempfile
from pathlib import Path

BASELINE_PATH = Path(__file__).parent / "storage" / "baseline.json"
KEY_PATH = Path(__file__).parent / "storage" / "baseline.key"


class BaselineIntegrityError(Exception):
    """Raised when baseline authentication or validation fails."""
    pass


def get_secret_key():
    """Load the existing key or create a new 32-byte key."""

    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)

    if KEY_PATH.exists():
        key = KEY_PATH.read_bytes()

        if len(key) != 32:
            raise BaselineIntegrityError("Invalid secret key.")

        return key

    # Never generate a replacement key for an existing baseline.
    if BASELINE_PATH.exists():
        raise BaselineIntegrityError(
            "Secret key is missing. Baseline cannot be verified."
        )

    key = secrets.token_bytes(32)

    try:
        fd = os.open(
            KEY_PATH,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600
        )

        with os.fdopen(fd, "wb") as file:
            file.write(key)

    except FileExistsError:
        key = KEY_PATH.read_bytes()

        if len(key) != 32:
            raise BaselineIntegrityError("Invalid secret key.")

    return key


def generate_signature(files, key):
    """Generate an HMAC-SHA256 signature for baseline records."""

    content = json.dumps(
        files,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    return hmac.new(
        key,
        content,
        hashlib.sha256
    ).hexdigest()


def validate_baseline_files(files):
    """Validate baseline paths and SHA-256 hash values."""

    if not isinstance(files, dict):
        raise BaselineIntegrityError("Invalid baseline file records.")

    for file_path, file_hash in files.items():

        if not isinstance(file_path, str) or not file_path:
            raise BaselineIntegrityError("Invalid file path in baseline.")

        if not isinstance(file_hash, str):
            raise BaselineIntegrityError("Invalid hash in baseline.")

        if len(file_hash) != 64:
            raise BaselineIntegrityError("Invalid SHA-256 hash length.")

        try:
            int(file_hash, 16)
        except ValueError:
            raise BaselineIntegrityError("Invalid SHA-256 hash format.")


def load_baseline():
    """Load and authenticate the baseline database."""

    if not BASELINE_PATH.exists():
        return {"files": {}}

    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)

    except (json.JSONDecodeError, OSError) as error:
        raise BaselineIntegrityError(
            f"Cannot read baseline: {error}"
        )

    if not isinstance(data, dict):
        raise BaselineIntegrityError("Invalid baseline structure.")

    files = data.get("files")
    stored_signature = data.get("hmac")

    if not isinstance(stored_signature, str):
        raise BaselineIntegrityError(
            "Baseline authentication data missing."
        )

    validate_baseline_files(files)

    key = get_secret_key()
    expected_signature = generate_signature(files, key)

    if not hmac.compare_digest(
        stored_signature,
        expected_signature
    ):
        raise BaselineIntegrityError(
            "Baseline authentication failed! Possible tampering."
        )

    return data


def save_baseline(file_path, file_hash):
    """Save a file hash and authenticate the complete baseline."""

    if not isinstance(file_hash, str) or len(file_hash) != 64:
        raise ValueError("Invalid SHA-256 hash.")

    try:
        int(file_hash, 16)
    except ValueError:
        raise ValueError("Invalid SHA-256 hash format.")

    data = load_baseline()

    absolute_path = str(Path(file_path).resolve())

    data["files"][absolute_path] = file_hash.lower()

    key = get_secret_key()

    data["hmac"] = generate_signature(data["files"], key)

    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Create a unique temporary file in the same directory.
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=BASELINE_PATH.parent,
            suffix=".tmp",
            delete=False
        ) as file:

            temp_path = Path(file.name)

            json.dump(data, file, indent=4)
            file.flush()
            os.fsync(file.fileno())

        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass

        # Replace the old baseline only after writing succeeds.
        os.replace(temp_path, BASELINE_PATH)

    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def display_baseline():
    """Display authenticated baseline records."""

    data = load_baseline()

    if not data["files"]:
        print("\nNo baseline records found.")
        return

    print("\n========== STORED BASELINE ==========")

    for file_path, file_hash in data["files"].items():
        print(f"\nFile: {file_path}")
        print(f"SHA-256: {file_hash}")

    print("\nBaseline authentication: VALID")
    print("=====================================")
