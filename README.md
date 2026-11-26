# File Integrity Checker

A Python-based tool that helps detect unexpected changes in log files using SHA-256 hashing and HMAC authentication.

## About the Project

Files can be modified without anyone noticing, especially when there is no proper way to track their original state.

I built **File Integrity Checker** to understand how file integrity monitoring works and how cryptographic techniques can help identify unauthorized changes.

The tool creates a trusted baseline of log files by calculating their SHA-256 hashes. Whenever I run an integrity check, it compares the current file hashes with the stored baseline and reports whether a file is unchanged, modified, missing, or newly added.

I also added HMAC-SHA256 authentication to protect the baseline data itself. This helps detect unauthorized changes to the stored hash records.

This project started as a way to practise Python and cybersecurity concepts, and gradually developed into a command-line security tool.

## Features

- **SHA-256 Hashing:** Calculates a unique hash for each monitored file.
- **Baseline Management:** Stores trusted file hashes in a JSON file.
- **HMAC Authentication:** Verifies the authenticity of stored baseline records.
- **Directory Scanning:** Recursively scans directories for `.log` files.
- **File Modification Detection:** Identifies changes by comparing current and stored hashes.
- **Missing File Detection:** Reports files that were previously monitored but are no longer present.
- **New File Detection:** Identifies log files that were not part of the original baseline.
- **Secret Key Protection:** Keeps the HMAC authentication key separate from the baseline data.
- **Command-Line Interface:** Provides commands to initialize, check, display, and update the baseline.
- **Automated Testing:** Uses Python's built-in `unittest` framework to test important functionality.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| hashlib | SHA-256 hashing |
| hmac | Baseline authentication |
| JSON | Baseline data storage |
| pathlib | File and directory handling |
| argparse | Command-line interface |
| unittest | Automated testing |

No third-party Python packages are required for the current implementation.

## Project Structure

```text
File-Integrity-Checker/
│
├── main.py
├── hasher.py
├── baseline.py
├── checker.py
├── scanner.py
│
├── storage/
│   ├── baseline.json
│   └── baseline.key
│
├── test_logs/
│   ├── application.log
│   ├── auth.log
│   └── system.log
│
├── tests/
│   ├── __init__.py
│   └── test_file_integrity.py
│
├── .gitignore
└── README.md
```

**A quick look at the main files:**

- `main.py` handles the command-line interface and connects the different modules.
- `hasher.py` calculates SHA-256 hashes.
- `baseline.py` manages the JSON baseline and HMAC authentication.
- `checker.py` compares current file hashes with stored records.
- `scanner.py` finds log files inside a given directory.
- `tests/` contains automated tests for the project.

The `storage/` directory is created when the application needs it. The baseline and secret key are local runtime files and should not be committed to GitHub.

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/R15H1-201/File-Integrity-Checker.git
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Open the project directory

```bash
cd File-Integrity-Checker
```

### 3. Check your Python installation

Python 3.8 or newer is recommended.

```bash
python --version
```

### 4. Run the application

```bash
python main.py --help
```

## Available Commands

The application uses a command-based interface.

### Initialize a baseline

```bash
python main.py init test_logs
```

This scans the specified directory, calculates the SHA-256 hashes of its log files, and stores them in the baseline.

### Check file integrity

```bash
python main.py check test_logs
```

This compares the current files against the stored baseline.

### Display the stored baseline

```bash
python main.py show
```

This displays the stored file paths and hashes after verifying the baseline's HMAC authentication.

### Update the baseline

```bash
python main.py update test_logs
```

Updating the baseline changes the trusted hashes. The application asks for confirmation before proceeding.

Only update the baseline after verifying that the current files are in a trusted state.

## Understanding the Results

During an integrity check, the application reports one of the following statuses:

| Status | Meaning |
|---|---|
| `UNMODIFIED` | The file matches its stored SHA-256 hash. |
| `MODIFIED` | The current hash differs from the stored hash. |
| `MISSING` | A previously monitored file could not be found. |
| `NEW` | A new log file was found that is not in the baseline. |
| `NOT_MONITORED` | The requested file does not have a stored baseline record. |

For example, if someone changes the contents of `application.log`, its SHA-256 hash will change. The next integrity check will report it as `MODIFIED`.

## How HMAC Authentication Works

File hashes alone are not enough if someone can also modify the stored baseline.

To address this, I implemented HMAC-SHA256 authentication.

The process works as follows:

1. The application calculates SHA-256 hashes for monitored files.
2. These hashes are stored in a JSON baseline.
3. A secret key is generated and stored separately.
4. The application uses HMAC-SHA256 to generate a signature for the baseline records.
5. During verification, it generates a new signature using the stored key.
6. It compares the newly generated signature with the saved signature.

If the signatures do not match, the application rejects the baseline.

This helps detect unauthorized modifications to the baseline data.

**Important:** Keep `storage/baseline.key` safe. If the key is lost, an existing authenticated baseline cannot be verified. If an attacker can access and replace both the baseline and its key, HMAC alone cannot protect against that attack.

## Running Automated Tests

The project includes automated tests using Python's built-in `unittest` framework.

Run the following command from the project directory:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

The test suite covers:

- SHA-256 hash generation
- Log file scanning
- Baseline saving and loading
- Baseline tampering detection
- Missing secret key detection
- Unmodified file detection
- Modified file detection
- New file detection
- Missing file detection

**Test result during development:** All 9 tests passed.

The tests use temporary directories to avoid modifying the actual project baseline and log files.

## Security Notes

A few things are important when using this project:

- Do not share or commit your `baseline.key`.
- Do not manually edit authenticated baseline records.
- Keep a secure backup of the baseline and its key.
- Initialize the baseline only when the files are in a trusted state.
- Review file changes before updating the baseline.

This project is a learning and demonstration tool. It is not a replacement for a production-grade file integrity monitoring system.

HMAC authentication protects against unauthorized changes to the baseline when the secret key remains trustworthy. It does not provide protection if an attacker controls both the baseline and the key.

## What I Learned

Building this project helped me understand several cybersecurity concepts beyond their theoretical definitions.

I got practical experience with:

- Cryptographic hashing and SHA-256.
- HMAC-based message authentication.
- File integrity monitoring.
- Working with files and directories in Python.
- JSON-based data storage.
- Handling errors and unexpected situations.
- Writing automated tests.
- Designing a command-line application.

One of the most interesting parts was understanding why protecting the baseline is just as important as calculating file hashes.

## Future Improvements

There is still room to improve the project. Some features I would like to explore next include:

- Support for more file types.
- Improved secret key storage and operating-system permissions.
- Detailed integrity reports with timestamps.
- Logging of detected changes.
- A graphical user interface.
- Scheduled integrity checks.
- More extensive automated and security testing.

## Author

**Rishi Kumavat**

Cybersecurity Student | Python Developer | Technology Enthusiast

- GitHub: https://github.com/R15H1-201
- LinkedIn: https://www.linkedin.com/in/rishi-kumavat
- Medium: https://medium.com/@r15h1-201

---

Built as a hands-on project to explore Python programming, cryptographic hashing, and file integrity monitoring.

If you find this project useful or have suggestions for improvement, feel free to explore the repository and share your feedback.

https://roadmap.sh/projects/file-integrity-checker