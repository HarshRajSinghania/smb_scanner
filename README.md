# SMB Server File Scanner

This is a Python script that allows you to authenticate with an SMB server, scan its files and directories, and perform various operations such as downloading, uploading, and deleting files. The script also includes logging and advanced filtering capabilities.

---

## Features

1. **Authentication**:
   - Authenticate using a username and password.
   - Supports guest login by default if no credentials are provided.

2. **Recursive Directory Scanning**:
   - Scans all files and directories within the SMB share.

3. **File Operations**:
   - **Download**: Download files from the SMB server to your local machine.
   - **Upload**: Upload files from your local machine to the SMB server.
   - **Delete**: Delete files or directories on the SMB server.

4. **Logging**:
   - Save detailed logs of all actions and errors to a file.

---

## Installation

### Prerequisites
- Python 3.7 or higher
- `smbprotocol` package for SMB interactions

### Install Required Libraries

pip install smbprotocol

## Usage

Run the script using the command line:

python smb_scanner.py <server> <share> [options]

### Required Arguments
- `server`: IP address or hostname of the SMB server.
- `share`: SMB share name to access.

### Optional Arguments
| Option             | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `--username`       | Username for authentication (default: `guest`).                           |
| `--password`       | Password for authentication (default: blank).                             |
| `--scan`           | Scan the SMB share and list all files and directories.                    |
| `--download`       | Path of the file on the SMB server to download.                           |
| `--output`         | Local path where the downloaded file will be saved.                       |
| `--upload`         | Local path of the file to upload to the SMB server.                       |
| `--destination`    | Path on the SMB server where the file will be uploaded.                   |
| `--delete`         | Path of the file or directory on the SMB server to delete.                |
| `--log`            | File path for saving detailed logs of operations.                        |

---

## Examples

### 2. Download a File

python smb_scanner.py 192.168.1.10 share_name --scan

### 1. Scan a Directory

### 2. Download a File

python smb_scanner.py 192.168.1.10 share_name --download "\\path\\to\\file.txt" --output "local_file.txt"

### 3. Upload a File

python smb_scanner.py 192.168.1.10 share_name --upload "local_file.txt" --destination "\\path\\to\\upload\\file.txt"

### 4. Delete a File or Directory

python smb_scanner.py 192.168.1.10 share_name --delete "\\path\\to\\file_or_directory"

### 5. Enable Logging

python smb_scanner.py 192.168.1.10 share_name --scan --log "scanner.log"

## Logging

Logs are saved in the file specified by the --log argument.
Includes information about successful operations, errors, and authentication status.

## Requirements

    Python 3.7+
    smbprotocol library

Install the dependencies with:

pip install smbprotocol

## GitHub Repository

```bash
# Clone the repository
git clone https://github.com/HarshRajSinghania/smb_scanner.git
cd smb_scanner

# Set up development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Limitations

This script supports SMBv2/SMBv3. It might not work on older SMB implementations.
Operations such as upload and delete require appropriate permissions on the SMB server.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request if you'd like to improve this project.
