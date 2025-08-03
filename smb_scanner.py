import argparse
import os
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from smbprotocol.file_info import FileAttributes
import logging
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def authenticate(server, username, password):
    """Authenticate with the SMB server."""
    try:
        if not server or not isinstance(server, str):
            raise ValueError("Invalid server address")

        connection = Connection(server_name=server, port=445, guid=uuid.uuid4())
        connection.connect(timeout=10)

        session = Session(connection, username=username, password=password)
        session.connect()
        logging.info(f"Authenticated successfully to {server}")
        return connection, session
    except Exception as e:
        logging.error(f"Authentication failed: {type(e).__name__} - {str(e)}")
        if "NT_STATUS_LOGON_FAILURE" in str(e):
            logging.error("Invalid credentials provided")
        elif "NT_STATUS_HOST_UNREACHABLE" in str(e):
            logging.error("Host unreachable - check network connection")
        return None, None


def list_directory(tree, path="\\"):
    """List files and directories at the specified path."""
    try:
        dir_handle = Open(tree, path, desired_access=FileAttributes.FILE_LIST_DIRECTORY)
        entries = dir_handle.query_directory()
        dir_handle.close()
        return entries
    except Exception as e:
        logging.error(f"Error listing directory {path}: {e}")
        return []


def scan_directory(tree, path="\\", results=None):
    """Recursively scan the directory."""
    if results is None:
        results = []

    entries = list_directory(tree, path)
    for entry in entries:
        name = entry['file_name'].get_value()
        is_directory = entry['file_attributes'].get_value() & FileAttributes.FILE_ATTRIBUTE_DIRECTORY

        full_path = os.path.join(path, name)
        results.append(full_path)

        if is_directory and name not in [".", ".."]:
            scan_directory(tree, full_path, results)

    return results


def download_file(tree, server_path, local_path):
    """Download a file from the SMB server."""
    try:
        file_handle = Open(tree, server_path, desired_access=FileAttributes.FILE_READ_DATA)
        file_data = file_handle.read(0, file_handle.end_of_file)
        file_handle.close()

        with open(local_path, "wb") as f:
            f.write(file_data)

        logging.info(f"File downloaded: {server_path} -> {local_path}")
    except Exception as e:
        logging.error(f"Error downloading file {server_path}: {e}")


def upload_file(tree, local_path, server_path):
    """Upload a file to the SMB server."""
    try:
        if not os.path.exists(local_path):
            logging.error(f"Local file not found: {local_path}")
            return

        with open(local_path, "rb") as f:
            file_data = f.read()

        file_handle = Open(tree, server_path, desired_access=FileAttributes.FILE_WRITE_DATA)
        file_handle.write(0, file_data)
        file_handle.close()

        logging.info(f"File uploaded: {local_path} -> {server_path}")
    except Exception as e:
        logging.error(f"Error uploading file {local_path}: {e}")


def delete_file_or_directory(tree, server_path):
    """Delete a file or directory from the SMB server."""
    try:
        file_handle = Open(tree, server_path, desired_access=FileAttributes.FILE_DELETE)
        file_handle.delete()
        file_handle.close()

        logging.info(f"Deleted: {server_path}")
    except Exception as e:
        logging.error(f"Error deleting {server_path}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Enhanced SMB Server File Scanner")
    parser.add_argument("server", type=str, help="SMB server address (IP or hostname)")
    parser.add_argument("share", type=str, help="SMB share name")
    parser.add_argument("--username", type=str, default="guest", help="Username for authentication")
    parser.add_argument("--password", type=str, default="", help="Password for authentication")
    parser.add_argument("--scan", action="store_true", help="Scan and list all files and directories")
    parser.add_argument("--download", type=str, help="Download a file from the server")
    parser.add_argument("--output", type=str, help="Local output path for downloaded file")
    parser.add_argument("--upload", type=str, help="Local file path to upload to the server")
    parser.add_argument("--destination", type=str, help="Server path to upload the file")
    parser.add_argument("--delete", type=str, help="Delete a file or directory on the server")
    parser.add_argument("--log", type=str, help="Log file path")

    args = parser.parse_args()

    # Configure logging to file if specified
    if args.log:
        logging.basicConfig(filename=args.log, level=logging.INFO)

    # Authenticate with the server
    connection, session = authenticate(args.server, args.username, args.password)
    if not connection or not session:
        return

    # Validate share name format
    if not args.share or "/" in args.share or " " in args.share:
        logging.error("Invalid share name. Must not contain spaces or slashes")
        return

    try:
        tree = TreeConnect(session, f"\\\\{args.server}\\{args.share}")
        tree.connect()
        logging.info(f"Connected to share: {args.share}")
    except Exception as e:
        logging.error(f"Failed to connect to share: {e}")
        return

    if args.scan:
        logging.info("Scanning directory structure...")
        files = scan_directory(tree)
        for file in files:
            print(file)

    if args.download and args.output:
        download_file(tree, args.download, args.output)

    if args.upload and args.destination:
        upload_file(tree, args.upload, args.destination)

    if args.delete:
        delete_file_or_directory(tree, args.delete)


if __name__ == "__main__":
    main()
