import argparse
from smbprotocol import SMBConnection, parse_url, Session, TreeConnect, Dialects
from smbprotocol.exceptions import SMBAuthenticationError
from smbprotocol.file import FileAttributes, CreateDisposition, CreateOptions, FileDirectoryInformation
from smbprotocol.transport import TcpTransport

# Function to authenticate and establish connection
def authenticate(server, username, password, domain=""):
    try:
        smb_conn = SMBConnection()
        smb_conn.set_credentials(username, password, domain)
        smb_conn.connect(server, 445)
        return smb_conn
    except SMBAuthenticationError:
        print(f"Authentication failed for {server} with username {username}.")
        return None

# Function to scan and list all files and directories recursively
def scan_directory(smb_conn, server, share_name, path="\\"):
    tree = TreeConnect(smb_conn, server, share_name)
    tree.connect()

    # Start from the root directory
    files = []
    _scan_dir_recursive(tree, path, files)

    # Display all the files found
    print(f"Files and directories found on {server}\\{share_name}{path}:")
    for file in files:
        print(file)

def _scan_dir_recursive(tree, path, files):
    try:
        # List files and directories in the current path
        directory = tree.query_directory(path)
        for file in directory:
            if file.is_directory:
                # Recursively scan subdirectories
                _scan_dir_recursive(tree, path + file.file_name + "\\", files)
            else:
                files.append(path + file.file_name)
    except Exception as e:
        print(f"Error scanning {path}: {e}")

# Main function to parse arguments and run the process
def main():
    parser = argparse.ArgumentParser(description="SMB Server File Scanner")
    parser.add_argument('server', type=str, help="IP address or hostname of the SMB server")
    parser.add_argument('share', type=str, help="The shared folder name to scan")
    parser.add_argument('--username', type=str, help="Username for authentication")
    parser.add_argument('--password', type=str, help="Password for authentication")
    parser.add_argument('--domain', type=str, help="Domain for authentication (optional)", default="")
    
    args = parser.parse_args()

    # If no login details are passed, try guest login
    username = args.username if args.username else "guest"
    password = args.password if args.password else ""

    # Authenticate with SMB server
    smb_conn = authenticate(args.server, username, password, args.domain)
    if smb_conn:
        scan_directory(smb_conn, args.server, args.share)
    else:
        print(f"Failed to connect to the server {args.server}.")

if __name__ == "__main__":
    main()
