# enum-trusts

A command-line tool to recursively enumerate Active Directory domain trust relationships. **enum-trusts** relies on the [Netexec](https://github.com/Pennyw0rth/NetExec) project for LDAP operations and requires either a password or an NTLM hash for authentication.

## Features

- Recursively identifies trust relationships across Active Directory domains.
- Supports both password and NTLM hash-based authentication (e.g., for pass-the-hash scenarios).
- Detects Primary Domain Controllers (PDCs) using DNS SRV records.
- Outputs a summary of discovered trusts, including direction and type (if applicable).
- Provides a debug mode for troubleshooting.

## Installation

### Prerequisite: Install Netexec

**Important:** Before installing **enum-trusts**, ensure that **Netexec** is installed.  
You can install Netexec directly from GitHub using:

```sh
pip install git+https://github.com/Pennyw0rth/NetExec.git
```

On some systems, you might also have a system package available (e.g., via apt on Debian/Ubuntu):

```sh
sudo apt install netexec
```

### Installing enum-trusts

#### Via pipx (recommended)

```sh
pipx install git+https://github.com/ADScanPro/enum-trusts.git
```

#### Via pip

```sh
pip install git+https://github.com/ADScanPro/enum-trusts.git
```

> **Note**  
> This tool automatically installs Netexec from its GitHub repository. Ensure you are running a recent version of pip (19.0+) to support direct Git dependencies.

## Usage

Once installed, you can run the tool directly:

```sh
enum-trusts -u <username> -p <password> -d <domain.local> -pdc <PDC_IP>
```

or using an NTLM hash:

```sh
enum-trusts -u <username> -H <ntlm_hash> -d <domain.local> -pdc <PDC_IP>
```

### Additional Options

- `--debug`: Enables debug mode with verbose output.
- `-h/--help`: Displays the help message and usage examples.

## Example

```sh
enum-trusts \
  -u administrator \
  -p "Passw0rd!" \
  -d example.local \
  -pdc 192.168.1.10 \
  --debug
```
## Credits

- **Netexec**: This tool would not be possible without the great work from [Netexec](https://github.com/Pennyw0rth/NetExec). Special thanks to its creators and contributors for providing such a powerful utility.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
