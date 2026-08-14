#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from ipaddress import ip_address, ip_network
from pathlib import Path

LAB_NETWORK = ip_network("10.77.0.0/24")


def assert_lab_ip(value: str) -> str:
    address = ip_address(value)
    if address not in LAB_NETWORK:
        raise SystemExit(f"destination outside isolated lab: {address}")
    return str(address)


def run_paramiko(args: argparse.Namespace) -> None:
    import paramiko

    dst = assert_lab_ip(args.dst)
    key_path = Path(args.key)
    if not key_path.is_file():
        raise SystemExit(f"SSH key missing: {key_path}")

    key = paramiko.Ed25519Key.from_private_key_file(str(key_path))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=dst,
        port=22,
        username="root",
        pkey=key,
        timeout=8,
        banner_timeout=8,
        auth_timeout=8,
        allow_agent=False,
        look_for_keys=False,
    )
    try:
        if args.action == "upload":
            local = Path(args.local)
            if not local.is_file():
                raise SystemExit(f"upload fixture missing: {local}")
            remote = args.remote or f"/tmp/{local.name}"
            sftp = client.open_sftp()
            try:
                sftp.put(str(local), remote)
            finally:
                sftp.close()
            return
        _, stdout, stderr = client.exec_command("true", timeout=8)
        status = stdout.channel.recv_exit_status()
        if status != 0:
            detail = stderr.read().decode("utf-8", errors="replace")[:300]
            raise SystemExit(f"Paramiko harmless command failed status={status}: {detail}")
    finally:
        client.close()


def run_smbprotocol(args: argparse.Namespace) -> None:
    import smbclient

    dst = assert_lab_ip(args.dst)
    share = fr"\\{dst}\adminlab_admin"
    smbclient.register_session(
        dst,
        username="adminlab_smb",
        password="AdminlabSMB-2026!",
        port=445,
        connection_timeout=8,
    )
    try:
        if args.action == "upload":
            local = Path(args.local)
            if not local.is_file():
                raise SystemExit(f"upload fixture missing: {local}")
            remote_name = args.remote or local.name
            remote = share + "\\" + os.path.basename(remote_name)
            with local.open("rb") as src, smbclient.open_file(remote, mode="wb") as dst_fh:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dst_fh.write(chunk)
            return
        names = smbclient.listdir(share)
        if not names:
            raise SystemExit("smbprotocol listing returned no entries")
        readme = share + "\\readme.txt"
        with smbclient.open_file(readme, mode="rb") as fh:
            fh.read(128)
    finally:
        try:
            smbclient.delete_session(dst)
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="client", required=True)

    ssh = sub.add_parser("paramiko")
    ssh.add_argument("--dst", required=True)
    ssh.add_argument("--key", required=True)
    ssh.add_argument("--action", choices=["exec", "upload"], required=True)
    ssh.add_argument("--local", default="")
    ssh.add_argument("--remote", default="")

    smb = sub.add_parser("smbprotocol")
    smb.add_argument("--dst", required=True)
    smb.add_argument("--action", choices=["list", "upload"], required=True)
    smb.add_argument("--local", default="")
    smb.add_argument("--remote", default="")

    args = parser.parse_args()
    if args.client == "paramiko":
        run_paramiko(args)
    elif args.client == "smbprotocol":
        run_smbprotocol(args)
    else:
        raise SystemExit(args.client)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
