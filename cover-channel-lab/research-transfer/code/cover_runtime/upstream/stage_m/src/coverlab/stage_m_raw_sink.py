from __future__ import annotations

import argparse
import socket


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument("--bind", default="10.20.0.20")
    ap.add_argument("--port", type=int, default=9091)
    a=ap.parse_args()
    if a.bind != "10.20.0.20" or a.port != 9091:
        raise SystemExit("Stage M raw UDP sink is fixed to the isolated lab endpoint")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((a.bind,a.port))
        while True:
            data,peer=s.recvfrom(65535)
            s.sendto(data[:256],peer)


if __name__=="__main__":
    main()
