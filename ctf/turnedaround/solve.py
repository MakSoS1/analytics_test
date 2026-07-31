#!/usr/bin/env python3
from __future__ import annotations

import base64
import re
import zlib
from collections import defaultdict
from pathlib import Path

SOURCE_ZLIB_B85 = 'c-qZb36g{$415q}UXbD=l>h(60s*-rN1R$}W>+vrCuxH^<~9Iu8~UgGFk1Wnm>uGE)0sH83-;rtv_gNqQZ_(8N0%R9j}Sp?RSxi{=n&CPA5G9#8t@z>P5MIgkYp;s!dX|QlqH<kKsF+cAoXQuQ6{KCut=5)ufW0UIfj8W)KKC&K(+$L)++nj`q@$jA4Xqj*KVy0o$|Jfrmw5%b(h9HEr<f7?2KvURjnO2%teO$gpBHpPR<{l^kj-w-PE|5CLn=i8Z;Ajr%FCwO*vDso~5c{JavGrNX2Uyn1VEg+Fxb@7)C&_(&Z!{Mgj6`Mn(oE8qr1YxH37hz_UVkzQij-Gxt%BYi?pGbi1S2m+VS}XHV4BcDh16t|lb3^l&+A<T9yR1+J>|r5;+78Rm-J5Vmc-@Wy!sHOhV?40hk`+0MkKfl{Z2qm8+B=DKaN;S=h%5ue}O0;rt<G_EfORJ5l)X@qzSkvbKd>a7!qhoLnxiAeQ=_hb@999Kkg<5LrJ<aZpu1=&1YZp|LwPSjABu(DPtB=Ti%(@zptcekekX@3jW@;$EJ<<dS!Dfb;Nc)a6MuttlRr6ov5gjOSuChDcr$X#7dLr0BACj-(QnU_Y3HK`kys#L9mC?&A6of}X36}nOgJHhCoIHeD3k&avpP&c=_HJnzp1l4h-T1P#zJwY5)nv23m+_65?cw+CdgH?3Rt_N%A=hma7@@n`}_1E|qCcNv8*}=xbSzL&S2j(wy76Y%2<94!~Ag;@-8bhAOvvy+X=3z~lyx++*4-eBl@r=!xc$HY{@SUAYp-y9)G&j$am3qXQOqOKD@N=0gpq@32^Oy2wN|vFoSVx?{tTybIm)c^E79AD0b!sVJtDcsxfX&2F>RxZa<m;t2qFZ%>d$DXK@khl%wGqySqk`;PvF$nC>lQ~oiw?5uT5USzpW?m;fG<y<KS}=P)pP0<&!RmbTUPj!$d3@<Velu;Tjrmo;SdY5?_*A(9pf9lCE4GtKS5aEA8ibgRLg{dB1sj&a@rt2z$29%Av~fPlEWmIB{59GnUcgMnJqzF{A>5g*YW=;8kE{GK7seVwU&ga1ha=IzF&Qn$?#C~pSgJc(D4I8`kx0sy6yV3{%rS>C+}AQ_@8@0+a1FF?0nyUWoX73'


def build_jumps(code: str) -> dict[int, int]:
    stack: list[int] = []
    jumps: dict[int, int] = {}
    for index, command in enumerate(code):
        if command == "[":
            stack.append(index)
        elif command == "]":
            if not stack:
                raise ValueError(f"Unmatched ] at offset {index}")
            opening = stack.pop()
            jumps[opening] = index
            jumps[index] = opening
    if stack:
        raise ValueError(f"Unmatched [ at offset {stack[-1]}")
    return jumps


def run_brainfuck(code: str, initial_cell: int = 0, step_limit: int = 2_000_000) -> bytes:
    jumps = build_jumps(code)
    tape: defaultdict[int, int] = defaultdict(int)
    tape[0] = initial_cell & 0xFF
    pointer = instruction = steps = 0
    output = bytearray()
    while instruction < len(code):
        if steps >= step_limit:
            raise RuntimeError("Brainfuck step limit exceeded")
        command = code[instruction]
        if command == ">": pointer += 1
        elif command == "<": pointer -= 1
        elif command == "+": tape[pointer] = (tape[pointer] + 1) & 0xFF
        elif command == "-": tape[pointer] = (tape[pointer] - 1) & 0xFF
        elif command == ".": output.append(tape[pointer])
        elif command == "[" and tape[pointer] == 0: instruction = jumps[instruction]
        elif command == "]" and tape[pointer] != 0: instruction = jumps[instruction]
        instruction += 1
        steps += 1
    return bytes(output)


def merge_masks(first: str, second: str) -> str:
    if len(first) != len(second):
        raise ValueError("Password masks have different lengths")
    result: list[str] = []
    for index, (left, right) in enumerate(zip(first, second)):
        known = {character for character in (left, right) if character != "_"}
        if len(known) != 1:
            raise ValueError(f"Unresolved character {index}: {left!r}, {right!r}")
        result.append(known.pop())
    return "".join(result)


def main() -> None:
    source = zlib.decompress(base64.b85decode(SOURCE_ZLIB_B85)).decode("ascii")
    decoy = run_brainfuck(source).decode("ascii")
    if decoy != "Nice try! Unfortunately it's not that easy...\n":
        raise ValueError("Unexpected outer-program output")

    first_output = run_brainfuck(source[1257:1956], initial_cell=1).decode("ascii")
    second_output = run_brainfuck(source[2287:10034], initial_cell=1).decode("ascii")
    first = re.search(r"partial password: ([^\n]+)", first_output)
    second = re.search(r"hidden password: ([^\n]+)", second_output)
    if first is None or second is None:
        raise ValueError("Could not recover both password masks")

    password = merge_masks(first.group(1), second.group(1))
    Path("result.txt").write_text(f"bushbash{{{password}}}\n", encoding="utf-8")
    print("Solved successfully; result stored in the artifact")


if __name__ == "__main__":
    main()
