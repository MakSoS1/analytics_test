#!/usr/bin/env python3
import os
import struct
from pathlib import Path

import MNN
import numpy as np

MASK = (1 << 64) - 1


def fnv1a(value: str) -> int:
    result = 0xCBF29CE484222325
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 0x100000001B3) & MASK
    return result


root = Path(__file__).resolve().parent
model = root / "touch_model.mnn"
output = root / "result.txt"

names = []
types = []

try:
    interpreter = MNN.Interpreter(str(model))
    config = {"backend": "CPU", "precision": "normal", "numThread": 1}
    session = interpreter.createSession(config)
    input_tensor = interpreter.getSessionInput(session, "touch")

    shape = tuple(input_tensor.getShape())
    if shape != (1, 5, 64):
        interpreter.resizeTensor(input_tensor, (1, 5, 64))
        interpreter.resizeSession(session)
        shape = tuple(input_tensor.getShape())

    host = MNN.Tensor(
        shape,
        MNN.Halide_Type_Float,
        np.zeros(shape, dtype=np.float32),
        MNN.Tensor_DimensionType_Caffe,
    )
    input_tensor.copyFrom(host)

    def before_callback(tensors, opinfo):
        return True

    def after_callback(tensors, opinfo):
        names.append(opinfo.getName())
        types.append(opinfo.getType())
        return True

    code = interpreter.runSessionWithCallBackInfo(
        session, before_callback, after_callback
    )

    callback_total = sum(fnv1a(name) for name in names) & MASK
    bridge_tag = (callback_total * 64) & MASK

    lines = [
        f"MNN_VERSION={getattr(MNN, '__version__', 'unknown')}",
        f"INPUT_SHAPE={shape}",
        f"RUN_CODE={code}",
        f"CALLBACK_COUNT={len(names)}",
    ]
    for index, (name, op_type) in enumerate(zip(names, types)):
        lines.append(
            f"CALLBACK[{index}]={name} TYPE={op_type} HASH=0x{fnv1a(name):016x}"
        )
    lines.extend(
        [
            f"CALLBACK_TOTAL=0x{callback_total:016x}",
            f"BRIDGE_TAG=0x{bridge_tag:016x}",
        ]
    )
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
except Exception as exc:
    output.write_text(
        f"ERROR_TYPE={type(exc).__name__}\nERROR={exc!r}\n",
        encoding="utf-8",
    )
    raise
