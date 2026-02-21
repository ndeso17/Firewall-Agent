#!/usr/bin/env python3
"""Python fallback ONNX runner for module/bin/infer_runner.sh."""

from __future__ import annotations

import argparse
import json
import sys


def emit(score: float, uid: str, reason: str) -> int:
    safe_score = max(0.0, min(1.0, float(score)))
    print(json.dumps({"score": safe_score, "uid": str(uid), "reason": reason}))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--input", required=True)
    return parser.parse_args()


def load_payload(path: str) -> tuple[list[float], str]:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    uid = "-"
    features = payload

    if isinstance(payload, dict):
        uid = str(payload.get("uid", payload.get("app_uid", "-")))
        if "features" in payload:
            features = payload["features"]
        elif "vector" in payload:
            features = payload["vector"]

    if not isinstance(features, list):
        raise ValueError("features must be a list")

    return [float(x) for x in features], uid


def main() -> int:
    args = parse_args()

    try:
        import numpy as np
        import onnxruntime as ort
    except Exception:
        return emit(0.0, "-", "python_dep_missing")

    try:
        features, uid = load_payload(args.input)
    except Exception:
        return emit(0.0, "-", "features_parse_error")

    try:
        sess = ort.InferenceSession(args.model, providers=["CPUExecutionProvider"])
        inp = sess.get_inputs()[0]
        expected = inp.shape[1] if len(inp.shape) > 1 else None

        if isinstance(expected, int) and expected > 0:
            if len(features) < expected:
                features.extend([0.0] * (expected - len(features)))
            elif len(features) > expected:
                features = features[:expected]

        x = np.array([features], dtype=np.float32)
        outputs = sess.run(None, {inp.name: x})
        raw = outputs[0]
        arr = np.asarray(raw).squeeze()

        if arr.ndim == 0:
            score = float(arr)
        elif arr.shape[0] >= 2:
            score = float(arr[1])
        else:
            score = float(arr[0])

        return emit(score, uid, "model_inference")
    except Exception:
        return emit(0.0, uid, "onnx_inference_error")


if __name__ == "__main__":
    sys.exit(main())
