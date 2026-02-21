# Native ONNX Runner

Output files in this directory:

- `infer_runner_native` (executable, Android arm64 or host build)
- `lib/libonnxruntime.so`

Build command:

```sh
export ONNXRUNTIME_ROOT=/path/to/onnxruntime-android-arm64
export ANDROID_NDK_ROOT=/path/to/android-ndk
bash scripts/build_infer_runner_native.sh --android --abi arm64-v8a
```

Host test build (optional):

```sh
export ONNXRUNTIME_ROOT=/path/to/onnxruntime-linux-x64
bash scripts/build_infer_runner_native.sh --host
```

CLI contract:

```sh
infer_runner_native --model /path/model.onnx --input /path/features.json
```

Output JSON:

```json
{"score":0.91,"uid":"10123","reason":"model_inference"}
```
