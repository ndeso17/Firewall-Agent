#include <onnxruntime_cxx_api.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string escape_json(const std::string& v) {
  std::string out;
  out.reserve(v.size());
  for (char c : v) {
    if (c == '"' || c == '\\') out.push_back('\\');
    if (c == '\n' || c == '\r') {
      out.push_back(' ');
      continue;
    }
    out.push_back(c);
  }
  return out;
}

void emit(double score, const std::string& uid, const std::string& reason) {
  if (score < 0.0) score = 0.0;
  if (score > 1.0) score = 1.0;
  std::cout << "{\"score\":" << score << ",\"uid\":\"" << escape_json(uid)
            << "\",\"reason\":\"" << escape_json(reason) << "\"}" << std::endl;
}

std::string read_file(const std::string& p) {
  std::ifstream ifs(p);
  if (!ifs) throw std::runtime_error("read_failed");
  std::stringstream ss;
  ss << ifs.rdbuf();
  return ss.str();
}

std::string find_uid(const std::string& json) {
  std::regex uid_re("\"uid\"\\s*:\\s*\"?([^\",}\\s]+)\"?");
  std::smatch m;
  if (std::regex_search(json, m, uid_re) && m.size() > 1) return m[1].str();
  return "-";
}

std::vector<float> parse_features(const std::string& json) {
  size_t key_pos = json.find("\"features\"");
  if (key_pos == std::string::npos) throw std::runtime_error("features_missing");
  size_t lb = json.find('[', key_pos);
  if (lb == std::string::npos) throw std::runtime_error("features_missing");

  size_t rb = lb;
  int depth = 0;
  for (; rb < json.size(); ++rb) {
    if (json[rb] == '[') depth++;
    else if (json[rb] == ']') {
      depth--;
      if (depth == 0) break;
    }
  }
  if (rb >= json.size()) throw std::runtime_error("features_missing");

  std::string body = json.substr(lb + 1, rb - lb - 1);
  for (char& c : body) {
    if (c == '\n' || c == '\r' || c == '\t') c = ' ';
  }

  std::vector<float> out;
  std::stringstream ss(body);
  std::string token;
  while (std::getline(ss, token, ',')) {
    size_t s = 0;
    while (s < token.size() && std::isspace(static_cast<unsigned char>(token[s]))) s++;
    size_t e = token.size();
    while (e > s && std::isspace(static_cast<unsigned char>(token[e - 1]))) e--;
    if (e <= s) continue;
    out.push_back(std::stof(token.substr(s, e - s)));
  }
  if (out.empty()) throw std::runtime_error("features_empty");
  return out;
}

double score_from_output(const std::vector<float>& out) {
  if (out.empty()) return 0.0;
  if (out.size() >= 2) return static_cast<double>(out[1]);
  return static_cast<double>(out[0]);
}

}  // namespace

int main(int argc, char** argv) {
  std::string model_path;
  std::string input_path;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--model" && i + 1 < argc) {
      model_path = argv[++i];
    } else if (arg == "--input" && i + 1 < argc) {
      input_path = argv[++i];
    }
  }

  if (model_path.empty() || input_path.empty()) {
    emit(0.0, "-", "invalid_args");
    return 0;
  }

  try {
    std::string payload = read_file(input_path);
    std::string uid = find_uid(payload);
    std::vector<float> features = parse_features(payload);

    Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "fw-agent");
    Ort::SessionOptions opts;
    opts.SetIntraOpNumThreads(1);
    opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_BASIC);
    Ort::Session session(env, model_path.c_str(), opts);

    Ort::AllocatorWithDefaultOptions allocator;
    auto input_name = session.GetInputNameAllocated(0, allocator);

    auto input_info = session.GetInputTypeInfo(0).GetTensorTypeAndShapeInfo();
    std::vector<int64_t> shape = input_info.GetShape();

    int64_t expected = -1;
    if (shape.size() > 1 && shape[1] > 0) expected = shape[1];
    if (expected > 0) {
      if (static_cast<int64_t>(features.size()) < expected) {
        features.resize(static_cast<size_t>(expected), 0.0f);
      } else if (static_cast<int64_t>(features.size()) > expected) {
        features.resize(static_cast<size_t>(expected));
      }
    }

    std::vector<int64_t> input_shape = {1, static_cast<int64_t>(features.size())};
    auto mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
        mem, features.data(), features.size(), input_shape.data(), input_shape.size());

    auto output_name = session.GetOutputNameAllocated(0, allocator);
    const char* input_names[] = {input_name.get()};
    const char* output_names[] = {output_name.get()};
    auto outs = session.Run(Ort::RunOptions{nullptr}, input_names, &input_tensor, 1,
                            output_names, 1);

    if (outs.empty() || !outs[0].IsTensor()) {
      emit(0.0, uid, "invalid_output");
      return 0;
    }

    auto out_info = outs[0].GetTensorTypeAndShapeInfo();
    size_t elem_count = out_info.GetElementCount();
    const float* out_data = outs[0].GetTensorData<float>();
    std::vector<float> out_vec(out_data, out_data + elem_count);
    emit(score_from_output(out_vec), uid, "model_inference");
    return 0;
  } catch (const std::exception&) {
    emit(0.0, "-", "native_inference_error");
    return 0;
  }
}
