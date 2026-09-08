#pragma once

#include "core/tensor.h"
#include "model/plain_attention.h"
#include "model/qwen_config.h"

#include <filesystem>
#include <iosfwd>
#include <string>
#include <vector>

namespace qwen
{

struct DecoderLayerWeights
{
    Tensor input_norm;
    Tensor query_weight;
    Tensor query_bias;
    Tensor key_weight;
    Tensor key_bias;
    Tensor value_weight;
    Tensor value_bias;
    Tensor output_weight;
    Tensor post_attention_norm;
    Tensor gate_weight;
    Tensor up_weight;
    Tensor down_weight;

    void validate(const QwenConfig &config) const;
};

struct TraceRecord
{
    std::string name;
    std::string shape;
    TensorStats stats;
};

class ExecutionTrace
{
public:
    ExecutionTrace() = default;
    explicit ExecutionTrace(std::filesystem::path dump_directory);

    void record(const std::string &name, const Tensor &tensor);
    const std::vector<TraceRecord> &records() const;
    void print(std::ostream &output) const;

private:
    void dump(const std::string &name, const Tensor &tensor);

    std::vector<TraceRecord> records_;
    std::filesystem::path dump_directory_;
};

class PlainDecoderLayer
{
public:
    PlainDecoderLayer(QwenConfig config, DecoderLayerWeights weights);

    Tensor forward(const Tensor &input, KVCache *cache = nullptr,
                   ExecutionTrace *trace = nullptr,
                   const std::string &trace_prefix = "") const;

private:
    QwenConfig config_;
    DecoderLayerWeights weights_;
};

DecoderLayerWeights make_demo_layer_weights(const QwenConfig &config, unsigned int seed = 7);
Tensor make_demo_hidden_states(std::size_t sequence_length, const QwenConfig &config);

} // namespace qwen
