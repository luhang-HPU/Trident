#include "model/plain_decoder.h"

#include "ops/plain_ops.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <ostream>
#include <random>
#include <stdexcept>
#include <utility>

namespace qwen
{
namespace
{

void require_shape(const Tensor &tensor, const std::vector<std::size_t> &shape,
                   const char *weight_name)
{
    if (tensor.shape() != shape)
    {
        throw std::invalid_argument(std::string(weight_name) + " has shape " +
                                    shape_string(tensor));
    }
}

void require_optional_bias(const Tensor &bias, std::size_t size, const char *bias_name)
{
    if (!bias.empty() && (bias.rank() != 1 || bias.dim(0) != size))
    {
        throw std::invalid_argument(std::string(bias_name) + " has invalid shape");
    }
}

const Tensor *optional_bias(const Tensor &bias)
{
    return bias.empty() ? nullptr : &bias;
}

Tensor random_weight(std::size_t output_size, std::size_t input_size, std::mt19937 &generator)
{
    const double bound = 0.4 / std::sqrt(static_cast<double>(input_size));
    std::uniform_real_distribution<double> distribution(-bound, bound);
    Tensor weight({output_size, input_size});
    for (double &value : weight.data())
    {
        value = distribution(generator);
    }
    return weight;
}

Tensor random_bias(std::size_t size, std::mt19937 &generator)
{
    std::uniform_real_distribution<double> distribution(-0.01, 0.01);
    Tensor bias({size});
    for (double &value : bias.data())
    {
        value = distribution(generator);
    }
    return bias;
}

void trace_tensor(ExecutionTrace *trace, const std::string &prefix, const char *name,
                  const Tensor &tensor)
{
    if (trace != nullptr)
    {
        trace->record(prefix + name, tensor);
    }
}

} // namespace

ExecutionTrace::ExecutionTrace(std::filesystem::path dump_directory)
    : dump_directory_(std::move(dump_directory))
{
    if (dump_directory_.empty())
    {
        throw std::invalid_argument("trace dump directory must not be empty");
    }
    std::filesystem::create_directories(dump_directory_);
    std::ofstream manifest(dump_directory_ / "manifest.tsv", std::ios::trunc);
    if (!manifest)
    {
        throw std::runtime_error("cannot create trace manifest");
    }
    manifest << "name\tshape\tfile\n";
}

void DecoderLayerWeights::validate(const QwenConfig &config) const
{
    config.validate();
    const std::size_t query_size = config.num_attention_heads * config.head_dim;
    const std::size_t kv_size = config.num_key_value_heads * config.head_dim;
    require_shape(input_norm, {config.hidden_size}, "input_norm");
    require_shape(query_weight, {query_size, config.hidden_size}, "query_weight");
    require_shape(key_weight, {kv_size, config.hidden_size}, "key_weight");
    require_shape(value_weight, {kv_size, config.hidden_size}, "value_weight");
    require_shape(output_weight, {config.hidden_size, query_size}, "output_weight");
    require_shape(post_attention_norm, {config.hidden_size}, "post_attention_norm");
    require_shape(gate_weight, {config.intermediate_size, config.hidden_size}, "gate_weight");
    require_shape(up_weight, {config.intermediate_size, config.hidden_size}, "up_weight");
    require_shape(down_weight, {config.hidden_size, config.intermediate_size}, "down_weight");
    require_optional_bias(query_bias, query_size, "query_bias");
    require_optional_bias(key_bias, kv_size, "key_bias");
    require_optional_bias(value_bias, kv_size, "value_bias");
}

void ExecutionTrace::record(const std::string &name, const Tensor &tensor)
{
    records_.push_back({name, shape_string(tensor), tensor_stats(tensor)});
    if (!dump_directory_.empty())
    {
        dump(name, tensor);
    }
}

const std::vector<TraceRecord> &ExecutionTrace::records() const
{
    return records_;
}

void ExecutionTrace::print(std::ostream &output) const
{
    output << std::setprecision(8);
    for (const TraceRecord &record : records_)
    {
        output << std::left << std::setw(24) << record.name << " shape=" << std::setw(12)
               << record.shape << " min=" << std::setw(13) << record.stats.min
               << " max=" << std::setw(13) << record.stats.max
               << " mean=" << std::setw(13) << record.stats.mean
               << " max_abs=" << record.stats.max_abs
               << " finite=" << (record.stats.all_finite ? "yes" : "no") << '\n';
    }
}

void ExecutionTrace::dump(const std::string &name, const Tensor &tensor)
{
    std::string file_stem = name;
    for (char &character : file_stem)
    {
        const unsigned char value = static_cast<unsigned char>(character);
        if (!std::isalnum(value) && character != '.' && character != '_' && character != '-')
        {
            character = '_';
        }
    }

    const std::filesystem::path file_path = dump_directory_ / (file_stem + ".f64");
    std::ofstream output(file_path, std::ios::binary | std::ios::trunc);
    if (!output)
    {
        throw std::runtime_error("cannot create trace tensor: " + file_path.string());
    }
    output.write(reinterpret_cast<const char *>(tensor.data().data()),
                 static_cast<std::streamsize>(tensor.numel() * sizeof(double)));
    if (!output)
    {
        throw std::runtime_error("cannot write trace tensor: " + file_path.string());
    }

    std::ofstream manifest(dump_directory_ / "manifest.tsv", std::ios::app);
    if (!manifest)
    {
        throw std::runtime_error("cannot append trace manifest");
    }
    manifest << name << '\t' << shape_string(tensor) << '\t'
             << file_path.filename().string() << '\n';
}

PlainDecoderLayer::PlainDecoderLayer(QwenConfig config, DecoderLayerWeights weights)
    : config_(std::move(config)), weights_(std::move(weights))
{
    config_.validate();
    weights_.validate(config_);
}

Tensor PlainDecoderLayer::forward(const Tensor &input, KVCache *cache, ExecutionTrace *trace,
                                  const std::string &trace_prefix) const
{
    if (input.rank() != 2 || input.dim(1) != config_.hidden_size)
    {
        throw std::invalid_argument("decoder input must have shape [tokens, hidden_size]");
    }
    trace_tensor(trace, trace_prefix, "input", input);

    const Tensor normalized =
        rms_norm(input, weights_.input_norm, config_.rms_norm_epsilon);
    trace_tensor(trace, trace_prefix, "input_rmsnorm", normalized);

    Tensor query = split_heads(
        linear(normalized, weights_.query_weight, optional_bias(weights_.query_bias)),
        config_.num_attention_heads, config_.head_dim);
    Tensor key =
        split_heads(linear(normalized, weights_.key_weight, optional_bias(weights_.key_bias)),
                    config_.num_key_value_heads, config_.head_dim);
    const Tensor value =
        split_heads(linear(normalized, weights_.value_weight, optional_bias(weights_.value_bias)),
                    config_.num_key_value_heads, config_.head_dim);
    trace_tensor(trace, trace_prefix, "query_projection", query);
    trace_tensor(trace, trace_prefix, "key_projection", key);
    trace_tensor(trace, trace_prefix, "value_projection", value);

    const std::size_t position_offset = cache == nullptr ? 0 : cache->size();
    apply_rope(query, key, position_offset, config_.rope_theta);
    trace_tensor(trace, trace_prefix, "query_rope", query);
    trace_tensor(trace, trace_prefix, "key_rope", key);

    const Tensor attention =
        causal_gqa_attention(query, key, value, config_, cache);
    trace_tensor(trace, trace_prefix, "attention", attention);
    const Tensor attention_output =
        linear(merge_heads(attention), weights_.output_weight);
    trace_tensor(trace, trace_prefix, "attention_output", attention_output);

    const Tensor post_attention = add(input, attention_output);
    trace_tensor(trace, trace_prefix, "post_attention_residual", post_attention);
    const Tensor mlp_input =
        rms_norm(post_attention, weights_.post_attention_norm, config_.rms_norm_epsilon);
    trace_tensor(trace, trace_prefix, "post_attention_rmsnorm", mlp_input);

    const Tensor gate = linear(mlp_input, weights_.gate_weight);
    const Tensor up = linear(mlp_input, weights_.up_weight);
    trace_tensor(trace, trace_prefix, "mlp_gate", gate);
    trace_tensor(trace, trace_prefix, "mlp_up", up);
    const Tensor activated = swiglu(gate, up);
    trace_tensor(trace, trace_prefix, "mlp_swiglu", activated);
    const Tensor mlp_output = linear(activated, weights_.down_weight);
    trace_tensor(trace, trace_prefix, "mlp_output", mlp_output);

    Tensor output = add(post_attention, mlp_output);
    trace_tensor(trace, trace_prefix, "output", output);
    return output;
}

DecoderLayerWeights make_demo_layer_weights(const QwenConfig &config, unsigned int seed)
{
    config.validate();
    std::mt19937 generator(seed);
    DecoderLayerWeights weights;
    weights.input_norm = Tensor({config.hidden_size});
    weights.post_attention_norm = Tensor({config.hidden_size});
    std::fill(weights.input_norm.data().begin(), weights.input_norm.data().end(), 1.0);
    std::fill(weights.post_attention_norm.data().begin(), weights.post_attention_norm.data().end(),
              1.0);

    const std::size_t query_size = config.num_attention_heads * config.head_dim;
    const std::size_t kv_size = config.num_key_value_heads * config.head_dim;
    weights.query_weight = random_weight(query_size, config.hidden_size, generator);
    weights.query_bias = random_bias(query_size, generator);
    weights.key_weight = random_weight(kv_size, config.hidden_size, generator);
    weights.key_bias = random_bias(kv_size, generator);
    weights.value_weight = random_weight(kv_size, config.hidden_size, generator);
    weights.value_bias = random_bias(kv_size, generator);
    weights.output_weight = random_weight(config.hidden_size, query_size, generator);
    weights.gate_weight =
        random_weight(config.intermediate_size, config.hidden_size, generator);
    weights.up_weight = random_weight(config.intermediate_size, config.hidden_size, generator);
    weights.down_weight =
        random_weight(config.hidden_size, config.intermediate_size, generator);
    return weights;
}

Tensor make_demo_hidden_states(std::size_t sequence_length, const QwenConfig &config)
{
    if (sequence_length == 0)
    {
        throw std::invalid_argument("demo sequence length must be positive");
    }
    config.validate();
    Tensor input({sequence_length, config.hidden_size});
    for (std::size_t token = 0; token < sequence_length; ++token)
    {
        for (std::size_t feature = 0; feature < config.hidden_size; ++feature)
        {
            const double index =
                static_cast<double>(token * config.hidden_size + feature + 1);
            input.at(token, feature) =
                0.35 * std::sin(index * 0.31) + 0.15 * std::cos(index * 0.17);
        }
    }
    return input;
}

} // namespace qwen
