#include "core/tensor.h"
#include "model/plain_decoder.h"
#include "model/plain_qwen.h"
#include "model/qwen_config.h"

#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace
{

std::size_t parse_positive(const char *value, const char *name)
{
    try
    {
        const std::string text(value);
        std::size_t parsed = 0;
        const unsigned long long result = std::stoull(text, &parsed);
        if (parsed != text.size() || result == 0)
        {
            throw std::invalid_argument("not positive");
        }
        return static_cast<std::size_t>(result);
    }
    catch (const std::exception &)
    {
        throw std::invalid_argument(std::string("invalid ") + name + ": " + value);
    }
}

std::size_t parse_nonnegative(const char *value, const char *name)
{
    try
    {
        const std::string text(value);
        std::size_t parsed = 0;
        const unsigned long long result = std::stoull(text, &parsed);
        if (parsed != text.size())
        {
            throw std::invalid_argument("trailing input");
        }
        return static_cast<std::size_t>(result);
    }
    catch (const std::exception &)
    {
        throw std::invalid_argument(std::string("invalid ") + name + ": " + value);
    }
}

std::vector<std::size_t> parse_token_ids(std::string text)
{
    for (char &character : text)
    {
        if (character == ',')
        {
            character = ' ';
        }
    }
    std::istringstream input(text);
    std::vector<std::size_t> tokens;
    long long token = 0;
    while (input >> token)
    {
        if (token < 0)
        {
            throw std::invalid_argument("token IDs must be nonnegative");
        }
        tokens.push_back(static_cast<std::size_t>(token));
    }
    if (!input.eof() || tokens.empty())
    {
        throw std::invalid_argument("input IDs must be a comma- or space-separated list");
    }
    return tokens;
}

void print_usage(const char *program)
{
    std::cout << "Synthetic decoder demo:\n"
              << "  " << program << " [--sequence N] [--threads N] [--seed N]\n"
              << "Real checkpoint inference:\n"
              << "  " << program
              << " --model DIR --input-ids IDS [--max-new-tokens N]"
                 " [--top-k N] [--threads N] [--trace]"
                 " [--dump-trace-dir DIR]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::size_t sequence_length = 8;
        std::size_t thread_count = 1;
        std::size_t max_new_tokens = 0;
        std::size_t top_k = 5;
        unsigned int seed = 7;
        std::filesystem::path model_path;
        std::filesystem::path dump_trace_directory;
        std::vector<std::size_t> input_ids;
        bool enable_trace = false;
        for (int index = 1; index < argc; ++index)
        {
            const std::string argument(argv[index]);
            if (argument == "--help")
            {
                print_usage(argv[0]);
                return 0;
            }
            if (argument == "--trace")
            {
                enable_trace = true;
                continue;
            }
            if (index + 1 >= argc)
            {
                throw std::invalid_argument("missing value for " + argument);
            }
            if (argument == "--sequence")
            {
                sequence_length = parse_positive(argv[++index], "sequence length");
            }
            else if (argument == "--threads")
            {
                thread_count = parse_positive(argv[++index], "thread count");
            }
            else if (argument == "--seed")
            {
                seed = static_cast<unsigned int>(parse_positive(argv[++index], "seed"));
            }
            else if (argument == "--model")
            {
                model_path = argv[++index];
            }
            else if (argument == "--input-ids")
            {
                input_ids = parse_token_ids(argv[++index]);
            }
            else if (argument == "--dump-trace-dir")
            {
                dump_trace_directory = argv[++index];
                enable_trace = true;
            }
            else if (argument == "--max-new-tokens")
            {
                max_new_tokens =
                    parse_nonnegative(argv[++index], "maximum new token count");
            }
            else if (argument == "--top-k")
            {
                top_k = parse_positive(argv[++index], "top-k count");
            }
            else
            {
                throw std::invalid_argument("unknown option: " + argument);
            }
        }

#ifdef _OPENMP
        omp_set_num_threads(static_cast<int>(thread_count));
#else
        if (thread_count != 1)
        {
            std::cerr << "warning: OpenMP is unavailable; using one CPU thread\n";
        }
#endif

        if (!model_path.empty())
        {
            if (input_ids.empty())
            {
                throw std::invalid_argument("--input-ids is required with --model");
            }
            const auto load_start = std::chrono::steady_clock::now();
            const qwen::PlainQwenModel model = qwen::load_plain_qwen_model(model_path);
            const auto load_stop = std::chrono::steady_clock::now();
            qwen::ExecutionTrace trace = dump_trace_directory.empty()
                                             ? qwen::ExecutionTrace()
                                             : qwen::ExecutionTrace(dump_trace_directory);
            qwen::ExecutionTrace *trace_pointer = enable_trace ? &trace : nullptr;

            const auto inference_start = std::chrono::steady_clock::now();
            if (max_new_tokens > 0)
            {
                const std::vector<std::size_t> generated =
                    model.generate(input_ids, max_new_tokens, trace_pointer);
                std::cout << "generated_token_ids:";
                for (std::size_t token : generated)
                {
                    std::cout << ' ' << token;
                }
                std::cout << '\n';
            }
            else
            {
                const qwen::Tensor logits =
                    model.last_token_logits(input_ids, nullptr, trace_pointer);
                std::cout << "top_logits:\n";
                for (const auto &[token, value] : qwen::top_k_logits(logits, top_k))
                {
                    std::cout << "  token=" << token << " logit=" << value << '\n';
                }
            }
            const auto inference_stop = std::chrono::steady_clock::now();
            if (enable_trace)
            {
                trace.print(std::cout);
            }
            const auto load_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(load_stop - load_start)
                    .count();
            const auto inference_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(inference_stop -
                                                                      inference_start)
                    .count();
            std::cout << "model=" << model_path << " layers=" << model.config().num_hidden_layers
                      << " hidden=" << model.config().hidden_size
                      << " vocab=" << model.config().vocab_size
                      << " threads=" << thread_count << " load_ms=" << load_ms
                      << " inference_ms=" << inference_ms << '\n';
            return 0;
        }
        if (!input_ids.empty())
        {
            throw std::invalid_argument("--input-ids requires --model");
        }

        const qwen::QwenConfig config = qwen::demo_config();
        const qwen::DecoderLayerWeights weights =
            qwen::make_demo_layer_weights(config, seed);
        const qwen::Tensor input = qwen::make_demo_hidden_states(sequence_length, config);
        const qwen::PlainDecoderLayer layer(config, weights);
        qwen::ExecutionTrace trace;

        const auto start = std::chrono::steady_clock::now();
        const qwen::Tensor output = layer.forward(input, nullptr, &trace);
        const auto stop = std::chrono::steady_clock::now();
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();

        std::cout << "Qwen CPU plaintext decoder demo\n";
        std::cout << "sequence=" << sequence_length << " hidden=" << config.hidden_size
                  << " query_heads=" << config.num_attention_heads
                  << " kv_heads=" << config.num_key_value_heads
                  << " intermediate=" << config.intermediate_size
                  << " threads=" << thread_count << '\n';
        trace.print(std::cout);
        qwen::print_tensor_summary("decoder_output", output, std::cout);
        std::cout << "elapsed_us=" << elapsed << '\n';
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_plain: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
