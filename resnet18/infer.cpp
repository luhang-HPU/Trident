#include "infer.h"

#include "encrypted_ops.h"
#include "encrypted_group_ops.h"
#include "encrypted_inference_timer.h"
#include "execution_mode.h"
#include "infer_config.h"
#include "infer_runtime.h"
#include "parallel_utils.h"
#include "parameter_loader.h"
#include "plain_cnn.h"
#include "progress_log.h"
#include "poseidon/advance/homomorphic_linear_transform.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <complex>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <sstream>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

using namespace std;
using namespace poseidon;

namespace fs = std::filesystem;

namespace
{

constexpr bool kRunFullStemCheck = true;

struct MockExecutionOptions
{
    bool mock_relu = false;
    bool mock_bootstrap = false;
};

struct ConvPlaintextCacheKey
{
    uintptr_t layer_identity = 0;
    parms_id_type parms_id{};
    uint32_t kind = 0;
    uint32_t input_pack = 0;
    uint32_t kernel_position = 0;
    uint32_t output_channel = 0;

    bool operator==(const ConvPlaintextCacheKey &other) const noexcept
    {
        return layer_identity == other.layer_identity &&
               parms_id == other.parms_id && kind == other.kind &&
               input_pack == other.input_pack &&
               kernel_position == other.kernel_position &&
               output_channel == other.output_channel;
    }
};

struct ConvPlaintextCacheKeyHash
{
    size_t operator()(const ConvPlaintextCacheKey &key) const noexcept
    {
        size_t hash = std::hash<uintptr_t>{}(key.layer_identity);
        auto mix = [&](size_t value) {
            hash ^= value + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
        };
        for (uint64_t word : key.parms_id)
        {
            mix(std::hash<uint64_t>{}(word));
        }
        mix(key.kind);
        mix(key.input_pack);
        mix(key.kernel_position);
        mix(key.output_channel);
        return hash;
    }
};

class ConvPlaintextCache
{
public:
    struct Stats
    {
        size_t resident_bytes = 0;
        size_t entries = 0;
        size_t hits = 0;
        size_t misses = 0;
        size_t evictions = 0;
        size_t encoded_bytes = 0;
    };

    explicit ConvPlaintextCache(size_t max_bytes) : max_bytes_(max_bytes) {}

    shared_ptr<const Plaintext> get_or_encode(
        const ConvPlaintextCacheKey &key, const vector<double> &values,
        parms_id_type parms_id, double scale, CKKSEncoder &encoder)
    {
        {
            lock_guard<mutex> lock(mutex_);
            auto found = entries_.find(key);
            if (found != entries_.end())
            {
                lru_.splice(lru_.begin(), lru_, found->second.lru_position);
                ++hits_;
                return found->second.plaintext;
            }
        }

        auto encoded = make_shared<Plaintext>();
        encoder.encode(values, parms_id, scale, *encoded);
        const size_t bytes = encoded->capacity() * sizeof(uint64_t);

        lock_guard<mutex> lock(mutex_);
        auto raced = entries_.find(key);
        if (raced != entries_.end())
        {
            lru_.splice(lru_.begin(), lru_, raced->second.lru_position);
            ++hits_;
            return raced->second.plaintext;
        }

        ++misses_;
        encoded_bytes_ += bytes;
        if (max_bytes_ == 0 || bytes > max_bytes_)
        {
            return encoded;
        }
        while (!lru_.empty() && resident_bytes_ + bytes > max_bytes_)
        {
            const ConvPlaintextCacheKey &old_key = lru_.back();
            auto old = entries_.find(old_key);
            resident_bytes_ -= old->second.bytes;
            entries_.erase(old);
            lru_.pop_back();
            ++evictions_;
        }
        lru_.push_front(key);
        entries_.emplace(
            key, Entry{encoded, bytes, lru_.begin()});
        resident_bytes_ += bytes;
        return encoded;
    }

    Stats stats() const
    {
        lock_guard<mutex> lock(mutex_);
        return {resident_bytes_, entries_.size(), hits_, misses_, evictions_,
                encoded_bytes_};
    }

    size_t max_bytes() const noexcept { return max_bytes_; }

private:
    struct Entry
    {
        shared_ptr<const Plaintext> plaintext;
        size_t bytes = 0;
        list<ConvPlaintextCacheKey>::iterator lru_position;
    };

    size_t max_bytes_ = 0;
    mutable mutex mutex_;
    list<ConvPlaintextCacheKey> lru_;
    unordered_map<ConvPlaintextCacheKey, Entry, ConvPlaintextCacheKeyHash> entries_;
    size_t resident_bytes_ = 0;
    size_t hits_ = 0;
    size_t misses_ = 0;
    size_t evictions_ = 0;
    size_t encoded_bytes_ = 0;
};

ConvPlaintextCache *active_conv_plaintext_cache = nullptr;

class ScopedConvPlaintextCache
{
public:
    explicit ScopedConvPlaintextCache(ConvPlaintextCache &cache)
        : previous_(active_conv_plaintext_cache)
    {
        active_conv_plaintext_cache = &cache;
    }

    ~ScopedConvPlaintextCache()
    {
        active_conv_plaintext_cache = previous_;
    }

private:
    ConvPlaintextCache *previous_ = nullptr;
};

bool parse_bool_env(const char *name)
{
    const char *raw = std::getenv(name);
    if (raw == nullptr)
    {
        return false;
    }
    string value(raw);
    transform(value.begin(), value.end(), value.begin(),
              [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value == "1" || value == "true" || value == "on" || value == "yes";
}

bool layer4_bsgs_enabled()
{
    const char *raw = std::getenv("RESNET18_LAYER4_BSGS");
    if (raw == nullptr)
    {
        return true;
    }
    string value(raw);
    transform(value.begin(), value.end(), value.begin(),
              [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value != "0" && value != "false" && value != "off" && value != "no";
}

bool layer3_bsgs_enabled()
{
    const char *raw = std::getenv("RESNET18_LAYER3_BSGS");
    if (raw == nullptr)
    {
        return true;
    }
    string value(raw);
    transform(value.begin(), value.end(), value.begin(),
              [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value != "0" && value != "false" && value != "off" && value != "no";
}

bool transition_bsgs_enabled()
{
    const char *raw = std::getenv("RESNET18_TRANSITION_BSGS");
    if (raw == nullptr)
    {
        return true;
    }
    string value(raw);
    transform(value.begin(), value.end(), value.begin(),
              [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value != "0" && value != "false" && value != "off" && value != "no";
}

bool layer2_transition_bsgs_enabled()
{
    return parse_bool_env("RESNET18_LAYER2_TRANSITION_BSGS");
}

bool fused_conv_bsgs_enabled()
{
    const char *raw = std::getenv("RESNET18_FUSED_CONV_BSGS");
    if (raw == nullptr)
    {
        return true;
    }
    string value(raw);
    transform(value.begin(), value.end(), value.begin(),
              [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value != "0" && value != "false" && value != "off" && value != "no";
}

size_t post_bootstrap_relu_input_level()
{
    static const size_t level = []() -> size_t {
        const char *raw = std::getenv("RESNET18_POST_BOOTSTRAP_LEVEL");
        if (raw == nullptr)
        {
            return static_cast<size_t>(16);
        }
        const string value(raw);
        size_t parsed = 0;
        const unsigned long long requested = stoull(value, &parsed, 10);
        if (parsed != value.size() || requested < 16 ||
            requested > kResNet18ComputePrimeCount)
        {
            throw invalid_argument(
                "RESNET18_POST_BOOTSTRAP_LEVEL must be in [16, 20]");
        }
        return static_cast<size_t>(requested);
    }();
    return level;
}

MockExecutionOptions read_mock_execution_options()
{
    MockExecutionOptions options;
    options.mock_relu = parse_bool_env("RESNET18_MOCK_RELU");
    options.mock_bootstrap = parse_bool_env("RESNET18_MOCK_BOOTSTRAP");
    return options;
}

string make_run_timestamp()
{
    const auto now = chrono::system_clock::now();
    const auto time = chrono::system_clock::to_time_t(now);
    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &time);
#else
    localtime_r(&time, &local_tm);
#endif

    ostringstream stamp;
    stamp << put_time(&local_tm, "%Y%m%d_%H%M%S");
    return stamp.str();
}

void write_value_list_preview(ostream &out, const vector<double> &values,
                              size_t limit = 128)
{
    const size_t count = min(limit, values.size());
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            out << ' ';
        }
        out << values.at(i);
    }
}

void write_complex_real_preview(ostream &out,
                                const vector<complex<double>> &values,
                                size_t limit = 128)
{
    const size_t count = min(limit, values.size());
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            out << ' ';
        }
        out << values.at(i).real();
    }
}

void write_complex_imag_preview(ostream &out,
                                const vector<complex<double>> &values,
                                size_t limit = 128)
{
    const size_t count = min(limit, values.size());
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            out << ' ';
        }
        out << values.at(i).imag();
    }
}

void dump_plain_cipher_preview(const string &label, const vector<double> &plain,
                               const vector<complex<double>> &cipher, ostream &out,
                               size_t limit = 128)
{
    out << "[value-dump] " << label << " plain_first" << limit << '=';
    write_value_list_preview(out, plain, limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_real_first" << limit << '=';
    write_complex_real_preview(out, cipher, limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_imag_first" << limit << '=';
    write_complex_imag_preview(out, cipher, limit);
    out << '\n';
}

void dump_selected_logits(const vector<double> &plain,
                          const vector<complex<double>> &cipher,
                          const vector<int> &labels, ostream &out)
{
    out << "[selected-logits]";
    set<int> printed;
    for (int label : labels)
    {
        if (label < 0 || label >= static_cast<int>(plain.size()) ||
            label >= static_cast<int>(cipher.size()) || printed.count(label) != 0)
        {
            continue;
        }
        printed.insert(label);
        const auto &cipher_value = cipher.at(static_cast<size_t>(label));
        const double plain_value = plain.at(static_cast<size_t>(label));
        out << " label=" << label
            << " plain=" << plain_value
            << " cipher_real=" << cipher_value.real()
            << " cipher_imag=" << cipher_value.imag()
            << " abs_error=" << abs(cipher_value.real() - plain_value);
    }
    out << '\n';
}

void dump_logit_decision_summary(const vector<double> &plain,
                                 const vector<complex<double>> &cipher,
                                 int true_label, int plain_pred,
                                 int encrypted_pred, ostream &out)
{
    auto print_one = [&](const string &role, int label) {
        if (label < 0 || label >= static_cast<int>(plain.size()) ||
            label >= static_cast<int>(cipher.size()))
        {
            out << "[logit-decision] role=" << role << " label=" << label
                << " unavailable\n";
            return;
        }
        const auto &cipher_value = cipher.at(static_cast<size_t>(label));
        const double plain_value = plain.at(static_cast<size_t>(label));
        out << "[logit-decision] role=" << role
            << " label=" << label
            << " plain=" << plain_value
            << " cipher_real=" << cipher_value.real()
            << " cipher_imag=" << cipher_value.imag()
            << " abs_error=" << abs(cipher_value.real() - plain_value)
            << '\n';
    };

    out << "[logit-decision] true_label=" << true_label
        << " plain_pred=" << plain_pred
        << " encrypted_pred=" << encrypted_pred
        << " prediction_match=" << (plain_pred == encrypted_pred ? 1 : 0)
        << '\n';
    print_one("true_label", true_label);
    print_one("plain_pred", plain_pred);
    print_one("encrypted_pred", encrypted_pred);
    if (plain_pred != encrypted_pred)
    {
        print_one("cipher_should_match_plain_pred", plain_pred);
    }
}

void log_plain_logits(const vector<double> &logits, ofstream &output)
{
    output << "plain logits:";
    for (double value : logits)
    {
        output << ' ' << value;
    }
    output << '\n';
}

void log_tensor_cipher_state(const string &label, const TensorCipher &tensor,
                             PoseidonRuntime &runtime)
{
    resnet18_progress_log() << "[cipher-state] " << label
                            << ": shape(h=" << tensor.h() << ", w=" << tensor.w()
                            << ", c=" << tensor.c()
                            << "), chain_index=" << cipher_chain_index(runtime, tensor.cipher())
                            << ", scale=" << tensor.cipher().scale() << endl;
}

void log_channel_group_cipher_state(const string &label, const ChannelCipherGroup &group,
                                    PoseidonRuntime &runtime)
{
    if (group.channels.empty())
    {
        resnet18_progress_log() << "[cipher-state] " << label << ": empty channel group" << endl;
        return;
    }

    const size_t first_chain = cipher_chain_index(runtime, group.channels.front());
    size_t min_chain = first_chain;
    size_t max_chain = first_chain;
    const double first_scale = group.channels.front().scale();
    double min_scale = first_scale;
    double max_scale = first_scale;

    for (const Ciphertext &cipher : group.channels)
    {
        const size_t chain = cipher_chain_index(runtime, cipher);
        min_chain = min(min_chain, chain);
        max_chain = max(max_chain, chain);
        const double scale = cipher.scale();
        min_scale = min(min_scale, scale);
        max_scale = max(max_scale, scale);
    }

    resnet18_progress_log() << "[cipher-state] " << label
                            << ": shape(h=" << group.h << ", w=" << group.w
                            << ", c=" << group.c << ", spatial=" << group.spatial_count
                            << "), channels=" << group.channels.size()
                            << ", chain_index(first/min/max)=" << first_chain << "/"
                            << min_chain << "/" << max_chain
                            << ", scale(first/min/max)=" << first_scale << "/" << min_scale
                            << "/" << max_scale << endl;
}

struct PackedChannelCipherGroup
{
    int h = 0;
    int w = 0;
    int c = 0;
    int channels_per_cipher = 2;
    size_t channel_stride = 0;
    size_t slot_count = 0;
    vector<Ciphertext> packs;
};

struct MultiplexedCipherGroup
{
    int h = 0;
    int w = 0;
    int c = 0;
    int k = 1;
    int pages_per_cipher = 2;
    size_t page_size = 0;
    size_t slot_count = 0;
    vector<Ciphertext> packs;
};

size_t ceil_div_size(size_t value, size_t divisor)
{
    return (value + divisor - 1) / divisor;
}

int multiplexed_channels_per_page(int k)
{
    if (k <= 0)
    {
        throw invalid_argument("multiplexed layout k must be positive");
    }
    return k * k;
}

size_t multiplexed_page_count(int channels, int k)
{
    return ceil_div_size(static_cast<size_t>(channels),
                         static_cast<size_t>(multiplexed_channels_per_page(k)));
}

size_t multiplexed_cipher_count(int channels, int k, int pages_per_cipher)
{
    if (pages_per_cipher <= 0)
    {
        throw invalid_argument("multiplexed layout pages_per_cipher must be positive");
    }
    return ceil_div_size(multiplexed_page_count(channels, k),
                         static_cast<size_t>(pages_per_cipher));
}

size_t multiplexed_slot_index(const MultiplexedCipherGroup &group, int channel, int row,
                              int col)
{
    if (channel < 0 || channel >= group.c || row < 0 || row >= group.h ||
        col < 0 || col >= group.w)
    {
        throw out_of_range("multiplexed slot index is out of range");
    }
    const int channels_per_page = multiplexed_channels_per_page(group.k);
    const int page = channel / channels_per_page;
    const int local_channel = channel % channels_per_page;
    const int local_page = page % group.pages_per_cipher;
    const int row_offset = local_channel / group.k;
    const int col_offset = local_channel % group.k;
    const int multiplexed_w = group.w * group.k;
    return static_cast<size_t>(local_page) * group.page_size +
           static_cast<size_t>(row * group.k + row_offset) *
               static_cast<size_t>(multiplexed_w) +
           static_cast<size_t>(col * group.k + col_offset);
}

size_t multiplexed_cipher_index_for_channel(const MultiplexedCipherGroup &group,
                                            int channel)
{
    if (channel < 0 || channel >= group.c)
    {
        throw out_of_range("multiplexed channel is out of range");
    }
    const int page = channel / multiplexed_channels_per_page(group.k);
    return static_cast<size_t>(page / group.pages_per_cipher);
}

MultiplexedCipherGroup make_multiplexed_shape(int h, int w, int c, int k,
                                              size_t slot_count)
{
    MultiplexedCipherGroup group;
    group.h = h;
    group.w = w;
    group.c = c;
    group.k = k;
    group.pages_per_cipher = 2;
    group.page_size = static_cast<size_t>(h * k) * static_cast<size_t>(w * k);
    group.slot_count = slot_count;
    if (group.page_size * static_cast<size_t>(group.pages_per_cipher) > slot_count)
    {
        throw invalid_argument("multiplexed layout does not fit two active pages per ciphertext");
    }
    group.packs.resize(multiplexed_cipher_count(c, k, group.pages_per_cipher));
    return group;
}

void log_multiplexed_group_cipher_state(const string &label,
                                        const MultiplexedCipherGroup &group,
                                        PoseidonRuntime &runtime)
{
    if (group.packs.empty())
    {
        resnet18_progress_log() << "[cipher-state] " << label
                                << ": empty multiplexed group" << endl;
        return;
    }

    const size_t first_chain = cipher_chain_index(runtime, group.packs.front());
    size_t min_chain = first_chain;
    size_t max_chain = first_chain;
    const double first_scale = group.packs.front().scale();
    double min_scale = first_scale;
    double max_scale = first_scale;
    for (const Ciphertext &cipher : group.packs)
    {
        const size_t chain = cipher_chain_index(runtime, cipher);
        min_chain = min(min_chain, chain);
        max_chain = max(max_chain, chain);
        const double scale = cipher.scale();
        min_scale = min(min_scale, scale);
        max_scale = max(max_scale, scale);
    }

    resnet18_progress_log() << "[cipher-state] " << label
                            << ": shape(h=" << group.h << ", w=" << group.w
                            << ", c=" << group.c << ", k=" << group.k
                            << "), page_size=" << group.page_size
                            << ", pages_per_cipher=" << group.pages_per_cipher
                            << ", ciphertexts=" << group.packs.size()
                            << ", active_slots_per_cipher<= "
                            << group.page_size *
                                   static_cast<size_t>(group.pages_per_cipher)
                            << ", chain_index(first/min/max)=" << first_chain << "/"
                            << min_chain << "/" << max_chain
                            << ", scale(first/min/max)=" << first_scale << "/" << min_scale
                            << "/" << max_scale << endl;
}

int next_rescale_prime_bits(const Ciphertext &cipher, PoseidonRuntime &runtime)
{
    auto context_data = runtime.context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id for next prime bit count");
    }
    const auto &modulus = context_data->coeff_modulus();
    if (modulus.empty())
    {
        throw runtime_error("ciphertext has no coefficient modulus primes");
    }
    return modulus.back().bit_count();
}

size_t drop_trailing_bootstrap_primes(Ciphertext &cipher, PoseidonRuntime &runtime)
{
    size_t dropped = 0;
    while (next_rescale_prime_bits(cipher, runtime) ==
           static_cast<int>(kResNet18BootstrapPrimeBits))
    {
        Ciphertext next;
        runtime.evaluator->drop_modulus_to_next(cipher, next);
        cipher = std::move(next);
        ++dropped;
    }
    return dropped;
}

size_t drop_trailing_bootstrap_primes(vector<Ciphertext> &ciphers,
                                      PoseidonRuntime &runtime)
{
    size_t max_dropped = 0;
    for (Ciphertext &cipher : ciphers)
    {
        max_dropped = max(max_dropped, drop_trailing_bootstrap_primes(cipher, runtime));
    }
    return max_dropped;
}

void log_cipher_vector_level_summary(const string &label, const vector<Ciphertext> &ciphers,
                                     PoseidonRuntime &runtime)
{
    if (ciphers.empty())
    {
        resnet18_progress_log() << "[cipher-state] " << label << ": empty" << endl;
        return;
    }

    const size_t first_chain = cipher_chain_index(runtime, ciphers.front());
    size_t min_chain = first_chain;
    size_t max_chain = first_chain;
    const int first_prime_bits = next_rescale_prime_bits(ciphers.front(), runtime);
    int min_prime_bits = first_prime_bits;
    int max_prime_bits = first_prime_bits;
    for (const Ciphertext &cipher : ciphers)
    {
        const size_t chain = cipher_chain_index(runtime, cipher);
        min_chain = min(min_chain, chain);
        max_chain = max(max_chain, chain);
        const int prime_bits = next_rescale_prime_bits(cipher, runtime);
        min_prime_bits = min(min_prime_bits, prime_bits);
        max_prime_bits = max(max_prime_bits, prime_bits);
    }

    resnet18_progress_log() << "[cipher-state] " << label
                            << ": count=" << ciphers.size()
                            << ", chain_index(first/min/max)=" << first_chain << "/"
                            << min_chain << "/" << max_chain
                            << ", next_prime_bits(first/min/max)=" << first_prime_bits
                            << "/" << min_prime_bits << "/" << max_prime_bits << endl;
}

void log_packed_channel_group_cipher_state(const string &label,
                                           const PackedChannelCipherGroup &group,
                                           PoseidonRuntime &runtime)
{
    if (group.packs.empty())
    {
        resnet18_progress_log() << "[cipher-state] " << label << ": empty packed group" << endl;
        return;
    }

    const size_t first_chain = cipher_chain_index(runtime, group.packs.front());
    size_t min_chain = first_chain;
    size_t max_chain = first_chain;
    const double first_scale = group.packs.front().scale();
    double min_scale = first_scale;
    double max_scale = first_scale;
    for (const Ciphertext &cipher : group.packs)
    {
        const size_t chain = cipher_chain_index(runtime, cipher);
        min_chain = min(min_chain, chain);
        max_chain = max(max_chain, chain);
        const double scale = cipher.scale();
        min_scale = min(min_scale, scale);
        max_scale = max(max_scale, scale);
    }

    resnet18_progress_log() << "[cipher-state] " << label
                            << ": shape(h=" << group.h << ", w=" << group.w
                            << ", c=" << group.c
                            << "), channels_per_cipher=" << group.channels_per_cipher
                            << ", channel_stride=" << group.channel_stride
                            << ", ciphertexts=" << group.packs.size()
                            << ", active_slots_per_cipher<= "
                            << group.channels_per_cipher * group.channel_stride
                            << ", chain_index(first/min/max)=" << first_chain << "/"
                            << min_chain << "/" << max_chain
                            << ", scale(first/min/max)=" << first_scale << "/" << min_scale
                            << "/" << max_scale << endl;
}

double local_multiply_plain_scale(const Ciphertext &input, const CKKSEncoder &encoder);

Ciphertext multiply_binary_mask_no_rescale(const Ciphertext &input, const vector<double> &mask,
                                           PoseidonRuntime &runtime)
{
    Plaintext plain;
    runtime.encoder.encode(mask, input.parms_id(),
                           local_multiply_plain_scale(input, runtime.encoder), plain);
    Ciphertext output;
    runtime.evaluator->multiply_plain(input, plain, output);
    runtime.evaluator->rescale_dynamic(output, output, input.scale());
    return output;
}

Ciphertext multiply_mask_by_constant_rescale(const Ciphertext &input,
                                             const vector<double> &binary_mask,
                                             double coeff, PoseidonRuntime &runtime)
{
    vector<double> fused(binary_mask.size(), 0.0);
    for (size_t i = 0; i < binary_mask.size(); ++i)
    {
        if (binary_mask[i] != 0.0)
        {
            fused[i] = binary_mask[i] * coeff;
        }
    }

    Plaintext plain;
    runtime.encoder.encode(fused, input.parms_id(),
                           local_multiply_plain_scale(input, runtime.encoder), plain);
    Ciphertext output;
    runtime.evaluator->multiply_plain(input, plain, output);
    runtime.evaluator->rescale_dynamic(output, output, input.scale());
    return output;
}

shared_ptr<const Plaintext> get_cached_conv_plaintext(
    const ConvPlaintextCacheKey &key, const vector<double> &plain_vector,
    parms_id_type parms_id, double scale, CKKSEncoder &encoder)
{
    if (active_conv_plaintext_cache != nullptr)
    {
        return active_conv_plaintext_cache->get_or_encode(
            key, plain_vector, parms_id, scale, encoder);
    }
    auto plain = make_shared<Plaintext>();
    encoder.encode(plain_vector, parms_id, scale, *plain);
    return plain;
}

Ciphertext multiply_preencoded_plain_rescale(
    const Ciphertext &input, const Plaintext &plain, PoseidonRuntime &runtime)
{
    Ciphertext output;
    runtime.evaluator->multiply_plain(input, plain, output);
    runtime.evaluator->rescale_dynamic(output, output, input.scale());
    return output;
}

int normalize_rotation_step(long long step, size_t slot_count)
{
    if (slot_count == 0)
    {
        throw invalid_argument("rotation slot count should not be zero");
    }
    long long normalized = step % static_cast<long long>(slot_count);
    if (normalized < 0)
    {
        normalized += static_cast<long long>(slot_count);
    }
    return static_cast<int>(normalized);
}

void rotate_with_direct_key(const Ciphertext &input, Ciphertext &output,
                            long long step, PoseidonRuntime &runtime)
{
    const int normalized_step = normalize_rotation_step(step, runtime.slot_count);
    if (normalized_step == 0)
    {
        output = input;
        return;
    }
    const auto galois_elt = runtime.context.crt_context()
                                ->galois_tool()
                                ->get_elt_from_step(normalized_step);
    if (!runtime.galois_keys.has_key(galois_elt))
    {
        throw logic_error("direct ResNet18 rotation key is missing for step " +
                          to_string(normalized_step));
    }
    runtime.evaluator->rotate(input, output, normalized_step, runtime.galois_keys);
}

bool local_coefficient_encodes_to_zero(const Ciphertext &input, double coeff,
                                       const CKKSEncoder &encoder);

Ciphertext multiply_constant_scalar_rescale(const Ciphertext &input, double coeff,
                                            PoseidonRuntime &runtime);

vector<double> packed_channel_mask(size_t slot_count, size_t channel_stride,
                                   int local_channel)
{
    vector<double> mask(slot_count, 0.0);
    const size_t offset = static_cast<size_t>(local_channel) * channel_stride;
    for (size_t i = 0; i < channel_stride; ++i)
    {
        mask[offset + i] = 1.0;
    }
    return mask;
}

MultiplexedCipherGroup pack_channel_group_as_multiplexed_k1(
    const ChannelCipherGroup &input, PoseidonRuntime &runtime)
{
    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;
    if (input.spatial_count != static_cast<size_t>(input.h * input.w))
    {
        throw invalid_argument("multiplexed k=1 pack expects dense channel ciphertexts");
    }

    MultiplexedCipherGroup output =
        make_multiplexed_shape(input.h, input.w, input.c, 1, input.slot_count);
    if (output.page_size != input.spatial_count)
    {
        throw invalid_argument("multiplexed k=1 pack page size mismatch");
    }

    const vector<double> first_page_mask =
        packed_channel_mask(input.slot_count, input.spatial_count, 0);
    vector<vector<double>> page_masks;
    page_masks.reserve(static_cast<size_t>(output.pages_per_cipher));
    for (int page = 0; page < output.pages_per_cipher; ++page)
    {
        page_masks.emplace_back(
            packed_channel_mask(input.slot_count, input.spatial_count, page));
    }
    resnet18_parallel_for(output.packs.size(), [&](size_t pack_index) {
        const size_t channel0 = pack_index * static_cast<size_t>(output.pages_per_cipher);
        Ciphertext packed = multiply_binary_mask_no_rescale(input.channels.at(channel0),
                                                            first_page_mask, runtime);
        for (int page = 1; page < output.pages_per_cipher; ++page)
        {
            const size_t channel = channel0 + static_cast<size_t>(page);
            if (channel >= input.channels.size())
            {
                continue;
            }
            Ciphertext masked = multiply_binary_mask_no_rescale(input.channels.at(channel),
                                                                first_page_mask, runtime);
            Ciphertext encrypted_zero;
            runtime.encryptor.encrypt_zero(masked.parms_id(), encrypted_zero);
            encrypted_zero.scale() = masked.scale();
            runtime.evaluator->add_dynamic(masked, encrypted_zero, masked, runtime.encoder);
            Ciphertext shifted;
            rotate_with_direct_key(
                masked, shifted,
                -static_cast<long long>(static_cast<size_t>(page) * input.spatial_count),
                runtime);
            Ciphertext target_page = multiply_binary_mask_no_rescale(
                shifted, page_masks.at(static_cast<size_t>(page)), runtime);
            runtime.evaluator->add_dynamic(packed, target_page, packed, runtime.encoder);
        }
        output.packs.at(pack_index) = std::move(packed);
    });
    return output;
}

vector<double> decrypt_multiplexed_group(const MultiplexedCipherGroup &group,
                                         PoseidonRuntime &runtime)
{
    vector<double> values(static_cast<size_t>(group.c) *
                              static_cast<size_t>(group.h * group.w),
                          0.0);
    vector<vector<complex<double>>> decoded(group.packs.size());
    for (size_t pack_index = 0; pack_index < group.packs.size(); ++pack_index)
    {
        Plaintext plain;
        runtime.decryptor.decrypt(group.packs.at(pack_index), plain);
        runtime.encoder.decode(plain, decoded.at(pack_index));
    }

    const size_t spatial_count = static_cast<size_t>(group.h * group.w);
    for (int channel = 0; channel < group.c; ++channel)
    {
        const size_t pack_index = multiplexed_cipher_index_for_channel(group, channel);
        for (int row = 0; row < group.h; ++row)
        {
            for (int col = 0; col < group.w; ++col)
            {
                const size_t slot = multiplexed_slot_index(group, channel, row, col);
                values[static_cast<size_t>(channel) * spatial_count +
                       static_cast<size_t>(row * group.w + col)] =
                    decoded.at(pack_index).at(slot).real();
            }
        }
    }
    return values;
}

vector<complex<double>> decrypt_multiplexed_group_complex(
    const MultiplexedCipherGroup &group, PoseidonRuntime &runtime)
{
    vector<complex<double>> values(static_cast<size_t>(group.c) *
                                       static_cast<size_t>(group.h * group.w),
                                   complex<double>(0.0, 0.0));
    vector<vector<complex<double>>> decoded(group.packs.size());
    for (size_t pack_index = 0; pack_index < group.packs.size(); ++pack_index)
    {
        Plaintext plain;
        runtime.decryptor.decrypt(group.packs.at(pack_index), plain);
        runtime.encoder.decode(plain, decoded.at(pack_index));
    }

    const size_t spatial_count = static_cast<size_t>(group.h * group.w);
    for (int channel = 0; channel < group.c; ++channel)
    {
        const size_t pack_index = multiplexed_cipher_index_for_channel(group, channel);
        for (int row = 0; row < group.h; ++row)
        {
            for (int col = 0; col < group.w; ++col)
            {
                const size_t slot = multiplexed_slot_index(group, channel, row, col);
                values[static_cast<size_t>(channel) * spatial_count +
                       static_cast<size_t>(row * group.w + col)] =
                    decoded.at(pack_index).at(slot);
            }
        }
    }
    return values;
}

vector<complex<double>> decrypt_channel_cipher_group_complex(
    const ChannelCipherGroup &group, PoseidonRuntime &runtime)
{
    vector<complex<double>> values(static_cast<size_t>(group.c) *
                                       static_cast<size_t>(group.h * group.w),
                                   complex<double>(0.0, 0.0));
    const size_t spatial_count = static_cast<size_t>(group.h * group.w);
    for (int channel = 0; channel < group.c; ++channel)
    {
        Plaintext plain;
        runtime.decryptor.decrypt(group.channels.at(static_cast<size_t>(channel)),
                                  plain);
        vector<complex<double>> decoded;
        runtime.encoder.decode(plain, decoded);
        for (size_t i = 0; i < spatial_count; ++i)
        {
            values[static_cast<size_t>(channel) * spatial_count + i] =
                decoded.at(i);
        }
    }
    return values;
}

double multiplexed_group_max_abs_error(const MultiplexedCipherGroup &group,
                                       const PlainTensor &plain,
                                       PoseidonRuntime &runtime,
                                       ostream *dump_output = nullptr,
                                       const string &dump_label = "")
{
    if (resnet18_execution::inference_only())
    {
        return -1.0;
    }
    vector<complex<double>> decrypted_complex =
        decrypt_multiplexed_group_complex(group, runtime);
    vector<double> decrypted(decrypted_complex.size(), 0.0);
    for (size_t i = 0; i < decrypted_complex.size(); ++i)
    {
        decrypted.at(i) = decrypted_complex.at(i).real();
    }
    if (decrypted.size() != plain.values.size())
    {
        throw invalid_argument("multiplexed group/plain tensor size mismatch");
    }
    if (dump_output != nullptr)
    {
        dump_plain_cipher_preview(dump_label, plain.values, decrypted_complex,
                                  *dump_output);
    }
    double max_abs_error = 0.0;
    for (size_t i = 0; i < decrypted.size(); ++i)
    {
        max_abs_error = max(max_abs_error, abs(decrypted[i] - plain.values.at(i)));
    }
    return max_abs_error;
}

double multiplexed_group_channel_max_abs_error(const MultiplexedCipherGroup &group,
                                               const PlainTensor &plain, int channel,
                                               PoseidonRuntime &runtime)
{
    if (resnet18_execution::inference_only())
    {
        return -1.0;
    }
    vector<double> decrypted = decrypt_multiplexed_group(group, runtime);
    const size_t spatial_count = static_cast<size_t>(group.h * group.w);
    if (decrypted.size() != plain.values.size() || channel < 0 || channel >= group.c)
    {
        throw invalid_argument("multiplexed channel/plain tensor size mismatch");
    }
    double max_abs_error = 0.0;
    const size_t base = static_cast<size_t>(channel) * spatial_count;
    for (size_t i = 0; i < spatial_count; ++i)
    {
        max_abs_error =
            max(max_abs_error, abs(decrypted.at(base + i) - plain.values.at(base + i)));
    }
    return max_abs_error;
}

double multiplexed_group_pair_max_abs_error(
    const vector<complex<double>> &before,
    const vector<complex<double>> &after)
{
    if (before.size() != after.size())
    {
        throw invalid_argument("multiplexed bootstrap before/after size mismatch");
    }
    double max_abs_error = 0.0;
    for (size_t i = 0; i < before.size(); ++i)
    {
        max_abs_error = max(max_abs_error, abs(after.at(i).real() - before.at(i).real()));
    }
    return max_abs_error;
}

MultiplexedCipherGroup encrypt_multiplexed_group_values(
    const MultiplexedCipherGroup &shape, const vector<double> &values,
    PoseidonRuntime &runtime)
{
    const size_t expected_size =
        static_cast<size_t>(shape.c) * static_cast<size_t>(shape.h * shape.w);
    if (values.size() != expected_size)
    {
        throw invalid_argument("mock multiplexed encrypt value count mismatch");
    }

    MultiplexedCipherGroup output = shape;
    output.packs.resize(shape.packs.size());
    const size_t spatial_count = static_cast<size_t>(shape.h * shape.w);
    for (size_t pack_index = 0; pack_index < output.packs.size(); ++pack_index)
    {
        vector<complex<double>> slots(shape.slot_count, {0.0, 0.0});
        for (int channel = 0; channel < shape.c; ++channel)
        {
            if (multiplexed_cipher_index_for_channel(shape, channel) != pack_index)
            {
                continue;
            }
            const size_t channel_base = static_cast<size_t>(channel) * spatial_count;
            for (int row = 0; row < shape.h; ++row)
            {
                for (int col = 0; col < shape.w; ++col)
                {
                    const size_t value_index =
                        channel_base + static_cast<size_t>(row * shape.w + col);
                    slots[multiplexed_slot_index(shape, channel, row, col)] =
                        {values.at(value_index), 0.0};
                }
            }
        }

        Plaintext plain;
        runtime.encoder.encode(slots, runtime.scale, plain);
        runtime.encryptor.encrypt(plain, output.packs.at(pack_index));
    }
    return output;
}

vector<int> multiplexed_average_pool2d_stride2_rotation_steps(
    const MultiplexedCipherGroup &input, int out_h, int out_w, int out_k)
{
    MultiplexedCipherGroup output =
        make_multiplexed_shape(out_h, out_w, input.c, out_k, input.slot_count);
    if (out_k != input.k * 2 || output.page_size != input.page_size)
    {
        throw invalid_argument("multiplexed avgpool expects k_out = 2*k_in with fixed page size");
    }

    set<int> steps;
    for (int channel = 0; channel < input.c; ++channel)
    {
        for (int kh = 0; kh < 3; ++kh)
        {
            for (int kw = 0; kw < 3; ++kw)
            {
                bool found_valid_position = false;
                for (int oh = 0; oh < out_h && !found_valid_position; ++oh)
                {
                    for (int ow = 0; ow < out_w && !found_valid_position; ++ow)
                    {
                        const int ih = oh * 2 + kh - 1;
                        const int iw = ow * 2 + kw - 1;
                        if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                        {
                            continue;
                        }
                        const long long source_slot = static_cast<long long>(
                            multiplexed_slot_index(input, channel, ih, iw));
                        const long long target_slot = static_cast<long long>(
                            multiplexed_slot_index(output, channel, oh, ow));
                        const long long step = source_slot - target_slot;
                        if (step != 0)
                        {
                            steps.insert(static_cast<int>(step));
                        }
                        found_valid_position = true;
                    }
                }
            }
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

vector<double> multiplexed_conv_output_mask(const MultiplexedCipherGroup &input,
                                            const MultiplexedCipherGroup &output,
                                            int output_channel, int stride, int fh, int fw,
                                            int kh, int kw)
{
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    vector<double> mask(output.slot_count, 0.0);
    for (int oh = 0; oh < output.h; ++oh)
    {
        for (int ow = 0; ow < output.w; ++ow)
        {
            const int ih = oh * stride + kh - pad_h;
            const int iw = ow * stride + kw - pad_w;
            if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
            {
                continue;
            }
            mask[multiplexed_slot_index(output, output_channel, oh, ow)] = 1.0;
        }
    }
    return mask;
}

int multiplexed_conv_rotation_step(const MultiplexedCipherGroup &input,
                                   const MultiplexedCipherGroup &output,
                                   int input_channel, int output_channel, int stride,
                                   int fh, int fw, int kh, int kw)
{
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    for (int oh = 0; oh < output.h; ++oh)
    {
        for (int ow = 0; ow < output.w; ++ow)
        {
            const int ih = oh * stride + kh - pad_h;
            const int iw = ow * stride + kw - pad_w;
            if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
            {
                continue;
            }
            const long long source_slot = static_cast<long long>(
                multiplexed_slot_index(input, input_channel, ih, iw));
            const long long target_slot = static_cast<long long>(
                multiplexed_slot_index(output, output_channel, oh, ow));
            return static_cast<int>(source_slot - target_slot);
        }
    }
    throw invalid_argument("multiplexed conv rotation step has no valid spatial position");
}

vector<int> multiplexed_conv2d_rotation_steps(const MultiplexedCipherGroup &input,
                                              int out_channels, int stride, int fh, int fw)
{
    if (stride != 1 && stride != 2)
    {
        throw invalid_argument("multiplexed conv expects stride 1 or 2");
    }
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("multiplexed conv expects odd kernel sizes");
    }
    const int out_k = (stride == 1) ? input.k : input.k * 2;
    MultiplexedCipherGroup output =
        make_multiplexed_shape(input.h / stride, input.w / stride, out_channels, out_k,
                               input.slot_count);
    set<int> steps;
    for (int output_channel = 0; output_channel < out_channels; ++output_channel)
    {
        for (int input_channel = 0; input_channel < input.c; ++input_channel)
        {
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    const int step = multiplexed_conv_rotation_step(
                        input, output, input_channel, output_channel, stride, fh, fw, kh, kw);
                    if (step != 0)
                    {
                        steps.insert(step);
                    }
                }
            }
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

vector<int> multiplexed_dense_conv2d_rotation_steps(const MultiplexedCipherGroup &input,
                                                    int out_channels, int fh, int fw)
{
    return multiplexed_conv2d_rotation_steps(input, out_channels, 1, fh, fw);
}

int exact_log2_power_of_two(int value)
{
    if (value <= 0 || (value & (value - 1)) != 0)
    {
        return -1;
    }
    int log_value = 0;
    while (value > 1)
    {
        value >>= 1;
        ++log_value;
    }
    return log_value;
}

int pow2_int(int exponent)
{
    return 1 << exponent;
}

int multiplexed_local_channel_index(const MultiplexedCipherGroup &group, int channel)
{
    const int channels_per_page = multiplexed_channels_per_page(group.k);
    const int page = channel / channels_per_page;
    const int local_page = page % group.pages_per_cipher;
    return local_page * channels_per_page + channel % channels_per_page;
}

vector<int> multiplexed_channels_for_pack(const MultiplexedCipherGroup &group,
                                          size_t pack_index)
{
    vector<int> channels;
    for (int channel = 0; channel < group.c; ++channel)
    {
        if (multiplexed_cipher_index_for_channel(group, channel) == pack_index)
        {
            channels.push_back(channel);
        }
    }
    return channels;
}

long long multiplexed_spatial_kernel_rotation_step(const MultiplexedCipherGroup &input,
                                                   int fh, int fw, int kh, int kw)
{
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    return static_cast<long long>(input.k) * static_cast<long long>(input.k) *
               static_cast<long long>(input.w) * static_cast<long long>(kh - pad_h) +
           static_cast<long long>(input.k) * static_cast<long long>(kw - pad_w);
}

long long multiplexed_output_channel_select_rotation_step(
    const MultiplexedCipherGroup &output, int output_channel)
{
    const int local_channel = multiplexed_local_channel_index(output, output_channel);
    const int channels_per_page = multiplexed_channels_per_page(output.k);
    const int local_page = local_channel / channels_per_page;
    const int channel_in_page = local_channel % channels_per_page;
    const int row_offset = channel_in_page / output.k;
    const int col_offset = channel_in_page % output.k;
    return -static_cast<long long>(local_page) * static_cast<long long>(output.page_size) -
           static_cast<long long>(row_offset) *
               static_cast<long long>(output.w * output.k) -
           static_cast<long long>(col_offset);
}

Ciphertext rotate_multiplexed_local_channel_sum_to_base(const Ciphertext &input_cipher,
                                                        const MultiplexedCipherGroup &input,
                                                        PoseidonRuntime &runtime)
{
    const int log_k = exact_log2_power_of_two(input.k);
    if (log_k < 0)
    {
        throw invalid_argument("multiplexed compact conv expects k to be a power of two");
    }

    Ciphertext sum = input_cipher;
    for (int x = 0; x < log_k; ++x)
    {
        Ciphertext rotated;
        rotate_with_direct_key(sum, rotated, pow2_int(x), runtime);
        runtime.evaluator->add(sum, rotated, sum);
    }
    for (int x = 0; x < log_k; ++x)
    {
        Ciphertext rotated;
        rotate_with_direct_key(
            sum, rotated,
            static_cast<long long>(pow2_int(x)) * static_cast<long long>(input.k) *
                static_cast<long long>(input.w),
            runtime);
        runtime.evaluator->add(sum, rotated, sum);
    }
    for (int page = 1; page < input.pages_per_cipher; ++page)
    {
        Ciphertext rotated;
        rotate_with_direct_key(
            sum, rotated,
            static_cast<long long>(page) * static_cast<long long>(input.page_size),
            runtime);
        runtime.evaluator->add(sum, rotated, sum);
    }
    return sum;
}

struct FusedConvBsgsTerm
{
    uint16_t output_channel = 0;
    uint8_t kh = 0;
    uint8_t kw = 0;
    double coefficient = 0.0;
};

struct FusedConvBsgsMatrixPlan
{
    MatrixPlain matrix;
    size_t input_pack_index = 0;
    size_t output_pack_index = 0;
    size_t diagonal_count = 0;
    size_t baby_rotation_count = 0;
    size_t giant_rotation_count = 0;
    size_t encoded_bytes = 0;
};

struct FusedConvBsgsPlan
{
    parms_id_type parms_id{};
    MultiplexedCipherGroup output_shape;
    vector<shared_ptr<FusedConvBsgsMatrixPlan>> matrices;
    size_t diagonal_count = 0;
    size_t rotation_count = 0;
    size_t encoded_bytes = 0;
    size_t prepare_thread_count = 0;
    int min_baby_step = 0;
    int max_baby_step = 0;
};

struct FusedConvBsgsCacheEntry
{
    shared_ptr<FusedConvBsgsPlan> plan;
    list<uintptr_t>::iterator lru_position;
};

size_t fused_conv_bsgs_cache_limit_bytes()
{
    static const size_t limit = []() -> size_t {
        const char *raw = std::getenv("RESNET18_FUSED_BSGS_CACHE_MB");
        if (raw == nullptr)
        {
            return static_cast<size_t>(0);
        }
        const string value(raw);
        size_t parsed = 0;
        const unsigned long long megabytes = stoull(value, &parsed, 10);
        if (parsed != value.size() ||
            megabytes > numeric_limits<size_t>::max() / (1024ULL * 1024ULL))
        {
            throw invalid_argument("invalid RESNET18_FUSED_BSGS_CACHE_MB");
        }
        return static_cast<size_t>(megabytes * 1024ULL * 1024ULL);
    }();
    return limit;
}

size_t fused_conv_bsgs_prepare_thread_count(size_t work_items)
{
    const char *raw = std::getenv("RESNET18_PREP_THREADS");
    if (raw == nullptr)
    {
        return resnet18_parallel_thread_count(work_items);
    }
    try
    {
        const string value(raw);
        size_t parsed = 0;
        const unsigned long long requested = stoull(value, &parsed, 10);
        if (parsed != value.size() || requested == 0)
        {
            throw invalid_argument("invalid thread count");
        }
        return max<size_t>(1, min<size_t>(static_cast<size_t>(requested),
                                          max<size_t>(1, work_items)));
    }
    catch (const exception &)
    {
        throw invalid_argument("invalid RESNET18_PREP_THREADS");
    }
}

mutex fused_conv_bsgs_plan_mutex;
list<uintptr_t> fused_conv_bsgs_plan_lru;
unordered_map<uintptr_t, FusedConvBsgsCacheEntry> fused_conv_bsgs_plans;
size_t fused_conv_bsgs_cache_resident_bytes = 0;

set<int> multiplexed_fused_conv_diagonal_steps_for_pack_pair(
    const MultiplexedCipherGroup &input, const MultiplexedCipherGroup &output,
    size_t input_pack_index, size_t output_pack_index, int fh, int fw)
{
    set<int> diagonal_steps;
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    const vector<int> input_channels =
        multiplexed_channels_for_pack(input, input_pack_index);
    const vector<int> output_channels =
        multiplexed_channels_for_pack(output, output_pack_index);
    for (int output_channel : output_channels)
    {
        const long long target_base = static_cast<long long>(
            multiplexed_slot_index(output, output_channel, 0, 0));
        for (int input_channel : input_channels)
        {
            const long long source_base = static_cast<long long>(
                multiplexed_slot_index(input, input_channel, 0, 0));
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    const long long spatial_step =
                        static_cast<long long>(input.k) * input.k * input.w *
                            (kh - pad_h) +
                        static_cast<long long>(input.k) * (kw - pad_w);
                    diagonal_steps.insert(normalize_rotation_step(
                        source_base - target_base + spatial_step,
                        input.slot_count));
                }
            }
        }
    }
    return diagonal_steps;
}

int fused_conv_best_bsgs_baby_step(const set<int> &diagonal_steps,
                                   size_t slot_count)
{
    if (diagonal_steps.empty() || slot_count == 0 ||
        (slot_count & (slot_count - 1)) != 0)
    {
        throw invalid_argument("fused convolution BSGS diagonal set is invalid");
    }
    size_t best_rotation_count = numeric_limits<size_t>::max();
    int best_baby_step = 1;
    for (size_t candidate = 1; candidate <= slot_count; candidate <<= 1)
    {
        set<int> baby_rotations;
        set<int> giant_rotations;
        for (const int step : diagonal_steps)
        {
            const int baby = step & (static_cast<int>(candidate) - 1);
            const int giant = step - baby;
            if (baby != 0)
            {
                baby_rotations.insert(baby);
            }
            if (giant != 0)
            {
                giant_rotations.insert(giant);
            }
        }
        const size_t rotation_count =
            baby_rotations.size() + giant_rotations.size();
        if (rotation_count < best_rotation_count)
        {
            best_rotation_count = rotation_count;
            best_baby_step = static_cast<int>(candidate);
        }
    }
    return best_baby_step;
}

MultiplexedCipherGroup collect_fused_conv_bsgs_rotation_steps(
    set<int> &rotations, const MultiplexedCipherGroup &input,
    int out_channels, int stride, int fh, int fw)
{
    const int out_k = stride == 1 ? input.k : input.k * stride;
    MultiplexedCipherGroup output = make_multiplexed_shape(
        input.h / stride, input.w / stride, out_channels, out_k,
        input.slot_count);
    for (size_t output_pack_index = 0;
         output_pack_index < output.packs.size(); ++output_pack_index)
    {
        for (size_t input_pack_index = 0;
             input_pack_index < input.packs.size(); ++input_pack_index)
        {
            const set<int> diagonal_steps =
                multiplexed_fused_conv_diagonal_steps_for_pack_pair(
                    input, output, input_pack_index, output_pack_index, fh, fw);
            const int baby_step = fused_conv_best_bsgs_baby_step(
                diagonal_steps, input.slot_count);
            for (const int step : diagonal_steps)
            {
                const int baby = step & (baby_step - 1);
                const int giant = step - baby;
                if (baby != 0)
                {
                    rotations.insert(baby);
                }
                if (giant != 0)
                {
                    rotations.insert(giant);
                }
            }
        }
    }
    return output;
}

shared_ptr<FusedConvBsgsPlan> prepare_fused_conv_bsgs_plan(
    const MultiplexedCipherGroup &input, int out_channels, int stride,
    int fh, int fw,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon,
    PoseidonRuntime &runtime)
{
    const uintptr_t layer_identity = reinterpret_cast<uintptr_t>(weights.data());
    {
        lock_guard<mutex> lock(fused_conv_bsgs_plan_mutex);
        const auto found = fused_conv_bsgs_plans.find(layer_identity);
        if (found != fused_conv_bsgs_plans.end())
        {
            if (found->second.plan->parms_id != input.packs.front().parms_id())
            {
                throw runtime_error("fused convolution BSGS plaintext plan level changed");
            }
            fused_conv_bsgs_plan_lru.splice(
                fused_conv_bsgs_plan_lru.begin(), fused_conv_bsgs_plan_lru,
                found->second.lru_position);
            return found->second.plan;
        }
    }

    const auto prepare_start = chrono::steady_clock::now();
    const int out_k = stride == 1 ? input.k : input.k * stride;
    MultiplexedCipherGroup output = make_multiplexed_shape(
        input.h / stride, input.w / stride, out_channels, out_k,
        input.slot_count);
    auto plan = make_shared<FusedConvBsgsPlan>();
    plan->parms_id = input.packs.front().parms_id();
    plan->output_shape = output;
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    const double plain_scale =
        local_multiply_plain_scale(input.packs.front(), runtime.encoder);

    for (size_t output_pack_index = 0;
         output_pack_index < output.packs.size(); ++output_pack_index)
    {
        const vector<int> output_channels =
            multiplexed_channels_for_pack(output, output_pack_index);
        for (size_t input_pack_index = 0;
             input_pack_index < input.packs.size(); ++input_pack_index)
        {
            const vector<int> input_channels =
                multiplexed_channels_for_pack(input, input_pack_index);
            map<int, vector<FusedConvBsgsTerm>> sparse_diagonals;
            for (int output_channel : output_channels)
            {
                const double folded_bn_scale =
                    constant_weight.at(output_channel) /
                    sqrt(running_var.at(output_channel) + epsilon);
                const long long target_base = static_cast<long long>(
                    multiplexed_slot_index(output, output_channel, 0, 0));
                for (int input_channel : input_channels)
                {
                    const long long source_base = static_cast<long long>(
                        multiplexed_slot_index(input, input_channel, 0, 0));
                    for (int kh = 0; kh < fh; ++kh)
                    {
                        for (int kw = 0; kw < fw; ++kw)
                        {
                            const size_t weight_index = static_cast<size_t>(
                                fh * fw * input.c * output_channel +
                                fh * fw * input_channel + fw * kh + kw);
                            const double coefficient =
                                weights.at(weight_index) * folded_bn_scale;
                            if (coefficient == 0.0)
                            {
                                continue;
                            }
                            const long long spatial_step =
                                static_cast<long long>(input.k) * input.k * input.w *
                                    (kh - pad_h) +
                                static_cast<long long>(input.k) * (kw - pad_w);
                            const int step = normalize_rotation_step(
                                source_base - target_base + spatial_step,
                                input.slot_count);
                            sparse_diagonals[step].push_back(
                                {static_cast<uint16_t>(output_channel),
                                 static_cast<uint8_t>(kh),
                                 static_cast<uint8_t>(kw), coefficient});
                        }
                    }
                }
            }

            vector<pair<int, vector<FusedConvBsgsTerm>>> diagonal_terms;
            diagonal_terms.reserve(sparse_diagonals.size());
            set<int> diagonal_steps;
            for (auto &entry : sparse_diagonals)
            {
                diagonal_steps.insert(entry.first);
                diagonal_terms.emplace_back(entry.first, std::move(entry.second));
            }
            sparse_diagonals.clear();
            if (diagonal_steps.empty())
            {
                continue;
            }
            // Keep n1 structural rather than weight-dependent. Evaluation keys are
            // planned before model weights are loaded, so exact-zero learned weights
            // must not select a different baby/giant decomposition at run time.
            const set<int> structural_diagonal_steps =
                multiplexed_fused_conv_diagonal_steps_for_pack_pair(
                    input, output, input_pack_index, output_pack_index, fh, fw);
            const int baby_step = fused_conv_best_bsgs_baby_step(
                structural_diagonal_steps, input.slot_count);

            vector<Plaintext> encoded_diagonals(diagonal_terms.size());
            const size_t prepare_threads =
                fused_conv_bsgs_prepare_thread_count(diagonal_terms.size());
            plan->prepare_thread_count =
                max(plan->prepare_thread_count, prepare_threads);
            resnet18_parallel_for_with_thread_count(
                diagonal_terms.size(), prepare_threads, [&](size_t diagonal_index) {
                const int step = diagonal_terms.at(diagonal_index).first;
                const int giant = step - (step & (baby_step - 1));
                vector<double> diagonal(input.slot_count, 0.0);
                for (const FusedConvBsgsTerm &term :
                     diagonal_terms.at(diagonal_index).second)
                {
                    for (int oh = 0; oh < output.h; ++oh)
                    {
                        const int ih = oh * stride +
                                       static_cast<int>(term.kh) - pad_h;
                        if (ih < 0 || ih >= input.h)
                        {
                            continue;
                        }
                        for (int ow = 0; ow < output.w; ++ow)
                        {
                            const int iw = ow * stride +
                                           static_cast<int>(term.kw) - pad_w;
                            if (iw < 0 || iw >= input.w)
                            {
                                continue;
                            }
                            diagonal.at(multiplexed_slot_index(
                                output, term.output_channel, oh, ow)) +=
                                term.coefficient;
                        }
                    }
                }

                const int coefficient_rotation = normalize_rotation_step(
                    -static_cast<long long>(giant), input.slot_count);
                vector<double> encoded_values(input.slot_count, 0.0);
                for (size_t slot = 0; slot < input.slot_count; ++slot)
                {
                    encoded_values.at(slot) = diagonal.at(
                        (slot + static_cast<size_t>(coefficient_rotation)) %
                        input.slot_count);
                }
                runtime.encoder.encode(
                    encoded_values, input.packs.front().parms_id(), plain_scale,
                    encoded_diagonals.at(diagonal_index));
            });

            auto matrix_plan = make_shared<FusedConvBsgsMatrixPlan>();
            matrix_plan->input_pack_index = input_pack_index;
            matrix_plan->output_pack_index = output_pack_index;
            matrix_plan->matrix.log_slots = static_cast<uint32_t>(
                exact_log2_power_of_two(static_cast<int>(input.slot_count)));
            matrix_plan->matrix.n1 = baby_step;
            matrix_plan->matrix.level = input.packs.front().level();
            matrix_plan->matrix.scale = plain_scale;
            matrix_plan->diagonal_count = diagonal_terms.size();
            set<int> baby_rotations;
            set<int> giant_rotations;
            for (size_t index = 0; index < diagonal_terms.size(); ++index)
            {
                const int step = diagonal_terms.at(index).first;
                const int baby = step & (baby_step - 1);
                const int giant = step - baby;
                if (baby != 0)
                {
                    baby_rotations.insert(baby);
                }
                if (giant != 0)
                {
                    giant_rotations.insert(giant);
                }
                matrix_plan->encoded_bytes +=
                    encoded_diagonals.at(index).capacity() * sizeof(uint64_t);
                matrix_plan->matrix.plain_vec.emplace(
                    step, std::move(encoded_diagonals.at(index)));
            }
            matrix_plan->baby_rotation_count = baby_rotations.size();
            matrix_plan->giant_rotation_count = giant_rotations.size();
            plan->diagonal_count += matrix_plan->diagonal_count;
            plan->rotation_count += matrix_plan->baby_rotation_count +
                                    matrix_plan->giant_rotation_count;
            plan->encoded_bytes += matrix_plan->encoded_bytes;
            if (plan->min_baby_step == 0)
            {
                plan->min_baby_step = baby_step;
            }
            else
            {
                plan->min_baby_step = min(plan->min_baby_step, baby_step);
            }
            plan->max_baby_step = max(plan->max_baby_step, baby_step);
            plan->matrices.push_back(std::move(matrix_plan));
        }
    }

    const size_t cache_limit = fused_conv_bsgs_cache_limit_bytes();
    bool retained = false;
    size_t cache_resident_after = 0;
    shared_ptr<FusedConvBsgsPlan> returned_plan = plan;
    {
        lock_guard<mutex> lock(fused_conv_bsgs_plan_mutex);
        const auto raced = fused_conv_bsgs_plans.find(layer_identity);
        if (raced != fused_conv_bsgs_plans.end())
        {
            fused_conv_bsgs_plan_lru.splice(
                fused_conv_bsgs_plan_lru.begin(), fused_conv_bsgs_plan_lru,
                raced->second.lru_position);
            returned_plan = raced->second.plan;
            retained = true;
        }
        else if (cache_limit != 0 && plan->encoded_bytes <= cache_limit)
        {
            while (!fused_conv_bsgs_plan_lru.empty() &&
                   fused_conv_bsgs_cache_resident_bytes >
                       cache_limit - plan->encoded_bytes)
            {
                const uintptr_t old_key = fused_conv_bsgs_plan_lru.back();
                const auto old = fused_conv_bsgs_plans.find(old_key);
                fused_conv_bsgs_cache_resident_bytes -=
                    old->second.plan->encoded_bytes;
                fused_conv_bsgs_plans.erase(old);
                fused_conv_bsgs_plan_lru.pop_back();
            }
            fused_conv_bsgs_plan_lru.push_front(layer_identity);
            fused_conv_bsgs_plans.emplace(
                layer_identity,
                FusedConvBsgsCacheEntry{plan,
                                        fused_conv_bsgs_plan_lru.begin()});
            fused_conv_bsgs_cache_resident_bytes += plan->encoded_bytes;
            retained = true;
        }
        cache_resident_after = fused_conv_bsgs_cache_resident_bytes;
    }

    const auto prepare_ms = chrono::duration_cast<chrono::milliseconds>(
        chrono::steady_clock::now() - prepare_start).count();
    resnet18_progress_log()
        << "fused convolution BSGS plaintext plan: input_shape="
        << input.c << "x" << input.h << "x" << input.w
        << ", output_shape=" << output.c << "x" << output.h << "x" << output.w
        << ", kernel=" << fh << "x" << fw << ", stride=" << stride
        << ", matrices=" << plan->matrices.size()
        << ", diagonals=" << plan->diagonal_count
        << ", n1_min_max=" << plan->min_baby_step << "/"
        << plan->max_baby_step << ", rotations<=" << plan->rotation_count
        << ", encoded_bytes=" << plan->encoded_bytes
        << ", prepare_threads=" << plan->prepare_thread_count
        << ", cache_retained=" << (retained ? 1 : 0)
        << ", cache_resident_bytes=" << cache_resident_after
        << ", cache_limit_bytes=" << cache_limit
        << ", prepare_time=" << prepare_ms << " ms" << endl;
    return returned_plan;
}

Ciphertext evaluate_fused_conv_bsgs_matrix_with_shared_babies(
    const Ciphertext &input, const MatrixPlain &matrix,
    const vector<Ciphertext> &baby_rotations, PoseidonRuntime &runtime)
{
    const auto [index, unused_giant_steps, unused_baby_steps] =
        bsgs_index(matrix.plain_vec, 1 << matrix.log_slots, matrix.n1);
    Ciphertext result;
    for (const auto &giant_group : index)
    {
        Ciphertext group_sum;
        for (const int baby_step : giant_group.second)
        {
            const Ciphertext &baby = baby_step == 0
                                         ? input
                                         : baby_rotations.at(
                                               static_cast<size_t>(baby_step));
            runtime.evaluator->multiply_plain_accumulate(
                baby, matrix.plain_vec.at(baby_step + giant_group.first),
                group_sum);
        }

        if (giant_group.first != 0)
        {
            Ciphertext rotated_group;
            rotate_with_direct_key(group_sum, rotated_group,
                                   giant_group.first, runtime);
            if (!result.is_valid())
            {
                result = std::move(rotated_group);
            }
            else
            {
                runtime.evaluator->add(result, rotated_group, result);
            }
        }
        else if (!result.is_valid())
        {
            result = std::move(group_sum);
        }
        else
        {
            runtime.evaluator->add(result, group_sum, result);
        }
    }
    if (!result.is_valid())
    {
        throw runtime_error("shared-baby BSGS matrix produced no terms");
    }
    Ciphertext output;
    runtime.evaluator->rescale_dynamic(result, output, input.scale());
    return output;
}

MultiplexedCipherGroup multiplexed_fused_conv2d_bsgs(
    const MultiplexedCipherGroup &input, int out_channels, int stride,
    int fh, int fw,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon,
    PoseidonRuntime &runtime)
{
    shared_ptr<FusedConvBsgsPlan> plan = prepare_fused_conv_bsgs_plan(
        input, out_channels, stride, fh, fw, weights, running_var,
        constant_weight, epsilon, runtime);
    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;
    MultiplexedCipherGroup output = plan->output_shape;
    vector<Ciphertext> output_pack_sums(output.packs.size());
    size_t shared_baby_rotation_count = 0;
    size_t giant_rotation_count = 0;
    for (size_t input_pack_index = 0;
         input_pack_index < input.packs.size(); ++input_pack_index)
    {
        map<int, vector<shared_ptr<FusedConvBsgsMatrixPlan>>> matrices_by_n1;
        for (const auto &matrix_plan : plan->matrices)
        {
            if (matrix_plan->input_pack_index == input_pack_index)
            {
                matrices_by_n1[static_cast<int>(matrix_plan->matrix.n1)]
                    .push_back(matrix_plan);
            }
        }
        for (const auto &n1_group : matrices_by_n1)
        {
            const int n1 = n1_group.first;
            set<int> required_baby_steps;
            for (const auto &matrix_plan : n1_group.second)
            {
                for (const auto &diagonal : matrix_plan->matrix.plain_vec)
                {
                    const int baby_step = diagonal.first & (n1 - 1);
                    if (baby_step != 0)
                    {
                        required_baby_steps.insert(baby_step);
                    }
                }
                giant_rotation_count += matrix_plan->giant_rotation_count;
            }
            const vector<int> baby_steps(required_baby_steps.begin(),
                                         required_baby_steps.end());
            vector<Ciphertext> baby_rotations(static_cast<size_t>(n1));
            resnet18_parallel_for(baby_steps.size(), [&](size_t baby_index) {
                const int baby_step = baby_steps.at(baby_index);
                rotate_with_direct_key(
                    input.packs.at(input_pack_index),
                    baby_rotations.at(static_cast<size_t>(baby_step)),
                    baby_step, runtime);
            });
            shared_baby_rotation_count += baby_steps.size();

            vector<Ciphertext> contributions(n1_group.second.size());
            resnet18_parallel_for(n1_group.second.size(), [&](size_t matrix_index) {
                contributions.at(matrix_index) =
                    evaluate_fused_conv_bsgs_matrix_with_shared_babies(
                        input.packs.at(input_pack_index),
                        n1_group.second.at(matrix_index)->matrix,
                        baby_rotations, runtime);
            });
            for (size_t matrix_index = 0;
                 matrix_index < n1_group.second.size(); ++matrix_index)
            {
                const size_t output_pack_index =
                    n1_group.second.at(matrix_index)->output_pack_index;
                if (!output_pack_sums.at(output_pack_index).is_valid())
                {
                    output_pack_sums.at(output_pack_index) =
                        std::move(contributions.at(matrix_index));
                }
                else
                {
                    runtime.evaluator->add(
                        output_pack_sums.at(output_pack_index),
                        contributions.at(matrix_index),
                        output_pack_sums.at(output_pack_index));
                }
            }
        }
    }
    for (size_t output_pack_index = 0;
         output_pack_index < output.packs.size(); ++output_pack_index)
    {
        if (!output_pack_sums.at(output_pack_index).is_valid())
        {
            throw runtime_error("fused convolution BSGS output pack has no terms");
        }
        output.packs.at(output_pack_index) =
            std::move(output_pack_sums.at(output_pack_index));
    }
    resnet18_progress_log()
        << "fused convolution BSGS evaluation: matrices="
        << plan->matrices.size() << ", diagonals=" << plan->diagonal_count
        << ", rotations_before_sharing<=" << plan->rotation_count
        << ", shared_baby_rotations=" << shared_baby_rotation_count
        << ", giant_rotations=" << giant_rotation_count
        << ", rotations_after_sharing<="
        << shared_baby_rotation_count + giant_rotation_count
        << ", rescale_operations=" << plan->matrices.size()
        << ", multiplicative_depth=1" << endl;
    log_multiplexed_group_cipher_state(
        "fused convolution BSGS output", output, runtime);
    return output;
}

bool should_use_fused_conv_bsgs(const MultiplexedCipherGroup &input,
                                int out_channels, int stride, int fh, int fw)
{
    if (!fused_conv_bsgs_enabled())
    {
        return false;
    }
    const bool supported_stage_transition =
        transition_bsgs_enabled() && stride == 2 &&
        out_channels == input.c * 2 &&
        (input.c == 128 || input.c == 256 ||
         (input.c == 64 && layer2_transition_bsgs_enabled())) &&
        ((fh == 3 && fw == 3) || (fh == 1 && fw == 1));
    const bool layer3_stride1 =
        layer3_bsgs_enabled() && stride == 1 && fh == 3 && fw == 3 &&
        input.h == 14 &&
        input.w == 14 && input.c == 256 && out_channels == 256 &&
        input.k == 8;
    const bool layer4_stride1 =
        layer4_bsgs_enabled() && stride == 1 && fh == 3 && fw == 3 &&
        input.h == 7 && input.w == 7 && input.c == 512 &&
        out_channels == 512 && input.k == 16;
    return supported_stage_transition || layer3_stride1 || layer4_stride1;
}

struct MultiplexedConvFusedKey
{
    size_t input_pack_index = 0;
    int kh = 0;
    int kw = 0;
    int step = 0;

    bool operator==(const MultiplexedConvFusedKey &other) const
    {
        return input_pack_index == other.input_pack_index && kh == other.kh &&
               kw == other.kw && step == other.step;
    }
};

struct MultiplexedConvFusedKeyHash
{
    size_t operator()(const MultiplexedConvFusedKey &key) const
    {
        size_t seed = key.input_pack_index;
        seed ^= static_cast<size_t>(key.kh + 0x9e3779b9) + (seed << 6) + (seed >> 2);
        seed ^= static_cast<size_t>(key.kw + 0x9e3779b9) + (seed << 6) + (seed >> 2);
        seed ^= static_cast<size_t>(key.step + 0x9e3779b9) + (seed << 6) + (seed >> 2);
        return seed;
    }
};

MultiplexedCipherGroup multiplexed_channel_conv2d_all_channels(
    const MultiplexedCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime)
{
    const ConvPlaintextCache::Stats plaintext_cache_before =
        active_conv_plaintext_cache != nullptr
            ? active_conv_plaintext_cache->stats()
            : ConvPlaintextCache::Stats{};
    const uintptr_t layer_identity =
        reinterpret_cast<uintptr_t>(weights.data());
    log_multiplexed_group_cipher_state("multiplexed_dense_conv2d_all_channels input",
                                       input, runtime);
    if (stride != 1 && stride != 2)
    {
        throw invalid_argument("multiplexed conv currently supports stride 1 or 2 only");
    }
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("multiplexed dense conv expects odd kernel sizes");
    }
    if (static_cast<int>(weights.size()) != fh * fw * input.c * out_channels)
    {
        throw invalid_argument("multiplexed dense conv weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("multiplexed dense conv BN fold vector size is invalid");
    }

    if (should_use_fused_conv_bsgs(
            input, out_channels, stride, fh, fw))
    {
        return multiplexed_fused_conv2d_bsgs(
            input, out_channels, stride, fh, fw, weights, running_var,
            constant_weight, epsilon, runtime);
    }

    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;

    const int out_k = (stride == 1) ? input.k : input.k * 2;
    MultiplexedCipherGroup output =
        make_multiplexed_shape(input.h / stride, input.w / stride, out_channels, out_k,
                               input.slot_count);
    size_t max_output_channels_per_pack = 0;
    for (size_t output_pack_index = 0; output_pack_index < output.packs.size();
         ++output_pack_index)
    {
        max_output_channels_per_pack =
            max(max_output_channels_per_pack,
                multiplexed_channels_for_pack(output, output_pack_index).size());
    }
    const size_t available_threads = resnet18_parallel_thread_count(
        max(output.packs.size(), max_output_channels_per_pack));
    const bool parallelize_output_channels =
        output.packs.size() < available_threads && max_output_channels_per_pack > 1;
    const size_t output_pack_threads = parallelize_output_channels
                                           ? 1
                                           : resnet18_parallel_thread_count(
                                                 output.packs.size());
    const size_t output_channel_threads =
        parallelize_output_channels
            ? min(available_threads, max_output_channels_per_pack)
            : 1;
    resnet18_progress_log()
        << "multiplexed dense conv compact-vector parallel mode: "
        << (parallelize_output_channels ? "output_channels_within_pack"
                                        : "output_packs")
        << ", pack_threads=" << output_pack_threads
        << ", channel_threads=" << output_channel_threads << endl;
    resnet18_progress_log()
        << "multiplexed dense conv compact-vector estimate: output_packs="
        << output.packs.size() << ", input_packs=" << input.packs.size()
        << ", max_output_channels_per_pack=" << max_output_channels_per_pack
        << ", spatial_rotations_per_pack<=" << input.packs.size() * fh * fw
        << ", plaintext_vector_multiplies_per_pack<="
        << input.packs.size() * max_output_channels_per_pack *
                   static_cast<size_t>(fh * fw) +
               max_output_channels_per_pack
        << endl;
    const int compact_local_sum_rotations =
        2 * exact_log2_power_of_two(input.k) +
        max(0, input.pages_per_cipher - 1);
    const size_t channel_placement_rotations_before =
        input.packs.size() * static_cast<size_t>(out_channels) *
        static_cast<size_t>(compact_local_sum_rotations + 1);
    const size_t channel_placement_rotations_after =
        static_cast<size_t>(out_channels) *
        static_cast<size_t>(compact_local_sum_rotations + 1);
    resnet18_progress_log()
        << "multiplexed dense conv pre-reduction cross-pack accumulation: "
        << "channel_reduce_and_place_rotations_before<="
        << channel_placement_rotations_before
        << ", after<=" << channel_placement_rotations_after
        << ", saved<="
        << channel_placement_rotations_before -
               channel_placement_rotations_after
        << endl;
    const size_t dense_kernel_term_count =
        input.packs.size() * static_cast<size_t>(out_channels) *
        static_cast<size_t>(fh * fw);
    const size_t dense_select_term_count =
        input.packs.size() * static_cast<size_t>(out_channels);
    const size_t cross_pack_select_term_count = static_cast<size_t>(out_channels);
    const size_t rescale_count_before_lazy =
        dense_kernel_term_count + dense_select_term_count;
    const size_t rescale_count_after_kernel_lazy = dense_select_term_count * 2;
    const size_t rescale_count_after_cross_pack_lazy =
        cross_pack_select_term_count * 2;
    resnet18_progress_log()
        << "multiplexed dense conv cross-pack lazy rescale: before<="
        << rescale_count_before_lazy
        << ", kernel_lazy_after<=" << rescale_count_after_kernel_lazy
        << ", cross_pack_after<=" << rescale_count_after_cross_pack_lazy
        << ", total_saved<="
        << rescale_count_before_lazy - rescale_count_after_cross_pack_lazy
        << ", select_plain_multiplies_before<=" << dense_select_term_count
        << ", select_plain_multiplies_after<=" << cross_pack_select_term_count
        << endl;

    const size_t kernel_position_count = static_cast<size_t>(fh * fw);
    const size_t cached_spatial_transform_count =
        input.packs.size() * kernel_position_count;
    const size_t previous_spatial_transform_count =
        output.packs.size() * cached_spatial_transform_count;
    const size_t nonzero_kernel_rotation_count =
        kernel_position_count > 0 ? kernel_position_count - 1 : 0;
    const size_t cached_direct_rotation_count =
        input.packs.size() * nonzero_kernel_rotation_count;
    const size_t previous_direct_rotation_count =
        output.packs.size() * cached_direct_rotation_count;
    vector<vector<Ciphertext>> spatially_rotated_inputs(input.packs.size());
    for (auto &rotations : spatially_rotated_inputs)
    {
        rotations.resize(kernel_position_count);
    }

    resnet18_progress_log()
        << "multiplexed dense conv spatial rotation cache: ciphertexts="
        << cached_spatial_transform_count
        << ", transforms_before=" << previous_spatial_transform_count
        << ", transforms_after=" << cached_spatial_transform_count
        << ", direct_rotations_before=" << previous_direct_rotation_count
        << ", direct_rotations_after=" << cached_direct_rotation_count
        << endl;
    resnet18_parallel_for(cached_spatial_transform_count, [&](size_t transform_index) {
        const size_t input_pack_index =
            transform_index / kernel_position_count;
        const size_t kernel_position =
            transform_index % kernel_position_count;
        const int kh = static_cast<int>(kernel_position / static_cast<size_t>(fw));
        const int kw = static_cast<int>(kernel_position % static_cast<size_t>(fw));
        rotate_with_direct_key(
            input.packs.at(input_pack_index),
            spatially_rotated_inputs.at(input_pack_index).at(kernel_position),
            multiplexed_spatial_kernel_rotation_step(input, fh, fw, kh, kw),
            runtime);
    });

    auto input_context_data = runtime.context.crt_context()->get_context_data(
        input.packs.front().parms_id());
    if (!input_context_data || !input_context_data->next_context_data())
    {
        throw runtime_error("multiplexed conv has no level for lazy rescale plaintexts");
    }
    const parms_id_type select_plain_parms_id =
        input_context_data->next_context_data()->parms_id();
    const double kernel_plain_scale =
        local_multiply_plain_scale(input.packs.front(), runtime.encoder);
    const double select_plain_scale = pow(
        2.0, static_cast<double>(input_context_data->next_context_data()
                                     ->coeff_modulus().back().bit_count()));

    auto compute_output_pack = [&](size_t output_pack_index) {
        const vector<int> output_channels =
            multiplexed_channels_for_pack(output, output_pack_index);
        if (output_channels.empty())
        {
            throw runtime_error("multiplexed compact conv output pack has no channels");
        }

        vector<Ciphertext> output_channel_terms(output_channels.size());
        vector<unsigned char> has_output_channel_terms(output_channels.size(), 0);
        vector<vector<double>> select_vectors(output_channels.size(),
                                              vector<double>(output.slot_count, 0.0));
        vector<shared_ptr<const Plaintext>> select_plaintexts(output_channels.size());
        auto for_each_output_channel = [&](auto fn) {
            if (parallelize_output_channels && output_channels.size() > 1)
            {
                resnet18_parallel_for(output_channels.size(), std::move(fn));
                return;
            }
            for (size_t output_channel_index = 0;
                 output_channel_index < output_channels.size(); ++output_channel_index)
            {
                fn(output_channel_index);
            }
        };

        for_each_output_channel([&](size_t output_channel_index) {
            const int output_channel = output_channels.at(output_channel_index);
            const double folded_bn_scale =
                constant_weight[output_channel] /
                sqrt(running_var[output_channel] + epsilon);
            if (folded_bn_scale == 0.0 ||
                local_coefficient_encodes_to_zero(input.packs.front(), folded_bn_scale,
                                                  runtime.encoder))
            {
                throw runtime_error("multiplexed compact conv output channel has zero BN scale");
            }

            for (int oh = 0; oh < output.h; ++oh)
            {
                for (int ow = 0; ow < output.w; ++ow)
                {
                    select_vectors.at(output_channel_index)
                        .at(multiplexed_slot_index(output, output_channel, oh, ow)) =
                        folded_bn_scale;
                }
            }
            const ConvPlaintextCacheKey select_key{
                layer_identity, select_plain_parms_id, 1, 0, 0,
                static_cast<uint32_t>(output_channel)};
            select_plaintexts.at(output_channel_index) =
                get_cached_conv_plaintext(
                    select_key, select_vectors.at(output_channel_index),
                    select_plain_parms_id, select_plain_scale, runtime.encoder);
        });

        for (size_t input_pack_index = 0; input_pack_index < input.packs.size();
             ++input_pack_index)
        {
            // Every input pack uses the same physical local-channel positions.
            // Accumulate all packs before the linear local-channel reduction and
            // output placement, so those rotations run once per output channel
            // instead of once per (input pack, output channel).
            const vector<int> input_channels =
                multiplexed_channels_for_pack(input, input_pack_index);
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    const size_t kernel_position = static_cast<size_t>(kh * fw + kw);
                    const Ciphertext &rotated =
                        spatially_rotated_inputs.at(input_pack_index).at(kernel_position);

                    for_each_output_channel([&](size_t output_channel_index) {
                        const int output_channel =
                            output_channels.at(output_channel_index);
                        vector<double> compact_weight(output.slot_count, 0.0);
                        bool has_compact_weight = false;
                        for (int input_channel : input_channels)
                        {
                            const size_t weight_index = static_cast<size_t>(
                                fh * fw * input.c * output_channel +
                                fh * fw * input_channel + fw * kh + kw);
                            const double coeff = weights[weight_index];
                            if (coeff == 0.0 ||
                                local_coefficient_encodes_to_zero(
                                    input.packs.at(input_pack_index), coeff,
                                    runtime.encoder))
                            {
                                continue;
                            }

                            const int pad_h = fh / 2;
                            const int pad_w = fw / 2;
                            for (int oh = 0; oh < output.h; ++oh)
                            {
                                for (int ow = 0; ow < output.w; ++ow)
                                {
                                    const int ih = oh * stride + kh - pad_h;
                                    const int iw = ow * stride + kw - pad_w;
                                    if (ih < 0 || ih >= input.h || iw < 0 ||
                                        iw >= input.w)
                                    {
                                        continue;
                                    }
                                    const size_t slot = multiplexed_slot_index(
                                        input, input_channel, oh * stride, ow * stride);
                                    compact_weight.at(slot) = coeff;
                                    has_compact_weight = true;
                                }
                            }
                        }
                        if (!has_compact_weight)
                        {
                            return;
                        }

                        const ConvPlaintextCacheKey kernel_key{
                            layer_identity, rotated.parms_id(), 0,
                            static_cast<uint32_t>(input_pack_index),
                            static_cast<uint32_t>(kernel_position),
                            static_cast<uint32_t>(output_channel)};
                        shared_ptr<const Plaintext> compact_plaintext =
                            get_cached_conv_plaintext(
                                kernel_key, compact_weight, rotated.parms_id(),
                                kernel_plain_scale, runtime.encoder);
                        if (!has_output_channel_terms.at(output_channel_index))
                        {
                            runtime.evaluator->multiply_plain(
                                rotated, *compact_plaintext,
                                output_channel_terms.at(output_channel_index));
                            has_output_channel_terms.at(output_channel_index) = 1;
                        }
                        else
                        {
                            runtime.evaluator->multiply_plain_accumulate(
                                rotated, *compact_plaintext,
                                output_channel_terms.at(output_channel_index));
                        }
                    });
                }
            }
        }

        for_each_output_channel([&](size_t output_channel_index) {
            if (!has_output_channel_terms.at(output_channel_index))
            {
                return;
            }

            Ciphertext folded = rotate_multiplexed_local_channel_sum_to_base(
                output_channel_terms.at(output_channel_index), input, runtime);
            Ciphertext cross_pack_sum;
            rotate_with_direct_key(
                folded, cross_pack_sum,
                multiplexed_output_channel_select_rotation_step(
                    output, output_channels.at(output_channel_index)),
                runtime);
            // This replaces one kernel rescale and one select/rescale per input
            // pack with exactly two rescales for the complete output channel.
            runtime.evaluator->rescale_dynamic(
                cross_pack_sum, cross_pack_sum, input.packs.front().scale());
            output_channel_terms.at(output_channel_index) =
                multiply_preencoded_plain_rescale(
                cross_pack_sum, *select_plaintexts.at(output_channel_index), runtime);
        });

        Ciphertext sum;
        bool has_sum = false;
        for (size_t output_channel_index = 0;
             output_channel_index < output_channels.size(); ++output_channel_index)
        {
            if (!has_output_channel_terms.at(output_channel_index))
            {
                throw runtime_error(
                    "multiplexed compact conv output channel produced no encrypted terms");
            }
            Ciphertext &term = output_channel_terms.at(output_channel_index);
            if (!has_sum)
            {
                sum = std::move(term);
                has_sum = true;
            }
            else
            {
                runtime.evaluator->add(sum, term, sum);
            }
        }
        if (!has_sum)
        {
            throw runtime_error("multiplexed dense conv output pack produced no encrypted terms");
        }
        output.packs.at(output_pack_index) = std::move(sum);
    };

    if (!parallelize_output_channels && output_pack_threads > 1)
    {
        resnet18_parallel_for(output.packs.size(), compute_output_pack);
    }
    else
    {
        for (size_t output_pack_index = 0; output_pack_index < output.packs.size();
             ++output_pack_index)
        {
            compute_output_pack(output_pack_index);
        }
    }

    resnet18_progress_log() << "multiplexed dense conv encrypted pack progress: "
                            << output.packs.size() << "/" << output.packs.size() << endl;
    log_multiplexed_group_cipher_state("multiplexed_dense_conv2d_all_channels output",
                                       output, runtime);
    if (active_conv_plaintext_cache != nullptr)
    {
        const ConvPlaintextCache::Stats plaintext_cache_after =
            active_conv_plaintext_cache->stats();
        resnet18_progress_log()
            << "multiplexed dense conv plaintext cache: hits="
            << plaintext_cache_after.hits - plaintext_cache_before.hits
            << ", misses="
            << plaintext_cache_after.misses - plaintext_cache_before.misses
            << ", newly_encoded_bytes="
            << plaintext_cache_after.encoded_bytes -
                   plaintext_cache_before.encoded_bytes
            << ", resident_bytes=" << plaintext_cache_after.resident_bytes
            << ", entries=" << plaintext_cache_after.entries
            << ", evictions="
            << plaintext_cache_after.evictions - plaintext_cache_before.evictions
            << endl;
    }
    return output;
}

MultiplexedCipherGroup multiplexed_channel_batch_norm(
    const MultiplexedCipherGroup &input, const vector<double> &bias,
    const vector<double> &running_mean, const vector<double> &running_var,
    const vector<double> &weight, double epsilon, double boundary,
    PoseidonRuntime &runtime)
{
    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;
    log_multiplexed_group_cipher_state("multiplexed_batch_norm input", input, runtime);
    if (static_cast<int>(bias.size()) != input.c ||
        static_cast<int>(running_mean.size()) != input.c ||
        static_cast<int>(running_var.size()) != input.c ||
        static_cast<int>(weight.size()) != input.c)
    {
        throw invalid_argument("multiplexed batch norm vector size is invalid");
    }

    MultiplexedCipherGroup output = input;
    output.packs.resize(input.packs.size());
    resnet18_parallel_for(input.packs.size(), [&](size_t pack_index) {
        vector<complex<double>> offsets(input.slot_count, {0.0, 0.0});
        for (int channel = 0; channel < input.c; ++channel)
        {
            if (multiplexed_cipher_index_for_channel(input, channel) != pack_index)
            {
                continue;
            }
            const double offset =
                (bias[channel] - running_mean[channel] * weight[channel] /
                                     sqrt(running_var[channel] + epsilon)) /
                boundary;
            for (int row = 0; row < input.h; ++row)
            {
                for (int col = 0; col < input.w; ++col)
                {
                    offsets[multiplexed_slot_index(input, channel, row, col)] =
                        {offset, 0.0};
                }
            }
        }
        Plaintext plain;
        runtime.encoder.encode(offsets, input.packs.at(pack_index).parms_id(),
                               input.packs.at(pack_index).scale(), plain);
        runtime.evaluator->add_plain(input.packs.at(pack_index), plain,
                                     output.packs.at(pack_index));
    });
    log_multiplexed_group_cipher_state("multiplexed_batch_norm output", output, runtime);
    return output;
}

PoseidonBootstrapContext make_resnet18_bootstrap_context(PoseidonRuntime &runtime)
{
    PoseidonBootstrapContext bootstrap_ctx;
    bootstrap_ctx.context = &runtime.context;
    bootstrap_ctx.evaluator = runtime.evaluator.get();
    bootstrap_ctx.encoder = &runtime.encoder;
    bootstrap_ctx.relin_keys = &runtime.relin_keys;
    bootstrap_ctx.galois_keys = &runtime.galois_keys;
    bootstrap_ctx.bootstrap_config = &runtime.bootstrap_config;
    return bootstrap_ctx;
}

MultiplexedCipherGroup multiplexed_channel_bootstrap(
    const MultiplexedCipherGroup &input, long logn, PoseidonRuntime &runtime,
    const string &label, const MockExecutionOptions &mock_options)
{
    log_multiplexed_group_cipher_state(label + " bootstrap input", input, runtime);
    const bool needs_decrypted_input =
        mock_options.mock_bootstrap || !resnet18_execution::inference_only();
    vector<complex<double>> bootstrap_input_values;
    vector<double> bootstrap_input_real;
    if (needs_decrypted_input)
    {
        bootstrap_input_values = decrypt_multiplexed_group_complex(input, runtime);
        bootstrap_input_real.resize(bootstrap_input_values.size(), 0.0);
        for (size_t i = 0; i < bootstrap_input_values.size(); ++i)
        {
            bootstrap_input_real.at(i) = bootstrap_input_values.at(i).real();
        }
    }
    MultiplexedCipherGroup output = input;
    output.packs.resize(input.packs.size());
    if (mock_options.mock_bootstrap)
    {
        (void)logn;
        resnet18_progress_log() << label
                                << " bootstrap MOCK decrypt-reencrypt evaluation" << endl;
        output = encrypt_multiplexed_group_values(input, bootstrap_input_real, runtime);
        const size_t dropped_bootstrap =
            drop_trailing_bootstrap_primes(output.packs, runtime);
        if (dropped_bootstrap > 0)
        {
            resnet18_progress_log() << label
                                    << " bootstrap MOCK drop trailing bootstrap primes after "
                                       "reencrypt: "
                                    << dropped_bootstrap << endl;
        }
    }
    else
    {
        const size_t thread_count =
            resnet18_parallel_thread_count(input.packs.size());
        atomic<size_t> completed_packs{0};
        resnet18_progress_log() << label << " bootstrap parallel threads: "
                                << thread_count << endl;
        resnet18_parallel_for(input.packs.size(), [&](size_t pack_index) {
            PoseidonBootstrapContext bootstrap_ctx =
                make_resnet18_bootstrap_context(runtime);
            TensorCipher tensor_in(static_cast<int>(logn), input.k, input.h, input.w, input.c,
                                   1, input.pages_per_cipher, input.packs.at(pack_index));
            TensorCipher tensor_out;
            bootstrap_tensor(tensor_in, tensor_out, bootstrap_ctx);
            output.packs.at(pack_index) = tensor_out.cipher();
            const size_t done = completed_packs.fetch_add(1) + 1;
            resnet18_progress_log() << label << " bootstrap ciphertext progress: "
                                    << done << "/" << input.packs.size()
                                    << ", pack=" << pack_index << endl;
        });
    }
    log_multiplexed_group_cipher_state(label + " bootstrap output", output, runtime);
    if (!resnet18_execution::inference_only())
    {
        const vector<complex<double>> bootstrap_output_values =
            decrypt_multiplexed_group_complex(output, runtime);
        const double bootstrap_self_max_abs_error =
            multiplexed_group_pair_max_abs_error(bootstrap_input_values,
                                                 bootstrap_output_values);
        resnet18_progress_log() << label
                                << " bootstrap self max_abs_error(before_vs_after): "
                                << bootstrap_self_max_abs_error << endl;
    }
    return output;
}

MultiplexedCipherGroup multiplexed_channel_homomorphic_relu(
    const MultiplexedCipherGroup &input, long logn, const ReluConfig &relu_config,
    PoseidonRuntime &runtime, const string &label,
    const MockExecutionOptions &mock_options)
{
    MultiplexedCipherGroup relu_input = input;
    if (!mock_options.mock_relu)
    {
        const size_t dropped_bootstrap =
            drop_trailing_bootstrap_primes(relu_input.packs, runtime);
        if (dropped_bootstrap > 0)
        {
            resnet18_progress_log() << label
                                    << " drop trailing bootstrap primes before ReLU: "
                                    << dropped_bootstrap << endl;
        }
    }
    log_multiplexed_group_cipher_state(
        label + (mock_options.mock_relu ? " mock ReLU input" : " homomorphic ReLU input"),
        relu_input, runtime);
    MultiplexedCipherGroup output = relu_input;
    output.packs.resize(relu_input.packs.size());
    if (mock_options.mock_relu)
    {
        (void)logn;
        vector<complex<double>> relu_input_values =
            decrypt_multiplexed_group_complex(relu_input, runtime);
        vector<double> relu_output_values(relu_input_values.size(), 0.0);
        for (size_t i = 0; i < relu_input_values.size(); ++i)
        {
            relu_output_values.at(i) = approximate_relu_plain(
                relu_input_values.at(i).real(), relu_config.deg, relu_config.alpha,
                relu_config.tree, relu_config.scaled_val);
        }
        resnet18_progress_log() << label
                                << " ReLU MOCK decrypt-polynomial-reencrypt evaluation"
                                << endl;
        output = encrypt_multiplexed_group_values(relu_input, relu_output_values, runtime);
        const size_t dropped_bootstrap =
            drop_trailing_bootstrap_primes(output.packs, runtime);
        if (dropped_bootstrap > 0)
        {
            resnet18_progress_log() << label
                                    << " ReLU MOCK drop trailing bootstrap primes after "
                                       "reencrypt: "
                                    << dropped_bootstrap << endl;
        }
    }
    else
    {
        const size_t thread_count =
            resnet18_parallel_thread_count(relu_input.packs.size());
        atomic<size_t> completed_packs{0};
        resnet18_progress_log() << label << " homomorphic ReLU parallel threads: "
                                << thread_count << endl;
        resnet18_parallel_for(relu_input.packs.size(), [&](size_t pack_index) {
            TensorCipher tensor_in(static_cast<int>(logn), relu_input.k, relu_input.h,
                                   relu_input.w, relu_input.c, 1,
                                   relu_input.pages_per_cipher,
                                   relu_input.packs.at(pack_index));
            TensorCipher tensor_out;
            relu(tensor_in, tensor_out, relu_config.comp_no, relu_config.deg,
                 relu_config.alpha, relu_config.tree, relu_config.scaled_val,
                 runtime.encryptor, *runtime.evaluator, runtime.encoder, runtime.relin_keys,
                 runtime.scale);
            output.packs.at(pack_index) = tensor_out.cipher();
            const size_t done = completed_packs.fetch_add(1) + 1;
            resnet18_progress_log() << label << " homomorphic ReLU ciphertext progress: "
                                    << done << "/" << relu_input.packs.size()
                                    << ", pack=" << pack_index << endl;
        });
    }
    log_multiplexed_group_cipher_state(
        label + (mock_options.mock_relu ? " mock ReLU output" : " homomorphic ReLU output"),
        output, runtime);
    return output;
}

MultiplexedCipherGroup multiplexed_channel_bootstrap_then_relu(
    const MultiplexedCipherGroup &input, long logn, const ReluConfig &relu_config,
    PoseidonRuntime &runtime, const string &label, bool bootstrap_before_relu,
    const MockExecutionOptions &mock_options,
    bool preserve_full_bootstrap_output = false)
{
    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;
    MultiplexedCipherGroup relu_input = input;
    if (bootstrap_before_relu)
    {
        relu_input = multiplexed_channel_bootstrap(input, logn, runtime, label,
                                                   mock_options);
        if (!preserve_full_bootstrap_output && !mock_options.mock_bootstrap &&
            !mock_options.mock_relu)
        {
            const size_t target_level = post_bootstrap_relu_input_level();
            const auto target =
                runtime.context.crt_context()->parms_id_map().find(target_level);
            if (target == runtime.context.crt_context()->parms_id_map().end())
            {
                throw runtime_error(
                    "post-bootstrap ReLU target level is missing from context");
            }
            resnet18_parallel_for(relu_input.packs.size(), [&](size_t pack_index) {
                const size_t current_level =
                    cipher_chain_index(runtime, relu_input.packs.at(pack_index));
                if (current_level < target_level)
                {
                    throw runtime_error(
                        "bootstrap output is below the configured ReLU input level");
                }
                if (current_level > target_level)
                {
                    runtime.evaluator->drop_modulus(
                        relu_input.packs.at(pack_index),
                        relu_input.packs.at(pack_index), target->second);
                }
            });
            log_multiplexed_group_cipher_state(
                label + " bootstrap output trimmed for ReLU", relu_input,
                runtime);
        }
    }
    return multiplexed_channel_homomorphic_relu(relu_input, logn, relu_config, runtime,
                                                label, mock_options);
}

MultiplexedCipherGroup multiplexed_channel_add(const MultiplexedCipherGroup &lhs,
                                               const MultiplexedCipherGroup &rhs,
                                               PoseidonRuntime &runtime)
{
    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;
    log_multiplexed_group_cipher_state("multiplexed_channel_add lhs input", lhs, runtime);
    log_multiplexed_group_cipher_state("multiplexed_channel_add rhs input", rhs, runtime);
    if (lhs.h != rhs.h || lhs.w != rhs.w || lhs.c != rhs.c || lhs.k != rhs.k ||
        lhs.pages_per_cipher != rhs.pages_per_cipher ||
        lhs.page_size != rhs.page_size || lhs.packs.size() != rhs.packs.size())
    {
        throw invalid_argument("multiplexed channel add layout mismatch");
    }
    MultiplexedCipherGroup output = lhs;
    output.packs.resize(lhs.packs.size());
    resnet18_parallel_for(lhs.packs.size(), [&](size_t pack_index) {
        Ciphertext lhs_cipher = lhs.packs.at(pack_index);
        Ciphertext rhs_cipher = rhs.packs.at(pack_index);
        const size_t lhs_chain = cipher_chain_index(runtime, lhs_cipher);
        const size_t rhs_chain = cipher_chain_index(runtime, rhs_cipher);
        if (lhs_chain > rhs_chain)
        {
            runtime.evaluator->drop_modulus(lhs_cipher, lhs_cipher, rhs_cipher.parms_id());
        }
        else if (rhs_chain > lhs_chain)
        {
            runtime.evaluator->drop_modulus(rhs_cipher, rhs_cipher, lhs_cipher.parms_id());
        }
        runtime.evaluator->add_dynamic(lhs_cipher, rhs_cipher,
                                       output.packs.at(pack_index), runtime.encoder);
    });
    log_multiplexed_group_cipher_state("multiplexed_channel_add output", output, runtime);
    return output;
}

MultiplexedCipherGroup multiplexed_average_pool2d_stride2(
    const MultiplexedCipherGroup &input, int out_h, int out_w, int out_k,
    PoseidonRuntime &runtime)
{
    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;
    log_multiplexed_group_cipher_state("multiplexed avgpool input", input, runtime);
    MultiplexedCipherGroup output =
        make_multiplexed_shape(out_h, out_w, input.c, out_k, input.slot_count);
    if (out_k != input.k * 2 || output.page_size != input.page_size)
    {
        throw invalid_argument("multiplexed avgpool expects k_out = 2*k_in with fixed page size");
    }

    resnet18_progress_log() << "multiplexed avgpool encrypted pack parallel threads: "
                            << resnet18_parallel_thread_count(output.packs.size()) << endl;
    atomic<size_t> completed_packs{0};
    resnet18_parallel_for(output.packs.size(), [&](size_t output_pack_index) {
        const auto pack_start = chrono::steady_clock::now();
        resnet18_progress_log() << "multiplexed avgpool pack start: pack="
                                << output_pack_index << "/" << output.packs.size()
                                << ", input_chain_index="
                                << cipher_chain_index(runtime, input.packs.front())
                                << ", next_prime_bits="
                                << next_rescale_prime_bits(input.packs.front(), runtime)
                                << endl;
        Ciphertext sum;
        bool has_sum = false;
        for (int channel = 0; channel < output.c; ++channel)
        {
            if (multiplexed_cipher_index_for_channel(output, channel) != output_pack_index)
            {
                continue;
            }
            const size_t input_pack_index =
                multiplexed_cipher_index_for_channel(input, channel);
            for (int kh = 0; kh < 3; ++kh)
            {
                for (int kw = 0; kw < 3; ++kw)
                {
                    vector<double> mask(output.slot_count, 0.0);
                    bool has_mask = false;
                    long long rotation_step = 0;
                    bool has_rotation_step = false;
                    for (int oh = 0; oh < out_h; ++oh)
                    {
                        for (int ow = 0; ow < out_w; ++ow)
                        {
                            const int ih = oh * 2 + kh - 1;
                            const int iw = ow * 2 + kw - 1;
                            if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                            {
                                continue;
                            }
                            const size_t target_slot =
                                multiplexed_slot_index(output, channel, oh, ow);
                            // Fold the 1/9 average into the spatial selection
                            // plaintext. This keeps pooling at one multiplicative
                            // level instead of masking/rescaling and then applying
                            // a second scalar multiply/rescale.
                            mask[target_slot] = 1.0 / 9.0;
                            if (!has_rotation_step)
                            {
                                const long long source_slot = static_cast<long long>(
                                    multiplexed_slot_index(input, channel, ih, iw));
                                rotation_step =
                                    source_slot - static_cast<long long>(target_slot);
                                has_rotation_step = true;
                            }
                            has_mask = true;
                        }
                    }
                    if (!has_mask)
                    {
                        continue;
                    }

                    Ciphertext rotated;
                    if (rotation_step == 0)
                    {
                        rotated = input.packs.at(input_pack_index);
                    }
                    else
                    {
                        rotate_with_direct_key(input.packs.at(input_pack_index), rotated,
                                               rotation_step, runtime);
                    }
                    Ciphertext term = multiply_binary_mask_no_rescale(rotated, mask, runtime);
                    if (!has_sum)
                    {
                        sum = std::move(term);
                        has_sum = true;
                    }
                    else
                    {
                        Ciphertext next_sum;
                        runtime.evaluator->add_dynamic(sum, term, next_sum, runtime.encoder);
                        sum = std::move(next_sum);
                    }
                }
            }
        }
        if (!has_sum)
        {
            throw runtime_error("multiplexed avgpool output pack produced no encrypted terms");
        }

        output.packs.at(output_pack_index) = std::move(sum);
        const size_t done = completed_packs.fetch_add(1) + 1;
        resnet18_progress_log() << "multiplexed avgpool pack done: " << done
                                << "/" << output.packs.size()
                                << ", pack=" << output_pack_index
                                << ", output_chain_index="
                                << cipher_chain_index(runtime,
                                                      output.packs.at(output_pack_index))
                                << ", elapsed_ms="
                                << chrono::duration_cast<chrono::milliseconds>(
                                       chrono::steady_clock::now() - pack_start)
                                       .count()
                                << endl;
    });

    log_multiplexed_group_cipher_state("multiplexed avgpool output", output, runtime);
    return output;
}

double local_multiply_plain_scale(const Ciphertext &input, const CKKSEncoder &encoder)
{
    auto context_data = encoder.context().crt_context()->get_context_data(input.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id for plain scale selection");
    }
    const int rescale_prime_bits = context_data->coeff_modulus().back().bit_count();
    return pow(2.0, static_cast<double>(rescale_prime_bits));
}

bool local_coefficient_encodes_to_zero(const Ciphertext &input, double coeff,
                                       const CKKSEncoder &encoder)
{
    return fabs(coeff * local_multiply_plain_scale(input, encoder)) < 0.5;
}

Ciphertext multiply_constant_scalar_rescale(const Ciphertext &input, double coeff,
                                            PoseidonRuntime &runtime)
{
    Plaintext plain;
    runtime.encoder.encode(coeff, input.parms_id(),
                           local_multiply_plain_scale(input, runtime.encoder), plain);
    Ciphertext output;
    runtime.evaluator->multiply_plain(input, plain, output);
    runtime.evaluator->rescale_dynamic(output, output, input.scale());
    return output;
}

vector<double> packed_conv_output_mask(size_t slot_count, size_t channel_stride,
                                       int output_local, int h, int w, int fh, int fw,
                                       int kh, int kw)
{
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    vector<double> mask(slot_count, 0.0);
    const size_t base = static_cast<size_t>(output_local) * channel_stride;
    for (int oh = 0; oh < h; ++oh)
    {
        for (int ow = 0; ow < w; ++ow)
        {
            const int ih = oh + kh - pad_h;
            const int iw = ow + kw - pad_w;
            if (ih < 0 || ih >= h || iw < 0 || iw >= w)
            {
                continue;
            }
            mask[base + static_cast<size_t>(oh * w + ow)] = 1.0;
        }
    }
    return mask;
}

vector<int> packed_dense_conv2d_rotation_steps(const PackedChannelCipherGroup &input,
                                               int output_channels_per_cipher, int fh, int fw)
{
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("packed dense conv expects odd kernel sizes");
    }
    set<int> steps;
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    for (int input_local = 0; input_local < input.channels_per_cipher; ++input_local)
    {
        const long long input_base =
            static_cast<long long>(static_cast<size_t>(input_local) * input.channel_stride);
        for (int output_local = 0; output_local < output_channels_per_cipher; ++output_local)
        {
            const long long output_base =
                static_cast<long long>(static_cast<size_t>(output_local) *
                                       input.channel_stride);
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    const long long spatial_step =
                        static_cast<long long>((kh - pad_h) * input.w + (kw - pad_w));
                    const long long step = input_base - output_base + spatial_step;
                    if (step != 0)
                    {
                        steps.insert(static_cast<int>(step));
                    }
                }
            }
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

vector<int> packed_sparse_stride_conv2d_rotation_steps(
    const PackedChannelCipherGroup &input, int output_channels_per_cipher, int fh, int fw)
{
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("packed sparse stride conv expects odd kernel sizes");
    }
    set<int> steps;
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    for (int input_local = 0; input_local < input.channels_per_cipher; ++input_local)
    {
        const long long input_base =
            static_cast<long long>(static_cast<size_t>(input_local) * input.channel_stride);
        for (int output_local = 0; output_local < output_channels_per_cipher; ++output_local)
        {
            const long long output_base =
                static_cast<long long>(static_cast<size_t>(output_local) *
                                       input.channel_stride);
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    const long long spatial_step =
                        static_cast<long long>((kh - pad_h) * input.w + (kw - pad_w));
                    const long long step = input_base - output_base + spatial_step;
                    if (step != 0)
                    {
                        steps.insert(static_cast<int>(step));
                    }
                }
            }
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

PackedChannelCipherGroup packed_channel_conv2d_all_channels(
    const PackedChannelCipherGroup &input, int out_channels, int output_channels_per_cipher,
    int stride, int fh, int fw, const vector<double> &weights,
    const vector<double> &running_var, const vector<double> &constant_weight, double epsilon,
    PoseidonRuntime &runtime)
{
    log_packed_channel_group_cipher_state("packed_dense_conv2d_all_channels input", input,
                                          runtime);
    if (stride != 1)
    {
        throw invalid_argument("packed dense conv currently supports stride 1 only");
    }
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("packed dense conv expects odd kernel sizes");
    }
    if (input.channel_stride != static_cast<size_t>(input.h * input.w))
    {
        throw invalid_argument("packed dense conv expects dense channel layout");
    }
    if (static_cast<int>(weights.size()) != fh * fw * input.c * out_channels)
    {
        throw invalid_argument("packed dense conv weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("packed dense conv BN fold vector size is invalid");
    }

    PackedChannelCipherGroup output;
    output.h = input.h;
    output.w = input.w;
    output.c = out_channels;
    output.channels_per_cipher = output_channels_per_cipher;
    output.channel_stride = static_cast<size_t>(output.h * output.w);
    output.slot_count = input.slot_count;
    if (output.channel_stride * static_cast<size_t>(output.channels_per_cipher) >
        output.slot_count)
    {
        throw invalid_argument("packed dense conv output does not fit in one ciphertext");
    }
    output.packs.resize((static_cast<size_t>(out_channels) +
                         static_cast<size_t>(output.channels_per_cipher) - 1) /
                        static_cast<size_t>(output.channels_per_cipher));

    resnet18_progress_log() << "packed dense conv encrypted pack parallel threads: "
                            << resnet18_parallel_thread_count(output.packs.size()) << endl;
    resnet18_parallel_for(output.packs.size(), [&](size_t output_pack_index) {
        Ciphertext sum;
        bool has_sum = false;
        for (int output_local = 0; output_local < output.channels_per_cipher; ++output_local)
        {
            const int output_channel =
                static_cast<int>(output_pack_index *
                                 static_cast<size_t>(output.channels_per_cipher) +
                                 static_cast<size_t>(output_local));
            if (output_channel >= out_channels)
            {
                continue;
            }
            const double folded_scale =
                constant_weight[output_channel] /
                sqrt(running_var[output_channel] + epsilon);
            const long long output_base =
                static_cast<long long>(static_cast<size_t>(output_local) *
                                       output.channel_stride);
            vector<vector<double>> output_local_masks(static_cast<size_t>(fh * fw));
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    output_local_masks.at(static_cast<size_t>(kh * fw + kw)) =
                        packed_conv_output_mask(output.slot_count, output.channel_stride,
                                                output_local, output.h, output.w, fh, fw, kh,
                                                kw);
                }
            }
            for (int input_channel = 0; input_channel < input.c; ++input_channel)
            {
                const size_t input_pack_index =
                    static_cast<size_t>(input_channel) /
                    static_cast<size_t>(input.channels_per_cipher);
                const int input_local =
                    input_channel % input.channels_per_cipher;
                const long long input_base =
                    static_cast<long long>(static_cast<size_t>(input_local) *
                                           input.channel_stride);
                for (int kh = 0; kh < fh; ++kh)
                {
                    for (int kw = 0; kw < fw; ++kw)
                    {
                        const size_t weight_index = static_cast<size_t>(
                            fh * fw * input.c * output_channel +
                            fh * fw * input_channel + fw * kh + kw);
                        const double coeff = weights[weight_index] * folded_scale;
                        const Ciphertext &source =
                            input.packs.at(input_pack_index);
                        if (coeff == 0.0 ||
                            local_coefficient_encodes_to_zero(source, coeff,
                                                              runtime.encoder))
                        {
                            continue;
                        }

                        const int spatial_step =
                            (kh - fh / 2) * input.w + (kw - fw / 2);
                        const long long step =
                            input_base - output_base +
                            static_cast<long long>(spatial_step);
                        Ciphertext rotated;
                        if (step == 0)
                        {
                            rotated = source;
                        }
                        else
                        {
                            rotate_with_direct_key(source, rotated, step, runtime);
                        }

                        Ciphertext masked = multiply_binary_mask_no_rescale(
                            rotated,
                            output_local_masks.at(static_cast<size_t>(kh * fw + kw)),
                            runtime);
                        Ciphertext term =
                            multiply_constant_scalar_rescale(masked, coeff, runtime);
                        if (!has_sum)
                        {
                            sum = std::move(term);
                            has_sum = true;
                        }
                        else
                        {
                            Ciphertext next_sum;
                            runtime.evaluator->add_dynamic(sum, term, next_sum,
                                                           runtime.encoder);
                            sum = std::move(next_sum);
                        }
                    }
                }
            }
        }
        if (!has_sum)
        {
            throw runtime_error("packed dense conv output pack produced no encrypted terms");
        }
        output.packs.at(output_pack_index) = std::move(sum);
    });

    resnet18_progress_log() << "packed dense conv encrypted pack progress: "
                            << output.packs.size() << "/" << output.packs.size() << endl;
    log_packed_channel_group_cipher_state("packed_dense_conv2d_all_channels output", output,
                                          runtime);
    return output;
}

vector<double> packed_sparse_stride_output_mask(size_t slot_count, size_t channel_stride,
                                                int output_local, int input_h, int input_w,
                                                int out_h, int out_w, int stride,
                                                int fh, int fw, int kh, int kw)
{
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    vector<double> mask(slot_count, 0.0);
    const size_t base = static_cast<size_t>(output_local) * channel_stride;
    for (int oh = 0; oh < out_h; ++oh)
    {
        for (int ow = 0; ow < out_w; ++ow)
        {
            const int ih = oh * stride + kh - pad_h;
            const int iw = ow * stride + kw - pad_w;
            if (ih < 0 || ih >= input_h || iw < 0 || iw >= input_w)
            {
                continue;
            }
            mask[base + static_cast<size_t>((oh * stride) * input_w + ow * stride)] = 1.0;
        }
    }
    return mask;
}

PackedChannelCipherGroup packed_channel_conv2d_sparse_stride_all_channels(
    const PackedChannelCipherGroup &input, int out_channels, int output_channels_per_cipher,
    int stride, int fh, int fw, const vector<double> &weights,
    const vector<double> &running_var, const vector<double> &constant_weight, double epsilon,
    PoseidonRuntime &runtime)
{
    log_packed_channel_group_cipher_state("packed_sparse_stride_conv2d_all_channels input",
                                          input, runtime);
    if (stride <= 1)
    {
        throw invalid_argument("packed sparse stride conv expects stride greater than 1");
    }
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("packed sparse stride conv expects odd kernel sizes");
    }
    if (input.channel_stride != static_cast<size_t>(input.h * input.w))
    {
        throw invalid_argument("packed sparse stride conv expects dense input layout");
    }
    if (static_cast<int>(weights.size()) != fh * fw * input.c * out_channels)
    {
        throw invalid_argument("packed sparse stride conv weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("packed sparse stride conv BN fold vector size is invalid");
    }

    const int out_h = input.h / stride;
    const int out_w = input.w / stride;
    PackedChannelCipherGroup output;
    output.h = input.h;
    output.w = input.w;
    output.c = out_channels;
    output.channels_per_cipher = output_channels_per_cipher;
    output.channel_stride = input.channel_stride;
    output.slot_count = input.slot_count;
    if (output.channel_stride * static_cast<size_t>(output.channels_per_cipher) >
        output.slot_count)
    {
        throw invalid_argument("packed sparse stride conv output does not fit in one ciphertext");
    }
    output.packs.resize((static_cast<size_t>(out_channels) +
                         static_cast<size_t>(output.channels_per_cipher) - 1) /
                        static_cast<size_t>(output.channels_per_cipher));

    resnet18_progress_log() << "packed sparse stride conv encrypted pack parallel threads: "
                            << resnet18_parallel_thread_count(output.packs.size()) << endl;
    resnet18_parallel_for(output.packs.size(), [&](size_t output_pack_index) {
        Ciphertext sum;
        bool has_sum = false;
        for (int output_local = 0; output_local < output.channels_per_cipher; ++output_local)
        {
            const int output_channel =
                static_cast<int>(output_pack_index *
                                 static_cast<size_t>(output.channels_per_cipher) +
                                 static_cast<size_t>(output_local));
            if (output_channel >= out_channels)
            {
                continue;
            }
            const double folded_scale =
                constant_weight[output_channel] /
                sqrt(running_var[output_channel] + epsilon);
            const long long output_base =
                static_cast<long long>(static_cast<size_t>(output_local) *
                                       output.channel_stride);
            vector<vector<double>> output_local_masks(static_cast<size_t>(fh * fw));
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    output_local_masks.at(static_cast<size_t>(kh * fw + kw)) =
                        packed_sparse_stride_output_mask(
                            output.slot_count, output.channel_stride, output_local,
                            input.h, input.w, out_h, out_w, stride, fh, fw, kh, kw);
                }
            }
            for (int input_channel = 0; input_channel < input.c; ++input_channel)
            {
                const size_t input_pack_index =
                    static_cast<size_t>(input_channel) /
                    static_cast<size_t>(input.channels_per_cipher);
                const int input_local = input_channel % input.channels_per_cipher;
                const long long input_base =
                    static_cast<long long>(static_cast<size_t>(input_local) *
                                           input.channel_stride);
                for (int kh = 0; kh < fh; ++kh)
                {
                    for (int kw = 0; kw < fw; ++kw)
                    {
                        const size_t weight_index = static_cast<size_t>(
                            fh * fw * input.c * output_channel +
                            fh * fw * input_channel + fw * kh + kw);
                        const double coeff = weights[weight_index] * folded_scale;
                        const Ciphertext &source = input.packs.at(input_pack_index);
                        if (coeff == 0.0 ||
                            local_coefficient_encodes_to_zero(source, coeff,
                                                              runtime.encoder))
                        {
                            continue;
                        }

                        const int spatial_step =
                            (kh - fh / 2) * input.w + (kw - fw / 2);
                        const long long step =
                            input_base - output_base +
                            static_cast<long long>(spatial_step);
                        Ciphertext rotated;
                        if (step == 0)
                        {
                            rotated = source;
                        }
                        else
                        {
                            rotate_with_direct_key(source, rotated, step, runtime);
                        }
                        Ciphertext masked = multiply_binary_mask_no_rescale(
                            rotated,
                            output_local_masks.at(static_cast<size_t>(kh * fw + kw)),
                            runtime);
                        Ciphertext term =
                            multiply_constant_scalar_rescale(masked, coeff, runtime);
                        if (!has_sum)
                        {
                            sum = std::move(term);
                            has_sum = true;
                        }
                        else
                        {
                            Ciphertext next_sum;
                            runtime.evaluator->add_dynamic(sum, term, next_sum,
                                                           runtime.encoder);
                            sum = std::move(next_sum);
                        }
                    }
                }
            }
        }
        if (!has_sum)
        {
            throw runtime_error("packed sparse stride conv output pack produced no encrypted terms");
        }
        output.packs.at(output_pack_index) = std::move(sum);
    });

    resnet18_progress_log() << "packed sparse stride conv encrypted pack progress: "
                            << output.packs.size() << "/" << output.packs.size() << endl;
    log_packed_channel_group_cipher_state("packed_sparse_stride_conv2d_all_channels output",
                                          output, runtime);
    return output;
}

PackedChannelCipherGroup packed_channel_add(const PackedChannelCipherGroup &lhs,
                                            const PackedChannelCipherGroup &rhs,
                                            PoseidonRuntime &runtime)
{
    log_packed_channel_group_cipher_state("packed_channel_add lhs input", lhs, runtime);
    log_packed_channel_group_cipher_state("packed_channel_add rhs input", rhs, runtime);
    if (lhs.h != rhs.h || lhs.w != rhs.w || lhs.c != rhs.c ||
        lhs.channels_per_cipher != rhs.channels_per_cipher ||
        lhs.channel_stride != rhs.channel_stride || lhs.packs.size() != rhs.packs.size())
    {
        throw invalid_argument("packed channel add layout mismatch");
    }
    PackedChannelCipherGroup output = lhs;
    output.packs.resize(lhs.packs.size());
    resnet18_progress_log() << "packed channel add parallel threads: "
                            << resnet18_parallel_thread_count(lhs.packs.size()) << endl;
    resnet18_parallel_for(lhs.packs.size(), [&](size_t pack_index) {
        Ciphertext lhs_cipher = lhs.packs.at(pack_index);
        Ciphertext rhs_cipher = rhs.packs.at(pack_index);
        const size_t lhs_chain = cipher_chain_index(runtime, lhs_cipher);
        const size_t rhs_chain = cipher_chain_index(runtime, rhs_cipher);
        if (lhs_chain > rhs_chain)
        {
            runtime.evaluator->drop_modulus(lhs_cipher, lhs_cipher, rhs_cipher.parms_id());
        }
        else if (rhs_chain > lhs_chain)
        {
            runtime.evaluator->drop_modulus(rhs_cipher, rhs_cipher, lhs_cipher.parms_id());
        }

        runtime.evaluator->add_dynamic(lhs_cipher, rhs_cipher,
                                       output.packs.at(pack_index), runtime.encoder);
    });
    log_packed_channel_group_cipher_state("packed_channel_add output", output, runtime);
    return output;
}

PackedChannelCipherGroup compact_sparse_stride_packed_channel_group(
    const PackedChannelCipherGroup &input, int dense_h, int dense_w, int stride,
    int output_channels_per_cipher, int logn, int logp, PoseidonRuntime &runtime)
{
    log_packed_channel_group_cipher_state("compact_sparse_stride_packed_channel_group input",
                                          input, runtime);
    if (stride <= 0 || dense_h <= 0 || dense_w <= 0 ||
        input.h < dense_h * stride || input.w < dense_w * stride)
    {
        throw invalid_argument("compact sparse stride packed group shape is invalid");
    }

    PackedChannelCipherGroup output;
    output.h = dense_h;
    output.w = dense_w;
    output.c = input.c;
    output.channels_per_cipher = output_channels_per_cipher;
    output.channel_stride = static_cast<size_t>(dense_h * dense_w);
    output.slot_count = input.slot_count;
    if (output.channel_stride * static_cast<size_t>(output.channels_per_cipher) >
        output.slot_count)
    {
        throw invalid_argument("compact sparse stride packed output does not fit in one ciphertext");
    }
    output.packs.resize((static_cast<size_t>(output.c) +
                         static_cast<size_t>(output.channels_per_cipher) - 1) /
                        static_cast<size_t>(output.channels_per_cipher));

    if (stride != 2)
    {
        throw invalid_argument("compact sparse stride packed group currently supports stride 2");
    }

    auto column_mask = [&](int ow) {
        vector<double> mask(input.slot_count, 0.0);
        for (int local = 0; local < input.channels_per_cipher; ++local)
        {
            const size_t base = static_cast<size_t>(local) * input.channel_stride;
            for (int oh = 0; oh < dense_h; ++oh)
            {
                mask[base + static_cast<size_t>((oh * stride) * input.w + ow)] = 1.0;
            }
        }
        return mask;
    };
    auto row_mask = [&](int oh) {
        vector<double> mask(input.slot_count, 0.0);
        for (int local = 0; local < input.channels_per_cipher; ++local)
        {
            const size_t base = static_cast<size_t>(local) * input.channel_stride;
            for (int ow = 0; ow < dense_w; ++ow)
            {
                mask[base + static_cast<size_t>(oh * dense_w + ow)] = 1.0;
            }
        }
        return mask;
    };
    auto output_channel_mask = [&](int output_local) {
        vector<double> mask(output.slot_count, 0.0);
        const size_t base = static_cast<size_t>(output_local) * output.channel_stride;
        for (size_t i = 0; i < output.channel_stride; ++i)
        {
            mask[base + i] = 1.0;
        }
        return mask;
    };

    vector<Ciphertext> spatial_compacted(input.packs.size());
    resnet18_parallel_for(input.packs.size(), [&](size_t pack_index) {
        Ciphertext column_sum;
        bool has_column_sum = false;
        for (int ow = 0; ow < dense_w; ++ow)
        {
            Ciphertext rotated;
            if (ow == 0)
            {
                rotated = input.packs.at(pack_index);
            }
            else
            {
                rotate_with_direct_key(input.packs.at(pack_index), rotated, ow, runtime);
            }
            Ciphertext term = multiply_binary_mask_no_rescale(rotated, column_mask(ow),
                                                              runtime);
            if (!has_column_sum)
            {
                column_sum = std::move(term);
                has_column_sum = true;
            }
            else
            {
                Ciphertext next_sum;
                runtime.evaluator->add_dynamic(column_sum, term, next_sum, runtime.encoder);
                column_sum = std::move(next_sum);
            }
        }
        if (!has_column_sum)
        {
            throw runtime_error("packed sparse compact column stage produced no terms");
        }

        Ciphertext row_sum;
        bool has_row_sum = false;
        for (int oh = 0; oh < dense_h; ++oh)
        {
            const int step = oh * (2 * input.w - dense_w);
            Ciphertext rotated;
            if (step == 0)
            {
                rotated = column_sum;
            }
            else
            {
                rotate_with_direct_key(column_sum, rotated, step, runtime);
            }
            Ciphertext term = multiply_binary_mask_no_rescale(rotated, row_mask(oh),
                                                              runtime);
            if (!has_row_sum)
            {
                row_sum = std::move(term);
                has_row_sum = true;
            }
            else
            {
                Ciphertext next_sum;
                runtime.evaluator->add_dynamic(row_sum, term, next_sum, runtime.encoder);
                row_sum = std::move(next_sum);
            }
        }
        if (!has_row_sum)
        {
            throw runtime_error("packed sparse compact row stage produced no terms");
        }
        spatial_compacted.at(pack_index) = std::move(row_sum);
    });

    vector<vector<double>> channel_masks(static_cast<size_t>(output.channels_per_cipher));
    for (int local = 0; local < output.channels_per_cipher; ++local)
    {
        channel_masks.at(static_cast<size_t>(local)) = output_channel_mask(local);
    }
    resnet18_parallel_for(output.packs.size(), [&](size_t output_pack_index) {
        Ciphertext pack_sum;
        bool has_pack_sum = false;
        for (int output_local = 0; output_local < output.channels_per_cipher; ++output_local)
        {
            const size_t channel =
                output_pack_index * static_cast<size_t>(output.channels_per_cipher) +
                static_cast<size_t>(output_local);
            if (channel >= static_cast<size_t>(output.c))
            {
                continue;
            }
            const size_t input_pack_index =
                channel / static_cast<size_t>(input.channels_per_cipher);
            const int input_local =
                static_cast<int>(channel % static_cast<size_t>(input.channels_per_cipher));
            const long long step =
                static_cast<long long>(static_cast<size_t>(input_local) *
                                       input.channel_stride) -
                static_cast<long long>(static_cast<size_t>(output_local) *
                                       output.channel_stride);
            Ciphertext rotated;
            if (step == 0)
            {
                rotated = spatial_compacted.at(input_pack_index);
            }
            else
            {
                rotate_with_direct_key(spatial_compacted.at(input_pack_index), rotated,
                                       step, runtime);
            }
            Ciphertext term = multiply_binary_mask_no_rescale(
                rotated, channel_masks.at(static_cast<size_t>(output_local)), runtime);
            if (!has_pack_sum)
            {
                pack_sum = std::move(term);
                has_pack_sum = true;
            }
            else
            {
                Ciphertext next_sum;
                runtime.evaluator->add_dynamic(pack_sum, term, next_sum, runtime.encoder);
                pack_sum = std::move(next_sum);
            }
        }
        if (!has_pack_sum)
        {
            throw runtime_error("packed sparse compact channel stage produced no terms");
        }
        output.packs.at(output_pack_index) = std::move(pack_sum);
    });
    (void)logn;
    (void)logp;
    log_packed_channel_group_cipher_state("compact_sparse_stride_packed_channel_group output",
                                          output, runtime);
    return output;
}

vector<int> packed_head_average_pool_rotation_steps(int channels, size_t channel_stride)
{
    set<int> steps;
    for (size_t offset = 1; offset < channel_stride; ++offset)
    {
        steps.insert(static_cast<int>(offset));
    }
    for (int channel = 1; channel < channels; ++channel)
    {
        const size_t source_slot = static_cast<size_t>(channel) * channel_stride;
        const size_t target_slot = static_cast<size_t>(channel);
        steps.insert(static_cast<int>(source_slot - target_slot));
    }
    return vector<int>(steps.begin(), steps.end());
}

TensorCipher encrypted_packed_head_average_pool(const PackedChannelCipherGroup &input,
                                                int logn, int logp, double boundary,
                                                PoseidonRuntime &runtime)
{
    if (input.packs.size() != 1 || input.channels_per_cipher < input.c ||
        input.h <= 0 || input.w <= 0 ||
        input.channel_stride != static_cast<size_t>(input.h * input.w))
    {
        throw invalid_argument("head average pool expects one dense packed final feature group");
    }

    vector<double> channel_base_mask(input.slot_count, 0.0);
    for (int channel = 0; channel < input.c; ++channel)
    {
        channel_base_mask[static_cast<size_t>(channel) * input.channel_stride] = 1.0;
    }

    Ciphertext base_average_sum;
    bool has_base_sum = false;
    for (size_t offset = 0; offset < input.channel_stride; ++offset)
    {
        Ciphertext rotated;
        if (offset == 0)
        {
            rotated = input.packs.front();
        }
        else
        {
            rotate_with_direct_key(input.packs.front(), rotated,
                                   static_cast<long long>(offset), runtime);
        }
        Ciphertext term = multiply_binary_mask_no_rescale(rotated, channel_base_mask, runtime);
        if (!has_base_sum)
        {
            base_average_sum = std::move(term);
            has_base_sum = true;
        }
        else
        {
            Ciphertext next_sum;
            runtime.evaluator->add_dynamic(base_average_sum, term, next_sum,
                                           runtime.encoder);
            base_average_sum = std::move(next_sum);
        }
    }
    if (!has_base_sum)
    {
        throw runtime_error("head average pool spatial sum produced no encrypted terms");
    }

    Ciphertext compacted_sum;
    bool has_compacted_sum = false;
    for (int channel = 0; channel < input.c; ++channel)
    {
        const size_t source_slot = static_cast<size_t>(channel) * input.channel_stride;
        const size_t target_slot = static_cast<size_t>(channel);
        const size_t step = source_slot - target_slot;
        Ciphertext rotated;
        if (step == 0)
        {
            rotated = base_average_sum;
        }
        else
        {
            rotate_with_direct_key(base_average_sum, rotated,
                                   static_cast<long long>(step), runtime);
        }

        vector<double> target_mask(input.slot_count, 0.0);
        target_mask[target_slot] = 1.0;
        Ciphertext term = multiply_binary_mask_no_rescale(rotated, target_mask, runtime);
        if (!has_compacted_sum)
        {
            compacted_sum = std::move(term);
            has_compacted_sum = true;
        }
        else
        {
            Ciphertext next_sum;
            runtime.evaluator->add_dynamic(compacted_sum, term, next_sum, runtime.encoder);
            compacted_sum = std::move(next_sum);
        }
    }
    if (!has_compacted_sum)
    {
        throw runtime_error("head average pool channel compact produced no encrypted terms");
    }

    Ciphertext averaged;
    const double average_coeff = boundary / static_cast<double>(input.channel_stride);
    runtime.evaluator->multiply_const(compacted_sum, average_coeff, runtime.scale, averaged,
                                      runtime.encoder);
    runtime.evaluator->rescale_dynamic(averaged, averaged, compacted_sum.scale());
    averaged.scale() = compacted_sum.scale();

    (void)logp;
    TensorCipher output(logn, 1, 1, 1, input.c, 1, 1, averaged);
    log_tensor_cipher_state("head avgpool encrypted packed output", output, runtime);
    return output;
}

vector<double> multiplexed_head_column_base_mask(const MultiplexedCipherGroup &input)
{
    vector<double> mask(input.slot_count, 0.0);
    for (int channel = 0; channel < input.c; ++channel)
    {
        for (int row = 0; row < input.h; ++row)
        {
            mask[multiplexed_slot_index(input, channel, row, 0)] = 1.0;
        }
    }
    return mask;
}

vector<double> multiplexed_head_channel_base_mask(const MultiplexedCipherGroup &input)
{
    vector<double> mask(input.slot_count, 0.0);
    for (int channel = 0; channel < input.c; ++channel)
    {
        mask[multiplexed_slot_index(input, channel, 0, 0)] = 1.0;
    }
    return mask;
}

vector<int> multiplexed_head_average_pool_rotation_steps(const MultiplexedCipherGroup &input)
{
    if (input.h <= 0 || input.w <= 0 || input.k <= 0)
    {
        throw invalid_argument("multiplexed head avgpool input shape is invalid");
    }

    set<int> steps;
    for (int col = 1; col < input.w; ++col)
    {
        steps.insert(col * input.k);
    }
    const int page_width = input.w * input.k;
    for (int row = 1; row < input.h; ++row)
    {
        steps.insert(row * input.k * page_width);
    }
    for (int channel = 0; channel < input.c; ++channel)
    {
        const size_t source_slot = multiplexed_slot_index(input, channel, 0, 0);
        const size_t target_slot = static_cast<size_t>(channel);
        const long long step =
            static_cast<long long>(source_slot) - static_cast<long long>(target_slot);
        if (step != 0)
        {
            steps.insert(static_cast<int>(step));
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

TensorCipher encrypted_multiplexed_head_average_pool(
    const MultiplexedCipherGroup &input, int logn, int logp, double boundary,
    PoseidonRuntime &runtime)
{
    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;
    if (input.packs.size() != 1 || input.h <= 0 || input.w <= 0 || input.c <= 0)
    {
        throw invalid_argument("head average pool expects one multiplexed final feature group");
    }
    log_multiplexed_group_cipher_state("head avgpool multiplexed input", input, runtime);

    const vector<double> column_mask = multiplexed_head_column_base_mask(input);
    Ciphertext column_sum;
    bool has_column_sum = false;
    for (int col = 0; col < input.w; ++col)
    {
        const int step = col * input.k;
        Ciphertext rotated;
        if (step == 0)
        {
            rotated = input.packs.front();
        }
        else
        {
            rotate_with_direct_key(input.packs.front(), rotated, step, runtime);
        }
        Ciphertext term = multiply_binary_mask_no_rescale(rotated, column_mask, runtime);
        if (!has_column_sum)
        {
            column_sum = std::move(term);
            has_column_sum = true;
        }
        else
        {
            Ciphertext next_sum;
            runtime.evaluator->add_dynamic(column_sum, term, next_sum, runtime.encoder);
            column_sum = std::move(next_sum);
        }
    }
    if (!has_column_sum)
    {
        throw runtime_error("multiplexed head avgpool column stage produced no terms");
    }

    const vector<double> channel_base_mask = multiplexed_head_channel_base_mask(input);
    vector<double> scaled_channel_base_mask = channel_base_mask;
    const double average_coeff =
        boundary / static_cast<double>(input.h * input.w);
    for (double &value : scaled_channel_base_mask)
    {
        value *= average_coeff;
    }
    const int page_width = input.w * input.k;
    Ciphertext spatial_sum;
    bool has_spatial_sum = false;
    for (int row = 0; row < input.h; ++row)
    {
        const int step = row * input.k * page_width;
        Ciphertext rotated;
        if (step == 0)
        {
            rotated = column_sum;
        }
        else
        {
            rotate_with_direct_key(column_sum, rotated, step, runtime);
        }
        Ciphertext term = multiply_binary_mask_no_rescale(
            rotated, scaled_channel_base_mask, runtime);
        if (!has_spatial_sum)
        {
            spatial_sum = std::move(term);
            has_spatial_sum = true;
        }
        else
        {
            Ciphertext next_sum;
            runtime.evaluator->add_dynamic(spatial_sum, term, next_sum, runtime.encoder);
            spatial_sum = std::move(next_sum);
        }
    }
    if (!has_spatial_sum)
    {
        throw runtime_error("multiplexed head avgpool row stage produced no terms");
    }

    Ciphertext compacted_sum;
    bool has_compacted_sum = false;
    for (int channel = 0; channel < input.c; ++channel)
    {
        const size_t source_slot = multiplexed_slot_index(input, channel, 0, 0);
        const size_t target_slot = static_cast<size_t>(channel);
        const long long step =
            static_cast<long long>(source_slot) - static_cast<long long>(target_slot);
        Ciphertext rotated;
        if (step == 0)
        {
            rotated = spatial_sum;
        }
        else
        {
            rotate_with_direct_key(spatial_sum, rotated, step, runtime);
        }

        vector<double> target_mask(input.slot_count, 0.0);
        target_mask[target_slot] = 1.0;
        Ciphertext term = multiply_binary_mask_no_rescale(rotated, target_mask, runtime);
        if (!has_compacted_sum)
        {
            compacted_sum = std::move(term);
            has_compacted_sum = true;
        }
        else
        {
            Ciphertext next_sum;
            runtime.evaluator->add_dynamic(compacted_sum, term, next_sum,
                                           runtime.encoder);
            compacted_sum = std::move(next_sum);
        }
    }
    if (!has_compacted_sum)
    {
        throw runtime_error("multiplexed head avgpool compact stage produced no terms");
    }

    Ciphertext averaged;
    runtime.evaluator->drop_modulus_to_next(compacted_sum, averaged);
    averaged.scale() = compacted_sum.scale();

    (void)logp;
    TensorCipher output(logn, 1, 1, 1, input.c, 1, 1, averaged);
    log_tensor_cipher_state("head avgpool encrypted multiplexed output", output, runtime);
    return output;
}

ChannelCipherGroup unpack_packed_channel_group(const PackedChannelCipherGroup &input,
                                               PoseidonRuntime &runtime)
{
    ChannelCipherGroup output;
    output.h = input.h;
    output.w = input.w;
    output.c = input.c;
    output.spatial_count = input.channel_stride;
    output.slot_count = input.slot_count;
    output.channels.resize(static_cast<size_t>(input.c));

    vector<vector<double>> local_masks;
    local_masks.reserve(static_cast<size_t>(input.channels_per_cipher));
    for (int local = 0; local < input.channels_per_cipher; ++local)
    {
        local_masks.emplace_back(
            packed_channel_mask(input.slot_count, input.channel_stride, local));
    }
    resnet18_parallel_for(static_cast<size_t>(input.c), [&](size_t channel) {
        const size_t pack_index = channel / static_cast<size_t>(input.channels_per_cipher);
        const int local = static_cast<int>(channel % static_cast<size_t>(input.channels_per_cipher));
        if (local == 0)
        {
            output.channels.at(channel) =
                multiply_binary_mask_no_rescale(input.packs.at(pack_index),
                                                local_masks.at(static_cast<size_t>(local)),
                                                runtime);
        }
        else
        {
            Ciphertext masked =
                multiply_binary_mask_no_rescale(input.packs.at(pack_index),
                                                local_masks.at(static_cast<size_t>(local)),
                                                runtime);
            rotate_with_direct_key(
                masked, output.channels.at(channel),
                static_cast<long long>(static_cast<size_t>(local) * input.channel_stride),
                runtime);
        }
    });
    return output;
}

class ScopedDurationLog
{
public:
    explicit ScopedDurationLog(string label)
        : label_(std::move(label)), start_(chrono::steady_clock::now())
    {
        resnet18_progress_log() << "[start] " << label_ << endl;
    }

    ~ScopedDurationLog()
    {
        const auto end = chrono::steady_clock::now();
        const auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start_).count();
        resnet18_progress_log() << "[duration] " << label_ << ": " << elapsed << " ms" << endl;
    }

private:
    string label_;
    chrono::steady_clock::time_point start_;
};

vector<double> decode_real_slots(const TensorCipher &tensor, PoseidonRuntime &runtime, size_t count)
{
    Plaintext plain;
    runtime.decryptor.decrypt(tensor.cipher(), plain);

    vector<complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);

    const size_t copy_count = min(count, decoded.size());
    vector<double> values(copy_count, 0.0);
    for (size_t i = 0; i < copy_count; ++i)
    {
        values[i] = decoded[i].real();
    }
    return values;
}

vector<complex<double>> decode_complex_slots(const TensorCipher &tensor,
                                             PoseidonRuntime &runtime,
                                             size_t count)
{
    Plaintext plain;
    runtime.decryptor.decrypt(tensor.cipher(), plain);

    vector<complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);

    const size_t copy_count = min(count, decoded.size());
    vector<complex<double>> values(copy_count, complex<double>(0.0, 0.0));
    for (size_t i = 0; i < copy_count; ++i)
    {
        values[i] = decoded[i];
    }
    return values;
}

int argmax_index(const vector<double> &values)
{
    if (values.empty())
    {
        throw invalid_argument("argmax input should not be empty");
    }
    return static_cast<int>(max_element(values.begin(), values.end()) - values.begin());
}

void insert_normalized_rotation_step(set<int> &steps, long long step,
                                     size_t slot_count)
{
    const int normalized = normalize_rotation_step(step, slot_count);
    if (normalized != 0)
    {
        steps.insert(normalized);
    }
}

void insert_normalized_rotation_steps(set<int> &destination,
                                      const vector<int> &source,
                                      size_t slot_count)
{
    for (const int step : source)
    {
        insert_normalized_rotation_step(destination, step, slot_count);
    }
}

MultiplexedCipherGroup collect_compact_conv_direct_rotation_steps(
    set<int> &steps, const MultiplexedCipherGroup &input, int out_channels,
    int stride, int fh, int fw)
{
    if ((stride != 1 && stride != 2) || fh <= 0 || fw <= 0 ||
        fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("invalid compact conv shape while collecting rotations");
    }

    const int out_k = stride == 1 ? input.k : input.k * 2;
    MultiplexedCipherGroup output = make_multiplexed_shape(
        input.h / stride, input.w / stride, out_channels, out_k,
        input.slot_count);

    for (int kh = 0; kh < fh; ++kh)
    {
        for (int kw = 0; kw < fw; ++kw)
        {
            insert_normalized_rotation_step(
                steps,
                multiplexed_spatial_kernel_rotation_step(input, fh, fw, kh, kw),
                input.slot_count);
        }
    }

    const int log_k = exact_log2_power_of_two(input.k);
    if (log_k < 0)
    {
        throw invalid_argument("compact conv k is not a power of two");
    }
    for (int x = 0; x < log_k; ++x)
    {
        insert_normalized_rotation_step(steps, pow2_int(x), input.slot_count);
        insert_normalized_rotation_step(
            steps,
            static_cast<long long>(pow2_int(x)) * input.k * input.w,
            input.slot_count);
    }
    for (int page = 1; page < input.pages_per_cipher; ++page)
    {
        insert_normalized_rotation_step(
            steps, static_cast<long long>(page) * input.page_size,
            input.slot_count);
    }
    for (int output_channel = 0; output_channel < output.c; ++output_channel)
    {
        insert_normalized_rotation_step(
            steps,
            multiplexed_output_channel_select_rotation_step(output, output_channel),
            output.slot_count);
    }
    return output;
}

vector<int> resnet18_network_direct_rotation_steps(size_t slot_count)
{
    set<int> steps;

    MultiplexedCipherGroup current = make_multiplexed_shape(
        kImageNetInputHeight / 2, kImageNetInputWidth / 2, 64, 1,
        slot_count);
    insert_normalized_rotation_step(
        steps, -static_cast<long long>(current.page_size), slot_count);

    MultiplexedCipherGroup pooled = make_multiplexed_shape(
        current.h / 2, current.w / 2, current.c, 2, slot_count);
    insert_normalized_rotation_steps(
        steps,
        multiplexed_average_pool2d_stride2_rotation_steps(
            current, pooled.h, pooled.w, pooled.k),
        slot_count);
    current = std::move(pooled);

    // layer1 has two BasicBlocks with two 3x3 convolutions each.
    for (int convolution = 0; convolution < 4; ++convolution)
    {
        current = collect_compact_conv_direct_rotation_steps(
            steps, current, 64, 1, 3, 3);
    }

    // layer2..layer4 each contain a stride-2 BasicBlock (including its 1x1
    // shortcut) followed by a stride-1 BasicBlock.
    for (const int out_channels : {128, 256, 512})
    {
        const MultiplexedCipherGroup block_input = current;
        MultiplexedCipherGroup block_output;
        if (should_use_fused_conv_bsgs(
                block_input, out_channels, 2, 3, 3))
        {
            block_output = collect_fused_conv_bsgs_rotation_steps(
                steps, block_input, out_channels, 2, 3, 3);
        }
        else
        {
            block_output = collect_compact_conv_direct_rotation_steps(
                steps, block_input, out_channels, 2, 3, 3);
        }
        if (should_use_fused_conv_bsgs(
                block_output, out_channels, 1, 3, 3))
        {
            block_output = collect_fused_conv_bsgs_rotation_steps(
                steps, block_output, out_channels, 1, 3, 3);
        }
        else
        {
            block_output = collect_compact_conv_direct_rotation_steps(
                steps, block_output, out_channels, 1, 3, 3);
        }
        MultiplexedCipherGroup shortcut;
        if (should_use_fused_conv_bsgs(
                block_input, out_channels, 2, 1, 1))
        {
            shortcut = collect_fused_conv_bsgs_rotation_steps(
                steps, block_input, out_channels, 2, 1, 1);
        }
        else
        {
            shortcut = collect_compact_conv_direct_rotation_steps(
                steps, block_input, out_channels, 2, 1, 1);
        }
        if (block_output.h != shortcut.h || block_output.w != shortcut.w ||
            block_output.c != shortcut.c || block_output.k != shortcut.k)
        {
            throw logic_error("ResNet18 shortcut rotation shape mismatch");
        }
        current = std::move(block_output);
        for (int convolution = 0; convolution < 2; ++convolution)
        {
            if (should_use_fused_conv_bsgs(
                    current, out_channels, 1, 3, 3))
            {
                current = collect_fused_conv_bsgs_rotation_steps(
                    steps, current, out_channels, 1, 3, 3);
            }
            else
            {
                current = collect_compact_conv_direct_rotation_steps(
                    steps, current, out_channels, 1, 3, 3);
            }
        }
    }

    insert_normalized_rotation_steps(
        steps, multiplexed_head_average_pool_rotation_steps(current), slot_count);
    insert_normalized_rotation_steps(
        steps,
        fully_connected_bsgs_rotation_steps(
            kImageNetClassCount, kResNet18FinalChannels, slot_count),
        slot_count);
    return vector<int>(steps.begin(), steps.end());
}

int bootstrap_bsgs_giant_step(int count)
{
    int best_value = count;
    int best_k = 1;
    for (int k = 1; k <= static_cast<int>(3 * sqrt(count)); ++k)
    {
        const int value = static_cast<int>(ceil(static_cast<double>(count) / k)) +
                          k - 1;
        if (value < best_value)
        {
            best_value = value;
            best_k = k;
        }
    }
    return best_k;
}

void collect_bootstrap_bsgs_rotation_steps(set<int> &steps, int total_len,
                                           int basic_step, size_t slot_count,
                                           bool rotated_variant)
{
    if (rotated_variant)
    {
        const int gs = bootstrap_bsgs_giant_step(total_len + 1);
        for (int i = 1; i < gs; ++i)
        {
            insert_normalized_rotation_step(
                steps, static_cast<long long>(i) * basic_step, slot_count);
        }
        for (int i = 1; i <= total_len / gs; ++i)
        {
            insert_normalized_rotation_step(
                steps, static_cast<long long>(i) * gs * basic_step,
                slot_count);
        }
        return;
    }

    const int gs = bootstrap_bsgs_giant_step(2 * total_len + 1);
    const int basic_start = -total_len + gs * (total_len / gs);
    const int giant_first = -(total_len / gs);
    const int giant_last = (2 * total_len / gs) + giant_first;
    for (int i = basic_start; i < basic_start + gs; ++i)
    {
        insert_normalized_rotation_step(
            steps, static_cast<long long>(i) * basic_step, slot_count);
    }
    for (int i = giant_first; i <= giant_last; ++i)
    {
        insert_normalized_rotation_step(
            steps, static_cast<long long>(i) * gs * basic_step, slot_count);
    }
}

vector<int> bootstrap_direct_rotation_steps(long log_slots, size_t slot_count)
{
    if (log_slots <= 0 || log_slots >= 31 ||
        slot_count != (static_cast<size_t>(1) << log_slots))
    {
        throw invalid_argument("invalid bootstrap rotation slot configuration");
    }

    set<int> steps;
    const int slot_to_coeff_div3 = static_cast<int>(floor(log_slots / 3.0));
    const int slot_to_coeff_div2 =
        static_cast<int>(floor((log_slots - slot_to_coeff_div3) / 2.0));
    const int slot_to_coeff_div1 =
        static_cast<int>(log_slots) - slot_to_coeff_div3 - slot_to_coeff_div2;
    collect_bootstrap_bsgs_rotation_steps(
        steps, (1 << slot_to_coeff_div1) - 1, 1, slot_count, false);
    collect_bootstrap_bsgs_rotation_steps(
        steps, (1 << slot_to_coeff_div2) - 1, 1 << slot_to_coeff_div1,
        slot_count, false);
    collect_bootstrap_bsgs_rotation_steps(
        steps, (1 << slot_to_coeff_div3) - 1,
        1 << (slot_to_coeff_div1 + slot_to_coeff_div2), slot_count, true);

    const int coeff_to_slot_div1 = static_cast<int>(floor(log_slots / 3.0));
    const int coeff_to_slot_div2 =
        static_cast<int>(floor((log_slots - coeff_to_slot_div1) / 2.0));
    const int coeff_to_slot_div3 =
        static_cast<int>(log_slots) - coeff_to_slot_div1 - coeff_to_slot_div2;
    collect_bootstrap_bsgs_rotation_steps(
        steps, (1 << coeff_to_slot_div1) - 1,
        1 << (static_cast<int>(log_slots) - coeff_to_slot_div1),
        slot_count, true);
    collect_bootstrap_bsgs_rotation_steps(
        steps, (1 << coeff_to_slot_div2) - 1,
        1 << (static_cast<int>(log_slots) - coeff_to_slot_div1 -
              coeff_to_slot_div2),
        slot_count, false);
    collect_bootstrap_bsgs_rotation_steps(
        steps, (1 << coeff_to_slot_div3) - 1, 1, slot_count, false);
    return vector<int>(steps.begin(), steps.end());
}

void prepare_resnet18_evaluation_keys(PoseidonRuntime &runtime, ofstream &output)
{
    const auto key_time_start = chrono::steady_clock::now();

    const vector<int> network_steps =
        resnet18_network_direct_rotation_steps(runtime.slot_count);
    const vector<int> bootstrap_steps = bootstrap_direct_rotation_steps(
        runtime.context.parameters_literal()->log_slots(), runtime.slot_count);
    set<int> merged_steps(network_steps.begin(), network_steps.end());
    merged_steps.insert(bootstrap_steps.begin(), bootstrap_steps.end());
    // Retain the complete signed power-of-two basis as a compatibility
    // fallback for diagnostic/legacy paths that are not part of the fixed
    // inference topology above.
    for (size_t step = 1; step < runtime.slot_count; step <<= 1)
    {
        insert_normalized_rotation_step(merged_steps,
                                        static_cast<long long>(step),
                                        runtime.slot_count);
        insert_normalized_rotation_step(merged_steps,
                                        -static_cast<long long>(step),
                                        runtime.slot_count);
    }
    // Step zero selects the CKKS complex-conjugation key used by bootstrap
    // and by the real projection in the homomorphic ReLU path.
    merged_steps.insert(0);
    const vector<int> galois_steps(merged_steps.begin(), merged_steps.end());

    output << "prepare evaluation key plan: galois_key_mode="
              "direct_resnet18_and_bootstrap_rotations"
           << ", network_rotation_key_count=" << network_steps.size()
           << ", bootstrap_rotation_key_count=" << bootstrap_steps.size()
           << ", compatibility_basis=complete_signed_power_of_two"
           << ", merged_galois_key_count=" << galois_steps.size() << '\n'
           << flush;
    resnet18_progress_log()
        << "prepare evaluation key plan: direct ResNet18 and bootstrap rotations"
        << ", network=" << network_steps.size()
        << ", bootstrap=" << bootstrap_steps.size()
        << ", merged_with_conjugation=" << galois_steps.size() << endl;

    KeyGenerator keygen(runtime.context, runtime.secret_key);
    keygen.create_relin_keys(runtime.relin_keys);
    keygen.create_galois_keys(galois_steps, runtime.galois_keys);
    output << "prepare evaluation keys: ready before first image\n";
    resnet18_progress_log()
        << "prepare evaluation keys: all direct keys ready before first image"
        << endl;

    const auto elapsed = chrono::duration_cast<chrono::milliseconds>(
                             chrono::steady_clock::now() - key_time_start)
                             .count();
    output << "prepare evaluation keys time: " << elapsed << " ms\n";
    resnet18_progress_log() << "[duration] prepare evaluation keys: " << elapsed
                            << " ms" << endl;
}

} // namespace

void ResNet_imagenet_sparse(size_t start_image_id, size_t end_image_id,
                            const ResNet18RunOptions &options)
{
    // Measure the complete inference run, including configuration, Poseidon context
    // construction, evaluation-key generation, input processing, and all images.
    const auto all_time_start = chrono::steady_clock::now();
    const PoseidonInferPlan plan = default_poseidon_plan(options.dnum);
    resnet18_execution::set_inference_only(options.inference_only);
    const size_t image_value_count =
        static_cast<size_t>(kImageNetInputHeight * kImageNetInputWidth * kImageNetInputChannels);
    const string run_timestamp = make_run_timestamp();
    ReluConfig relu_config = default_relu_config(plan);
    const MockExecutionOptions mock_options = read_mock_execution_options();

    fs::create_directories(result_dir());
    const fs::path run_result_path =
        result_dir() / (string(kResNet18ResultPrefix) + "_run_" + to_string(start_image_id) +
                        "_" + to_string(end_image_id) + "_" + run_timestamp + ".txt");
    ofstream out_log(run_result_path);
    if (!out_log.is_open())
    {
        throw runtime_error("failed to open run log file");
    }
    ScopedProgressLogTarget progress_log_target(out_log);

    resnet18_progress_log() << "Setting Poseidon Parameters" << endl;
    PoseidonRuntime runtime = make_poseidon_runtime(plan, false);
    resnet18_progress_log() << "Poseidon slot count: " << runtime.slot_count << endl;
    resnet18_progress_log() << "Poseidon scale: " << runtime.scale << endl;
    resnet18_progress_log()
        << "Poseidon modulus config: Q=1x45 + 20x40 + 14x45 (35 primes, 1475 bits)"
        << ", P=" << logp_chain(plan.logq_chain.size(), plan.dnum).size()
        << "x51, dnum=" << plan.dnum << endl;
    resnet18_progress_log()
        << "Poseidon scales: compute=" << plan.log_scale
        << " bits, bootstrap_evalmod=" << runtime.bootstrap_config.scaling_log
        << " bits, bootstrap_output="
        << runtime.bootstrap_config.output_scaling_log << " bits" << endl;
    resnet18_progress_log() << "ImageNet input values: " << image_value_count << endl;

    out_log << "run_start: start_image_id=" << start_image_id
            << ", end_image_id=" << end_image_id
            << ", dnum=" << plan.dnum
            << ", q_config=1x45+20x40+14x45"
            << ", p_count="
            << logp_chain(plan.logq_chain.size(), plan.dnum).size()
            << ", p_prime_bits=51"
            << ", compute_scale_bits=" << plan.log_scale
            << ", bootstrap_scale_bits=" << runtime.bootstrap_config.scaling_log
            << ", bootstrap_output_scale_bits="
            << runtime.bootstrap_config.output_scaling_log
            << ", plain_relu_reference=homomorphic_polynomial"
            << ", mock_relu=" << (mock_options.mock_relu ? 1 : 0)
            << ", mock_bootstrap=" << (mock_options.mock_bootstrap ? 1 : 0)
            << ", inference_only=" << (options.inference_only ? 1 : 0)
            << ", fused_conv_bsgs=" << (fused_conv_bsgs_enabled() ? 1 : 0)
            << ", transition_bsgs=" << (transition_bsgs_enabled() ? 1 : 0)
            << ", layer2_transition_bsgs="
            << (layer2_transition_bsgs_enabled() ? 1 : 0)
            << ", layer3_bsgs=" << (layer3_bsgs_enabled() ? 1 : 0)
            << ", layer4_bsgs=" << (layer4_bsgs_enabled() ? 1 : 0)
            << ", post_bootstrap_relu_input_level="
            << post_bootstrap_relu_input_level()
            << ", fused_bsgs_cache_mb="
            << fused_conv_bsgs_cache_limit_bytes() / (1024ULL * 1024ULL)
            << ", conv_plaintext_cache_mb=" << options.conv_plaintext_cache_mb
            << ", run_timestamp=" << run_timestamp
            << ", log_file=" << run_result_path << '\n';
    prepare_resnet18_evaluation_keys(runtime, out_log);

    const auto plaintext_prepare_start = chrono::steady_clock::now();
    ModelWeights weights = load_resnet18_parameters();
    const auto &parms_id_map = runtime.context.crt_context()->parms_id_map();
    const auto fc_input_parms_it = parms_id_map.find(2);
    const auto fc_output_parms_it = parms_id_map.find(1);
    if (fc_input_parms_it == parms_id_map.end() ||
        fc_output_parms_it == parms_id_map.end())
    {
        throw runtime_error("failed to locate FC input/output levels for plaintext plan");
    }
    FullyConnectedBsgsPlainPlan fc_plain_plan =
        prepare_fully_connected_bsgs_plain_plan(
            weights.linear_weight, weights.linear_bias,
            kImageNetClassCount, kResNet18FinalChannels,
            static_cast<int>(plan.logN), fc_input_parms_it->second,
            runtime.scale, fc_output_parms_it->second, runtime.encoder);
    const auto plaintext_prepare_ms = chrono::duration_cast<chrono::milliseconds>(
        chrono::steady_clock::now() - plaintext_prepare_start).count();
    out_log << "prepare FC BSGS plaintext plan: baby_step="
            << fc_plain_plan.baby_step
            << ", groups=" << fc_plain_plan.groups.size()
            << ", encoded_bytes=" << fc_plain_plan.encoded_bytes
            << ", time_ms=" << plaintext_prepare_ms << '\n';
    resnet18_progress_log()
        << "prepare FC BSGS plaintext plan: encoded_bytes="
        << fc_plain_plan.encoded_bytes << ", time_ms=" << plaintext_prepare_ms
        << endl;

    if (options.conv_plaintext_cache_mb >
        numeric_limits<size_t>::max() / (1024ULL * 1024ULL))
    {
        throw invalid_argument("conv plaintext cache size is too large");
    }
    const size_t conv_plaintext_cache_bytes =
        options.conv_plaintext_cache_mb * 1024ULL * 1024ULL;
    ConvPlaintextCache conv_plaintext_cache(conv_plaintext_cache_bytes);
    ScopedConvPlaintextCache scoped_conv_plaintext_cache(conv_plaintext_cache);
    out_log << "conv plaintext cache: max_bytes="
            << conv_plaintext_cache.max_bytes()
            << ", policy=bounded_lru_layer_identity\n";
    resnet18_progress_log()
        << "conv plaintext cache: max_bytes="
        << conv_plaintext_cache.max_bytes()
        << ", policy=bounded LRU by layer/input-pack/kernel/output-channel"
        << endl;

    for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
    {
        const auto image_time_start = chrono::high_resolution_clock::now();
        out_log << "image_start: " << image_id << '\n';
        out_log.flush();
        ofstream &output = out_log;

        output << "\n==================== run_start ====================\n";
        output << "image_id: " << image_id << '\n';
        output << "run_timestamp: " << run_timestamp << '\n';
        output << "log_file: " << run_result_path << '\n';

        vector<double> image_values = read_plain_image_values(image_id, plan.boundary);
        const int image_label = read_image_label(image_id);

        output << "runtime: poseidon ready\n";
        output << "input values=" << image_values.size()
               << ", slot_count=" << runtime.slot_count << '\n';

        PlainTensor plain_input;
        if (!resnet18_execution::inference_only())
        {
            plain_input = PlainTensor(
                kImageNetInputHeight, kImageNetInputWidth,
                kImageNetInputChannels, image_values);
        }
        PlainTensor plain_conv1 = plain_convolution(
            plain_input, 64, 2, 7, 7, weights.conv_weight.at(0), weights.bn_running_var.at(0),
            weights.bn_weight.at(0), kBatchNormEpsilon);

        output << "conv1 im2col packing: encrypting 7x7x3 patch ciphertexts\n";
        resnet18_progress_log() << "conv1 im2col encrypt patches" << endl;
        Im2ColCipherGroup conv1_im2col = encrypt_conv2d_im2col_patches(
            image_values, kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels, 2, 7,
            7, runtime, plan.log_scale);
        output << "conv1 im2col bootstrap tail retained for stem computation\n";
        resnet18_progress_log()
            << "conv1 im2col bootstrap tail retained for stem computation" << endl;
        log_cipher_vector_level_summary("conv1 im2col patches with bootstrap tail retained",
                                        conv1_im2col.patches, runtime);
        output << "conv1 im2col patches: " << conv1_im2col.patches.size()
               << ", spatial_count=" << conv1_im2col.spatial_count << '\n';
        resnet18_progress_log() << "conv1 im2col patches: " << conv1_im2col.patches.size() << endl;

        PlainTensor plain_conv1_bn =
            plain_batch_norm(plain_conv1, weights.bn_bias.at(0), weights.bn_running_mean.at(0),
                             weights.bn_running_var.at(0), weights.bn_weight.at(0),
                             kBatchNormEpsilon, kResNet18Boundary);
        PlainTensor plain_conv1_relu =
            plain_polynomial_relu_reference(plain_conv1_bn, relu_config);
        PlainTensor plain_conv1_pool = plain_average_pool2d(plain_conv1_relu, 3, 2, 1);

        double stem_conv1_all_max_abs_error = -1.0;
        double stem_bn_all_max_abs_error = -1.0;
        double stem_relu_refresh_all_max_abs_error = -1.0;
        double stem_avgpool_all_max_abs_error = -1.0;
        double stem_multiplex_avgpool_all_max_abs_error = -1.0;
        double layer1_block0_conv1_multiplex_all_max_abs_error = -1.0;
        double layer1_block0_bn1_multiplex_all_max_abs_error = -1.0;
        double layer1_block0_relu1_multiplex_refresh_all_max_abs_error = -1.0;
        double layer1_block0_conv2_multiplex_all_max_abs_error = -1.0;
        double layer1_block0_bn2_multiplex_all_max_abs_error = -1.0;
        double layer1_block0_add_multiplex_all_max_abs_error = -1.0;
        double layer1_block0_output_multiplex_refresh_all_max_abs_error = -1.0;
        double layer1_block0_conv1_all_max_abs_error = -1.0;
        double layer1_block0_bn1_all_max_abs_error = -1.0;
        double layer1_block0_relu1_refresh_all_max_abs_error = -1.0;
        double layer1_block0_conv2_all_max_abs_error = -1.0;
        double layer1_block0_bn2_all_max_abs_error = -1.0;
        double layer1_block0_add_all_max_abs_error = -1.0;
        double layer1_block0_output_refresh_all_max_abs_error = -1.0;
        double layer1_block1_conv1_all_max_abs_error = -1.0;
        double layer1_block1_bn1_all_max_abs_error = -1.0;
        double layer1_block1_relu1_refresh_all_max_abs_error = -1.0;
        double layer1_block1_conv2_all_max_abs_error = -1.0;
        double layer1_block1_bn2_all_max_abs_error = -1.0;
        double layer1_block1_add_all_max_abs_error = -1.0;
        double layer1_block1_output_refresh_all_max_abs_error = -1.0;
        double layer2_block0_conv1_sparse_max_abs_error = -1.0;
        double layer2_block0_bn1_sparse_max_abs_error = -1.0;
        double layer2_block0_relu1_refresh_all_max_abs_error = -1.0;
        double layer2_block0_conv2_all_max_abs_error = -1.0;
        double layer2_block0_bn2_all_max_abs_error = -1.0;
        double layer2_block0_shortcut_all_max_abs_error = -1.0;
        double layer2_block0_add_all_max_abs_error = -1.0;
        double layer2_block0_output_refresh_all_max_abs_error = -1.0;
        double layer2_block1_conv1_all_max_abs_error = -1.0;
        double layer2_block1_bn1_all_max_abs_error = -1.0;
        double layer2_block1_relu1_refresh_all_max_abs_error = -1.0;
        double layer2_block1_conv2_all_max_abs_error = -1.0;
        double layer2_block1_bn2_all_max_abs_error = -1.0;
        double layer2_block1_add_all_max_abs_error = -1.0;
        double layer2_block1_output_refresh_all_max_abs_error = -1.0;
        double layer3_block0_conv1_sparse_max_abs_error = -1.0;
        double layer3_block0_bn1_sparse_max_abs_error = -1.0;
        double layer3_block0_relu1_refresh_all_max_abs_error = -1.0;
        double layer3_block0_conv2_all_max_abs_error = -1.0;
        double layer3_block0_bn2_all_max_abs_error = -1.0;
        double layer3_block0_shortcut_all_max_abs_error = -1.0;
        double layer3_block0_add_all_max_abs_error = -1.0;
        double layer3_block0_output_refresh_all_max_abs_error = -1.0;
        double layer3_block1_conv1_all_max_abs_error = -1.0;
        double layer3_block1_bn1_all_max_abs_error = -1.0;
        double layer3_block1_relu1_refresh_all_max_abs_error = -1.0;
        double layer3_block1_conv2_all_max_abs_error = -1.0;
        double layer3_block1_bn2_all_max_abs_error = -1.0;
        double layer3_block1_add_all_max_abs_error = -1.0;
        double layer3_block1_output_refresh_all_max_abs_error = -1.0;
        double layer4_block0_conv1_sparse_max_abs_error = -1.0;
        double layer4_block0_bn1_sparse_max_abs_error = -1.0;
        double layer4_block0_relu1_refresh_all_max_abs_error = -1.0;
        double layer4_block0_conv2_all_max_abs_error = -1.0;
        double layer4_block0_bn2_all_max_abs_error = -1.0;
        double layer4_block0_shortcut_all_max_abs_error = -1.0;
        double layer4_block0_add_all_max_abs_error = -1.0;
        double layer4_block0_output_refresh_all_max_abs_error = -1.0;
        double layer4_block1_conv1_all_max_abs_error = -1.0;
        double layer4_block1_bn1_all_max_abs_error = -1.0;
        double layer4_block1_relu1_refresh_all_max_abs_error = -1.0;
        double layer4_block1_conv2_all_max_abs_error = -1.0;
        double layer4_block1_bn2_all_max_abs_error = -1.0;
        double layer4_block1_add_all_max_abs_error = -1.0;
        double layer4_block1_output_refresh_all_max_abs_error = -1.0;
        double head_avgpool_debug_pack_max_abs_error = -1.0;
        double head_logits_max_abs_error = -1.0;
        int encrypted_predicted_label = -1;
        int plain_head_predicted_label = -1;
        // Input patch ciphertexts are ready at this point. The session only
        // accumulates functions marked as encrypted inference operations, so
        // interleaved plaintext reference work and decrypt/validation calls
        // are excluded from this metric.
        resnet18_timing::EncryptedInferenceTimerSession encrypted_inference_timer;
        if (kRunFullStemCheck)
        {
            output << "stem full 64-channel: encrypted conv1 evaluation\n";
            resnet18_progress_log() << "stem full 64-channel conv1 encrypted evaluation" << endl;
            ChannelCipherGroup stem_conv1_group = encrypted_conv2d_im2col_all_channels(
                conv1_im2col, 64, weights.conv_weight.at(0), weights.bn_running_var.at(0),
                weights.bn_weight.at(0), kBatchNormEpsilon, runtime);
            if (!resnet18_execution::inference_only())
            {
                vector<double> decrypted_stem_conv1 =
                    decrypt_channel_cipher_group(stem_conv1_group, runtime);
                stem_conv1_all_max_abs_error = 0.0;
                dump_plain_cipher_preview(
                    "stem conv1 all", plain_conv1.values,
                    decrypt_channel_cipher_group_complex(stem_conv1_group, runtime), output);
                for (size_t i = 0; i < decrypted_stem_conv1.size(); ++i)
                {
                    stem_conv1_all_max_abs_error =
                        max(stem_conv1_all_max_abs_error,
                            abs(decrypted_stem_conv1[i] - plain_conv1.values.at(i)));
                }
                output << "stem conv1 all max_abs_error: "
                       << stem_conv1_all_max_abs_error << '\n';
                resnet18_progress_log()
                    << "stem conv1 all max_abs_error: "
                    << stem_conv1_all_max_abs_error << endl;
            }

            output << "stem conv1: pack output as multiplexed k=1\n";
            resnet18_progress_log() << "stem conv1 pack output as multiplexed k=1" << endl;
            MultiplexedCipherGroup stem_conv1_multiplex_k1_group =
                pack_channel_group_as_multiplexed_k1(stem_conv1_group, runtime);
            log_multiplexed_group_cipher_state("stem conv1 multiplexed k=1 output",
                                               stem_conv1_multiplex_k1_group, runtime);
            double stem_conv1_multiplex_pack_max_abs_error =
                multiplexed_group_max_abs_error(stem_conv1_multiplex_k1_group,
                                                plain_conv1, runtime, &output,
                                                "stem conv1 multiplexed pack");
            output << "stem conv1 multiplexed pack max_abs_error: "
                   << stem_conv1_multiplex_pack_max_abs_error << '\n';
            resnet18_progress_log()
                << "stem conv1 multiplexed pack max_abs_error: "
                << stem_conv1_multiplex_pack_max_abs_error << endl;
            output << "stem conv1 multiplexed pack channel0 max_abs_error: "
                   << multiplexed_group_channel_max_abs_error(
                          stem_conv1_multiplex_k1_group, plain_conv1, 0, runtime)
                   << '\n';
            output << "stem conv1 multiplexed pack channel1 max_abs_error: "
                   << multiplexed_group_channel_max_abs_error(
                          stem_conv1_multiplex_k1_group, plain_conv1, 1, runtime)
                   << '\n';
            output << "stem conv1 multiplexed k=1 ciphertexts: "
                   << stem_conv1_multiplex_k1_group.packs.size()
                   << ", page_size=" << stem_conv1_multiplex_k1_group.page_size
                   << ", active_slots_per_cipher<="
                   << stem_conv1_multiplex_k1_group.page_size *
                          static_cast<size_t>(
                              stem_conv1_multiplex_k1_group.pages_per_cipher)
                   << '\n';

            output << "stem multiplexed k=1: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "stem multiplexed k=1 BN encrypted evaluation" << endl;
            MultiplexedCipherGroup stem_bn_multiplex_k1_group =
                multiplexed_channel_batch_norm(
                    stem_conv1_multiplex_k1_group, weights.bn_bias.at(0),
                    weights.bn_running_mean.at(0), weights.bn_running_var.at(0),
                    weights.bn_weight.at(0), kBatchNormEpsilon, kResNet18Boundary, runtime);
            stem_bn_all_max_abs_error = multiplexed_group_max_abs_error(
                stem_bn_multiplex_k1_group, plain_conv1_bn, runtime, &output,
                "stem BN");
            output << "stem BN all max_abs_error: " << stem_bn_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem BN all max_abs_error: " << stem_bn_all_max_abs_error << endl;

            output << "stem multiplexed k=1: homomorphic ReLU evaluation (first ReLU, no bootstrap)\n";
            resnet18_progress_log()
                << "stem multiplexed k=1 homomorphic ReLU evaluation (first ReLU, no bootstrap)" << endl;
            const auto stem_relu_time_start = chrono::steady_clock::now();
            MultiplexedCipherGroup stem_relu_multiplex_k1_group =
                multiplexed_channel_bootstrap_then_relu(stem_bn_multiplex_k1_group, plan.logN, relu_config, runtime, "stem ReLU", false, mock_options);
            stem_relu_refresh_all_max_abs_error = multiplexed_group_max_abs_error(
                stem_relu_multiplex_k1_group, plain_conv1_relu, runtime, &output,
                "stem ReLU");
            output << "stem homomorphic ReLU all max_abs_error: "
                   << stem_relu_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem homomorphic ReLU all max_abs_error: "
                 << stem_relu_refresh_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] stem homomorphic ReLU: "
                 << chrono::duration_cast<chrono::milliseconds>(
                        chrono::steady_clock::now() - stem_relu_time_start)
                        .count()
                 << " ms" << endl;

            output << "stem multiplexed layout: avgpool k=1 -> k=2\n";
            resnet18_progress_log()
                << "stem multiplexed avgpool k=1 -> k=2 encrypted evaluation" << endl;
            const auto stem_multiplex_avgpool_time_start = chrono::steady_clock::now();
            log_multiplexed_group_cipher_state("stem ReLU multiplexed k=1 input",
                                               stem_relu_multiplex_k1_group, runtime);
            MultiplexedCipherGroup stem_avgpool_multiplex_k2_group =
                multiplexed_average_pool2d_stride2(stem_relu_multiplex_k1_group,
                                                   stem_relu_multiplex_k1_group.h / 2,
                                                   stem_relu_multiplex_k1_group.w / 2, 2,
                                                   runtime);
            stem_multiplex_avgpool_all_max_abs_error =
                multiplexed_group_max_abs_error(stem_avgpool_multiplex_k2_group,
                                                plain_conv1_pool, runtime, &output,
                                                "stem avgpool");
            output << "stem multiplexed avgpool k=2 ciphertexts: "
                   << stem_avgpool_multiplex_k2_group.packs.size()
                   << ", page_size=" << stem_avgpool_multiplex_k2_group.page_size
                   << ", active_slots_per_cipher<="
                   << stem_avgpool_multiplex_k2_group.page_size *
                          static_cast<size_t>(
                              stem_avgpool_multiplex_k2_group.pages_per_cipher)
                   << '\n';
            output << "stem multiplexed avgpool all max_abs_error: "
                   << stem_multiplex_avgpool_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem multiplexed avgpool all max_abs_error: "
                                    << stem_multiplex_avgpool_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] stem multiplexed avgpool: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           stem_multiplex_avgpool_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer1 block0 conv1 multiplexed k=2: encrypted dense conv evaluation\n";
            resnet18_progress_log()
                << "layer1 block0 conv1 multiplexed k=2 encrypted evaluation" << endl;
            const auto layer1_block0_conv1_multiplex_time_start =
                chrono::steady_clock::now();
            PlainTensor plain_layer1_block0_conv1_multiplex = plain_convolution(
                plain_conv1_pool, 64, 1, 3, 3, weights.conv_weight.at(1),
                weights.bn_running_var.at(1), weights.bn_weight.at(1), kBatchNormEpsilon);
            MultiplexedCipherGroup layer1_block0_conv1_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    stem_avgpool_multiplex_k2_group, 64, 1, 3, 3,
                    weights.conv_weight.at(1), weights.bn_running_var.at(1),
                    weights.bn_weight.at(1), kBatchNormEpsilon, runtime);
            layer1_block0_conv1_multiplex_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_conv1_multiplex_group,
                                                plain_layer1_block0_conv1_multiplex,
                                                runtime, &output,
                                                "layer1 block0 conv1");
            output << "layer1 block0 conv1 multiplexed k=2 ciphertexts: "
                   << layer1_block0_conv1_multiplex_group.packs.size()
                   << ", page_size=" << layer1_block0_conv1_multiplex_group.page_size
                   << ", active_slots_per_cipher<="
                   << layer1_block0_conv1_multiplex_group.page_size *
                          static_cast<size_t>(
                              layer1_block0_conv1_multiplex_group.pages_per_cipher)
                   << '\n';
            output << "layer1 block0 conv1 multiplexed all max_abs_error: "
                   << layer1_block0_conv1_multiplex_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block0 conv1 multiplexed all max_abs_error: "
                << layer1_block0_conv1_multiplex_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer1 block0 conv1 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer1_block0_conv1_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer1 block0 bn1 multiplexed k=2: encrypted BN offset evaluation\n";
            resnet18_progress_log()
                << "layer1 block0 bn1 multiplexed k=2 encrypted evaluation" << endl;
            PlainTensor plain_layer1_block0_bn1_multiplex = plain_batch_norm(
                plain_layer1_block0_conv1_multiplex, weights.bn_bias.at(1),
                weights.bn_running_mean.at(1), weights.bn_running_var.at(1),
                weights.bn_weight.at(1), kBatchNormEpsilon, kResNet18Boundary);
            MultiplexedCipherGroup layer1_block0_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer1_block0_conv1_multiplex_group, weights.bn_bias.at(1),
                    weights.bn_running_mean.at(1), weights.bn_running_var.at(1),
                    weights.bn_weight.at(1), kBatchNormEpsilon, kResNet18Boundary, runtime);
            layer1_block0_bn1_multiplex_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_bn1_multiplex_group,
                                                plain_layer1_block0_bn1_multiplex,
                                                runtime, &output,
                                                "layer1 block0 bn1");
            output << "layer1 block0 bn1 multiplexed all max_abs_error: "
                   << layer1_block0_bn1_multiplex_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block0 bn1 multiplexed all max_abs_error: "
                << layer1_block0_bn1_multiplex_all_max_abs_error << endl;

            output << "layer1 block0 relu1 multiplexed k=2: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer1 block0 relu1 multiplexed k=2 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer1_block0_relu1_multiplex =
                plain_polynomial_relu_reference(plain_layer1_block0_bn1_multiplex, relu_config);
            MultiplexedCipherGroup layer1_block0_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer1_block0_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer1 block0 relu1", kBootstrapBeforeReluExceptFirst, mock_options);
            layer1_block0_relu1_multiplex_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_relu1_multiplex_group,
                                                plain_layer1_block0_relu1_multiplex,
                                                runtime, &output,
                                                "layer1 block0 relu1");
            output << "layer1 block0 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                   << layer1_block0_relu1_multiplex_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block0 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                << layer1_block0_relu1_multiplex_refresh_all_max_abs_error << endl;

            output << "layer1 block0 conv2 multiplexed k=2: encrypted dense conv evaluation\n";
            resnet18_progress_log()
                << "layer1 block0 conv2 multiplexed k=2 encrypted evaluation" << endl;
            const auto layer1_block0_conv2_multiplex_time_start =
                chrono::steady_clock::now();
            PlainTensor plain_layer1_block0_conv2_multiplex = plain_convolution(
                plain_layer1_block0_relu1_multiplex, 64, 1, 3, 3,
                weights.conv_weight.at(2), weights.bn_running_var.at(2),
                weights.bn_weight.at(2), kBatchNormEpsilon);
            MultiplexedCipherGroup layer1_block0_conv2_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer1_block0_relu1_multiplex_group, 64, 1, 3, 3,
                    weights.conv_weight.at(2), weights.bn_running_var.at(2),
                    weights.bn_weight.at(2), kBatchNormEpsilon, runtime);
            layer1_block0_conv2_multiplex_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_conv2_multiplex_group,
                                                plain_layer1_block0_conv2_multiplex,
                                                runtime, &output,
                                                "layer1 block0 conv2");
            output << "layer1 block0 conv2 multiplexed all max_abs_error: "
                   << layer1_block0_conv2_multiplex_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block0 conv2 multiplexed all max_abs_error: "
                << layer1_block0_conv2_multiplex_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer1 block0 conv2 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer1_block0_conv2_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer1 block0 bn2 multiplexed k=2: encrypted BN offset evaluation\n";
            resnet18_progress_log()
                << "layer1 block0 bn2 multiplexed k=2 encrypted evaluation" << endl;
            PlainTensor plain_layer1_block0_bn2_multiplex = plain_batch_norm(
                plain_layer1_block0_conv2_multiplex, weights.bn_bias.at(2),
                weights.bn_running_mean.at(2), weights.bn_running_var.at(2),
                weights.bn_weight.at(2), kBatchNormEpsilon, kResNet18Boundary);
            MultiplexedCipherGroup layer1_block0_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer1_block0_conv2_multiplex_group, weights.bn_bias.at(2),
                    weights.bn_running_mean.at(2), weights.bn_running_var.at(2),
                    weights.bn_weight.at(2), kBatchNormEpsilon, kResNet18Boundary, runtime);
            layer1_block0_bn2_multiplex_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_bn2_multiplex_group,
                                                plain_layer1_block0_bn2_multiplex,
                                                runtime, &output,
                                                "layer1 block0 bn2");
            output << "layer1 block0 bn2 multiplexed all max_abs_error: "
                   << layer1_block0_bn2_multiplex_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block0 bn2 multiplexed all max_abs_error: "
                << layer1_block0_bn2_multiplex_all_max_abs_error << endl;

            output << "layer1 block0 residual add multiplexed k=2 evaluation\n";
            resnet18_progress_log()
                << "layer1 block0 residual add multiplexed k=2 evaluation" << endl;
            PlainTensor plain_layer1_block0_add_multiplex =
                plain_add(plain_layer1_block0_bn2_multiplex, plain_conv1_pool);
            MultiplexedCipherGroup layer1_block0_add_multiplex_group =
                multiplexed_channel_add(layer1_block0_bn2_multiplex_group,
                                        stem_avgpool_multiplex_k2_group, runtime);
            layer1_block0_add_multiplex_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_add_multiplex_group,
                                                plain_layer1_block0_add_multiplex,
                                                runtime, &output,
                                                "layer1 block0 add");
            output << "layer1 block0 add multiplexed all max_abs_error: "
                   << layer1_block0_add_multiplex_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block0 add multiplexed all max_abs_error: "
                << layer1_block0_add_multiplex_all_max_abs_error << endl;

            output << "layer1 block0 output relu multiplexed k=2: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer1 block0 output relu multiplexed k=2 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer1_block0_output_multiplex =
                plain_polynomial_relu_reference(plain_layer1_block0_add_multiplex, relu_config);
            MultiplexedCipherGroup layer1_block0_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer1_block0_add_multiplex_group, plan.logN, relu_config, runtime, "layer1 block0 output relu", kBootstrapBeforeReluExceptFirst, mock_options);
            layer1_block0_output_multiplex_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_output_multiplex_group,
                                                plain_layer1_block0_output_multiplex,
                                                runtime, &output,
                                                "layer1 block0 output relu");
            output << "layer1 block0 output relu multiplexed homomorphic ReLU all max_abs_error: "
                   << layer1_block0_output_multiplex_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block0 output relu multiplexed homomorphic ReLU all max_abs_error: "
                << layer1_block0_output_multiplex_refresh_all_max_abs_error << endl;

            stem_avgpool_all_max_abs_error = stem_multiplex_avgpool_all_max_abs_error;
            layer1_block0_conv1_all_max_abs_error =
                layer1_block0_conv1_multiplex_all_max_abs_error;
            layer1_block0_bn1_all_max_abs_error =
                layer1_block0_bn1_multiplex_all_max_abs_error;
            layer1_block0_relu1_refresh_all_max_abs_error =
                layer1_block0_relu1_multiplex_refresh_all_max_abs_error;
            layer1_block0_conv2_all_max_abs_error =
                layer1_block0_conv2_multiplex_all_max_abs_error;
            layer1_block0_bn2_all_max_abs_error =
                layer1_block0_bn2_multiplex_all_max_abs_error;
            layer1_block0_add_all_max_abs_error =
                layer1_block0_add_multiplex_all_max_abs_error;
            layer1_block0_output_refresh_all_max_abs_error =
                layer1_block0_output_multiplex_refresh_all_max_abs_error;

            PlainTensor plain_layer1_block0_output =
                plain_layer1_block0_output_multiplex;

            output << "layer1 block1 conv1 multiplexed k=2: encrypted dense conv evaluation\n";
            resnet18_progress_log()
                << "layer1 block1 conv1 multiplexed k=2 encrypted evaluation" << endl;
            const auto layer1_block1_conv1_multiplex_time_start =
                chrono::steady_clock::now();
            PlainTensor plain_layer1_block1_conv1 = plain_convolution(
                plain_layer1_block0_output, 64, 1, 3, 3, weights.conv_weight.at(3),
                weights.bn_running_var.at(3), weights.bn_weight.at(3), kBatchNormEpsilon);
            MultiplexedCipherGroup layer1_block1_conv1_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer1_block0_output_multiplex_group, 64, 1, 3, 3,
                    weights.conv_weight.at(3), weights.bn_running_var.at(3),
                    weights.bn_weight.at(3), kBatchNormEpsilon, runtime);
            layer1_block1_conv1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer1_block1_conv1_multiplex_group, plain_layer1_block1_conv1,
                runtime, &output, "layer1 block1 conv1");
            output << "layer1 block1 conv1 multiplexed all max_abs_error: "
                   << layer1_block1_conv1_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block1 conv1 multiplexed all max_abs_error: "
                << layer1_block1_conv1_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer1 block1 conv1 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer1_block1_conv1_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer1 block1 bn1 multiplexed k=2: encrypted BN offset evaluation\n";
            resnet18_progress_log()
                << "layer1 block1 bn1 multiplexed k=2 encrypted evaluation" << endl;
            MultiplexedCipherGroup layer1_block1_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer1_block1_conv1_multiplex_group, weights.bn_bias.at(3),
                    weights.bn_running_mean.at(3), weights.bn_running_var.at(3),
                    weights.bn_weight.at(3), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer1_block1_bn1 =
                plain_batch_norm(plain_layer1_block1_conv1, weights.bn_bias.at(3),
                                 weights.bn_running_mean.at(3),
                                 weights.bn_running_var.at(3), weights.bn_weight.at(3),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer1_block1_bn1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer1_block1_bn1_multiplex_group, plain_layer1_block1_bn1,
                runtime, &output, "layer1 block1 bn1");
            output << "layer1 block1 bn1 multiplexed all max_abs_error: "
                   << layer1_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block1 bn1 multiplexed all max_abs_error: "
                << layer1_block1_bn1_all_max_abs_error << endl;

            output << "layer1 block1 relu1 multiplexed k=2: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer1 block1 relu1 multiplexed k=2 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer1_block1_relu1 =
                plain_polynomial_relu_reference(plain_layer1_block1_bn1, relu_config);
            MultiplexedCipherGroup layer1_block1_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer1_block1_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer1 block1 relu1", kBootstrapBeforeReluExceptFirst, mock_options);
            layer1_block1_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block1_relu1_multiplex_group,
                                                plain_layer1_block1_relu1, runtime,
                                                &output, "layer1 block1 relu1");
            output << "layer1 block1 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                   << layer1_block1_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block1 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                << layer1_block1_relu1_refresh_all_max_abs_error << endl;

            output << "layer1 block1 conv2 multiplexed k=2: encrypted dense conv evaluation\n";
            resnet18_progress_log()
                << "layer1 block1 conv2 multiplexed k=2 encrypted evaluation" << endl;
            const auto layer1_block1_conv2_multiplex_time_start =
                chrono::steady_clock::now();
            MultiplexedCipherGroup layer1_block1_conv2_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer1_block1_relu1_multiplex_group, 64, 1, 3, 3,
                    weights.conv_weight.at(4), weights.bn_running_var.at(4),
                    weights.bn_weight.at(4), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer1_block1_conv2 = plain_convolution(
                plain_layer1_block1_relu1, 64, 1, 3, 3, weights.conv_weight.at(4),
                weights.bn_running_var.at(4), weights.bn_weight.at(4), kBatchNormEpsilon);
            layer1_block1_conv2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer1_block1_conv2_multiplex_group, plain_layer1_block1_conv2,
                runtime, &output, "layer1 block1 conv2");
            output << "layer1 block1 conv2 multiplexed all max_abs_error: "
                   << layer1_block1_conv2_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block1 conv2 multiplexed all max_abs_error: "
                << layer1_block1_conv2_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer1 block1 conv2 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer1_block1_conv2_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer1 block1 bn2 multiplexed k=2: encrypted BN offset evaluation\n";
            resnet18_progress_log()
                << "layer1 block1 bn2 multiplexed k=2 encrypted evaluation" << endl;
            MultiplexedCipherGroup layer1_block1_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer1_block1_conv2_multiplex_group, weights.bn_bias.at(4),
                    weights.bn_running_mean.at(4), weights.bn_running_var.at(4),
                    weights.bn_weight.at(4), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer1_block1_bn2 =
                plain_batch_norm(plain_layer1_block1_conv2, weights.bn_bias.at(4),
                                 weights.bn_running_mean.at(4),
                                 weights.bn_running_var.at(4), weights.bn_weight.at(4),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer1_block1_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer1_block1_bn2_multiplex_group, plain_layer1_block1_bn2,
                runtime, &output, "layer1 block1 bn2");
            output << "layer1 block1 bn2 multiplexed all max_abs_error: "
                   << layer1_block1_bn2_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block1 bn2 multiplexed all max_abs_error: "
                << layer1_block1_bn2_all_max_abs_error << endl;

            output << "layer1 block1 residual add multiplexed k=2 evaluation\n";
            resnet18_progress_log()
                << "layer1 block1 residual add multiplexed k=2 evaluation" << endl;
            MultiplexedCipherGroup layer1_block1_add_multiplex_group =
                multiplexed_channel_add(layer1_block1_bn2_multiplex_group,
                                        layer1_block0_output_multiplex_group, runtime);
            PlainTensor plain_layer1_block1_add =
                plain_add(plain_layer1_block1_bn2, plain_layer1_block0_output);
            layer1_block1_add_all_max_abs_error = multiplexed_group_max_abs_error(
                layer1_block1_add_multiplex_group, plain_layer1_block1_add,
                runtime, &output, "layer1 block1 add");
            output << "layer1 block1 add multiplexed all max_abs_error: "
                   << layer1_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block1 add multiplexed all max_abs_error: "
                << layer1_block1_add_all_max_abs_error << endl;

            output << "layer1 block1 output relu multiplexed k=2: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer1 block1 output relu multiplexed k=2 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer1_block1_output =
                plain_polynomial_relu_reference(plain_layer1_block1_add, relu_config);
            MultiplexedCipherGroup layer1_block1_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer1_block1_add_multiplex_group, plan.logN, relu_config, runtime, "layer1 block1 output relu", kBootstrapBeforeReluExceptFirst, mock_options);
            layer1_block1_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block1_output_multiplex_group,
                                                plain_layer1_block1_output, runtime,
                                                &output, "layer1 block1 output relu");
            output << "layer1 block1 output relu multiplexed homomorphic ReLU all max_abs_error: "
                   << layer1_block1_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer1 block1 output relu multiplexed homomorphic ReLU all max_abs_error: "
                << layer1_block1_output_refresh_all_max_abs_error << endl;

            output << "layer2 block0 conv1 multiplexed k=2->k=4 stride-2 evaluation\n";
            resnet18_progress_log()
                << "layer2 block0 conv1 multiplexed k=2->k=4 stride-2 evaluation"
                << endl;
            const auto layer2_block0_conv1_multiplex_time_start =
                chrono::steady_clock::now();
            PlainTensor plain_layer2_block0_conv1 = plain_convolution(
                plain_layer1_block1_output, 128, 2, 3, 3, weights.conv_weight.at(5),
                weights.bn_running_var.at(5), weights.bn_weight.at(5), kBatchNormEpsilon);
            MultiplexedCipherGroup layer2_block0_conv1_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer1_block1_output_multiplex_group, 128, 2, 3, 3,
                    weights.conv_weight.at(5), weights.bn_running_var.at(5),
                    weights.bn_weight.at(5), kBatchNormEpsilon, runtime);
            layer2_block0_conv1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_conv1_multiplex_group, plain_layer2_block0_conv1,
                runtime, &output, "layer2 block0 conv1");
            output << "layer2 block0 conv1 multiplexed max_abs_error: "
                   << layer2_block0_conv1_sparse_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer2 block0 conv1 multiplexed max_abs_error: "
                << layer2_block0_conv1_sparse_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer2 block0 conv1 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer2_block0_conv1_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer2 block0 bn1 multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block0 bn1 multiplexed k=4 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer2_block0_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer2_block0_conv1_multiplex_group, weights.bn_bias.at(5),
                    weights.bn_running_mean.at(5), weights.bn_running_var.at(5),
                    weights.bn_weight.at(5), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer2_block0_bn1 =
                plain_batch_norm(plain_layer2_block0_conv1, weights.bn_bias.at(5),
                                 weights.bn_running_mean.at(5),
                                 weights.bn_running_var.at(5), weights.bn_weight.at(5),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer2_block0_bn1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_bn1_multiplex_group, plain_layer2_block0_bn1,
                runtime, &output, "layer2 block0 bn1");
            output << "layer2 block0 bn1 multiplexed max_abs_error: "
                   << layer2_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 bn1 multiplexed max_abs_error: "
                                    << layer2_block0_bn1_sparse_max_abs_error << endl;

            output << "layer2 block0 relu1 multiplexed k=4: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer2 block0 relu1 multiplexed k=4 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer2_block0_relu1 =
                plain_polynomial_relu_reference(plain_layer2_block0_bn1, relu_config);
            MultiplexedCipherGroup layer2_block0_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer2_block0_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer2 block0 relu1", kBootstrapBeforeReluExceptFirst, mock_options);
            layer2_block0_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(
                layer2_block0_relu1_multiplex_group, plain_layer2_block0_relu1,
                runtime, &output, "layer2 block0 relu1");
            output << "layer2 block0 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                   << layer2_block0_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer2 block0 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                                    << layer2_block0_relu1_refresh_all_max_abs_error << endl;

            output << "layer2 block0 conv2 multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block0 conv2 multiplexed k=4 evaluation"
                                    << endl;
            const auto layer2_block0_conv2_multiplex_time_start =
                chrono::steady_clock::now();
            MultiplexedCipherGroup layer2_block0_conv2_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer2_block0_relu1_multiplex_group, 128, 1, 3, 3,
                    weights.conv_weight.at(6), weights.bn_running_var.at(6),
                    weights.bn_weight.at(6), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer2_block0_conv2 = plain_convolution(
                plain_layer2_block0_relu1, 128, 1, 3, 3, weights.conv_weight.at(6),
                weights.bn_running_var.at(6), weights.bn_weight.at(6), kBatchNormEpsilon);
            layer2_block0_conv2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_conv2_multiplex_group, plain_layer2_block0_conv2,
                runtime, &output, "layer2 block0 conv2");
            output << "layer2 block0 conv2 multiplexed all max_abs_error: "
                   << layer2_block0_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 conv2 multiplexed all max_abs_error: "
                 << layer2_block0_conv2_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer2 block0 conv2 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer2_block0_conv2_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer2 block0 bn2 multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block0 bn2 multiplexed k=4 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer2_block0_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer2_block0_conv2_multiplex_group, weights.bn_bias.at(6),
                    weights.bn_running_mean.at(6), weights.bn_running_var.at(6),
                    weights.bn_weight.at(6), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer2_block0_bn2 =
                plain_batch_norm(plain_layer2_block0_conv2, weights.bn_bias.at(6),
                                 weights.bn_running_mean.at(6),
                                 weights.bn_running_var.at(6), weights.bn_weight.at(6),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer2_block0_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_bn2_multiplex_group, plain_layer2_block0_bn2,
                runtime, &output, "layer2 block0 bn2");
            output << "layer2 block0 bn2 multiplexed all max_abs_error: "
                   << layer2_block0_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 bn2 multiplexed all max_abs_error: "
                 << layer2_block0_bn2_all_max_abs_error << endl;

            output << "layer2 block0 projection shortcut multiplexed k=2->k=4 stride-2 evaluation\n";
            resnet18_progress_log()
                << "layer2 block0 projection shortcut multiplexed k=2->k=4 stride-2 evaluation"
                << endl;
            PlainTensor plain_layer2_block0_shortcut_conv = plain_convolution(
                plain_layer1_block1_output, 128, 2, 1, 1,
                weights.downsample_weight.at(0),
                weights.downsample_bn_running_var.at(0),
                weights.downsample_bn_weight.at(0), kBatchNormEpsilon);
            MultiplexedCipherGroup layer2_block0_shortcut_conv_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer1_block1_output_multiplex_group, 128, 2, 1, 1,
                    weights.downsample_weight.at(0),
                    weights.downsample_bn_running_var.at(0),
                    weights.downsample_bn_weight.at(0), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer2_block0_shortcut =
                plain_batch_norm(plain_layer2_block0_shortcut_conv,
                                 weights.downsample_bn_bias.at(0),
                                 weights.downsample_bn_running_mean.at(0),
                                 weights.downsample_bn_running_var.at(0),
                                 weights.downsample_bn_weight.at(0), kBatchNormEpsilon,
                                 kResNet18Boundary);
            MultiplexedCipherGroup layer2_block0_shortcut_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer2_block0_shortcut_conv_multiplex_group,
                    weights.downsample_bn_bias.at(0),
                    weights.downsample_bn_running_mean.at(0),
                    weights.downsample_bn_running_var.at(0),
                    weights.downsample_bn_weight.at(0), kBatchNormEpsilon, kResNet18Boundary, runtime);
            layer2_block0_shortcut_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_shortcut_multiplex_group, plain_layer2_block0_shortcut,
                runtime, &output, "layer2 block0 shortcut");
            output << "layer2 block0 shortcut multiplexed all max_abs_error: "
                   << layer2_block0_shortcut_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer2 block0 shortcut multiplexed all max_abs_error: "
                                    << layer2_block0_shortcut_all_max_abs_error << endl;

            output << "layer2 block0 residual add multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block0 residual add multiplexed k=4 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer2_block0_add_multiplex_group =
                multiplexed_channel_add(layer2_block0_bn2_multiplex_group,
                                        layer2_block0_shortcut_multiplex_group, runtime);
            PlainTensor plain_layer2_block0_add =
                plain_add(plain_layer2_block0_bn2, plain_layer2_block0_shortcut);
            layer2_block0_add_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_add_multiplex_group, plain_layer2_block0_add,
                runtime, &output, "layer2 block0 add");
            output << "layer2 block0 add multiplexed all max_abs_error: "
                   << layer2_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 add multiplexed all max_abs_error: "
                 << layer2_block0_add_all_max_abs_error << endl;

            output << "layer2 block0 output ReLU multiplexed k=4: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer2 block0 output ReLU multiplexed k=4 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer2_block0_output =
                plain_polynomial_relu_reference(plain_layer2_block0_add, relu_config);
            MultiplexedCipherGroup layer2_block0_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer2_block0_add_multiplex_group, plan.logN, relu_config, runtime, "layer2 block0 output relu", kBootstrapBeforeReluExceptFirst, mock_options);
            layer2_block0_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer2_block0_output_multiplex_group,
                                                plain_layer2_block0_output, runtime,
                                                &output, "layer2 block0 output relu");
            output << "layer2 block0 output multiplexed homomorphic ReLU all max_abs_error: "
                   << layer2_block0_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer2 block0 output multiplexed homomorphic ReLU all max_abs_error: "
                 << layer2_block0_output_refresh_all_max_abs_error << endl;

            output << "layer2 block1 conv1 multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block1 conv1 multiplexed k=4 evaluation"
                                    << endl;
            const auto layer2_block1_conv1_multiplex_time_start =
                chrono::steady_clock::now();
            MultiplexedCipherGroup layer2_block1_conv1_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer2_block0_output_multiplex_group, 128, 1, 3, 3,
                    weights.conv_weight.at(7), weights.bn_running_var.at(7),
                    weights.bn_weight.at(7), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer2_block1_conv1 = plain_convolution(
                plain_layer2_block0_output, 128, 1, 3, 3, weights.conv_weight.at(7),
                weights.bn_running_var.at(7), weights.bn_weight.at(7), kBatchNormEpsilon);
            layer2_block1_conv1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block1_conv1_multiplex_group, plain_layer2_block1_conv1,
                runtime, &output, "layer2 block1 conv1");
            output << "layer2 block1 conv1 multiplexed all max_abs_error: "
                   << layer2_block1_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 conv1 multiplexed all max_abs_error: "
                 << layer2_block1_conv1_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer2 block1 conv1 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer2_block1_conv1_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer2 block1 bn1 multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block1 bn1 multiplexed k=4 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer2_block1_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer2_block1_conv1_multiplex_group, weights.bn_bias.at(7),
                    weights.bn_running_mean.at(7), weights.bn_running_var.at(7),
                    weights.bn_weight.at(7), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer2_block1_bn1 =
                plain_batch_norm(plain_layer2_block1_conv1, weights.bn_bias.at(7),
                                 weights.bn_running_mean.at(7),
                                 weights.bn_running_var.at(7), weights.bn_weight.at(7),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer2_block1_bn1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block1_bn1_multiplex_group, plain_layer2_block1_bn1,
                runtime, &output, "layer2 block1 bn1");
            output << "layer2 block1 bn1 multiplexed all max_abs_error: "
                   << layer2_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 bn1 multiplexed all max_abs_error: "
                 << layer2_block1_bn1_all_max_abs_error << endl;

            output << "layer2 block1 relu1 multiplexed k=4: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer2 block1 relu1 multiplexed k=4 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer2_block1_relu1 =
                plain_polynomial_relu_reference(plain_layer2_block1_bn1, relu_config);
            MultiplexedCipherGroup layer2_block1_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer2_block1_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer2 block1 relu1", kBootstrapBeforeReluExceptFirst, mock_options);
            layer2_block1_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer2_block1_relu1_multiplex_group,
                                                plain_layer2_block1_relu1, runtime,
                                                &output, "layer2 block1 relu1");
            output << "layer2 block1 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                   << layer2_block1_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer2 block1 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                 << layer2_block1_relu1_refresh_all_max_abs_error << endl;

            output << "layer2 block1 conv2 multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block1 conv2 multiplexed k=4 evaluation"
                                    << endl;
            const auto layer2_block1_conv2_multiplex_time_start =
                chrono::steady_clock::now();
            MultiplexedCipherGroup layer2_block1_conv2_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer2_block1_relu1_multiplex_group, 128, 1, 3, 3,
                    weights.conv_weight.at(8), weights.bn_running_var.at(8),
                    weights.bn_weight.at(8), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer2_block1_conv2 = plain_convolution(
                plain_layer2_block1_relu1, 128, 1, 3, 3, weights.conv_weight.at(8),
                weights.bn_running_var.at(8), weights.bn_weight.at(8), kBatchNormEpsilon);
            layer2_block1_conv2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block1_conv2_multiplex_group, plain_layer2_block1_conv2,
                runtime, &output, "layer2 block1 conv2");
            output << "layer2 block1 conv2 multiplexed all max_abs_error: "
                   << layer2_block1_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 conv2 multiplexed all max_abs_error: "
                 << layer2_block1_conv2_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer2 block1 conv2 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer2_block1_conv2_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer2 block1 bn2 multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block1 bn2 multiplexed k=4 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer2_block1_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer2_block1_conv2_multiplex_group, weights.bn_bias.at(8),
                    weights.bn_running_mean.at(8), weights.bn_running_var.at(8),
                    weights.bn_weight.at(8), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer2_block1_bn2 =
                plain_batch_norm(plain_layer2_block1_conv2, weights.bn_bias.at(8),
                                 weights.bn_running_mean.at(8),
                                 weights.bn_running_var.at(8), weights.bn_weight.at(8),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer2_block1_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block1_bn2_multiplex_group, plain_layer2_block1_bn2,
                runtime, &output, "layer2 block1 bn2");
            output << "layer2 block1 bn2 multiplexed all max_abs_error: "
                   << layer2_block1_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 bn2 multiplexed all max_abs_error: "
                 << layer2_block1_bn2_all_max_abs_error << endl;

            output << "layer2 block1 residual add multiplexed k=4 evaluation\n";
            resnet18_progress_log() << "layer2 block1 residual add multiplexed k=4 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer2_block1_add_multiplex_group =
                multiplexed_channel_add(layer2_block1_bn2_multiplex_group,
                                        layer2_block0_output_multiplex_group, runtime);
            PlainTensor plain_layer2_block1_add =
                plain_add(plain_layer2_block1_bn2, plain_layer2_block0_output);
            layer2_block1_add_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block1_add_multiplex_group, plain_layer2_block1_add,
                runtime, &output, "layer2 block1 add");
            output << "layer2 block1 add multiplexed all max_abs_error: "
                   << layer2_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 add multiplexed all max_abs_error: "
                 << layer2_block1_add_all_max_abs_error << endl;

            output << "layer2 block1 output ReLU multiplexed k=4: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer2 block1 output ReLU multiplexed k=4 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer2_block1_output =
                plain_polynomial_relu_reference(plain_layer2_block1_add, relu_config);
            MultiplexedCipherGroup layer2_block1_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer2_block1_add_multiplex_group, plan.logN, relu_config, runtime, "layer2 block1 output relu", kBootstrapBeforeReluExceptFirst, mock_options);
            layer2_block1_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer2_block1_output_multiplex_group,
                                                plain_layer2_block1_output, runtime,
                                                &output, "layer2 block1 output relu");
            output << "layer2 block1 output multiplexed homomorphic ReLU all max_abs_error: "
                   << layer2_block1_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer2 block1 output multiplexed homomorphic ReLU all max_abs_error: "
                 << layer2_block1_output_refresh_all_max_abs_error << endl;

            output << "layer3 block0 conv1 multiplexed k=4->k=8 stride-2 evaluation\n";
            resnet18_progress_log()
                << "layer3 block0 conv1 multiplexed k=4->k=8 stride-2 evaluation"
                << endl;
            const auto layer3_block0_conv1_multiplex_time_start =
                chrono::steady_clock::now();
            PlainTensor plain_layer3_block0_conv1 = plain_convolution(
                plain_layer2_block1_output, 256, 2, 3, 3, weights.conv_weight.at(9),
                weights.bn_running_var.at(9), weights.bn_weight.at(9), kBatchNormEpsilon);
            MultiplexedCipherGroup layer3_block0_conv1_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer2_block1_output_multiplex_group, 256, 2, 3, 3,
                    weights.conv_weight.at(9), weights.bn_running_var.at(9),
                    weights.bn_weight.at(9), kBatchNormEpsilon, runtime);
            layer3_block0_conv1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_conv1_multiplex_group, plain_layer3_block0_conv1,
                runtime, &output, "layer3 block0 conv1");
            output << "layer3 block0 conv1 multiplexed max_abs_error: "
                   << layer3_block0_conv1_sparse_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer3 block0 conv1 multiplexed max_abs_error: "
                << layer3_block0_conv1_sparse_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer3 block0 conv1 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer3_block0_conv1_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer3 block0 bn1 multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block0 bn1 multiplexed k=8 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer3_block0_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer3_block0_conv1_multiplex_group, weights.bn_bias.at(9),
                    weights.bn_running_mean.at(9), weights.bn_running_var.at(9),
                    weights.bn_weight.at(9), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer3_block0_bn1 =
                plain_batch_norm(plain_layer3_block0_conv1, weights.bn_bias.at(9),
                                 weights.bn_running_mean.at(9),
                                 weights.bn_running_var.at(9), weights.bn_weight.at(9),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer3_block0_bn1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_bn1_multiplex_group, plain_layer3_block0_bn1,
                runtime, &output, "layer3 block0 bn1");
            output << "layer3 block0 bn1 multiplexed max_abs_error: "
                   << layer3_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 bn1 multiplexed max_abs_error: "
                                    << layer3_block0_bn1_sparse_max_abs_error << endl;

            output << "layer3 block0 relu1 multiplexed k=8: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer3 block0 relu1 multiplexed k=8 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer3_block0_relu1 =
                plain_polynomial_relu_reference(plain_layer3_block0_bn1, relu_config);
            MultiplexedCipherGroup layer3_block0_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer3_block0_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer3 block0 relu1", kBootstrapBeforeReluExceptFirst, mock_options);
            layer3_block0_relu1_refresh_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_relu1_multiplex_group, plain_layer3_block0_relu1,
                runtime, &output, "layer3 block0 relu1");
            output << "layer3 block0 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                   << layer3_block0_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer3 block0 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                                    << layer3_block0_relu1_refresh_all_max_abs_error << endl;

            output << "layer3 block0 conv2 multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block0 conv2 multiplexed k=8 evaluation"
                                    << endl;
            const auto layer3_block0_conv2_multiplex_time_start =
                chrono::steady_clock::now();
            MultiplexedCipherGroup layer3_block0_conv2_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer3_block0_relu1_multiplex_group, 256, 1, 3, 3,
                    weights.conv_weight.at(10), weights.bn_running_var.at(10),
                    weights.bn_weight.at(10), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer3_block0_conv2 = plain_convolution(
                plain_layer3_block0_relu1, 256, 1, 3, 3, weights.conv_weight.at(10),
                weights.bn_running_var.at(10), weights.bn_weight.at(10), kBatchNormEpsilon);
            layer3_block0_conv2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_conv2_multiplex_group, plain_layer3_block0_conv2,
                runtime, &output, "layer3 block0 conv2");
            output << "layer3 block0 conv2 multiplexed all max_abs_error: "
                   << layer3_block0_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 conv2 multiplexed all max_abs_error: "
                 << layer3_block0_conv2_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer3 block0 conv2 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer3_block0_conv2_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer3 block0 bn2 multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block0 bn2 multiplexed k=8 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer3_block0_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer3_block0_conv2_multiplex_group, weights.bn_bias.at(10),
                    weights.bn_running_mean.at(10), weights.bn_running_var.at(10),
                    weights.bn_weight.at(10), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer3_block0_bn2 =
                plain_batch_norm(plain_layer3_block0_conv2, weights.bn_bias.at(10),
                                 weights.bn_running_mean.at(10),
                                 weights.bn_running_var.at(10), weights.bn_weight.at(10),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer3_block0_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_bn2_multiplex_group, plain_layer3_block0_bn2,
                runtime, &output, "layer3 block0 bn2");
            output << "layer3 block0 bn2 multiplexed all max_abs_error: "
                   << layer3_block0_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 bn2 multiplexed all max_abs_error: "
                 << layer3_block0_bn2_all_max_abs_error << endl;

            output << "layer3 block0 projection shortcut multiplexed k=4->k=8 stride-2 evaluation\n";
            resnet18_progress_log()
                << "layer3 block0 projection shortcut multiplexed k=4->k=8 stride-2 evaluation"
                << endl;
            PlainTensor plain_layer3_block0_shortcut_conv = plain_convolution(
                plain_layer2_block1_output, 256, 2, 1, 1,
                weights.downsample_weight.at(1),
                weights.downsample_bn_running_var.at(1),
                weights.downsample_bn_weight.at(1), kBatchNormEpsilon);
            MultiplexedCipherGroup layer3_block0_shortcut_conv_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer2_block1_output_multiplex_group, 256, 2, 1, 1,
                    weights.downsample_weight.at(1),
                    weights.downsample_bn_running_var.at(1),
                    weights.downsample_bn_weight.at(1), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer3_block0_shortcut =
                plain_batch_norm(plain_layer3_block0_shortcut_conv,
                                 weights.downsample_bn_bias.at(1),
                                 weights.downsample_bn_running_mean.at(1),
                                 weights.downsample_bn_running_var.at(1),
                                 weights.downsample_bn_weight.at(1), kBatchNormEpsilon,
                                 kResNet18Boundary);
            MultiplexedCipherGroup layer3_block0_shortcut_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer3_block0_shortcut_conv_multiplex_group,
                    weights.downsample_bn_bias.at(1),
                    weights.downsample_bn_running_mean.at(1),
                    weights.downsample_bn_running_var.at(1),
                    weights.downsample_bn_weight.at(1), kBatchNormEpsilon, kResNet18Boundary, runtime);
            layer3_block0_shortcut_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_shortcut_multiplex_group, plain_layer3_block0_shortcut,
                runtime, &output, "layer3 block0 shortcut");
            output << "layer3 block0 shortcut multiplexed all max_abs_error: "
                   << layer3_block0_shortcut_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer3 block0 shortcut multiplexed all max_abs_error: "
                                    << layer3_block0_shortcut_all_max_abs_error << endl;

            output << "layer3 block0 residual add multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block0 residual add multiplexed k=8 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer3_block0_add_multiplex_group =
                multiplexed_channel_add(layer3_block0_bn2_multiplex_group,
                                        layer3_block0_shortcut_multiplex_group, runtime);
            PlainTensor plain_layer3_block0_add =
                plain_add(plain_layer3_block0_bn2, plain_layer3_block0_shortcut);
            layer3_block0_add_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_add_multiplex_group, plain_layer3_block0_add,
                runtime, &output, "layer3 block0 add");
            output << "layer3 block0 add multiplexed all max_abs_error: "
                   << layer3_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 add multiplexed all max_abs_error: "
                 << layer3_block0_add_all_max_abs_error << endl;

            output << "layer3 block0 output ReLU multiplexed k=8: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer3 block0 output ReLU multiplexed k=8 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer3_block0_output =
                plain_polynomial_relu_reference(plain_layer3_block0_add, relu_config);
            MultiplexedCipherGroup layer3_block0_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer3_block0_add_multiplex_group, plan.logN, relu_config, runtime, "layer3 block0 output relu", kBootstrapBeforeReluExceptFirst, mock_options);
            layer3_block0_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer3_block0_output_multiplex_group,
                                                plain_layer3_block0_output, runtime,
                                                &output, "layer3 block0 output relu");
            output << "layer3 block0 output multiplexed homomorphic ReLU all max_abs_error: "
                   << layer3_block0_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer3 block0 output multiplexed homomorphic ReLU all max_abs_error: "
                 << layer3_block0_output_refresh_all_max_abs_error << endl;

            output << "layer3 block1 conv1 multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block1 conv1 multiplexed k=8 evaluation"
                                    << endl;
            const auto layer3_block1_conv1_multiplex_time_start =
                chrono::steady_clock::now();
            MultiplexedCipherGroup layer3_block1_conv1_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer3_block0_output_multiplex_group, 256, 1, 3, 3,
                    weights.conv_weight.at(11), weights.bn_running_var.at(11),
                    weights.bn_weight.at(11), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer3_block1_conv1 = plain_convolution(
                plain_layer3_block0_output, 256, 1, 3, 3, weights.conv_weight.at(11),
                weights.bn_running_var.at(11), weights.bn_weight.at(11), kBatchNormEpsilon);
            layer3_block1_conv1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block1_conv1_multiplex_group, plain_layer3_block1_conv1,
                runtime, &output, "layer3 block1 conv1");
            output << "layer3 block1 conv1 multiplexed all max_abs_error: "
                   << layer3_block1_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 conv1 multiplexed all max_abs_error: "
                 << layer3_block1_conv1_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer3 block1 conv1 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer3_block1_conv1_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer3 block1 bn1 multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block1 bn1 multiplexed k=8 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer3_block1_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer3_block1_conv1_multiplex_group, weights.bn_bias.at(11),
                    weights.bn_running_mean.at(11), weights.bn_running_var.at(11),
                    weights.bn_weight.at(11), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer3_block1_bn1 =
                plain_batch_norm(plain_layer3_block1_conv1, weights.bn_bias.at(11),
                                 weights.bn_running_mean.at(11),
                                 weights.bn_running_var.at(11), weights.bn_weight.at(11),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer3_block1_bn1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block1_bn1_multiplex_group, plain_layer3_block1_bn1,
                runtime, &output, "layer3 block1 bn1");
            output << "layer3 block1 bn1 multiplexed all max_abs_error: "
                   << layer3_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 bn1 multiplexed all max_abs_error: "
                 << layer3_block1_bn1_all_max_abs_error << endl;

            output << "layer3 block1 relu1 multiplexed k=8: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer3 block1 relu1 multiplexed k=8 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer3_block1_relu1 =
                plain_polynomial_relu_reference(plain_layer3_block1_bn1, relu_config);
            MultiplexedCipherGroup layer3_block1_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer3_block1_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer3 block1 relu1", kBootstrapBeforeReluExceptFirst, mock_options);
            layer3_block1_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer3_block1_relu1_multiplex_group,
                                                plain_layer3_block1_relu1, runtime,
                                                &output, "layer3 block1 relu1");
            output << "layer3 block1 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                   << layer3_block1_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer3 block1 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                 << layer3_block1_relu1_refresh_all_max_abs_error << endl;

            output << "layer3 block1 conv2 multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block1 conv2 multiplexed k=8 evaluation"
                                    << endl;
            const auto layer3_block1_conv2_multiplex_time_start =
                chrono::steady_clock::now();
            MultiplexedCipherGroup layer3_block1_conv2_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer3_block1_relu1_multiplex_group, 256, 1, 3, 3,
                    weights.conv_weight.at(12), weights.bn_running_var.at(12),
                    weights.bn_weight.at(12), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer3_block1_conv2 = plain_convolution(
                plain_layer3_block1_relu1, 256, 1, 3, 3, weights.conv_weight.at(12),
                weights.bn_running_var.at(12), weights.bn_weight.at(12), kBatchNormEpsilon);
            layer3_block1_conv2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block1_conv2_multiplex_group, plain_layer3_block1_conv2,
                runtime, &output, "layer3 block1 conv2");
            output << "layer3 block1 conv2 multiplexed all max_abs_error: "
                   << layer3_block1_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 conv2 multiplexed all max_abs_error: "
                 << layer3_block1_conv2_all_max_abs_error << endl;
            resnet18_progress_log() << "[duration] layer3 block1 conv2 multiplexed: "
                                    << chrono::duration_cast<chrono::milliseconds>(
                                           chrono::steady_clock::now() -
                                           layer3_block1_conv2_multiplex_time_start)
                                           .count()
                                    << " ms" << endl;

            output << "layer3 block1 bn2 multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block1 bn2 multiplexed k=8 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer3_block1_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer3_block1_conv2_multiplex_group, weights.bn_bias.at(12),
                    weights.bn_running_mean.at(12), weights.bn_running_var.at(12),
                    weights.bn_weight.at(12), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer3_block1_bn2 =
                plain_batch_norm(plain_layer3_block1_conv2, weights.bn_bias.at(12),
                                 weights.bn_running_mean.at(12),
                                 weights.bn_running_var.at(12), weights.bn_weight.at(12),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer3_block1_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block1_bn2_multiplex_group, plain_layer3_block1_bn2,
                runtime, &output, "layer3 block1 bn2");
            output << "layer3 block1 bn2 multiplexed all max_abs_error: "
                   << layer3_block1_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 bn2 multiplexed all max_abs_error: "
                 << layer3_block1_bn2_all_max_abs_error << endl;

            output << "layer3 block1 residual add multiplexed k=8 evaluation\n";
            resnet18_progress_log() << "layer3 block1 residual add multiplexed k=8 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer3_block1_add_multiplex_group =
                multiplexed_channel_add(layer3_block1_bn2_multiplex_group,
                                        layer3_block0_output_multiplex_group, runtime);
            PlainTensor plain_layer3_block1_add =
                plain_add(plain_layer3_block1_bn2, plain_layer3_block0_output);
            layer3_block1_add_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block1_add_multiplex_group, plain_layer3_block1_add,
                runtime, &output, "layer3 block1 add");
            output << "layer3 block1 add multiplexed all max_abs_error: "
                   << layer3_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 add multiplexed all max_abs_error: "
                 << layer3_block1_add_all_max_abs_error << endl;

            output << "layer3 block1 output ReLU multiplexed k=8: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer3 block1 output ReLU multiplexed k=8 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer3_block1_output =
                plain_polynomial_relu_reference(plain_layer3_block1_add, relu_config);
            MultiplexedCipherGroup layer3_block1_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer3_block1_add_multiplex_group, plan.logN, relu_config, runtime, "layer3 block1 output relu", kBootstrapBeforeReluExceptFirst, mock_options);
            layer3_block1_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer3_block1_output_multiplex_group,
                                                plain_layer3_block1_output, runtime,
                                                &output, "layer3 block1 output relu");
            output << "layer3 block1 output multiplexed homomorphic ReLU all max_abs_error: "
                   << layer3_block1_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer3 block1 output multiplexed homomorphic ReLU all max_abs_error: "
                 << layer3_block1_output_refresh_all_max_abs_error << endl;

            output << "layer4 block0 conv1 multiplexed k=8->k=16 stride-2 evaluation\n";
            resnet18_progress_log()
                << "layer4 block0 conv1 multiplexed k=8->k=16 stride-2 evaluation"
                << endl;
            PlainTensor plain_layer4_block0_conv1 = plain_convolution(
                plain_layer3_block1_output, 512, 2, 3, 3, weights.conv_weight.at(13),
                weights.bn_running_var.at(13), weights.bn_weight.at(13), kBatchNormEpsilon);
            MultiplexedCipherGroup layer4_block0_conv1_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer3_block1_output_multiplex_group, 512, 2, 3, 3,
                    weights.conv_weight.at(13), weights.bn_running_var.at(13),
                    weights.bn_weight.at(13), kBatchNormEpsilon, runtime);
            layer4_block0_conv1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_conv1_multiplex_group, plain_layer4_block0_conv1,
                runtime, &output, "layer4 block0 conv1");
            output << "layer4 block0 conv1 multiplexed max_abs_error: "
                   << layer4_block0_conv1_sparse_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer4 block0 conv1 multiplexed max_abs_error: "
                << layer4_block0_conv1_sparse_max_abs_error << endl;

            output << "layer4 block0 bn1 multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block0 bn1 multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block0_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer4_block0_conv1_multiplex_group, weights.bn_bias.at(13),
                    weights.bn_running_mean.at(13), weights.bn_running_var.at(13),
                    weights.bn_weight.at(13), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer4_block0_bn1 =
                plain_batch_norm(plain_layer4_block0_conv1, weights.bn_bias.at(13),
                                 weights.bn_running_mean.at(13),
                                 weights.bn_running_var.at(13), weights.bn_weight.at(13),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer4_block0_bn1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_bn1_multiplex_group, plain_layer4_block0_bn1,
                runtime, &output, "layer4 block0 bn1");
            output << "layer4 block0 bn1 multiplexed max_abs_error: "
                   << layer4_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 bn1 multiplexed max_abs_error: "
                                    << layer4_block0_bn1_sparse_max_abs_error << endl;

            output << "layer4 block0 relu1 multiplexed k=16: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer4 block0 relu1 multiplexed k=16 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer4_block0_relu1 =
                plain_polynomial_relu_reference(plain_layer4_block0_bn1, relu_config);
            MultiplexedCipherGroup layer4_block0_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer4_block0_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer4 block0 relu1", kBootstrapBeforeReluExceptFirst, mock_options);
            layer4_block0_relu1_refresh_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_relu1_multiplex_group, plain_layer4_block0_relu1,
                runtime, &output, "layer4 block0 relu1");
            output << "layer4 block0 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                   << layer4_block0_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer4 block0 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                                    << layer4_block0_relu1_refresh_all_max_abs_error << endl;

            output << "layer4 block0 conv2 multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block0 conv2 multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block0_conv2_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer4_block0_relu1_multiplex_group, 512, 1, 3, 3,
                    weights.conv_weight.at(14), weights.bn_running_var.at(14),
                    weights.bn_weight.at(14), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer4_block0_conv2 = plain_convolution(
                plain_layer4_block0_relu1, 512, 1, 3, 3, weights.conv_weight.at(14),
                weights.bn_running_var.at(14), weights.bn_weight.at(14), kBatchNormEpsilon);
            layer4_block0_conv2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_conv2_multiplex_group, plain_layer4_block0_conv2,
                runtime, &output, "layer4 block0 conv2");
            output << "layer4 block0 conv2 multiplexed all max_abs_error: "
                   << layer4_block0_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 conv2 multiplexed all max_abs_error: "
                 << layer4_block0_conv2_all_max_abs_error << endl;

            output << "layer4 block0 bn2 multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block0 bn2 multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block0_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer4_block0_conv2_multiplex_group, weights.bn_bias.at(14),
                    weights.bn_running_mean.at(14), weights.bn_running_var.at(14),
                    weights.bn_weight.at(14), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer4_block0_bn2 =
                plain_batch_norm(plain_layer4_block0_conv2, weights.bn_bias.at(14),
                                 weights.bn_running_mean.at(14),
                                 weights.bn_running_var.at(14), weights.bn_weight.at(14),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer4_block0_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_bn2_multiplex_group, plain_layer4_block0_bn2,
                runtime, &output, "layer4 block0 bn2");
            output << "layer4 block0 bn2 multiplexed all max_abs_error: "
                   << layer4_block0_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 bn2 multiplexed all max_abs_error: "
                 << layer4_block0_bn2_all_max_abs_error << endl;

            output << "layer4 block0 projection shortcut multiplexed k=8->k=16 stride-2 evaluation\n";
            resnet18_progress_log()
                << "layer4 block0 projection shortcut multiplexed k=8->k=16 stride-2 evaluation"
                << endl;
            PlainTensor plain_layer4_block0_shortcut_conv = plain_convolution(
                plain_layer3_block1_output, 512, 2, 1, 1,
                weights.downsample_weight.at(2),
                weights.downsample_bn_running_var.at(2),
                weights.downsample_bn_weight.at(2), kBatchNormEpsilon);
            MultiplexedCipherGroup layer4_block0_shortcut_conv_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer3_block1_output_multiplex_group, 512, 2, 1, 1,
                    weights.downsample_weight.at(2),
                    weights.downsample_bn_running_var.at(2),
                    weights.downsample_bn_weight.at(2), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer4_block0_shortcut =
                plain_batch_norm(plain_layer4_block0_shortcut_conv,
                                 weights.downsample_bn_bias.at(2),
                                 weights.downsample_bn_running_mean.at(2),
                                 weights.downsample_bn_running_var.at(2),
                                 weights.downsample_bn_weight.at(2), kBatchNormEpsilon,
                                 kResNet18Boundary);
            MultiplexedCipherGroup layer4_block0_shortcut_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer4_block0_shortcut_conv_multiplex_group,
                    weights.downsample_bn_bias.at(2),
                    weights.downsample_bn_running_mean.at(2),
                    weights.downsample_bn_running_var.at(2),
                    weights.downsample_bn_weight.at(2), kBatchNormEpsilon, kResNet18Boundary, runtime);
            layer4_block0_shortcut_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_shortcut_multiplex_group, plain_layer4_block0_shortcut,
                runtime, &output, "layer4 block0 shortcut");
            output << "layer4 block0 shortcut multiplexed all max_abs_error: "
                   << layer4_block0_shortcut_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer4 block0 shortcut multiplexed all max_abs_error: "
                                    << layer4_block0_shortcut_all_max_abs_error << endl;

            output << "layer4 block0 residual add multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block0 residual add multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block0_add_multiplex_group =
                multiplexed_channel_add(layer4_block0_bn2_multiplex_group,
                                        layer4_block0_shortcut_multiplex_group, runtime);
            PlainTensor plain_layer4_block0_add =
                plain_add(plain_layer4_block0_bn2, plain_layer4_block0_shortcut);
            layer4_block0_add_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_add_multiplex_group, plain_layer4_block0_add,
                runtime, &output, "layer4 block0 add");
            output << "layer4 block0 add multiplexed all max_abs_error: "
                   << layer4_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 add multiplexed all max_abs_error: "
                 << layer4_block0_add_all_max_abs_error << endl;

            output << "layer4 block0 output ReLU multiplexed k=16: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer4 block0 output ReLU multiplexed k=16 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer4_block0_output =
                plain_polynomial_relu_reference(plain_layer4_block0_add, relu_config);
            MultiplexedCipherGroup layer4_block0_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer4_block0_add_multiplex_group, plan.logN, relu_config, runtime, "layer4 block0 output relu", kBootstrapBeforeReluExceptFirst, mock_options);
            layer4_block0_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer4_block0_output_multiplex_group,
                                                plain_layer4_block0_output, runtime,
                                                &output, "layer4 block0 output relu");
            output << "layer4 block0 output multiplexed homomorphic ReLU all max_abs_error: "
                   << layer4_block0_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer4 block0 output multiplexed homomorphic ReLU all max_abs_error: "
                 << layer4_block0_output_refresh_all_max_abs_error << endl;

            output << "layer4 block1 conv1 multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block1 conv1 multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block1_conv1_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer4_block0_output_multiplex_group, 512, 1, 3, 3,
                    weights.conv_weight.at(15), weights.bn_running_var.at(15),
                    weights.bn_weight.at(15), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer4_block1_conv1 = plain_convolution(
                plain_layer4_block0_output, 512, 1, 3, 3, weights.conv_weight.at(15),
                weights.bn_running_var.at(15), weights.bn_weight.at(15), kBatchNormEpsilon);
            layer4_block1_conv1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block1_conv1_multiplex_group, plain_layer4_block1_conv1,
                runtime, &output, "layer4 block1 conv1");
            output << "layer4 block1 conv1 multiplexed all max_abs_error: "
                   << layer4_block1_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 conv1 multiplexed all max_abs_error: "
                 << layer4_block1_conv1_all_max_abs_error << endl;

            output << "layer4 block1 bn1 multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block1 bn1 multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block1_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer4_block1_conv1_multiplex_group, weights.bn_bias.at(15),
                    weights.bn_running_mean.at(15), weights.bn_running_var.at(15),
                    weights.bn_weight.at(15), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer4_block1_bn1 =
                plain_batch_norm(plain_layer4_block1_conv1, weights.bn_bias.at(15),
                                 weights.bn_running_mean.at(15),
                                 weights.bn_running_var.at(15), weights.bn_weight.at(15),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer4_block1_bn1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block1_bn1_multiplex_group, plain_layer4_block1_bn1,
                runtime, &output, "layer4 block1 bn1");
            output << "layer4 block1 bn1 multiplexed all max_abs_error: "
                   << layer4_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 bn1 multiplexed all max_abs_error: "
                 << layer4_block1_bn1_all_max_abs_error << endl;

            output << "layer4 block1 relu1 multiplexed k=16: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer4 block1 relu1 multiplexed k=16 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer4_block1_relu1 =
                plain_polynomial_relu_reference(plain_layer4_block1_bn1, relu_config);
            MultiplexedCipherGroup layer4_block1_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer4_block1_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer4 block1 relu1", kBootstrapBeforeReluExceptFirst, mock_options);
            layer4_block1_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer4_block1_relu1_multiplex_group,
                                                plain_layer4_block1_relu1, runtime,
                                                &output, "layer4 block1 relu1");
            output << "layer4 block1 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                   << layer4_block1_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer4 block1 relu1 multiplexed homomorphic ReLU all max_abs_error: "
                 << layer4_block1_relu1_refresh_all_max_abs_error << endl;

            output << "layer4 block1 conv2 multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block1 conv2 multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block1_conv2_multiplex_group =
                multiplexed_channel_conv2d_all_channels(
                    layer4_block1_relu1_multiplex_group, 512, 1, 3, 3,
                    weights.conv_weight.at(16), weights.bn_running_var.at(16),
                    weights.bn_weight.at(16), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer4_block1_conv2 = plain_convolution(
                plain_layer4_block1_relu1, 512, 1, 3, 3, weights.conv_weight.at(16),
                weights.bn_running_var.at(16), weights.bn_weight.at(16), kBatchNormEpsilon);
            layer4_block1_conv2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block1_conv2_multiplex_group, plain_layer4_block1_conv2,
                runtime, &output, "layer4 block1 conv2");
            output << "layer4 block1 conv2 multiplexed all max_abs_error: "
                   << layer4_block1_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 conv2 multiplexed all max_abs_error: "
                 << layer4_block1_conv2_all_max_abs_error << endl;

            output << "layer4 block1 bn2 multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block1 bn2 multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block1_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer4_block1_conv2_multiplex_group, weights.bn_bias.at(16),
                    weights.bn_running_mean.at(16), weights.bn_running_var.at(16),
                    weights.bn_weight.at(16), kBatchNormEpsilon, kResNet18Boundary, runtime);
            PlainTensor plain_layer4_block1_bn2 =
                plain_batch_norm(plain_layer4_block1_conv2, weights.bn_bias.at(16),
                                 weights.bn_running_mean.at(16),
                                 weights.bn_running_var.at(16), weights.bn_weight.at(16),
                                 kBatchNormEpsilon, kResNet18Boundary);
            layer4_block1_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block1_bn2_multiplex_group, plain_layer4_block1_bn2,
                runtime, &output, "layer4 block1 bn2");
            output << "layer4 block1 bn2 multiplexed all max_abs_error: "
                   << layer4_block1_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 bn2 multiplexed all max_abs_error: "
                 << layer4_block1_bn2_all_max_abs_error << endl;

            output << "layer4 block1 residual add multiplexed k=16 evaluation\n";
            resnet18_progress_log() << "layer4 block1 residual add multiplexed k=16 evaluation"
                                    << endl;
            MultiplexedCipherGroup layer4_block1_add_multiplex_group =
                multiplexed_channel_add(layer4_block1_bn2_multiplex_group,
                                        layer4_block0_output_multiplex_group, runtime);
            PlainTensor plain_layer4_block1_add =
                plain_add(plain_layer4_block1_bn2, plain_layer4_block0_output);
            layer4_block1_add_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block1_add_multiplex_group, plain_layer4_block1_add,
                runtime, &output, "layer4 block1 add");
            output << "layer4 block1 add multiplexed all max_abs_error: "
                   << layer4_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 add multiplexed all max_abs_error: "
                 << layer4_block1_add_all_max_abs_error << endl;

            output << "layer4 block1 output ReLU multiplexed k=16: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer4 block1 output ReLU multiplexed k=16 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer4_block1_output =
                plain_polynomial_relu_reference(plain_layer4_block1_add, relu_config);
            MultiplexedCipherGroup layer4_block1_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(
                    layer4_block1_add_multiplex_group, plan.logN, relu_config,
                    runtime, "layer4 block1 output relu",
                    kBootstrapBeforeReluExceptFirst, mock_options,
                    true /* preserve levels needed by the current head */);
            layer4_block1_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer4_block1_output_multiplex_group,
                                                plain_layer4_block1_output, runtime,
                                                &output, "layer4 block1 output relu");
            output << "layer4 block1 output multiplexed homomorphic ReLU all max_abs_error: "
                   << layer4_block1_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log()
                << "layer4 block1 output multiplexed homomorphic ReLU all max_abs_error: "
                 << layer4_block1_output_refresh_all_max_abs_error << endl;

            output << "head avgpool encrypted multiplexed: using precomputed rotation keys\n";
            vector<int> head_pool_steps = multiplexed_head_average_pool_rotation_steps(
                layer4_block1_output_multiplex_group);
            resnet18_progress_log() << "head avgpool rotation key count: "
                                    << head_pool_steps.size() << endl;
            output << "head avgpool rotation key count: " << head_pool_steps.size()
                   << '\n';

            output << "head avgpool encrypted multiplexed: rotate/mask/add evaluation\n";
            resnet18_progress_log() << "head avgpool encrypted multiplexed evaluation"
                                    << endl;
            PlainTensor plain_head_pooled = plain_average_pool(plain_layer4_block1_output, kResNet18Boundary);
            TensorCipher encrypted_head_pooled = encrypted_multiplexed_head_average_pool(
                layer4_block1_output_multiplex_group, static_cast<int>(plan.logN),
                plan.log_scale, kResNet18Boundary, runtime);
            if (!resnet18_execution::inference_only())
            {
                vector<double> encrypted_pooled_values =
                    decode_real_slots(encrypted_head_pooled, runtime,
                                      kResNet18FinalChannels);
                dump_plain_cipher_preview(
                    "head avgpool", plain_head_pooled.values,
                    decode_complex_slots(encrypted_head_pooled, runtime,
                                         kResNet18FinalChannels),
                    output);
                head_avgpool_debug_pack_max_abs_error = 0.0;
                for (int channel = 0; channel < kResNet18FinalChannels; ++channel)
                {
                    head_avgpool_debug_pack_max_abs_error =
                        max(head_avgpool_debug_pack_max_abs_error,
                            abs(encrypted_pooled_values.at(static_cast<size_t>(channel)) -
                                plain_head_pooled.at(channel, 0, 0)));
                }
                output << "head avgpool encrypted multiplexed max_abs_error: "
                       << head_avgpool_debug_pack_max_abs_error << '\n';
                resnet18_progress_log()
                    << "head avgpool encrypted multiplexed max_abs_error: "
                    << head_avgpool_debug_pack_max_abs_error << endl;
            }

            output << "head fully connected: BSGS using precomputed direct rotation keys\n";
            vector<int> fc_steps =
                fully_connected_bsgs_rotation_steps(
                    kImageNetClassCount, kResNet18FinalChannels,
                    runtime.slot_count);
            const int fc_baby_step = fully_connected_bsgs_baby_step(
                kImageNetClassCount, kResNet18FinalChannels,
                runtime.slot_count);
            resnet18_progress_log()
                << "head fully connected BSGS: baby_step=" << fc_baby_step
                << ", direct_rotation_key_count=" << fc_steps.size()
                << endl;
            output << "head fully connected BSGS baby_step: " << fc_baby_step
                   << ", direct rotation key count: " << fc_steps.size() << '\n';

            output << "head fully connected: encrypted logits evaluation\n";
            resnet18_progress_log() << "head fully connected encrypted logits evaluation" << endl;
            TensorCipher encrypted_head_logits;
            {
                ScopedDurationLog duration("head fully connected");
                matrix_multiplication(
                    encrypted_head_pooled, encrypted_head_logits, fc_plain_plan,
                    *runtime.evaluator, runtime.galois_keys, runtime.encoder);
            }
            log_tensor_cipher_state("head fully connected logits output", encrypted_head_logits,
                                    runtime);

            vector<double> plain_head_logits =
                plain_fully_connected(plain_head_pooled, weights.linear_weight,
                                      weights.linear_bias, kImageNetClassCount,
                                      kResNet18FinalChannels);
            if (!resnet18_execution::inference_only())
            {
                vector<double> decrypted_head_logits =
                    decode_real_slots(encrypted_head_logits, runtime,
                                      kImageNetClassCount);
                vector<complex<double>> decrypted_head_logits_complex =
                    decode_complex_slots(encrypted_head_logits, runtime,
                                         kImageNetClassCount);
                dump_plain_cipher_preview(
                    "head logits", plain_head_logits, decrypted_head_logits_complex,
                    output, kImageNetClassCount);
                head_logits_max_abs_error = 0.0;
                for (int i = 0; i < kImageNetClassCount; ++i)
                {
                    head_logits_max_abs_error =
                        max(head_logits_max_abs_error,
                            abs(decrypted_head_logits.at(static_cast<size_t>(i)) -
                                plain_head_logits.at(static_cast<size_t>(i))));
                }
                encrypted_predicted_label = argmax_index(decrypted_head_logits);
                plain_head_predicted_label = argmax_index(plain_head_logits);
                dump_logit_decision_summary(
                    plain_head_logits, decrypted_head_logits_complex, image_label,
                    plain_head_predicted_label, encrypted_predicted_label, output);
                dump_selected_logits(
                    plain_head_logits, decrypted_head_logits_complex,
                    {image_label, plain_head_predicted_label, encrypted_predicted_label},
                    output);
                output << "head logits max_abs_error: " << head_logits_max_abs_error
                       << '\n';
                output << "head plain predicted label: "
                       << plain_head_predicted_label
                       << ", encrypted predicted label: "
                       << encrypted_predicted_label << '\n';
                resnet18_progress_log()
                    << "head logits max_abs_error: " << head_logits_max_abs_error
                    << endl;
                resnet18_progress_log()
                    << "head plain predicted label: " << plain_head_predicted_label
                    << ", encrypted predicted label: " << encrypted_predicted_label
                    << endl;
            }
        }

        const long long encrypted_inference_time_ms =
            encrypted_inference_timer.elapsed_milliseconds();
        const size_t encrypted_inference_operation_count =
            encrypted_inference_timer.operation_count();
        output << "encrypted inference time : " << encrypted_inference_time_ms
               << " ms, operation_count=" << encrypted_inference_operation_count
               << '\n';
        resnet18_progress_log()
            << "[duration] encrypted inference (input ciphertext ready to encrypted logits): "
            << encrypted_inference_time_ms
            << " ms, operation_count=" << encrypted_inference_operation_count
            << endl;

        const auto image_time_end = chrono::high_resolution_clock::now();
        const auto image_time_diff =
            chrono::duration_cast<chrono::milliseconds>(image_time_end - image_time_start);
        output << "image label: " << image_label << '\n';
        output << "image time : " << image_time_diff.count() << " ms" << endl;

        out_log << "image_id: " << image_id << ", image label: " << image_label
                  << ", stem_conv1_all_max_abs_error: "
                  << stem_conv1_all_max_abs_error
                  << ", stem_bn_all_max_abs_error: " << stem_bn_all_max_abs_error
                  << ", stem_relu_refresh_all_max_abs_error: "
                  << stem_relu_refresh_all_max_abs_error
                  << ", stem_avgpool_all_max_abs_error: "
                  << stem_avgpool_all_max_abs_error
                  << ", layer1_block0_conv1_all_max_abs_error: "
                  << layer1_block0_conv1_all_max_abs_error
                  << ", layer1_block0_bn1_all_max_abs_error: "
                  << layer1_block0_bn1_all_max_abs_error
                  << ", layer1_block0_relu1_refresh_all_max_abs_error: "
                  << layer1_block0_relu1_refresh_all_max_abs_error
                  << ", layer1_block0_conv2_all_max_abs_error: "
                  << layer1_block0_conv2_all_max_abs_error
                  << ", layer1_block0_bn2_all_max_abs_error: "
                  << layer1_block0_bn2_all_max_abs_error
                  << ", layer1_block0_add_all_max_abs_error: "
                  << layer1_block0_add_all_max_abs_error
                  << ", layer1_block0_output_refresh_all_max_abs_error: "
                  << layer1_block0_output_refresh_all_max_abs_error
                  << ", layer1_block1_conv1_all_max_abs_error: "
                  << layer1_block1_conv1_all_max_abs_error
                  << ", layer1_block1_bn1_all_max_abs_error: "
                  << layer1_block1_bn1_all_max_abs_error
                  << ", layer1_block1_relu1_refresh_all_max_abs_error: "
                  << layer1_block1_relu1_refresh_all_max_abs_error
                  << ", layer1_block1_conv2_all_max_abs_error: "
                  << layer1_block1_conv2_all_max_abs_error
                  << ", layer1_block1_bn2_all_max_abs_error: "
                  << layer1_block1_bn2_all_max_abs_error
                  << ", layer1_block1_add_all_max_abs_error: "
                  << layer1_block1_add_all_max_abs_error
                  << ", layer1_block1_output_refresh_all_max_abs_error: "
                  << layer1_block1_output_refresh_all_max_abs_error
                  << ", layer2_block0_conv1_sparse_max_abs_error: "
                  << layer2_block0_conv1_sparse_max_abs_error
                  << ", layer2_block0_bn1_sparse_max_abs_error: "
                  << layer2_block0_bn1_sparse_max_abs_error
                  << ", layer2_block0_relu1_refresh_all_max_abs_error: "
                  << layer2_block0_relu1_refresh_all_max_abs_error
                  << ", layer2_block0_conv2_all_max_abs_error: "
                  << layer2_block0_conv2_all_max_abs_error
                  << ", layer2_block0_bn2_all_max_abs_error: "
                  << layer2_block0_bn2_all_max_abs_error
                  << ", layer2_block0_shortcut_all_max_abs_error: "
                  << layer2_block0_shortcut_all_max_abs_error
                  << ", layer2_block0_add_all_max_abs_error: "
                  << layer2_block0_add_all_max_abs_error
                  << ", layer2_block0_output_refresh_all_max_abs_error: "
                  << layer2_block0_output_refresh_all_max_abs_error
                  << ", layer2_block1_conv1_all_max_abs_error: "
                  << layer2_block1_conv1_all_max_abs_error
                  << ", layer2_block1_bn1_all_max_abs_error: "
                  << layer2_block1_bn1_all_max_abs_error
                  << ", layer2_block1_relu1_refresh_all_max_abs_error: "
                  << layer2_block1_relu1_refresh_all_max_abs_error
                  << ", layer2_block1_conv2_all_max_abs_error: "
                  << layer2_block1_conv2_all_max_abs_error
                  << ", layer2_block1_bn2_all_max_abs_error: "
                  << layer2_block1_bn2_all_max_abs_error
                  << ", layer2_block1_add_all_max_abs_error: "
                  << layer2_block1_add_all_max_abs_error
                  << ", layer2_block1_output_refresh_all_max_abs_error: "
                  << layer2_block1_output_refresh_all_max_abs_error
                  << ", layer3_block0_conv1_sparse_max_abs_error: "
                  << layer3_block0_conv1_sparse_max_abs_error
                  << ", layer3_block0_bn1_sparse_max_abs_error: "
                  << layer3_block0_bn1_sparse_max_abs_error
                  << ", layer3_block0_relu1_refresh_all_max_abs_error: "
                  << layer3_block0_relu1_refresh_all_max_abs_error
                  << ", layer3_block0_conv2_all_max_abs_error: "
                  << layer3_block0_conv2_all_max_abs_error
                  << ", layer3_block0_bn2_all_max_abs_error: "
                  << layer3_block0_bn2_all_max_abs_error
                  << ", layer3_block0_shortcut_all_max_abs_error: "
                  << layer3_block0_shortcut_all_max_abs_error
                  << ", layer3_block0_add_all_max_abs_error: "
                  << layer3_block0_add_all_max_abs_error
                  << ", layer3_block0_output_refresh_all_max_abs_error: "
                  << layer3_block0_output_refresh_all_max_abs_error
                  << ", layer3_block1_conv1_all_max_abs_error: "
                  << layer3_block1_conv1_all_max_abs_error
                  << ", layer3_block1_bn1_all_max_abs_error: "
                  << layer3_block1_bn1_all_max_abs_error
                  << ", layer3_block1_relu1_refresh_all_max_abs_error: "
                  << layer3_block1_relu1_refresh_all_max_abs_error
                  << ", layer3_block1_conv2_all_max_abs_error: "
                  << layer3_block1_conv2_all_max_abs_error
                  << ", layer3_block1_bn2_all_max_abs_error: "
                  << layer3_block1_bn2_all_max_abs_error
                  << ", layer3_block1_add_all_max_abs_error: "
                  << layer3_block1_add_all_max_abs_error
                  << ", layer3_block1_output_refresh_all_max_abs_error: "
                  << layer3_block1_output_refresh_all_max_abs_error
                  << ", layer4_block0_conv1_sparse_max_abs_error: "
                  << layer4_block0_conv1_sparse_max_abs_error
                  << ", layer4_block0_bn1_sparse_max_abs_error: "
                  << layer4_block0_bn1_sparse_max_abs_error
                  << ", layer4_block0_relu1_refresh_all_max_abs_error: "
                  << layer4_block0_relu1_refresh_all_max_abs_error
                  << ", layer4_block0_conv2_all_max_abs_error: "
                  << layer4_block0_conv2_all_max_abs_error
                  << ", layer4_block0_bn2_all_max_abs_error: "
                  << layer4_block0_bn2_all_max_abs_error
                  << ", layer4_block0_shortcut_all_max_abs_error: "
                  << layer4_block0_shortcut_all_max_abs_error
                  << ", layer4_block0_add_all_max_abs_error: "
                  << layer4_block0_add_all_max_abs_error
                  << ", layer4_block0_output_refresh_all_max_abs_error: "
                  << layer4_block0_output_refresh_all_max_abs_error
                  << ", layer4_block1_conv1_all_max_abs_error: "
                  << layer4_block1_conv1_all_max_abs_error
                  << ", layer4_block1_bn1_all_max_abs_error: "
                  << layer4_block1_bn1_all_max_abs_error
                  << ", layer4_block1_relu1_refresh_all_max_abs_error: "
                  << layer4_block1_relu1_refresh_all_max_abs_error
                  << ", layer4_block1_conv2_all_max_abs_error: "
                  << layer4_block1_conv2_all_max_abs_error
                  << ", layer4_block1_bn2_all_max_abs_error: "
                  << layer4_block1_bn2_all_max_abs_error
                  << ", layer4_block1_add_all_max_abs_error: "
                  << layer4_block1_add_all_max_abs_error
                  << ", layer4_block1_output_refresh_all_max_abs_error: "
                  << layer4_block1_output_refresh_all_max_abs_error
                  << ", head_avgpool_debug_pack_max_abs_error: "
                  << head_avgpool_debug_pack_max_abs_error
                  << ", head_logits_max_abs_error: " << head_logits_max_abs_error
                  << ", plain_head_predicted_label: " << plain_head_predicted_label
                  << ", encrypted_predicted_label: " << encrypted_predicted_label
                  << ", image time : " << image_time_diff.count() << " ms" << endl;
        resnet18_progress_log() << "image_id: " << image_id << ", image label: " << image_label
             << ", stem_conv1_all_max_abs_error: "
             << stem_conv1_all_max_abs_error
             << ", stem_bn_all_max_abs_error: " << stem_bn_all_max_abs_error
             << ", stem_relu_refresh_all_max_abs_error: "
             << stem_relu_refresh_all_max_abs_error
             << ", stem_avgpool_all_max_abs_error: "
             << stem_avgpool_all_max_abs_error
             << ", layer1_block0_conv1_all_max_abs_error: "
             << layer1_block0_conv1_all_max_abs_error
             << ", layer1_block0_bn1_all_max_abs_error: "
             << layer1_block0_bn1_all_max_abs_error
             << ", layer1_block0_relu1_refresh_all_max_abs_error: "
             << layer1_block0_relu1_refresh_all_max_abs_error
             << ", layer1_block0_conv2_all_max_abs_error: "
             << layer1_block0_conv2_all_max_abs_error
             << ", layer1_block0_bn2_all_max_abs_error: "
             << layer1_block0_bn2_all_max_abs_error
             << ", layer1_block0_add_all_max_abs_error: "
             << layer1_block0_add_all_max_abs_error
             << ", layer1_block0_output_refresh_all_max_abs_error: "
             << layer1_block0_output_refresh_all_max_abs_error
             << ", layer1_block1_conv1_all_max_abs_error: "
             << layer1_block1_conv1_all_max_abs_error
             << ", layer1_block1_bn1_all_max_abs_error: "
             << layer1_block1_bn1_all_max_abs_error
             << ", layer1_block1_relu1_refresh_all_max_abs_error: "
             << layer1_block1_relu1_refresh_all_max_abs_error
             << ", layer1_block1_conv2_all_max_abs_error: "
             << layer1_block1_conv2_all_max_abs_error
             << ", layer1_block1_bn2_all_max_abs_error: "
             << layer1_block1_bn2_all_max_abs_error
             << ", layer1_block1_add_all_max_abs_error: "
             << layer1_block1_add_all_max_abs_error
             << ", layer1_block1_output_refresh_all_max_abs_error: "
             << layer1_block1_output_refresh_all_max_abs_error
             << ", layer2_block0_conv1_sparse_max_abs_error: "
             << layer2_block0_conv1_sparse_max_abs_error
             << ", layer2_block0_bn1_sparse_max_abs_error: "
             << layer2_block0_bn1_sparse_max_abs_error
             << ", layer2_block0_relu1_refresh_all_max_abs_error: "
             << layer2_block0_relu1_refresh_all_max_abs_error
             << ", layer2_block0_conv2_all_max_abs_error: "
             << layer2_block0_conv2_all_max_abs_error
             << ", layer2_block0_bn2_all_max_abs_error: "
             << layer2_block0_bn2_all_max_abs_error
             << ", layer2_block0_shortcut_all_max_abs_error: "
             << layer2_block0_shortcut_all_max_abs_error
             << ", layer2_block0_add_all_max_abs_error: "
             << layer2_block0_add_all_max_abs_error
             << ", layer2_block0_output_refresh_all_max_abs_error: "
             << layer2_block0_output_refresh_all_max_abs_error
             << ", layer2_block1_conv1_all_max_abs_error: "
             << layer2_block1_conv1_all_max_abs_error
             << ", layer2_block1_bn1_all_max_abs_error: "
             << layer2_block1_bn1_all_max_abs_error
             << ", layer2_block1_relu1_refresh_all_max_abs_error: "
             << layer2_block1_relu1_refresh_all_max_abs_error
             << ", layer2_block1_conv2_all_max_abs_error: "
             << layer2_block1_conv2_all_max_abs_error
             << ", layer2_block1_bn2_all_max_abs_error: "
             << layer2_block1_bn2_all_max_abs_error
             << ", layer2_block1_add_all_max_abs_error: "
             << layer2_block1_add_all_max_abs_error
             << ", layer2_block1_output_refresh_all_max_abs_error: "
             << layer2_block1_output_refresh_all_max_abs_error
             << ", layer3_block0_conv1_sparse_max_abs_error: "
             << layer3_block0_conv1_sparse_max_abs_error
             << ", layer3_block0_bn1_sparse_max_abs_error: "
             << layer3_block0_bn1_sparse_max_abs_error
             << ", layer3_block0_relu1_refresh_all_max_abs_error: "
             << layer3_block0_relu1_refresh_all_max_abs_error
             << ", layer3_block0_conv2_all_max_abs_error: "
             << layer3_block0_conv2_all_max_abs_error
             << ", layer3_block0_bn2_all_max_abs_error: "
             << layer3_block0_bn2_all_max_abs_error
             << ", layer3_block0_shortcut_all_max_abs_error: "
             << layer3_block0_shortcut_all_max_abs_error
             << ", layer3_block0_add_all_max_abs_error: "
             << layer3_block0_add_all_max_abs_error
             << ", layer3_block0_output_refresh_all_max_abs_error: "
             << layer3_block0_output_refresh_all_max_abs_error
             << ", layer3_block1_conv1_all_max_abs_error: "
             << layer3_block1_conv1_all_max_abs_error
             << ", layer3_block1_bn1_all_max_abs_error: "
             << layer3_block1_bn1_all_max_abs_error
             << ", layer3_block1_relu1_refresh_all_max_abs_error: "
             << layer3_block1_relu1_refresh_all_max_abs_error
             << ", layer3_block1_conv2_all_max_abs_error: "
             << layer3_block1_conv2_all_max_abs_error
             << ", layer3_block1_bn2_all_max_abs_error: "
             << layer3_block1_bn2_all_max_abs_error
             << ", layer3_block1_add_all_max_abs_error: "
             << layer3_block1_add_all_max_abs_error
             << ", layer3_block1_output_refresh_all_max_abs_error: "
             << layer3_block1_output_refresh_all_max_abs_error
             << ", layer4_block0_conv1_sparse_max_abs_error: "
             << layer4_block0_conv1_sparse_max_abs_error
             << ", layer4_block0_bn1_sparse_max_abs_error: "
             << layer4_block0_bn1_sparse_max_abs_error
             << ", layer4_block0_relu1_refresh_all_max_abs_error: "
             << layer4_block0_relu1_refresh_all_max_abs_error
             << ", layer4_block0_conv2_all_max_abs_error: "
             << layer4_block0_conv2_all_max_abs_error
             << ", layer4_block0_bn2_all_max_abs_error: "
             << layer4_block0_bn2_all_max_abs_error
             << ", layer4_block0_shortcut_all_max_abs_error: "
             << layer4_block0_shortcut_all_max_abs_error
             << ", layer4_block0_add_all_max_abs_error: "
             << layer4_block0_add_all_max_abs_error
             << ", layer4_block0_output_refresh_all_max_abs_error: "
             << layer4_block0_output_refresh_all_max_abs_error
             << ", layer4_block1_conv1_all_max_abs_error: "
             << layer4_block1_conv1_all_max_abs_error
             << ", layer4_block1_bn1_all_max_abs_error: "
             << layer4_block1_bn1_all_max_abs_error
             << ", layer4_block1_relu1_refresh_all_max_abs_error: "
             << layer4_block1_relu1_refresh_all_max_abs_error
             << ", layer4_block1_conv2_all_max_abs_error: "
             << layer4_block1_conv2_all_max_abs_error
             << ", layer4_block1_bn2_all_max_abs_error: "
             << layer4_block1_bn2_all_max_abs_error
             << ", layer4_block1_add_all_max_abs_error: "
             << layer4_block1_add_all_max_abs_error
             << ", layer4_block1_output_refresh_all_max_abs_error: "
             << layer4_block1_output_refresh_all_max_abs_error
             << ", head_avgpool_debug_pack_max_abs_error: "
             << head_avgpool_debug_pack_max_abs_error
             << ", head_logits_max_abs_error: " << head_logits_max_abs_error
             << ", plain_head_predicted_label: " << plain_head_predicted_label
             << ", encrypted_predicted_label: " << encrypted_predicted_label
             << ", image time : " << image_time_diff.count() << " ms" << endl;
        out_log << "image_done: " << image_id
                   << ", image label: " << image_label
                   << ", stem_conv1_all_max_abs_error="
                   << stem_conv1_all_max_abs_error
                   << ", stem_bn_all_max_abs_error=" << stem_bn_all_max_abs_error
                   << ", stem_relu_refresh_all_max_abs_error="
                   << stem_relu_refresh_all_max_abs_error
                   << ", stem_avgpool_all_max_abs_error="
                   << stem_avgpool_all_max_abs_error
                   << ", layer1_block0_conv1_all_max_abs_error="
                   << layer1_block0_conv1_all_max_abs_error
                   << ", layer1_block0_bn1_all_max_abs_error="
                   << layer1_block0_bn1_all_max_abs_error
                   << ", layer1_block0_relu1_refresh_all_max_abs_error="
                   << layer1_block0_relu1_refresh_all_max_abs_error
                   << ", layer1_block0_conv2_all_max_abs_error="
                   << layer1_block0_conv2_all_max_abs_error
                   << ", layer1_block0_bn2_all_max_abs_error="
                   << layer1_block0_bn2_all_max_abs_error
                   << ", layer1_block0_add_all_max_abs_error="
                   << layer1_block0_add_all_max_abs_error
                   << ", layer1_block0_output_refresh_all_max_abs_error="
                   << layer1_block0_output_refresh_all_max_abs_error
                   << ", layer1_block1_conv1_all_max_abs_error="
                   << layer1_block1_conv1_all_max_abs_error
                   << ", layer1_block1_bn1_all_max_abs_error="
                   << layer1_block1_bn1_all_max_abs_error
                   << ", layer1_block1_relu1_refresh_all_max_abs_error="
                   << layer1_block1_relu1_refresh_all_max_abs_error
                   << ", layer1_block1_conv2_all_max_abs_error="
                   << layer1_block1_conv2_all_max_abs_error
                   << ", layer1_block1_bn2_all_max_abs_error="
                   << layer1_block1_bn2_all_max_abs_error
                   << ", layer1_block1_add_all_max_abs_error="
                   << layer1_block1_add_all_max_abs_error
                   << ", layer1_block1_output_refresh_all_max_abs_error="
                   << layer1_block1_output_refresh_all_max_abs_error
                   << ", layer2_block0_conv1_sparse_max_abs_error="
                   << layer2_block0_conv1_sparse_max_abs_error
                   << ", layer2_block0_bn1_sparse_max_abs_error="
                   << layer2_block0_bn1_sparse_max_abs_error
                   << ", layer2_block0_relu1_refresh_all_max_abs_error="
                   << layer2_block0_relu1_refresh_all_max_abs_error
                   << ", layer2_block0_conv2_all_max_abs_error="
                   << layer2_block0_conv2_all_max_abs_error
                   << ", layer2_block0_bn2_all_max_abs_error="
                   << layer2_block0_bn2_all_max_abs_error
                   << ", layer2_block0_shortcut_all_max_abs_error="
                   << layer2_block0_shortcut_all_max_abs_error
                   << ", layer2_block0_add_all_max_abs_error="
                   << layer2_block0_add_all_max_abs_error
                   << ", layer2_block0_output_refresh_all_max_abs_error="
                   << layer2_block0_output_refresh_all_max_abs_error
                   << ", layer2_block1_conv1_all_max_abs_error="
                   << layer2_block1_conv1_all_max_abs_error
                   << ", layer2_block1_bn1_all_max_abs_error="
                   << layer2_block1_bn1_all_max_abs_error
                   << ", layer2_block1_relu1_refresh_all_max_abs_error="
                   << layer2_block1_relu1_refresh_all_max_abs_error
                   << ", layer2_block1_conv2_all_max_abs_error="
                   << layer2_block1_conv2_all_max_abs_error
                   << ", layer2_block1_bn2_all_max_abs_error="
                   << layer2_block1_bn2_all_max_abs_error
                   << ", layer2_block1_add_all_max_abs_error="
                   << layer2_block1_add_all_max_abs_error
                   << ", layer2_block1_output_refresh_all_max_abs_error="
                   << layer2_block1_output_refresh_all_max_abs_error
                   << ", layer3_block0_conv1_sparse_max_abs_error="
                   << layer3_block0_conv1_sparse_max_abs_error
                   << ", layer3_block0_bn1_sparse_max_abs_error="
                   << layer3_block0_bn1_sparse_max_abs_error
                   << ", layer3_block0_relu1_refresh_all_max_abs_error="
                   << layer3_block0_relu1_refresh_all_max_abs_error
                   << ", layer3_block0_conv2_all_max_abs_error="
                   << layer3_block0_conv2_all_max_abs_error
                   << ", layer3_block0_bn2_all_max_abs_error="
                   << layer3_block0_bn2_all_max_abs_error
                   << ", layer3_block0_shortcut_all_max_abs_error="
                   << layer3_block0_shortcut_all_max_abs_error
                   << ", layer3_block0_add_all_max_abs_error="
                   << layer3_block0_add_all_max_abs_error
                   << ", layer3_block0_output_refresh_all_max_abs_error="
                   << layer3_block0_output_refresh_all_max_abs_error
                   << ", layer3_block1_conv1_all_max_abs_error="
                   << layer3_block1_conv1_all_max_abs_error
                   << ", layer3_block1_bn1_all_max_abs_error="
                   << layer3_block1_bn1_all_max_abs_error
                   << ", layer3_block1_relu1_refresh_all_max_abs_error="
                   << layer3_block1_relu1_refresh_all_max_abs_error
                   << ", layer3_block1_conv2_all_max_abs_error="
                   << layer3_block1_conv2_all_max_abs_error
                   << ", layer3_block1_bn2_all_max_abs_error="
                   << layer3_block1_bn2_all_max_abs_error
                   << ", layer3_block1_add_all_max_abs_error="
                   << layer3_block1_add_all_max_abs_error
                   << ", layer3_block1_output_refresh_all_max_abs_error="
                   << layer3_block1_output_refresh_all_max_abs_error
                   << ", layer4_block0_conv1_sparse_max_abs_error="
                   << layer4_block0_conv1_sparse_max_abs_error
                   << ", layer4_block0_bn1_sparse_max_abs_error="
                   << layer4_block0_bn1_sparse_max_abs_error
                   << ", layer4_block0_relu1_refresh_all_max_abs_error="
                   << layer4_block0_relu1_refresh_all_max_abs_error
                   << ", layer4_block0_conv2_all_max_abs_error="
                   << layer4_block0_conv2_all_max_abs_error
                   << ", layer4_block0_bn2_all_max_abs_error="
                   << layer4_block0_bn2_all_max_abs_error
                   << ", layer4_block0_shortcut_all_max_abs_error="
                   << layer4_block0_shortcut_all_max_abs_error
                   << ", layer4_block0_add_all_max_abs_error="
                   << layer4_block0_add_all_max_abs_error
                   << ", layer4_block0_output_refresh_all_max_abs_error="
                   << layer4_block0_output_refresh_all_max_abs_error
                   << ", layer4_block1_conv1_all_max_abs_error="
                   << layer4_block1_conv1_all_max_abs_error
                   << ", layer4_block1_bn1_all_max_abs_error="
                   << layer4_block1_bn1_all_max_abs_error
                   << ", layer4_block1_relu1_refresh_all_max_abs_error="
                   << layer4_block1_relu1_refresh_all_max_abs_error
                   << ", layer4_block1_conv2_all_max_abs_error="
                   << layer4_block1_conv2_all_max_abs_error
                   << ", layer4_block1_bn2_all_max_abs_error="
                   << layer4_block1_bn2_all_max_abs_error
                   << ", layer4_block1_add_all_max_abs_error="
                   << layer4_block1_add_all_max_abs_error
                   << ", layer4_block1_output_refresh_all_max_abs_error="
                   << layer4_block1_output_refresh_all_max_abs_error
                   << ", head_avgpool_debug_pack_max_abs_error="
                   << head_avgpool_debug_pack_max_abs_error
                   << ", head_logits_max_abs_error=" << head_logits_max_abs_error
                   << ", plain_head_predicted_label=" << plain_head_predicted_label
                   << ", encrypted_predicted_label=" << encrypted_predicted_label
                   << ", encrypted_inference_time_ms="
                   << encrypted_inference_time_ms
                   << ", encrypted_inference_operation_count="
                   << encrypted_inference_operation_count
                   << ", image_time_ms=" << image_time_diff.count() << '\n';
        out_log.flush();
    }

    const auto all_time_end = chrono::steady_clock::now();
    const auto all_time_diff =
        chrono::duration_cast<chrono::milliseconds>(all_time_end - all_time_start);
    resnet18_progress_log() << "total time : " << all_time_diff.count() << " ms" << endl;
    out_log << endl << "total time : " << all_time_diff.count() << " ms" << endl;
    const ConvPlaintextCache::Stats final_plaintext_cache_stats =
        conv_plaintext_cache.stats();
    out_log << "conv plaintext cache final: hits="
            << final_plaintext_cache_stats.hits
            << ", misses=" << final_plaintext_cache_stats.misses
            << ", resident_bytes=" << final_plaintext_cache_stats.resident_bytes
            << ", entries=" << final_plaintext_cache_stats.entries
            << ", evictions=" << final_plaintext_cache_stats.evictions
            << ", encoded_bytes=" << final_plaintext_cache_stats.encoded_bytes
            << '\n';
    out_log << "run_done: total_time_ms=" << all_time_diff.count() << '\n';
}
