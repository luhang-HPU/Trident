#include "infer.h"

#include "encrypted_ops.h"
#include "encrypted_group_ops.h"
#include "infer_config.h"
#include "infer_runtime.h"
#include "parallel_utils.h"
#include "parameter_loader.h"
#include "plain_cnn.h"
#include "progress_log.h"
#include "tensor_cipher_group.h"

#include "poseidon/advance/homomorphic_dft.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <complex>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <set>
#include <stdexcept>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace std;
using namespace poseidon;

namespace fs = std::filesystem;

namespace
{

constexpr bool kRunFullStemCheck = true;

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

size_t drop_trailing_51_bit_primes(Ciphertext &cipher, PoseidonRuntime &runtime)
{
    size_t dropped = 0;
    while (next_rescale_prime_bits(cipher, runtime) == 51)
    {
        Ciphertext next;
        runtime.evaluator->drop_modulus_to_next(cipher, next);
        cipher = std::move(next);
        ++dropped;
    }
    return dropped;
}

size_t drop_trailing_51_bit_primes(vector<Ciphertext> &ciphers, PoseidonRuntime &runtime)
{
    size_t max_dropped = 0;
    for (Ciphertext &cipher : ciphers)
    {
        max_dropped = max(max_dropped, drop_trailing_51_bit_primes(cipher, runtime));
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

Ciphertext multiply_plain_vector_rescale(const Ciphertext &input,
                                         const vector<double> &plain_vector,
                                         PoseidonRuntime &runtime)
{
    Plaintext plain;
    runtime.encoder.encode(plain_vector, input.parms_id(),
                           local_multiply_plain_scale(input, runtime.encoder), plain);
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

vector<int> power_of_two_rotation_steps(size_t slot_count)
{
    vector<int> steps;
    for (size_t step = 1; step < slot_count; step <<= 1)
    {
        steps.push_back(static_cast<int>(step));
    }
    return steps;
}

void rotate_with_power_of_two_keys(const Ciphertext &input, Ciphertext &output,
                                   long long step, PoseidonRuntime &runtime)
{
    int remaining = normalize_rotation_step(step, runtime.slot_count);
    if (remaining == 0)
    {
        output = input;
        return;
    }

    Ciphertext current = input;
    int bit = 1;
    while (remaining > 0)
    {
        if ((remaining & bit) != 0)
        {
            Ciphertext rotated;
            runtime.evaluator->rotate(current, rotated, bit, runtime.galois_keys);
            current = std::move(rotated);
            remaining -= bit;
        }
        bit <<= 1;
    }
    output = std::move(current);
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
            rotate_with_power_of_two_keys(
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

double multiplexed_group_max_abs_error(const MultiplexedCipherGroup &group,
                                       const PlainTensor &plain,
                                       PoseidonRuntime &runtime)
{
    vector<double> decrypted = decrypt_multiplexed_group(group, runtime);
    if (decrypted.size() != plain.values.size())
    {
        throw invalid_argument("multiplexed group/plain tensor size mismatch");
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
        rotate_with_power_of_two_keys(sum, rotated, pow2_int(x), runtime);
        Ciphertext next_sum;
        runtime.evaluator->add_dynamic(sum, rotated, next_sum, runtime.encoder);
        sum = std::move(next_sum);
    }
    for (int x = 0; x < log_k; ++x)
    {
        Ciphertext rotated;
        rotate_with_power_of_two_keys(
            sum, rotated,
            static_cast<long long>(pow2_int(x)) * static_cast<long long>(input.k) *
                static_cast<long long>(input.w),
            runtime);
        Ciphertext next_sum;
        runtime.evaluator->add_dynamic(sum, rotated, next_sum, runtime.encoder);
        sum = std::move(next_sum);
    }
    for (int page = 1; page < input.pages_per_cipher; ++page)
    {
        Ciphertext rotated;
        rotate_with_power_of_two_keys(
            sum, rotated,
            static_cast<long long>(page) * static_cast<long long>(input.page_size),
            runtime);
        Ciphertext next_sum;
        runtime.evaluator->add_dynamic(sum, rotated, next_sum, runtime.encoder);
        sum = std::move(next_sum);
    }
    return sum;
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

    const int out_k = (stride == 1) ? input.k : input.k * 2;
    MultiplexedCipherGroup output =
        make_multiplexed_shape(input.h / stride, input.w / stride, out_channels, out_k,
                               input.slot_count);
    const size_t output_pack_threads = resnet18_parallel_thread_count(output.packs.size());
    resnet18_progress_log()
        << "multiplexed dense conv compact-vector output pack threads: "
        << output_pack_threads << endl;
    size_t max_output_channels_per_pack = 0;
    for (size_t output_pack_index = 0; output_pack_index < output.packs.size();
         ++output_pack_index)
    {
        max_output_channels_per_pack =
            max(max_output_channels_per_pack,
                multiplexed_channels_for_pack(output, output_pack_index).size());
    }
    resnet18_progress_log()
        << "multiplexed dense conv compact-vector estimate: output_packs="
        << output.packs.size() << ", input_packs=" << input.packs.size()
        << ", max_output_channels_per_pack=" << max_output_channels_per_pack
        << ", spatial_rotations_per_pack<=" << input.packs.size() * fh * fw
        << ", plaintext_vector_multiplies_per_pack<="
        << input.packs.size() * max_output_channels_per_pack *
               (static_cast<size_t>(fh * fw) + 1)
        << endl;

    auto compute_output_pack = [&](size_t output_pack_index) {
        const vector<int> output_channels =
            multiplexed_channels_for_pack(output, output_pack_index);
        if (output_channels.empty())
        {
            throw runtime_error("multiplexed compact conv output pack has no channels");
        }

        vector<Ciphertext> output_channel_terms(output_channels.size());
        vector<bool> has_output_channel_terms(output_channels.size(), false);
        vector<vector<double>> select_vectors(output_channels.size(),
                                              vector<double>(output.slot_count, 0.0));
        for (size_t output_channel_index = 0;
             output_channel_index < output_channels.size(); ++output_channel_index)
        {
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
        }

        for (size_t input_pack_index = 0; input_pack_index < input.packs.size();
             ++input_pack_index)
        {
            vector<Ciphertext> input_pack_channel_sums(output_channels.size());
            vector<bool> has_input_pack_channel_sums(output_channels.size(), false);
            const vector<int> input_channels =
                multiplexed_channels_for_pack(input, input_pack_index);
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    Ciphertext rotated;
                    rotate_with_power_of_two_keys(
                        input.packs.at(input_pack_index), rotated,
                        multiplexed_spatial_kernel_rotation_step(input, fh, fw, kh, kw),
                        runtime);

                    for (size_t output_channel_index = 0;
                         output_channel_index < output_channels.size();
                         ++output_channel_index)
                    {
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
                            continue;
                        }

                        Ciphertext weighted = multiply_plain_vector_rescale(
                            rotated, compact_weight, runtime);
                        if (!has_input_pack_channel_sums.at(output_channel_index))
                        {
                            input_pack_channel_sums.at(output_channel_index) =
                                std::move(weighted);
                            has_input_pack_channel_sums.at(output_channel_index) = true;
                        }
                        else
                        {
                            Ciphertext next_sum;
                            runtime.evaluator->add_dynamic(
                                input_pack_channel_sums.at(output_channel_index), weighted,
                                next_sum, runtime.encoder);
                            input_pack_channel_sums.at(output_channel_index) =
                                std::move(next_sum);
                        }
                    }
                }
            }

            for (size_t output_channel_index = 0;
                 output_channel_index < output_channels.size(); ++output_channel_index)
            {
                if (!has_input_pack_channel_sums.at(output_channel_index))
                {
                    continue;
                }

                Ciphertext folded =
                    rotate_multiplexed_local_channel_sum_to_base(
                        input_pack_channel_sums.at(output_channel_index), input, runtime);
                Ciphertext shifted;
                rotate_with_power_of_two_keys(
                    folded, shifted,
                    multiplexed_output_channel_select_rotation_step(
                        output, output_channels.at(output_channel_index)),
                    runtime);
                Ciphertext selected =
                    multiply_plain_vector_rescale(
                        shifted, select_vectors.at(output_channel_index), runtime);
                if (!has_output_channel_terms.at(output_channel_index))
                {
                    output_channel_terms.at(output_channel_index) = std::move(selected);
                    has_output_channel_terms.at(output_channel_index) = true;
                }
                else
                {
                    Ciphertext next_sum;
                    runtime.evaluator->add_dynamic(
                        output_channel_terms.at(output_channel_index), selected, next_sum,
                        runtime.encoder);
                    output_channel_terms.at(output_channel_index) = std::move(next_sum);
                }
            }
        }

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
                Ciphertext next_sum;
                runtime.evaluator->add_dynamic(sum, term, next_sum, runtime.encoder);
                sum = std::move(next_sum);
            }
        }
        if (!has_sum)
        {
            throw runtime_error("multiplexed dense conv output pack produced no encrypted terms");
        }
        output.packs.at(output_pack_index) = std::move(sum);
    };

    if (output_pack_threads > 1)
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
    return output;
}

MultiplexedCipherGroup multiplexed_channel_batch_norm(
    const MultiplexedCipherGroup &input, const vector<double> &bias,
    const vector<double> &running_mean, const vector<double> &running_var,
    const vector<double> &weight, double epsilon, double boundary,
    PoseidonRuntime &runtime)
{
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
    bootstrap_ctx.bootstrap_poly = runtime.bootstrap_poly.get();
    return bootstrap_ctx;
}

MultiplexedCipherGroup multiplexed_channel_bootstrap(
    const MultiplexedCipherGroup &input, long logn, PoseidonRuntime &runtime,
    const string &label)
{
    log_multiplexed_group_cipher_state(label + " bootstrap input", input, runtime);
    MultiplexedCipherGroup output = input;
    output.packs.resize(input.packs.size());
    PoseidonBootstrapContext bootstrap_ctx = make_resnet18_bootstrap_context(runtime);
    for (size_t pack_index = 0; pack_index < input.packs.size(); ++pack_index)
    {
        TensorCipher tensor_in(static_cast<int>(logn), input.k, input.h, input.w, input.c,
                               1, input.pages_per_cipher, input.packs.at(pack_index));
        TensorCipher tensor_out;
        bootstrap_tensor(tensor_in, tensor_out, bootstrap_ctx, runtime.encoder);
        output.packs.at(pack_index) = tensor_out.cipher();
        resnet18_progress_log() << label << " bootstrap ciphertext progress: "
                                << (pack_index + 1) << "/" << input.packs.size() << endl;
    }
    log_multiplexed_group_cipher_state(label + " bootstrap output", output, runtime);
    return output;
}

MultiplexedCipherGroup multiplexed_channel_homomorphic_relu(
    const MultiplexedCipherGroup &input, long logn, const ReluConfig &relu_config,
    PoseidonRuntime &runtime, const string &label)
{
    MultiplexedCipherGroup relu_input = input;
    const size_t dropped_51 = drop_trailing_51_bit_primes(relu_input.packs, runtime);
    if (dropped_51 > 0)
    {
        resnet18_progress_log() << label
                                << " drop trailing 51-bit primes before ReLU: "
                                << dropped_51 << endl;
    }
    log_multiplexed_group_cipher_state(label + " homomorphic ReLU input", relu_input,
                                       runtime);
    MultiplexedCipherGroup output = relu_input;
    output.packs.resize(relu_input.packs.size());
    for (size_t pack_index = 0; pack_index < relu_input.packs.size(); ++pack_index)
    {
        TensorCipher tensor_in(static_cast<int>(logn), relu_input.k, relu_input.h,
                               relu_input.w, relu_input.c, 1, relu_input.pages_per_cipher,
                               relu_input.packs.at(pack_index));
        TensorCipher tensor_out;
        relu(tensor_in, tensor_out, relu_config.comp_no, relu_config.deg,
             relu_config.alpha, relu_config.tree, relu_config.scaled_val,
             runtime.encryptor, *runtime.evaluator, runtime.encoder, runtime.relin_keys,
             runtime.scale);
        output.packs.at(pack_index) = tensor_out.cipher();
        resnet18_progress_log() << label << " homomorphic ReLU ciphertext progress: "
                                << (pack_index + 1) << "/" << relu_input.packs.size()
                                << endl;
    }
    log_multiplexed_group_cipher_state(label + " homomorphic ReLU output", output, runtime);
    return output;
}

MultiplexedCipherGroup multiplexed_channel_bootstrap_then_relu(
    const MultiplexedCipherGroup &input, long logn, const ReluConfig &relu_config,
    PoseidonRuntime &runtime, const string &label, bool bootstrap_before_relu)
{
    MultiplexedCipherGroup relu_input = input;
    if (bootstrap_before_relu)
    {
        relu_input = multiplexed_channel_bootstrap(input, logn, runtime, label);
    }
    return multiplexed_channel_homomorphic_relu(relu_input, logn, relu_config, runtime,
                                                label);
}

MultiplexedCipherGroup multiplexed_channel_add(const MultiplexedCipherGroup &lhs,
                                               const MultiplexedCipherGroup &rhs,
                                               PoseidonRuntime &runtime)
{
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
                            mask[target_slot] = 1.0;
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
                        rotate_with_power_of_two_keys(input.packs.at(input_pack_index),
                                                      rotated, rotation_step, runtime);
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

        Ciphertext averaged;
        runtime.evaluator->multiply_const(sum, 1.0 / 9.0, runtime.scale, averaged,
                                          runtime.encoder);
        runtime.evaluator->rescale_dynamic(averaged, averaged, sum.scale());
        averaged.scale() = sum.scale();
        output.packs.at(output_pack_index) = std::move(averaged);
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

vector<int> packed_sparse_stride_compact_rotation_steps(
    int input_channels_per_cipher, int output_channels_per_cipher, int out_channels,
    int sparse_h, int sparse_w, int dense_h, int dense_w, size_t sparse_channel_stride,
    size_t dense_channel_stride)
{
    set<int> steps;
    for (int ow = 1; ow < dense_w; ++ow)
    {
        steps.insert(ow);
    }
    for (int oh = 1; oh < dense_h; ++oh)
    {
        steps.insert(oh * (2 * sparse_w - dense_w));
    }
    for (int channel = 0; channel < out_channels; ++channel)
    {
        const int source_local = channel % input_channels_per_cipher;
        const int target_local = channel % output_channels_per_cipher;
        const long long step =
            static_cast<long long>(static_cast<size_t>(source_local) *
                                   sparse_channel_stride) -
            static_cast<long long>(static_cast<size_t>(target_local) *
                                   dense_channel_stride);
        if (step != 0)
        {
            steps.insert(static_cast<int>(step));
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
                            rotate_with_power_of_two_keys(source, rotated, step, runtime);
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
                            rotate_with_power_of_two_keys(source, rotated, step, runtime);
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
                rotate_with_power_of_two_keys(input.packs.at(pack_index), rotated, ow,
                                              runtime);
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
                rotate_with_power_of_two_keys(column_sum, rotated, step, runtime);
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
                rotate_with_power_of_two_keys(spatial_compacted.at(input_pack_index),
                                              rotated, step, runtime);
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
            rotate_with_power_of_two_keys(input.packs.front(), rotated,
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
            rotate_with_power_of_two_keys(base_average_sum, rotated,
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
            rotate_with_power_of_two_keys(input.packs.front(), rotated, step, runtime);
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
            rotate_with_power_of_two_keys(column_sum, rotated, step, runtime);
        }
        Ciphertext term = multiply_binary_mask_no_rescale(rotated, channel_base_mask, runtime);
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
            rotate_with_power_of_two_keys(spatial_sum, rotated, step, runtime);
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
    const double average_coeff =
        boundary / static_cast<double>(input.h * input.w);
    runtime.evaluator->multiply_const(compacted_sum, average_coeff, runtime.scale, averaged,
                                      runtime.encoder);
    runtime.evaluator->rescale_dynamic(averaged, averaged, compacted_sum.scale());
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
            rotate_with_power_of_two_keys(
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

int argmax_index(const vector<double> &values)
{
    if (values.empty())
    {
        throw invalid_argument("argmax input should not be empty");
    }
    return static_cast<int>(max_element(values.begin(), values.end()) - values.begin());
}

vector<int> fully_connected_rotation_steps(int q, int r)
{
    if (q <= 0 || r <= 0)
    {
        throw invalid_argument("fully connected rotation shape is invalid");
    }

    set<int> steps;
    for (int s = 0; s < q + r - 1; ++s)
    {
        const int step = r - 1 - s;
        if (step != 0)
        {
            steps.insert(step);
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

PackedChannelCipherGroup make_packed_shape_for_key_plan(
    int h, int w, int c, int channels_per_cipher, size_t slot_count)
{
    PackedChannelCipherGroup group;
    group.h = h;
    group.w = w;
    group.c = c;
    group.channels_per_cipher = channels_per_cipher;
    group.channel_stride = static_cast<size_t>(h * w);
    group.slot_count = slot_count;
    group.packs.resize((static_cast<size_t>(c) +
                        static_cast<size_t>(channels_per_cipher) - 1) /
                       static_cast<size_t>(channels_per_cipher));
    return group;
}

void insert_rotation_steps_allow_zero(set<int> &target, const vector<int> &steps)
{
    for (int step : steps)
    {
        target.insert(step);
    }
}

vector<int> collect_resnet18_multiplexed_rotation_steps(size_t slot_count)
{
    vector<int> steps = power_of_two_rotation_steps(slot_count);
    steps.push_back(-static_cast<int>(112 * 112));
    steps.push_back(static_cast<int>(112 * 112));
    sort(steps.begin(), steps.end());
    steps.erase(unique(steps.begin(), steps.end()), steps.end());
    return steps;
}

void insert_dft_rotation_steps(HomomorphicDFTMatrixLiteral &literal, set<int> &target)
{
    const int slots = 1 << literal.get_log_slots();
    vector<int> dft_steps;
    auto matrices = literal.gen_matrices();
    for (auto &matrix : matrices)
    {
        const int n1 = find_best_bsgs_ratio(matrix, slots, literal.get_log_bsgs_ratio());
        add_matrix_rot_to_list(matrix, dft_steps, n1, slots, false);
    }
    insert_rotation_steps_allow_zero(target, dft_steps);
}

vector<int> collect_resnet18_bootstrap_rotation_steps(PoseidonRuntime &runtime)
{
    set<int> unique_steps;
    unique_steps.insert(0); // CKKS conjugation key, used by bootstrap real projection.

    const auto params_literal = runtime.context.parameters_literal();
    const uint32_t logn = params_literal->log_n();
    const uint32_t log_slots = params_literal->log_slots();
    const uint32_t top_level = static_cast<uint32_t>(params_literal->q().size() - 1);

    HomomorphicDFTMatrixLiteral coeff_to_slot_literal(
        encode, logn, log_slots, top_level, vector<uint32_t>(3, 1), true, 1.0, false, 1);
    insert_dft_rotation_steps(coeff_to_slot_literal, unique_steps);

    HomomorphicDFTMatrixLiteral slot_to_coeff_literal(
        decode, logn, log_slots, top_level, vector<uint32_t>(3, 1), true, 1.0, false, 1);
    insert_dft_rotation_steps(slot_to_coeff_literal, unique_steps);

    return vector<int>(unique_steps.begin(), unique_steps.end());
}

void prepare_resnet18_rotation_keys(PoseidonRuntime &runtime, ofstream &output)
{
    const auto key_time_start = chrono::steady_clock::now();

    set<int> all_steps;
    const vector<int> network_steps =
        collect_resnet18_multiplexed_rotation_steps(runtime.slot_count);
    insert_rotation_steps_allow_zero(all_steps, network_steps);

    vector<int> bootstrap_steps;
    if (kEnableHomomorphicRelu && kBootstrapBeforeReluExceptFirst)
    {
        bootstrap_steps = collect_resnet18_bootstrap_rotation_steps(runtime);
        insert_rotation_steps_allow_zero(all_steps, bootstrap_steps);
    }

    vector<int> steps(all_steps.begin(), all_steps.end());
    output << "prepare evaluation keys: network_rotation_key_count="
           << network_steps.size()
           << ", bootstrap_rotation_key_count=" << bootstrap_steps.size()
           << ", merged_galois_key_count=" << steps.size() << '\n';
    output << "prepare galois keys: steps";
    for (int step : steps)
    {
        output << ' ' << step;
    }
    output << '\n';
    resnet18_progress_log()
        << "prepare evaluation keys merged galois key count: " << steps.size() << endl;

    KeyGenerator keygen(runtime.context, runtime.secret_key);
    keygen.create_relin_keys(runtime.relin_keys);
    if (kEnableHomomorphicRelu && kBootstrapBeforeReluExceptFirst)
    {
        runtime.bootstrap_poly = std::make_unique<EvalModPoly>(
            runtime.context, CosDiscrete, static_cast<std::uint64_t>(1) << 51,
            1, 16, 3, 16, 0, 30);
    }
    keygen.create_galois_keys(steps, runtime.galois_keys);

    const auto elapsed = chrono::duration_cast<chrono::milliseconds>(
                             chrono::steady_clock::now() - key_time_start)
                             .count();
    output << "prepare evaluation keys time: " << elapsed << " ms\n";
    resnet18_progress_log() << "[duration] prepare evaluation keys: " << elapsed
                            << " ms" << endl;
}

} // namespace

void ResNet_imagenet_sparse(size_t start_image_id, size_t end_image_id)
{
    const PoseidonInferPlan plan = default_poseidon_plan();
    const size_t image_value_count =
        static_cast<size_t>(kImageNetInputHeight * kImageNetInputWidth * kImageNetInputChannels);
    const size_t slot_count = static_cast<size_t>(1) << plan.log_slots;
    const size_t input_channel_value_count =
        static_cast<size_t>(kImageNetInputHeight * kImageNetInputWidth);
    const size_t input_chunks_per_channel =
        (input_channel_value_count + slot_count - 1) / slot_count;
    const size_t input_chunk_count =
        static_cast<size_t>(kImageNetInputChannels) * input_chunks_per_channel;
    const string run_timestamp = make_run_timestamp();
    ReluConfig relu_config = default_relu_config(plan);

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
    resnet18_progress_log() << "ImageNet input values: " << image_value_count
         << ", encrypted input chunks: " << input_chunk_count << endl;

    out_log << "run_start: start_image_id=" << start_image_id
            << ", end_image_id=" << end_image_id
            << ", run_timestamp=" << run_timestamp
            << ", log_file=" << run_result_path << '\n';
    prepare_resnet18_rotation_keys(runtime, out_log);

    const auto all_time_start = chrono::high_resolution_clock::now();
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
        output << "input values=" << image_values.size() << ", slot_count=" << slot_count
               << ", input_chunk_count=" << input_chunk_count << '\n';

        TensorCipherGroup input_group(static_cast<int>(plan.logN), kImageNetInputHeight,
                                      kImageNetInputWidth, kImageNetInputChannels, image_values,
                                      runtime.encryptor, runtime.encoder, plan.log_scale);
        const size_t input_dropped_51 =
            drop_trailing_51_bit_primes(input_group.chunks(), runtime);
        output << "input drop trailing 51-bit primes: " << input_dropped_51 << '\n';
        resnet18_progress_log()
            << "input drop trailing 51-bit primes: " << input_dropped_51 << endl;
        log_cipher_vector_level_summary("input chunks after 51-bit drop",
                                        input_group.chunks(), runtime);
        input_group.print_summary(output);

        vector<double> decrypted_input = input_group.decrypt_values(runtime.decryptor,
                                                                    runtime.encoder);
        double max_abs_error = 0.0;
        for (size_t i = 0; i < min(image_values.size(), decrypted_input.size()); ++i)
        {
            max_abs_error = max(max_abs_error, abs(image_values[i] - decrypted_input[i]));
        }
        output << "input decrypt max_abs_error: " << max_abs_error << '\n';

        ModelWeights weights = load_resnet18_parameters();
        PlainTensor plain_input(kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels,
                                image_values);
        PlainTensor plain_conv1 = plain_convolution(
            plain_input, 64, 2, 7, 7, weights.conv_weight.at(0), weights.bn_running_var.at(0),
            weights.bn_weight.at(0), kBatchNormEpsilon);

        output << "conv1 im2col packing: encrypting 7x7x3 patch ciphertexts\n";
        resnet18_progress_log() << "conv1 im2col encrypt patches" << endl;
        Im2ColCipherGroup conv1_im2col = encrypt_conv2d_im2col_patches(
            image_values, kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels, 2, 7,
            7, runtime, plan.log_scale);
        const size_t conv1_im2col_dropped_51 =
            drop_trailing_51_bit_primes(conv1_im2col.patches, runtime);
        output << "conv1 im2col drop trailing 51-bit primes: "
               << conv1_im2col_dropped_51 << '\n';
        resnet18_progress_log()
            << "conv1 im2col drop trailing 51-bit primes: "
            << conv1_im2col_dropped_51 << endl;
        log_cipher_vector_level_summary("conv1 im2col patches after 51-bit drop",
                                        conv1_im2col.patches, runtime);
        output << "conv1 im2col patches: " << conv1_im2col.patches.size()
               << ", spatial_count=" << conv1_im2col.spatial_count << '\n';
        resnet18_progress_log() << "conv1 im2col patches: " << conv1_im2col.patches.size() << endl;

        PlainTensor plain_conv1_bn =
            plain_batch_norm(plain_conv1, weights.bn_bias.at(0), weights.bn_running_mean.at(0),
                             weights.bn_running_var.at(0), weights.bn_weight.at(0),
                             kBatchNormEpsilon, 40.0);
        PlainTensor plain_conv1_relu = plain_relu_reference(plain_conv1_bn);
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
        if (kRunFullStemCheck)
        {
            output << "stem full 64-channel: encrypted conv1 evaluation\n";
            resnet18_progress_log() << "stem full 64-channel conv1 encrypted evaluation" << endl;
            ChannelCipherGroup stem_conv1_group = encrypted_conv2d_im2col_all_channels(
                conv1_im2col, 64, weights.conv_weight.at(0), weights.bn_running_var.at(0),
                weights.bn_weight.at(0), kBatchNormEpsilon, runtime);
            vector<double> decrypted_stem_conv1 = decrypt_channel_cipher_group(stem_conv1_group,
                                                                               runtime);
            stem_conv1_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_stem_conv1.size(); ++i)
            {
                stem_conv1_all_max_abs_error =
                    max(stem_conv1_all_max_abs_error,
                        abs(decrypted_stem_conv1[i] - plain_conv1.values.at(i)));
            }
            output << "stem conv1 all max_abs_error: " << stem_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem conv1 all max_abs_error: " << stem_conv1_all_max_abs_error << endl;

            output << "stem conv1: pack output as multiplexed k=1\n";
            resnet18_progress_log() << "stem conv1 pack output as multiplexed k=1" << endl;
            MultiplexedCipherGroup stem_conv1_multiplex_k1_group =
                pack_channel_group_as_multiplexed_k1(stem_conv1_group, runtime);
            log_multiplexed_group_cipher_state("stem conv1 multiplexed k=1 output",
                                               stem_conv1_multiplex_k1_group, runtime);
            double stem_conv1_multiplex_pack_max_abs_error =
                multiplexed_group_max_abs_error(stem_conv1_multiplex_k1_group,
                                                plain_conv1, runtime);
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
                    weights.bn_weight.at(0), kBatchNormEpsilon, 40.0, runtime);
            stem_bn_all_max_abs_error = multiplexed_group_max_abs_error(
                stem_bn_multiplex_k1_group, plain_conv1_bn, runtime);
            output << "stem BN all max_abs_error: " << stem_bn_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem BN all max_abs_error: " << stem_bn_all_max_abs_error << endl;

            output << "stem multiplexed k=1: homomorphic ReLU evaluation (first ReLU, no bootstrap)\n";
            resnet18_progress_log()
                << "stem multiplexed k=1 homomorphic ReLU evaluation (first ReLU, no bootstrap)" << endl;
            const auto stem_relu_time_start = chrono::steady_clock::now();
            MultiplexedCipherGroup stem_relu_multiplex_k1_group =
                multiplexed_channel_bootstrap_then_relu(stem_bn_multiplex_k1_group, plan.logN, relu_config, runtime, "stem ReLU", false);
            stem_relu_refresh_all_max_abs_error = multiplexed_group_max_abs_error(
                stem_relu_multiplex_k1_group, plain_conv1_relu, runtime);
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
                                                   plain_conv1_pool.h, plain_conv1_pool.w, 2,
                                                   runtime);
            stem_multiplex_avgpool_all_max_abs_error =
                multiplexed_group_max_abs_error(stem_avgpool_multiplex_k2_group,
                                                plain_conv1_pool, runtime);
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
                                                runtime);
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
                weights.bn_weight.at(1), kBatchNormEpsilon, 40.0);
            MultiplexedCipherGroup layer1_block0_bn1_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer1_block0_conv1_multiplex_group, weights.bn_bias.at(1),
                    weights.bn_running_mean.at(1), weights.bn_running_var.at(1),
                    weights.bn_weight.at(1), kBatchNormEpsilon, 40.0, runtime);
            layer1_block0_bn1_multiplex_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_bn1_multiplex_group,
                                                plain_layer1_block0_bn1_multiplex,
                                                runtime);
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
                plain_relu_reference(plain_layer1_block0_bn1_multiplex);
            MultiplexedCipherGroup layer1_block0_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer1_block0_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer1 block0 relu1", kBootstrapBeforeReluExceptFirst);
            layer1_block0_relu1_multiplex_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_relu1_multiplex_group,
                                                plain_layer1_block0_relu1_multiplex,
                                                runtime);
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
                                                runtime);
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
                weights.bn_weight.at(2), kBatchNormEpsilon, 40.0);
            MultiplexedCipherGroup layer1_block0_bn2_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer1_block0_conv2_multiplex_group, weights.bn_bias.at(2),
                    weights.bn_running_mean.at(2), weights.bn_running_var.at(2),
                    weights.bn_weight.at(2), kBatchNormEpsilon, 40.0, runtime);
            layer1_block0_bn2_multiplex_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_bn2_multiplex_group,
                                                plain_layer1_block0_bn2_multiplex,
                                                runtime);
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
                                                runtime);
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
                plain_relu_reference(plain_layer1_block0_add_multiplex);
            MultiplexedCipherGroup layer1_block0_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer1_block0_add_multiplex_group, plan.logN, relu_config, runtime, "layer1 block0 output relu", kBootstrapBeforeReluExceptFirst);
            layer1_block0_output_multiplex_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block0_output_multiplex_group,
                                                plain_layer1_block0_output_multiplex,
                                                runtime);
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
                layer1_block1_conv1_multiplex_group, plain_layer1_block1_conv1, runtime);
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
                    weights.bn_weight.at(3), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer1_block1_bn1 =
                plain_batch_norm(plain_layer1_block1_conv1, weights.bn_bias.at(3),
                                 weights.bn_running_mean.at(3),
                                 weights.bn_running_var.at(3), weights.bn_weight.at(3),
                                 kBatchNormEpsilon, 40.0);
            layer1_block1_bn1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer1_block1_bn1_multiplex_group, plain_layer1_block1_bn1, runtime);
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
                plain_relu_reference(plain_layer1_block1_bn1);
            MultiplexedCipherGroup layer1_block1_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer1_block1_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer1 block1 relu1", kBootstrapBeforeReluExceptFirst);
            layer1_block1_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block1_relu1_multiplex_group,
                                                plain_layer1_block1_relu1, runtime);
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
                layer1_block1_conv2_multiplex_group, plain_layer1_block1_conv2, runtime);
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
                    weights.bn_weight.at(4), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer1_block1_bn2 =
                plain_batch_norm(plain_layer1_block1_conv2, weights.bn_bias.at(4),
                                 weights.bn_running_mean.at(4),
                                 weights.bn_running_var.at(4), weights.bn_weight.at(4),
                                 kBatchNormEpsilon, 40.0);
            layer1_block1_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer1_block1_bn2_multiplex_group, plain_layer1_block1_bn2, runtime);
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
                layer1_block1_add_multiplex_group, plain_layer1_block1_add, runtime);
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
                plain_relu_reference(plain_layer1_block1_add);
            MultiplexedCipherGroup layer1_block1_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer1_block1_add_multiplex_group, plan.logN, relu_config, runtime, "layer1 block1 output relu", kBootstrapBeforeReluExceptFirst);
            layer1_block1_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer1_block1_output_multiplex_group,
                                                plain_layer1_block1_output, runtime);
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
                layer2_block0_conv1_multiplex_group, plain_layer2_block0_conv1, runtime);
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
                    weights.bn_weight.at(5), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer2_block0_bn1 =
                plain_batch_norm(plain_layer2_block0_conv1, weights.bn_bias.at(5),
                                 weights.bn_running_mean.at(5),
                                 weights.bn_running_var.at(5), weights.bn_weight.at(5),
                                 kBatchNormEpsilon, 40.0);
            layer2_block0_bn1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_bn1_multiplex_group, plain_layer2_block0_bn1, runtime);
            output << "layer2 block0 bn1 multiplexed max_abs_error: "
                   << layer2_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 bn1 multiplexed max_abs_error: "
                                    << layer2_block0_bn1_sparse_max_abs_error << endl;

            output << "layer2 block0 relu1 multiplexed k=4: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer2 block0 relu1 multiplexed k=4 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer2_block0_relu1 =
                plain_relu_reference(plain_layer2_block0_bn1);
            MultiplexedCipherGroup layer2_block0_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer2_block0_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer2 block0 relu1", kBootstrapBeforeReluExceptFirst);
            layer2_block0_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(
                layer2_block0_relu1_multiplex_group, plain_layer2_block0_relu1, runtime);
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
                layer2_block0_conv2_multiplex_group, plain_layer2_block0_conv2, runtime);
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
                    weights.bn_weight.at(6), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer2_block0_bn2 =
                plain_batch_norm(plain_layer2_block0_conv2, weights.bn_bias.at(6),
                                 weights.bn_running_mean.at(6),
                                 weights.bn_running_var.at(6), weights.bn_weight.at(6),
                                 kBatchNormEpsilon, 40.0);
            layer2_block0_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_bn2_multiplex_group, plain_layer2_block0_bn2, runtime);
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
                                 40.0);
            MultiplexedCipherGroup layer2_block0_shortcut_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer2_block0_shortcut_conv_multiplex_group,
                    weights.downsample_bn_bias.at(0),
                    weights.downsample_bn_running_mean.at(0),
                    weights.downsample_bn_running_var.at(0),
                    weights.downsample_bn_weight.at(0), kBatchNormEpsilon, 40.0, runtime);
            layer2_block0_shortcut_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block0_shortcut_multiplex_group, plain_layer2_block0_shortcut, runtime);
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
                layer2_block0_add_multiplex_group, plain_layer2_block0_add, runtime);
            output << "layer2 block0 add multiplexed all max_abs_error: "
                   << layer2_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 add multiplexed all max_abs_error: "
                 << layer2_block0_add_all_max_abs_error << endl;

            output << "layer2 block0 output ReLU multiplexed k=4: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer2 block0 output ReLU multiplexed k=4 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer2_block0_output =
                plain_relu_reference(plain_layer2_block0_add);
            MultiplexedCipherGroup layer2_block0_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer2_block0_add_multiplex_group, plan.logN, relu_config, runtime, "layer2 block0 output relu", kBootstrapBeforeReluExceptFirst);
            layer2_block0_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer2_block0_output_multiplex_group,
                                                plain_layer2_block0_output, runtime);
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
                layer2_block1_conv1_multiplex_group, plain_layer2_block1_conv1, runtime);
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
                    weights.bn_weight.at(7), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer2_block1_bn1 =
                plain_batch_norm(plain_layer2_block1_conv1, weights.bn_bias.at(7),
                                 weights.bn_running_mean.at(7),
                                 weights.bn_running_var.at(7), weights.bn_weight.at(7),
                                 kBatchNormEpsilon, 40.0);
            layer2_block1_bn1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block1_bn1_multiplex_group, plain_layer2_block1_bn1, runtime);
            output << "layer2 block1 bn1 multiplexed all max_abs_error: "
                   << layer2_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 bn1 multiplexed all max_abs_error: "
                 << layer2_block1_bn1_all_max_abs_error << endl;

            output << "layer2 block1 relu1 multiplexed k=4: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer2 block1 relu1 multiplexed k=4 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer2_block1_relu1 =
                plain_relu_reference(plain_layer2_block1_bn1);
            MultiplexedCipherGroup layer2_block1_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer2_block1_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer2 block1 relu1", kBootstrapBeforeReluExceptFirst);
            layer2_block1_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer2_block1_relu1_multiplex_group,
                                                plain_layer2_block1_relu1, runtime);
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
                layer2_block1_conv2_multiplex_group, plain_layer2_block1_conv2, runtime);
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
                    weights.bn_weight.at(8), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer2_block1_bn2 =
                plain_batch_norm(plain_layer2_block1_conv2, weights.bn_bias.at(8),
                                 weights.bn_running_mean.at(8),
                                 weights.bn_running_var.at(8), weights.bn_weight.at(8),
                                 kBatchNormEpsilon, 40.0);
            layer2_block1_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer2_block1_bn2_multiplex_group, plain_layer2_block1_bn2, runtime);
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
                layer2_block1_add_multiplex_group, plain_layer2_block1_add, runtime);
            output << "layer2 block1 add multiplexed all max_abs_error: "
                   << layer2_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 add multiplexed all max_abs_error: "
                 << layer2_block1_add_all_max_abs_error << endl;

            output << "layer2 block1 output ReLU multiplexed k=4: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer2 block1 output ReLU multiplexed k=4 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer2_block1_output =
                plain_relu_reference(plain_layer2_block1_add);
            MultiplexedCipherGroup layer2_block1_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer2_block1_add_multiplex_group, plan.logN, relu_config, runtime, "layer2 block1 output relu", kBootstrapBeforeReluExceptFirst);
            layer2_block1_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer2_block1_output_multiplex_group,
                                                plain_layer2_block1_output, runtime);
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
                layer3_block0_conv1_multiplex_group, plain_layer3_block0_conv1, runtime);
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
                    weights.bn_weight.at(9), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer3_block0_bn1 =
                plain_batch_norm(plain_layer3_block0_conv1, weights.bn_bias.at(9),
                                 weights.bn_running_mean.at(9),
                                 weights.bn_running_var.at(9), weights.bn_weight.at(9),
                                 kBatchNormEpsilon, 40.0);
            layer3_block0_bn1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_bn1_multiplex_group, plain_layer3_block0_bn1, runtime);
            output << "layer3 block0 bn1 multiplexed max_abs_error: "
                   << layer3_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 bn1 multiplexed max_abs_error: "
                                    << layer3_block0_bn1_sparse_max_abs_error << endl;

            output << "layer3 block0 relu1 multiplexed k=8: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer3 block0 relu1 multiplexed k=8 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer3_block0_relu1 =
                plain_relu_reference(plain_layer3_block0_bn1);
            MultiplexedCipherGroup layer3_block0_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer3_block0_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer3 block0 relu1", kBootstrapBeforeReluExceptFirst);
            layer3_block0_relu1_refresh_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_relu1_multiplex_group, plain_layer3_block0_relu1, runtime);
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
                layer3_block0_conv2_multiplex_group, plain_layer3_block0_conv2, runtime);
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
                    weights.bn_weight.at(10), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer3_block0_bn2 =
                plain_batch_norm(plain_layer3_block0_conv2, weights.bn_bias.at(10),
                                 weights.bn_running_mean.at(10),
                                 weights.bn_running_var.at(10), weights.bn_weight.at(10),
                                 kBatchNormEpsilon, 40.0);
            layer3_block0_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_bn2_multiplex_group, plain_layer3_block0_bn2, runtime);
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
                                 40.0);
            MultiplexedCipherGroup layer3_block0_shortcut_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer3_block0_shortcut_conv_multiplex_group,
                    weights.downsample_bn_bias.at(1),
                    weights.downsample_bn_running_mean.at(1),
                    weights.downsample_bn_running_var.at(1),
                    weights.downsample_bn_weight.at(1), kBatchNormEpsilon, 40.0, runtime);
            layer3_block0_shortcut_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block0_shortcut_multiplex_group, plain_layer3_block0_shortcut, runtime);
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
                layer3_block0_add_multiplex_group, plain_layer3_block0_add, runtime);
            output << "layer3 block0 add multiplexed all max_abs_error: "
                   << layer3_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 add multiplexed all max_abs_error: "
                 << layer3_block0_add_all_max_abs_error << endl;

            output << "layer3 block0 output ReLU multiplexed k=8: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer3 block0 output ReLU multiplexed k=8 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer3_block0_output =
                plain_relu_reference(plain_layer3_block0_add);
            MultiplexedCipherGroup layer3_block0_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer3_block0_add_multiplex_group, plan.logN, relu_config, runtime, "layer3 block0 output relu", kBootstrapBeforeReluExceptFirst);
            layer3_block0_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer3_block0_output_multiplex_group,
                                                plain_layer3_block0_output, runtime);
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
                layer3_block1_conv1_multiplex_group, plain_layer3_block1_conv1, runtime);
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
                    weights.bn_weight.at(11), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer3_block1_bn1 =
                plain_batch_norm(plain_layer3_block1_conv1, weights.bn_bias.at(11),
                                 weights.bn_running_mean.at(11),
                                 weights.bn_running_var.at(11), weights.bn_weight.at(11),
                                 kBatchNormEpsilon, 40.0);
            layer3_block1_bn1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block1_bn1_multiplex_group, plain_layer3_block1_bn1, runtime);
            output << "layer3 block1 bn1 multiplexed all max_abs_error: "
                   << layer3_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 bn1 multiplexed all max_abs_error: "
                 << layer3_block1_bn1_all_max_abs_error << endl;

            output << "layer3 block1 relu1 multiplexed k=8: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer3 block1 relu1 multiplexed k=8 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer3_block1_relu1 =
                plain_relu_reference(plain_layer3_block1_bn1);
            MultiplexedCipherGroup layer3_block1_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer3_block1_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer3 block1 relu1", kBootstrapBeforeReluExceptFirst);
            layer3_block1_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer3_block1_relu1_multiplex_group,
                                                plain_layer3_block1_relu1, runtime);
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
                layer3_block1_conv2_multiplex_group, plain_layer3_block1_conv2, runtime);
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
                    weights.bn_weight.at(12), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer3_block1_bn2 =
                plain_batch_norm(plain_layer3_block1_conv2, weights.bn_bias.at(12),
                                 weights.bn_running_mean.at(12),
                                 weights.bn_running_var.at(12), weights.bn_weight.at(12),
                                 kBatchNormEpsilon, 40.0);
            layer3_block1_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer3_block1_bn2_multiplex_group, plain_layer3_block1_bn2, runtime);
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
                layer3_block1_add_multiplex_group, plain_layer3_block1_add, runtime);
            output << "layer3 block1 add multiplexed all max_abs_error: "
                   << layer3_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 add multiplexed all max_abs_error: "
                 << layer3_block1_add_all_max_abs_error << endl;

            output << "layer3 block1 output ReLU multiplexed k=8: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer3 block1 output ReLU multiplexed k=8 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer3_block1_output =
                plain_relu_reference(plain_layer3_block1_add);
            MultiplexedCipherGroup layer3_block1_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer3_block1_add_multiplex_group, plan.logN, relu_config, runtime, "layer3 block1 output relu", kBootstrapBeforeReluExceptFirst);
            layer3_block1_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer3_block1_output_multiplex_group,
                                                plain_layer3_block1_output, runtime);
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
                layer4_block0_conv1_multiplex_group, plain_layer4_block0_conv1, runtime);
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
                    weights.bn_weight.at(13), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer4_block0_bn1 =
                plain_batch_norm(plain_layer4_block0_conv1, weights.bn_bias.at(13),
                                 weights.bn_running_mean.at(13),
                                 weights.bn_running_var.at(13), weights.bn_weight.at(13),
                                 kBatchNormEpsilon, 40.0);
            layer4_block0_bn1_sparse_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_bn1_multiplex_group, plain_layer4_block0_bn1, runtime);
            output << "layer4 block0 bn1 multiplexed max_abs_error: "
                   << layer4_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 bn1 multiplexed max_abs_error: "
                                    << layer4_block0_bn1_sparse_max_abs_error << endl;

            output << "layer4 block0 relu1 multiplexed k=16: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer4 block0 relu1 multiplexed k=16 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer4_block0_relu1 =
                plain_relu_reference(plain_layer4_block0_bn1);
            MultiplexedCipherGroup layer4_block0_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer4_block0_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer4 block0 relu1", kBootstrapBeforeReluExceptFirst);
            layer4_block0_relu1_refresh_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_relu1_multiplex_group, plain_layer4_block0_relu1, runtime);
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
                layer4_block0_conv2_multiplex_group, plain_layer4_block0_conv2, runtime);
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
                    weights.bn_weight.at(14), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer4_block0_bn2 =
                plain_batch_norm(plain_layer4_block0_conv2, weights.bn_bias.at(14),
                                 weights.bn_running_mean.at(14),
                                 weights.bn_running_var.at(14), weights.bn_weight.at(14),
                                 kBatchNormEpsilon, 40.0);
            layer4_block0_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_bn2_multiplex_group, plain_layer4_block0_bn2, runtime);
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
                                 40.0);
            MultiplexedCipherGroup layer4_block0_shortcut_multiplex_group =
                multiplexed_channel_batch_norm(
                    layer4_block0_shortcut_conv_multiplex_group,
                    weights.downsample_bn_bias.at(2),
                    weights.downsample_bn_running_mean.at(2),
                    weights.downsample_bn_running_var.at(2),
                    weights.downsample_bn_weight.at(2), kBatchNormEpsilon, 40.0, runtime);
            layer4_block0_shortcut_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block0_shortcut_multiplex_group, plain_layer4_block0_shortcut, runtime);
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
                layer4_block0_add_multiplex_group, plain_layer4_block0_add, runtime);
            output << "layer4 block0 add multiplexed all max_abs_error: "
                   << layer4_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 add multiplexed all max_abs_error: "
                 << layer4_block0_add_all_max_abs_error << endl;

            output << "layer4 block0 output ReLU multiplexed k=16: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer4 block0 output ReLU multiplexed k=16 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer4_block0_output =
                plain_relu_reference(plain_layer4_block0_add);
            MultiplexedCipherGroup layer4_block0_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer4_block0_add_multiplex_group, plan.logN, relu_config, runtime, "layer4 block0 output relu", kBootstrapBeforeReluExceptFirst);
            layer4_block0_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer4_block0_output_multiplex_group,
                                                plain_layer4_block0_output, runtime);
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
                layer4_block1_conv1_multiplex_group, plain_layer4_block1_conv1, runtime);
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
                    weights.bn_weight.at(15), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer4_block1_bn1 =
                plain_batch_norm(plain_layer4_block1_conv1, weights.bn_bias.at(15),
                                 weights.bn_running_mean.at(15),
                                 weights.bn_running_var.at(15), weights.bn_weight.at(15),
                                 kBatchNormEpsilon, 40.0);
            layer4_block1_bn1_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block1_bn1_multiplex_group, plain_layer4_block1_bn1, runtime);
            output << "layer4 block1 bn1 multiplexed all max_abs_error: "
                   << layer4_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 bn1 multiplexed all max_abs_error: "
                 << layer4_block1_bn1_all_max_abs_error << endl;

            output << "layer4 block1 relu1 multiplexed k=16: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer4 block1 relu1 multiplexed k=16 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer4_block1_relu1 =
                plain_relu_reference(plain_layer4_block1_bn1);
            MultiplexedCipherGroup layer4_block1_relu1_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer4_block1_bn1_multiplex_group, plan.logN, relu_config, runtime, "layer4 block1 relu1", kBootstrapBeforeReluExceptFirst);
            layer4_block1_relu1_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer4_block1_relu1_multiplex_group,
                                                plain_layer4_block1_relu1, runtime);
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
                layer4_block1_conv2_multiplex_group, plain_layer4_block1_conv2, runtime);
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
                    weights.bn_weight.at(16), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer4_block1_bn2 =
                plain_batch_norm(plain_layer4_block1_conv2, weights.bn_bias.at(16),
                                 weights.bn_running_mean.at(16),
                                 weights.bn_running_var.at(16), weights.bn_weight.at(16),
                                 kBatchNormEpsilon, 40.0);
            layer4_block1_bn2_all_max_abs_error = multiplexed_group_max_abs_error(
                layer4_block1_bn2_multiplex_group, plain_layer4_block1_bn2, runtime);
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
                layer4_block1_add_multiplex_group, plain_layer4_block1_add, runtime);
            output << "layer4 block1 add multiplexed all max_abs_error: "
                   << layer4_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 add multiplexed all max_abs_error: "
                 << layer4_block1_add_all_max_abs_error << endl;

            output << "layer4 block1 output ReLU multiplexed k=16: bootstrap + homomorphic ReLU evaluation\n";
            resnet18_progress_log()
                << "layer4 block1 output ReLU multiplexed k=16 bootstrap + homomorphic ReLU evaluation"
                << endl;
            PlainTensor plain_layer4_block1_output =
                plain_relu_reference(plain_layer4_block1_add);
            MultiplexedCipherGroup layer4_block1_output_multiplex_group =
                multiplexed_channel_bootstrap_then_relu(layer4_block1_add_multiplex_group, plan.logN, relu_config, runtime, "layer4 block1 output relu", kBootstrapBeforeReluExceptFirst);
            layer4_block1_output_refresh_all_max_abs_error =
                multiplexed_group_max_abs_error(layer4_block1_output_multiplex_group,
                                                plain_layer4_block1_output, runtime);
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
            PlainTensor plain_head_pooled = plain_average_pool(plain_layer4_block1_output, 40.0);
            TensorCipher encrypted_head_pooled = encrypted_multiplexed_head_average_pool(
                layer4_block1_output_multiplex_group, static_cast<int>(plan.logN),
                plan.log_scale, 40.0, runtime);
            vector<double> encrypted_pooled_values =
                decode_real_slots(encrypted_head_pooled, runtime, kResNet18FinalChannels);
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

            output << "head fully connected: using power-of-two rotation keys\n";
            vector<int> fc_steps =
                fully_connected_rotation_steps(kImageNetClassCount, kResNet18FinalChannels);
            resnet18_progress_log()
                << "head fully connected logical rotation step count: " << fc_steps.size()
                << endl;
            output << "head fully connected logical rotation step count: "
                   << fc_steps.size() << '\n';

            output << "head fully connected: encrypted logits evaluation\n";
            resnet18_progress_log() << "head fully connected encrypted logits evaluation" << endl;
            TensorCipher encrypted_head_logits;
            {
                ScopedDurationLog duration("head fully connected");
                fully_connected_print(
                    encrypted_head_pooled, encrypted_head_logits, weights.linear_weight,
                    weights.linear_bias, kImageNetClassCount, kResNet18FinalChannels,
                    *runtime.evaluator, runtime.galois_keys, output, runtime.decryptor,
                    runtime.encoder, runtime.context);
            }
            log_tensor_cipher_state("head fully connected logits output", encrypted_head_logits,
                                    runtime);

            vector<double> decrypted_head_logits =
                decode_real_slots(encrypted_head_logits, runtime, kImageNetClassCount);
            vector<double> plain_head_logits =
                plain_fully_connected(plain_head_pooled, weights.linear_weight,
                                      weights.linear_bias, kImageNetClassCount,
                                      kResNet18FinalChannels);
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
            output << "head logits max_abs_error: " << head_logits_max_abs_error << '\n';
            output << "head plain predicted label: " << plain_head_predicted_label
                   << ", encrypted predicted label: " << encrypted_predicted_label << '\n';
            resnet18_progress_log() << "head logits max_abs_error: " << head_logits_max_abs_error << endl;
            resnet18_progress_log() << "head plain predicted label: " << plain_head_predicted_label
                 << ", encrypted predicted label: " << encrypted_predicted_label << endl;
        }

        const auto image_time_end = chrono::high_resolution_clock::now();
        const auto image_time_diff =
            chrono::duration_cast<chrono::milliseconds>(image_time_end - image_time_start);
        output << "image label: " << image_label << '\n';
        output << "image time : " << image_time_diff.count() << " ms" << endl;

        out_log << "image_id: " << image_id << ", image label: " << image_label
                  << ", encrypted_input_chunks: " << input_group.chunk_count()
                  << ", input_decrypt_max_abs_error: " << max_abs_error
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
             << ", encrypted_input_chunks: " << input_group.chunk_count()
             << ", input_decrypt_max_abs_error: " << max_abs_error
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
                   << ", encrypted_input_chunks=" << input_group.chunk_count()
                   << ", input_decrypt_max_abs_error=" << max_abs_error
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
                   << ", image_time_ms=" << image_time_diff.count() << '\n';
        out_log.flush();
    }

    const auto all_time_end = chrono::high_resolution_clock::now();
    const auto all_time_diff =
        chrono::duration_cast<chrono::milliseconds>(all_time_end - all_time_start);
    resnet18_progress_log() << "total time : " << all_time_diff.count() << " ms" << endl;
    out_log << endl << "total time : " << all_time_diff.count() << " ms" << endl;
    out_log << "run_done: total_time_ms=" << all_time_diff.count() << '\n';
}
