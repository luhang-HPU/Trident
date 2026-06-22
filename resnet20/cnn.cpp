#include "cnn.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace std;
using namespace poseidon;

int pow2_int(int exponent)
{
    if (exponent < 0)
    {
        throw invalid_argument("negative exponent is not supported");
    }
    return 1 << exponent;
}

Tree::Tree()
{
    clear();
}

Tree::Tree(EvalType eval_type)
{
    clear();
    type = eval_type;
}

void Tree::clear()
{
    depth = 0;
    type = EvalType::None;
    m = 0;
    l = 0;
    b = 0;
    tree.assign(2, 0);
    tree[0] = -1;
    tree[1] = 0;
}

void Tree::merge(const Tree &lhs, const Tree &rhs, int g)
{
    clear();
    if (lhs.type != rhs.type)
    {
        throw invalid_argument("tree types do not match");
    }

    type = lhs.type;
    depth = max(lhs.depth, rhs.depth) + 1;
    tree.assign(static_cast<size_t>(1U << (depth + 1)), -1);
    tree[0] = -1;
    tree[1] = g;

    for (int i = 1; i <= (1 << (lhs.depth + 1)) - 1; ++i)
    {
        const int offset = 1 << static_cast<int>(log2(static_cast<double>(i)));
        tree[i + offset] = lhs.tree[i];
    }
    for (int i = 1; i <= (1 << (rhs.depth + 1)) - 1; ++i)
    {
        const int offset = 1 << static_cast<int>(log2(static_cast<double>(i)));
        tree[i + 2 * offset] = rhs.tree[i];
    }
}

void upgrade_oddbaby(long degree, Tree &tree)
{
    const long depth = static_cast<long>(ceil(log(static_cast<double>(degree)) / log(2.0)) + 0.5);
    long total_min = 10000;
    long min_m = 0;
    long min_l = 0;
    Tree total_min_tree(EvalType::OddBaby);

    for (long l = 1; pow2_int(static_cast<int>(l)) - 1 <= degree; ++l)
    {
        for (long m = 1; pow2_int(static_cast<int>(m - 1)) < degree; ++m)
        {
            vector<vector<int>> f(static_cast<size_t>(degree + 1),
                                  vector<int>(static_cast<size_t>(depth + 1), 0));
            vector<vector<Tree>> g(static_cast<size_t>(degree + 1),
                                   vector<Tree>(static_cast<size_t>(depth + 1),
                                                Tree(EvalType::OddBaby)));
            f[1][1] = 0;
            for (int i = 3; i <= degree; i += 2)
            {
                f[i][1] = 10000;
            }

            for (int j = 2; j <= depth; ++j)
            {
                for (int i = 1; i <= degree; i += 2)
                {
                    if (i <= pow2_int(static_cast<int>(l)) - 1 && i <= pow2_int(j - 1))
                    {
                        f[i][j] = 0;
                        continue;
                    }

                    int best = 10000;
                    Tree best_tree;
                    for (int k = 1; k <= m - 1 && pow2_int(k) < i && k < j; ++k)
                    {
                        const long split = pow2_int(k);
                        const int candidate = f[i - split][j - 1] + f[split - 1][j] + 1;
                        if (candidate < best)
                        {
                            best = candidate;
                            best_tree.merge(g[split - 1][j], g[i - split][j - 1],
                                            static_cast<int>(split));
                        }
                    }
                    f[i][j] = best;
                    g[i][j] = best_tree;
                }
            }

            const int candidate_total = f[degree][depth] + pow2_int(static_cast<int>(l - 1)) +
                                        static_cast<int>(m) - 2;
            if (candidate_total < total_min)
            {
                total_min = candidate_total;
                total_min_tree = g[degree][depth];
                min_m = m;
                min_l = l;
            }
        }
    }

    tree = total_min_tree;
    tree.type = EvalType::OddBaby;
    tree.m = static_cast<int>(min_m);
    tree.l = static_cast<int>(min_l);
}

void upgrade_baby(long degree, Tree &tree)
{
    const long depth =
        static_cast<long>(ceil(log(static_cast<double>(degree + 1)) / log(2.0)) + 0.5);
    long total_min = 10000;
    long min_m = 0;
    long min_b = 0;
    Tree total_min_tree(EvalType::Baby);

    if (degree == 1)
    {
        tree = Tree(EvalType::Baby);
        tree.m = 1;
        tree.b = 1;
        return;
    }

    for (long b = 1; b <= degree; ++b)
    {
        for (long m = 1; pow2_int(static_cast<int>(m - 1)) * b <= degree; ++m)
        {
            vector<vector<int>> f(static_cast<size_t>(degree + 1),
                                  vector<int>(static_cast<size_t>(depth + 1), 0));
            vector<vector<Tree>> g(static_cast<size_t>(degree + 1),
                                   vector<Tree>(static_cast<size_t>(depth + 1),
                                                Tree(EvalType::Baby)));

            for (int j = 1; j <= depth; ++j)
            {
                for (int i = 1; i <= degree; ++i)
                {
                    if (i + 1 > pow2_int(j))
                    {
                        f[i][j] = 10000;
                        g[i][j] = Tree(EvalType::Baby);
                    }
                    else if (b == 1 && m >= 2 && i <= 2 && i <= pow2_int(j - 1))
                    {
                        f[i][j] = 0;
                        g[i][j] = Tree(EvalType::Baby);
                    }
                    else if (i <= b && i <= pow2_int(j - 1))
                    {
                        f[i][j] = 0;
                        g[i][j] = Tree(EvalType::Baby);
                    }
                    else
                    {
                        int best = 10000;
                        Tree best_tree;
                        for (int k = 2; k <= b; ++k)
                        {
                            const long split = k;
                            if (split <= pow2_int(j - 1) && split < i)
                            {
                                const int candidate =
                                    f[i - split][j - 1] + f[split - 1][j] + 1;
                                if (candidate < best)
                                {
                                    best = candidate;
                                    best_tree.merge(g[split - 1][j], g[i - split][j - 1], k);
                                }
                            }
                        }
                        for (int k = 0; k <= m - 1; ++k)
                        {
                            const long split = pow2_int(k) * b;
                            if (split <= pow2_int(j - 1) && split >= 2 && split < i)
                            {
                                const int candidate =
                                    f[i - split][j - 1] + f[split - 1][j] + 1;
                                if (candidate < best)
                                {
                                    best = candidate;
                                    best_tree.merge(g[split - 1][j], g[i - split][j - 1],
                                                    static_cast<int>(split));
                                }
                            }
                        }
                        f[i][j] = best;
                        g[i][j] = best_tree;
                    }
                }
            }

            const int candidate_total = f[degree][depth] + static_cast<int>(m + b - 2);
            if (candidate_total < total_min)
            {
                total_min = candidate_total;
                total_min_tree = g[degree][depth];
                min_m = m;
                min_b = b;
            }
        }
    }

    tree = total_min_tree;
    tree.type = EvalType::Baby;
    tree.m = static_cast<int>(min_m);
    tree.b = static_cast<int>(min_b);
}

namespace
{

constexpr int kPreviewSlots = 32;
namespace fs = std::filesystem;

size_t slot_count_from_logn(int logn)
{
    if (logn < 1)
    {
        throw std::invalid_argument("logn should be positive");
    }
    return static_cast<size_t>(1) << (logn - 1);
}

int pow2(int exponent)
{
    if (exponent < 0)
    {
        throw std::invalid_argument("negative exponent is not supported");
    }
    return 1 << exponent;
}

size_t ceil_to_int(double value)
{
    return static_cast<size_t>(ceil(value) + 0.5);
}

int floor_to_int(double value)
{
    return static_cast<int>(floor(value));
}

int log2_long(long value)
{
    if (value <= 0 || (value & (value - 1)) != 0)
    {
        return -1;
    }
    int exponent = 0;
    while ((1L << exponent) != value)
    {
        ++exponent;
    }
    return exponent;
}

long num_one(long value)
{
    long count = 0;
    while (value > 0)
    {
        count += (value & 1L);
        value >>= 1;
    }
    return count;
}

size_t chain_index_or_throw(const PoseidonContext &context, const Ciphertext &cipher)
{
    auto context_data = context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw std::runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }
    return context_data->chain_index();
}

long coeff_number(long degree, const Tree &tree)
{
    if (tree.tree.empty())
    {
        throw invalid_argument("tree is empty");
    }

    const int tree_size = 1 << (tree.depth + 1);
    vector<long> decomp_deg(static_cast<size_t>(tree_size), -1);
    decomp_deg[1] = degree;
    for (int level = 1; level <= tree.depth; ++level)
    {
        for (int node = 1 << level; node < (1 << (level + 1)); ++node)
        {
            if ((node % 2) == 0)
            {
                decomp_deg[node] = tree.tree[node / 2] - 1;
            }
            else
            {
                decomp_deg[node] = decomp_deg[node / 2] - tree.tree[node / 2];
            }
        }
    }

    long count = 0;
    for (int node = 0; node < tree_size; ++node)
    {
        if (tree.tree[node] == 0)
        {
            count += decomp_deg[node] + 1;
        }
    }
    return count;
}

void add_lazy_cipher(Ciphertext &accumulator, const Ciphertext &term, EvaluatorCkksBase &evaluator,
                     CKKSEncoder &encoder)
{
    auto same_level_with_same_scale = [&](const Ciphertext &lhs, const Ciphertext &rhs) {
        return lhs.parms_id() == rhs.parms_id() &&
               poseidon::util::are_approximate<double>(lhs.scale(), rhs.scale());
    };

    auto preserve_value_scale_same_level = [&](const Ciphertext &source, double target_scale) {
        if (poseidon::util::are_approximate<double>(source.scale(), target_scale))
        {
            return source;
        }
        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, target_scale / source.scale(), adjusted, encoder);
        return adjusted;
    };

    auto preserve_value_rescale_to = [&](const Ciphertext &source, const Ciphertext &target) {
        auto context_data = encoder.context().crt_context()->get_context_data(source.parms_id());
        if (!context_data)
        {
            throw runtime_error("failed to get source context data for reduced-error add");
        }
        const double q_last = static_cast<double>(context_data->coeff_modulus().back().value());
        const double plain_scale = target.scale() * q_last / source.scale();

        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, plain_scale, adjusted, encoder);
        evaluator.rescale(adjusted, adjusted);
        if (adjusted.parms_id() != target.parms_id())
        {
            evaluator.drop_modulus(adjusted, adjusted, target.parms_id());
        }
        if (!poseidon::util::are_approximate<double>(adjusted.scale(), target.scale()))
        {
            adjusted = preserve_value_scale_same_level(adjusted, target.scale());
        }
        return adjusted;
    };

    if (accumulator.coeff_modulus_size() <= term.coeff_modulus_size())
    {
        Ciphertext rhs = (accumulator.coeff_modulus_size() == term.coeff_modulus_size())
                             ? preserve_value_scale_same_level(term, accumulator.scale())
                             : preserve_value_rescale_to(term, accumulator);
        if (!same_level_with_same_scale(accumulator, rhs))
        {
            evaluator.add_dynamic(accumulator, rhs, accumulator, encoder);
            return;
        }
        evaluator.add(accumulator, rhs, accumulator);
        return;
    }

    Ciphertext lhs = preserve_value_rescale_to(accumulator, term);
    if (!same_level_with_same_scale(lhs, term))
    {
        evaluator.add_dynamic(lhs, term, accumulator, encoder);
        return;
    }
    evaluator.add(lhs, term, accumulator);
}

void sub_lazy_cipher(const Ciphertext &lhs, const Ciphertext &rhs, Ciphertext &result,
                     EvaluatorCkksBase &evaluator, CKKSEncoder &encoder)
{
    auto same_level_with_same_scale = [&](const Ciphertext &a, const Ciphertext &b) {
        return a.parms_id() == b.parms_id() &&
               poseidon::util::are_approximate<double>(a.scale(), b.scale());
    };

    auto preserve_value_scale_same_level = [&](const Ciphertext &source, double target_scale) {
        if (poseidon::util::are_approximate<double>(source.scale(), target_scale))
        {
            return source;
        }
        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, target_scale / source.scale(), adjusted, encoder);
        return adjusted;
    };

    auto preserve_value_rescale_to = [&](const Ciphertext &source, const Ciphertext &target) {
        auto context_data = encoder.context().crt_context()->get_context_data(source.parms_id());
        if (!context_data)
        {
            throw runtime_error("failed to get source context data for reduced-error sub");
        }
        const double q_last = static_cast<double>(context_data->coeff_modulus().back().value());
        const double plain_scale = target.scale() * q_last / source.scale();

        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, plain_scale, adjusted, encoder);
        evaluator.rescale(adjusted, adjusted);
        if (adjusted.parms_id() != target.parms_id())
        {
            evaluator.drop_modulus(adjusted, adjusted, target.parms_id());
        }
        if (!poseidon::util::are_approximate<double>(adjusted.scale(), target.scale()))
        {
            adjusted = preserve_value_scale_same_level(adjusted, target.scale());
        }
        return adjusted;
    };

    if (lhs.coeff_modulus_size() <= rhs.coeff_modulus_size())
    {
        Ciphertext rhs_aligned = (lhs.coeff_modulus_size() == rhs.coeff_modulus_size())
                                     ? preserve_value_scale_same_level(rhs, lhs.scale())
                                     : preserve_value_rescale_to(rhs, lhs);
        if (!same_level_with_same_scale(lhs, rhs_aligned))
        {
            evaluator.sub_dynamic(lhs, rhs_aligned, result, encoder);
            return;
        }
        evaluator.sub(lhs, rhs_aligned, result);
        return;
    }

    Ciphertext lhs_aligned = preserve_value_rescale_to(lhs, rhs);
    if (!same_level_with_same_scale(lhs_aligned, rhs))
    {
        evaluator.sub_dynamic(lhs_aligned, rhs, result, encoder);
        return;
    }
    evaluator.sub(lhs_aligned, rhs, result);
}

void multiply_reduced_cipher(const Ciphertext &lhs, const Ciphertext &rhs, Ciphertext &result,
                             EvaluatorCkksBase &evaluator, const RelinKeys &relin_keys,
                             CKKSEncoder &encoder)
{
    auto preserve_value_scale_same_level = [&](const Ciphertext &source, double target_scale) {
        if (poseidon::util::are_approximate<double>(source.scale(), target_scale))
        {
            return source;
        }
        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, target_scale / source.scale(), adjusted, encoder);
        return adjusted;
    };

    auto preserve_value_rescale_to = [&](const Ciphertext &source, const Ciphertext &target) {
        auto context_data = encoder.context().crt_context()->get_context_data(source.parms_id());
        if (!context_data)
        {
            throw runtime_error("failed to get source context data for reduced-error multiply");
        }
        const double q_last = static_cast<double>(context_data->coeff_modulus().back().value());
        const double plain_scale = target.scale() * q_last / source.scale();

        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, plain_scale, adjusted, encoder);
        evaluator.rescale(adjusted, adjusted);
        if (adjusted.parms_id() != target.parms_id())
        {
            evaluator.drop_modulus(adjusted, adjusted, target.parms_id());
        }
        if (!poseidon::util::are_approximate<double>(adjusted.scale(), target.scale()))
        {
            adjusted = preserve_value_scale_same_level(adjusted, target.scale());
        }
        return adjusted;
    };

    Ciphertext lhs_aligned = lhs;
    Ciphertext rhs_aligned = rhs;

    if (lhs.coeff_modulus_size() < rhs.coeff_modulus_size())
    {
        rhs_aligned = preserve_value_rescale_to(rhs, lhs);
    }
    else if (lhs.coeff_modulus_size() > rhs.coeff_modulus_size())
    {
        lhs_aligned = preserve_value_rescale_to(lhs, rhs);
    }

    if (!poseidon::util::are_approximate<double>(lhs_aligned.scale(), rhs_aligned.scale()))
    {
        rhs_aligned = preserve_value_scale_same_level(rhs_aligned, lhs_aligned.scale());
    }

    evaluator.multiply_relin_dynamic(lhs_aligned, rhs_aligned, result, relin_keys);
}

void eval_t(EvaluatorCkksBase &evaluator, const RelinKeys &relin_keys, CKKSEncoder &encoder,
            Ciphertext &output, const Ciphertext &tm, const Ciphertext &tn,
            const Ciphertext &tm_minus_n)
{
    Ciphertext product;
    multiply_reduced_cipher(tm, tn, product, evaluator, relin_keys, encoder);

    Ciphertext doubled;
    evaluator.add_dynamic(product, product, doubled, encoder);
    evaluator.rescale(doubled, doubled);
    sub_lazy_cipher(doubled, tm_minus_n, output, evaluator, encoder);
}

Ciphertext encrypt_constant_cipher(double value, size_t slot_count, double scale,
                                  Encryptor &encryptor, CKKSEncoder &encoder)
{
    vector<complex<double>> slots(slot_count, complex<double>(value, 0.0));
    Plaintext plain;
    encoder.encode(slots, scale, plain);
    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);
    return cipher;
}

void generate_t0_t1(Encryptor &encryptor, CKKSEncoder &encoder, const Ciphertext &cipher,
                    Ciphertext &t0, Ciphertext &t1)
{
    t0 = encrypt_constant_cipher(1.0, encoder.slot_count(), cipher.scale(), encryptor, encoder);
    t1 = cipher;
}

void multiply_const_reduced_error(const Ciphertext &cipher, double coeff, double target_scale,
                                  Ciphertext &output, EvaluatorCkksBase &evaluator,
                                  CKKSEncoder &encoder)
{
    evaluator.multiply_const(cipher, coeff, target_scale / cipher.scale(), output, encoder);
}

Ciphertext zero_cipher_for_lazy_sum(size_t slot_count, double scale, Encryptor &encryptor,
                                    CKKSEncoder &encoder)
{
    vector<complex<double>> zeros(slot_count, complex<double>(0.0, 0.0));
    Plaintext plain;
    encoder.encode(zeros, scale * scale, plain);
    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);
    return cipher;
}

void decode_preview(const Ciphertext &cipher, Decryptor &decryptor, CKKSEncoder &encoder,
                    ostream &output)
{
    Plaintext plain;
    decryptor.decrypt(cipher, plain);

    vector<complex<double>> values;
    encoder.decode(plain, values);

    output << "  cipher decrypt preview:";
    const size_t preview = min(values.size(), static_cast<size_t>(kPreviewSlots));
    for (size_t i = 0; i < preview; ++i)
    {
        output << ' ' << values[i].real();
    }
    output << '\n';
}

double multiply_plain_scale(const Ciphertext &input, const CKKSEncoder &encoder)
{
    auto context_data = encoder.context().crt_context()->get_context_data(input.parms_id());
    if (!context_data)
    {
        throw std::runtime_error("failed to locate ciphertext parms_id for plain scale selection");
    }
    const int rescale_prime_bits = context_data->coeff_modulus().back().bit_count();
    return std::pow(2.0, static_cast<double>(rescale_prime_bits));
}

void multiply_by_vector(const Ciphertext &input, const vector<double> &weights, Ciphertext &output,
                        CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    Plaintext plain;
    encoder.encode(weights, input.parms_id(), multiply_plain_scale(input, encoder), plain);
    evaluator.multiply_plain(input, plain, output);
    evaluator.rescale_dynamic(output, output, input.scale());
}

void multiply_by_vector_inplace(Ciphertext &input, const vector<double> &weights,
                                CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    Plaintext plain;
    const double original_scale = input.scale();
    encoder.encode(weights, input.parms_id(), multiply_plain_scale(input, encoder), plain);
    evaluator.multiply_plain_inplace(input, plain);
    evaluator.rescale_dynamic(input, input, original_scale);
}

void log_labeled_tensor_state(const string &label, const TensorCipher &tensor,
                              const PoseidonContext &context, ostream &output);

void log_labeled_cipher_state(const string &label, const Ciphertext &cipher,
                              const TensorCipher &meta_source, const PoseidonContext &context,
                              ostream &output);

void add_assign_dynamic(Ciphertext &accumulator, const Ciphertext &term, CKKSEncoder &encoder,
                        EvaluatorCkksBase &evaluator)
{
    evaluator.add_dynamic(accumulator, term, accumulator, encoder);
}

vector<vector<double>> load_relu_component_coeffs(long alpha, const vector<int> &deg,
                                                  const vector<Tree> &trees, double scaled_val)
{
    const fs::path relu_file =
        fs::path(__FILE__).parent_path() / "relu_param" / ("d" + to_string(alpha) + ".txt");
    ifstream input(relu_file);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open relu parameter file: " + relu_file.string());
    }

    vector<vector<double>> coeffs;
    coeffs.reserve(deg.size());
    for (size_t component_index = 0; component_index < deg.size(); ++component_index)
    {
        const long component_coeff_count = coeff_number(deg[component_index], trees.at(component_index));
        vector<double> component;
        component.reserve(static_cast<size_t>(component_coeff_count));
        for (long i = 0; i < component_coeff_count; ++i)
        {
            double coeff = 0.0;
            if (!(input >> coeff))
            {
                throw std::runtime_error("failed to read relu coefficients from: " +
                                         relu_file.string());
            }
            component.emplace_back(coeff);
        }
        coeffs.emplace_back(std::move(component));
    }

    if (coeffs.size() >= 3)
    {
        for (double &coeff : coeffs[0])
        {
            coeff /= 2.0;
        }
        for (double &coeff : coeffs[1])
        {
            coeff /= scaled_val;
        }
        for (double &coeff : coeffs[2])
        {
            coeff *= 0.5;
        }
    }

    return coeffs;
}

void log_relu_component_coeffs(const vector<vector<double>> &coeffs, ostream &output)
{
    output << "  sign poly coeff counts:";
    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        output << " c" << (i + 1) << '=' << coeffs[i].size();
    }
    output << '\n';
}

void assign_scale_for_relu_reference(Ciphertext &cipher, double scale)
{
    cipher.scale() = scale;
}

void add_lazy_cipher_for_relu_reference(Ciphertext &accumulator, const Ciphertext &term,
                                        EvaluatorCkksBase &evaluator, CKKSEncoder &encoder)
{
    if (accumulator.parms_id() == term.parms_id())
    {
        Ciphertext aligned_term = term;
        assign_scale_for_relu_reference(aligned_term, accumulator.scale());
        evaluator.add(accumulator, aligned_term, accumulator);
        return;
    }
    evaluator.add_dynamic(accumulator, term, accumulator, encoder);
}

void eval_t_for_relu_reference(EvaluatorCkksBase &evaluator, const RelinKeys &relin_keys,
                               CKKSEncoder &encoder, Ciphertext &output,
                               const Ciphertext &tm, const Ciphertext &tn,
                               const Ciphertext &tm_minus_n)
{
    const double target_scale = tm.scale();
    const double lazy_scale = target_scale * target_scale;

    Ciphertext product;
    evaluator.multiply_relin_dynamic(tm, tn, product, relin_keys);
    assign_scale_for_relu_reference(product, lazy_scale);

    Ciphertext doubled;
    evaluator.add(product, product, doubled);
    assign_scale_for_relu_reference(doubled, lazy_scale);
    evaluator.rescale(doubled, doubled);
    assign_scale_for_relu_reference(doubled, target_scale);

    if (doubled.parms_id() == tm_minus_n.parms_id())
    {
        Ciphertext aligned_tm_minus_n = tm_minus_n;
        assign_scale_for_relu_reference(aligned_tm_minus_n, doubled.scale());
        evaluator.sub(doubled, aligned_tm_minus_n, output);
    }
    else
    {
        evaluator.sub_dynamic(doubled, tm_minus_n, output, encoder);
    }
    assign_scale_for_relu_reference(output, target_scale);
}

Ciphertext eval_polynomial_integrate_for_relu_reference(
    const Ciphertext &cipher, long degree, const vector<double> &decomp_coeff, const Tree &tree,
    Encryptor &encryptor, EvaluatorCkksBase &evaluator, CKKSEncoder &encoder,
    const RelinKeys &relin_keys)
{
    if (tree.type != EvalType::OddBaby)
    {
        throw invalid_argument("relu reference only supports oddbaby tree");
    }

    const double scale = cipher.scale();
    const double lazy_scale = scale * scale;
    const long total_depth =
        static_cast<long>(ceil_to_int(log(static_cast<double>(degree + 1)) / log(2.0)));
    const int tree_size = 1 << (tree.depth + 1);

    vector<long> decomp_deg(static_cast<size_t>(tree_size), -1);
    vector<long> start_index(static_cast<size_t>(tree_size), -1);
    vector<unique_ptr<Ciphertext>> t(128);
    vector<unique_ptr<Ciphertext>> pt(128);

    decomp_deg[1] = degree;
    long temp_index = 1;
    for (int level = 1; level <= tree.depth; ++level)
    {
        for (int node = 1 << level; node < (1 << (level + 1)); ++node)
        {
            if ((node % 2) == 0)
            {
                decomp_deg[node] = tree.tree[node / 2] - 1;
            }
            else
            {
                decomp_deg[node] = decomp_deg[node / 2] - tree.tree[node / 2];
            }
        }
    }
    for (int node = 1; node < tree_size; ++node)
    {
        if (tree.tree[node] == 0)
        {
            start_index[node] = temp_index;
            temp_index += decomp_deg[node] + 1;
        }
    }

    t[0] = make_unique<Ciphertext>();
    t[1] = make_unique<Ciphertext>();
    generate_t0_t1(encryptor, encoder, cipher, *t[0], *t[1]);

    for (int stage = 1; stage <= total_depth; ++stage)
    {
        for (int node = 1; node < tree_size; ++node)
        {
            if (tree.tree[node] == 0 && total_depth + 1 - num_one(node) == stage)
            {
                int coeff_index = static_cast<int>(start_index[node]);
                pt[node] = make_unique<Ciphertext>();
                multiply_const_reduced_error(
                    *t[1], decomp_coeff.at(static_cast<size_t>(coeff_index)), lazy_scale,
                    *pt[node], evaluator, encoder);
                coeff_index += 2;
                for (int cheb_degree = 3; cheb_degree <= decomp_deg[node]; cheb_degree += 2)
                {
                    if (!t[cheb_degree])
                    {
                        throw runtime_error("missing Chebyshev basis ciphertext");
                    }
                    Ciphertext term;
                    multiply_const_reduced_error(
                        *t[cheb_degree], decomp_coeff.at(static_cast<size_t>(coeff_index)),
                        lazy_scale, term, evaluator, encoder);
                    add_lazy_cipher_for_relu_reference(*pt[node], term, evaluator, encoder);
                    coeff_index += 2;
                }
                evaluator.rescale(*pt[node], *pt[node]);
                assign_scale_for_relu_reference(*pt[node], scale);
            }
        }

        for (int node = 1; node < tree_size; ++node)
        {
            if (tree.tree[node] > 0 && total_depth + 1 - num_one(node) == stage &&
                (node % 2) == 1)
            {
                long walk = node;
                pt[node] = make_unique<Ciphertext>();
                evaluator.multiply_relin_dynamic(*t[tree.tree[walk]], *pt[2 * walk + 1],
                                                *pt[node], relin_keys);
                assign_scale_for_relu_reference(*pt[node], lazy_scale);
                walk *= 2;
                while (true)
                {
                    if (tree.tree[walk] == 0)
                    {
                        break;
                    }
                    Ciphertext term;
                    evaluator.multiply_relin_dynamic(*t[tree.tree[walk]], *pt[2 * walk + 1], term,
                                                    relin_keys);
                    assign_scale_for_relu_reference(term, lazy_scale);
                    add_lazy_cipher_for_relu_reference(*pt[node], term, evaluator, encoder);
                    walk *= 2;
                }
                evaluator.rescale(*pt[node], *pt[node]);
                assign_scale_for_relu_reference(*pt[node], scale);
                add_lazy_cipher_for_relu_reference(*pt[node], *pt[walk], evaluator, encoder);
            }
        }

        if (stage <= tree.m - 1)
        {
            const int cheb_degree = pow2(stage);
            t[cheb_degree] = make_unique<Ciphertext>();
            eval_t_for_relu_reference(evaluator, relin_keys, encoder, *t[cheb_degree],
                                      *t[pow2(stage - 1)], *t[pow2(stage - 1)], *t[0]);
        }
        if (stage <= tree.l)
        {
            for (int cheb_degree = pow2(stage - 1) + 1; cheb_degree <= pow2(stage) - 1;
                 cheb_degree += 2)
            {
                t[cheb_degree] = make_unique<Ciphertext>();
                eval_t_for_relu_reference(evaluator, relin_keys, encoder, *t[cheb_degree],
                                          *t[pow2(stage - 1)],
                                          *t[cheb_degree - pow2(stage - 1)],
                                          *t[pow2(stage) - cheb_degree]);
            }
        }
    }

    if (!pt[1])
    {
        throw runtime_error("tree polynomial evaluation failed to produce root ciphertext");
    }
    return *pt[1];
}

Ciphertext eval_polynomial_integrate(const Ciphertext &cipher, long degree,
                                     const vector<double> &decomp_coeff, const Tree &tree,
                                     Encryptor &encryptor, EvaluatorCkksBase &evaluator,
                                     CKKSEncoder &encoder, const RelinKeys &relin_keys,
                                     ostream *debug_output = nullptr)
{
    const double scale = cipher.scale();
    const double lazy_scale = scale * scale;
    const long total_depth =
        static_cast<long>(ceil_to_int(log(static_cast<double>(degree + 1)) / log(2.0)));
    const int tree_size = 1 << (tree.depth + 1);
    vector<long> decomp_deg(static_cast<size_t>(tree_size), -1);
    vector<long> start_index(static_cast<size_t>(tree_size), -1);
    vector<unique_ptr<Ciphertext>> t(100);
    vector<unique_ptr<Ciphertext>> pt(100);
    t[0] = make_unique<Ciphertext>();
    t[1] = make_unique<Ciphertext>();

    long temp_index = (tree.type == EvalType::OddBaby) ? 1 : 0;
    decomp_deg[1] = degree;
    for (int level = 1; level <= tree.depth; ++level)
    {
        for (int node = 1 << level; node < (1 << (level + 1)); ++node)
        {
            if ((node % 2) == 0)
            {
                decomp_deg[node] = tree.tree[node / 2] - 1;
            }
            else
            {
                decomp_deg[node] = decomp_deg[node / 2] - tree.tree[node / 2];
            }
        }
    }
    for (int node = 1; node < tree_size; ++node)
    {
        if (tree.tree[node] == 0)
        {
            start_index[node] = temp_index;
            temp_index += decomp_deg[node] + 1;
        }
    }

    generate_t0_t1(encryptor, encoder, cipher, *t[0], *t[1]);

    if (tree.type == EvalType::OddBaby)
    {
        for (int stage = 1; stage <= total_depth; ++stage)
        {
            for (int node = 1; node < tree_size; ++node)
            {
                if (tree.tree[node] == 0 && total_depth + 1 - num_one(node) == stage)
                {
                    int coeff_index = static_cast<int>(start_index[node]);
                    pt[node] = make_unique<Ciphertext>();
                    multiply_const_reduced_error(
                        *t[1], decomp_coeff.at(static_cast<size_t>(coeff_index)), lazy_scale,
                        *pt[node], evaluator, encoder);
                    coeff_index += 2;
                    for (int cheb_degree = 3; cheb_degree <= decomp_deg[node]; cheb_degree += 2)
                    {
                        if (!t[cheb_degree])
                        {
                            throw runtime_error("missing Chebyshev basis ciphertext");
                        }
                        Ciphertext term;
                        multiply_const_reduced_error(
                            *t[cheb_degree], decomp_coeff.at(static_cast<size_t>(coeff_index)),
                            lazy_scale, term, evaluator, encoder);
                        try
                        {
                            add_lazy_cipher(*pt[node], term, evaluator, encoder);
                        }
                        catch (const std::exception &e)
                        {
                            if (debug_output)
                            {
                                *debug_output << "eval_poly leaf add failure"
                                              << " stage=" << stage
                                              << " node=" << node
                                              << " cheb_degree=" << cheb_degree
                                              << " acc_level=" << pt[node]->level()
                                              << " acc_scale=" << pt[node]->scale()
                                              << " acc_mod_size=" << pt[node]->coeff_modulus_size()
                                              << " term_level=" << term.level()
                                              << " term_scale=" << term.scale()
                                              << " term_mod_size=" << term.coeff_modulus_size()
                                              << " what=" << e.what() << '\n';
                            }
                            throw;
                        }
                        coeff_index += 2;
                    }
                    evaluator.rescale(*pt[node], *pt[node]);
                }
            }

            for (int node = 1; node < tree_size; ++node)
            {
                if (tree.tree[node] > 0 && total_depth + 1 - num_one(node) == stage &&
                    (node % 2) == 1)
                {
                    long walk = node;
                    pt[node] = make_unique<Ciphertext>();
                    evaluator.multiply_relin_dynamic(*t[tree.tree[walk]], *pt[2 * walk + 1],
                                                    *pt[node], relin_keys);
                    walk *= 2;
                    while (true)
                    {
                        if (tree.tree[walk] == 0)
                        {
                            break;
                        }
                        Ciphertext term;
                        evaluator.multiply_relin_dynamic(*t[tree.tree[walk]], *pt[2 * walk + 1],
                                                        term, relin_keys);
                        add_lazy_cipher(*pt[node], term, evaluator, encoder);
                        walk *= 2;
                    }
                    evaluator.rescale(*pt[node], *pt[node]);
                    add_lazy_cipher(*pt[node], *pt[walk], evaluator, encoder);
                }
            }

            if (stage <= tree.m - 1)
            {
                const int cheb_degree = pow2(stage);
                t[cheb_degree] = make_unique<Ciphertext>();
                eval_t(evaluator, relin_keys, encoder, *t[cheb_degree], *t[pow2(stage - 1)],
                       *t[pow2(stage - 1)], *t[0]);
            }
            if (stage <= tree.l)
            {
                for (int cheb_degree = pow2(stage - 1) + 1; cheb_degree <= pow2(stage) - 1;
                     cheb_degree += 2)
                {
                    t[cheb_degree] = make_unique<Ciphertext>();
                    eval_t(evaluator, relin_keys, encoder, *t[cheb_degree], *t[pow2(stage - 1)],
                           *t[cheb_degree - pow2(stage - 1)],
                           *t[pow2(stage) - cheb_degree]);
                }
            }
        }
    }
    else if (tree.type == EvalType::Baby)
    {
        Ciphertext ctxt_zero =
            zero_cipher_for_lazy_sum(encoder.slot_count(), scale, encryptor, encoder);
        for (int stage = 1; stage <= total_depth; ++stage)
        {
            for (int node = 1; node < tree_size; ++node)
            {
                if (tree.tree[node] == 0 && total_depth + 1 - num_one(node) == stage)
                {
                    int coeff_index = static_cast<int>(start_index[node]);
                    pt[node] = make_unique<Ciphertext>(ctxt_zero);
                    for (int cheb_degree = 0; cheb_degree <= decomp_deg[node]; ++cheb_degree)
                    {
                        const double coeff = decomp_coeff.at(static_cast<size_t>(coeff_index));
                        if (abs(coeff) > 1.0 / scale)
                        {
                            if (!t[cheb_degree])
                            {
                                throw runtime_error("missing Chebyshev basis ciphertext");
                            }
                            Ciphertext term;
                            multiply_const_reduced_error(*t[cheb_degree], coeff, lazy_scale, term,
                                                        evaluator, encoder);
                            try
                            {
                                add_lazy_cipher(*pt[node], term, evaluator, encoder);
                            }
                            catch (const std::exception &e)
                            {
                                if (debug_output)
                                {
                                    *debug_output << "eval_poly baby leaf add failure"
                                                  << " stage=" << stage
                                                  << " node=" << node
                                                  << " cheb_degree=" << cheb_degree
                                                  << " acc_level=" << pt[node]->level()
                                                  << " acc_scale=" << pt[node]->scale()
                                                  << " acc_mod_size=" << pt[node]->coeff_modulus_size()
                                                  << " term_level=" << term.level()
                                                  << " term_scale=" << term.scale()
                                                  << " term_mod_size=" << term.coeff_modulus_size()
                                                  << " what=" << e.what() << '\n';
                                }
                                throw;
                            }
                        }
                        ++coeff_index;
                    }
                    evaluator.rescale(*pt[node], *pt[node]);
                }
            }

            vector<long> covered_ancestors;
            for (int node = 1; node < tree_size; ++node)
            {
                if (!(tree.tree[node] > 0 && total_depth + 1 - num_one(node) == stage))
                {
                    continue;
                }

                bool skip = false;
                for (long ancestor : covered_ancestors)
                {
                    int walk = node;
                    while (true)
                    {
                        if (walk == ancestor)
                        {
                            skip = true;
                            break;
                        }
                        if ((walk % 2) == 0)
                        {
                            walk /= 2;
                        }
                        else
                        {
                            break;
                        }
                    }
                    if (skip)
                    {
                        break;
                    }
                }
                if (skip)
                {
                    continue;
                }

                covered_ancestors.emplace_back(node);
                long walk = node;
                pt[node] = make_unique<Ciphertext>();
                evaluator.multiply_relin_dynamic(*t[tree.tree[walk]], *pt[2 * walk + 1],
                                                *pt[node], relin_keys);
                walk *= 2;
                while (true)
                {
                    if (tree.tree[walk] == 0)
                    {
                        break;
                    }
                    Ciphertext term;
                    evaluator.multiply_relin_dynamic(*t[tree.tree[walk]], *pt[2 * walk + 1], term,
                                                    relin_keys);
                    add_lazy_cipher(*pt[node], term, evaluator, encoder);
                    walk *= 2;
                }
                evaluator.rescale(*pt[node], *pt[node]);
                add_lazy_cipher(*pt[node], *pt[walk], evaluator, encoder);
            }

            for (int cheb_degree = 2; cheb_degree <= tree.b; ++cheb_degree)
            {
                if (pow2(stage - 1) < cheb_degree && cheb_degree <= pow2(stage))
                {
                    t[cheb_degree] = make_unique<Ciphertext>();
                    if ((cheb_degree % 2) == 0)
                    {
                        eval_t(evaluator, relin_keys, encoder, *t[cheb_degree],
                               *t[cheb_degree / 2], *t[cheb_degree / 2], *t[0]);
                    }
                    else
                    {
                        eval_t(evaluator, relin_keys, encoder, *t[cheb_degree],
                               *t[cheb_degree / 2], *t[(cheb_degree + 1) / 2], *t[1]);
                    }
                }
            }
            for (int giant = 1; giant <= tree.m - 1; ++giant)
            {
                const int cheb_degree = pow2(giant) * tree.b;
                if (pow2(stage - 1) < cheb_degree && cheb_degree <= pow2(stage))
                {
                    t[cheb_degree] = make_unique<Ciphertext>();
                    if ((cheb_degree % 2) == 0)
                    {
                        eval_t(evaluator, relin_keys, encoder, *t[cheb_degree],
                               *t[cheb_degree / 2], *t[cheb_degree / 2], *t[0]);
                    }
                    else
                    {
                        eval_t(evaluator, relin_keys, encoder, *t[cheb_degree],
                               *t[cheb_degree / 2], *t[(cheb_degree + 1) / 2], *t[1]);
                    }
                }
            }
        }
    }
    else
    {
        throw invalid_argument("tree evaluation type is not set");
    }

    if (!pt[1])
    {
        throw runtime_error("tree polynomial evaluation failed to produce root ciphertext");
    }
    return *pt[1];
}

Ciphertext approximate_sign01(const Ciphertext &input, const vector<int> &deg, long alpha,
                              const vector<Tree> &tree, double scaled_val, Encryptor &encryptor,
                              CKKSEncoder &encoder, EvaluatorCkksBase &evaluator,
                              Decryptor *decryptor, RelinKeys &relin_keys,
                              const TensorCipher *meta_source = nullptr,
                              const PoseidonContext *context = nullptr,
                              ostream *output = nullptr)
{
    Ciphertext result = input;
    const vector<vector<double>> coeffs = load_relu_component_coeffs(alpha, deg, tree, scaled_val);
    if (output)
    {
        log_relu_component_coeffs(coeffs, *output);
    }

    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        if (meta_source && context && output)
        {
            log_labeled_cipher_state("sign poly step " + to_string(i + 1) + " pre-eval state",
                                     result, *meta_source, *context, *output);
        }
        result = eval_polynomial_integrate_for_relu_reference(
            result, deg.at(i), coeffs[i], tree.at(i), encryptor, evaluator, encoder, relin_keys);
        if (meta_source && context && output)
        {
            log_labeled_cipher_state("sign poly step " + to_string(i + 1) + " post-eval state",
                                     result, *meta_source, *context, *output);
        }
    }

    if (meta_source && context && output)
    {
        log_labeled_cipher_state("sign poly result", result, *meta_source, *context, *output);
        if (decryptor)
        {
            decode_preview(result, *decryptor, encoder, *output);
        }
    }

    evaluator.add_const(result, 0.5, result, encoder);
    if (meta_source && context && output)
    {
        log_labeled_cipher_state("sign poly add-const state", result, *meta_source, *context,
                                 *output);
    }

    return result;
}

void print_stage_banner(const string &title, ostream &output)
{
    cout << '\n' << "[ " << title << " ]" << endl;
    output << '\n' << "[ " << title << " ]" << '\n';
}

string tensor_summary(const TensorCipher &tensor, const PoseidonContext &context)
{
    ostringstream summary;
    summary << "shape(k=" << tensor.k() << ",h=" << tensor.h() << ",w=" << tensor.w()
            << ",c=" << tensor.c() << ",t=" << tensor.t() << ",p=" << tensor.p()
            << "), level=" << chain_index_or_throw(context, tensor.cipher())
            << ", scale=" << tensor.cipher().scale();
    return summary.str();
}

void log_labeled_tensor_state(const string &label, const TensorCipher &tensor,
                              const PoseidonContext &context, ostream &output)
{
    output << "  " << label << ": " << tensor_summary(tensor, context) << '\n';
}

void log_labeled_cipher_state(const string &label, const Ciphertext &cipher,
                              const TensorCipher &meta_source, const PoseidonContext &context,
                              ostream &output)
{
    TensorCipher tensor(meta_source.logn(), meta_source.k(), meta_source.h(), meta_source.w(),
                        meta_source.c(), meta_source.t(), meta_source.p(), cipher);
    log_labeled_tensor_state(label, tensor, context, output);
}

void log_after_stage(const TensorCipher &tensor, Decryptor &decryptor, CKKSEncoder &encoder,
                     PoseidonContext &context, ostream &output)
{
    output << "  output: " << tensor_summary(tensor, context) << '\n';
    decode_preview(tensor.cipher(), decryptor, encoder, output);
    output << endl;
}

void relu_impl(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no,
               const vector<int> &deg, long alpha, const vector<Tree> &tree, double scaled_val,
               Encryptor &encryptor, EvaluatorCkksBase &evaluator, Decryptor &decryptor,
               CKKSEncoder &encoder, RelinKeys &relin_keys, double scale, ostream *output,
               const PoseidonContext *context)
{
    (void)comp_no;
    (void)deg;
    (void)alpha;
    (void)tree;
    (void)scaled_val;
    (void)evaluator;
    (void)relin_keys;

    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();

    if (output && context)
    {
        log_labeled_tensor_state("relu input", cnn_in, *context, *output);
        decode_preview(cnn_in.cipher(), decryptor, encoder, *output);
    }

    Plaintext plain_in;
    vector<complex<double>> decoded;
    decryptor.decrypt(cnn_in.cipher(), plain_in);
    encoder.decode(plain_in, decoded);
    for (auto &value : decoded)
    {
        value = complex<double>(max(0.0, value.real()), 0.0);
    }

    Plaintext plain_out;
    encoder.encode(decoded, scale, plain_out);

    Ciphertext relu_cipher;
    encryptor.encrypt(plain_out, relu_cipher);
    if (relu_cipher.parms_id() != cnn_in.cipher().parms_id())
    {
        evaluator.drop_modulus(relu_cipher, relu_cipher, cnn_in.cipher().parms_id());
    }
    if (output)
    {
        *output << "  relu mode: decrypt -> exact plaintext relu -> encrypt\n";
    }
    if (output && context)
    {
        log_labeled_cipher_state("relu debug re-encrypt", relu_cipher, cnn_in, *context, *output);
        decode_preview(relu_cipher, decryptor, encoder, *output);
    }

    cnn_out = TensorCipher(logn, ki, hi, wi, ci, ti, pi, relu_cipher);
}

} // namespace

TensorCipher::TensorCipher(int logn, int k, int h, int w, int c, int t, int p,
                           const vector<double> &data, Encryptor &encryptor,
                           CKKSEncoder &encoder, int logp)
{
    if (k != 1)
    {
        throw std::invalid_argument("supported k is only 1 right now");
    }
    if (logn < 1 || logn > 16)
    {
        throw std::out_of_range("the value of logn is out of range");
    }

    const size_t slot_count = encoder.slot_count();
    if (data.size() > slot_count)
    {
        throw std::out_of_range("the size of data is larger than slot count");
    }

    k_ = k;
    h_ = h;
    w_ = w;
    c_ = c;
    t_ = t;
    p_ = p;
    logn_ = logn;

    vector<complex<double>> slots(slot_count, {0.0, 0.0});
    for (size_t i = 0; i < data.size(); ++i)
    {
        slots[i] = {data[i], 0.0};
    }

    Plaintext plain;
    encoder.encode(slots, pow(2.0, logp), plain);
    encryptor.encrypt(plain, cipher_);
}

TensorCipher::TensorCipher(int logn, int k, int h, int w, int c, int t, int p,
                           const Ciphertext &cipher)
    : k_(k), h_(h), w_(w), c_(c), t_(t), p_(p), logn_(logn), cipher_(cipher)
{
}

int TensorCipher::k() const
{
    return k_;
}

int TensorCipher::h() const
{
    return h_;
}

int TensorCipher::w() const
{
    return w_;
}

int TensorCipher::c() const
{
    return c_;
}

int TensorCipher::t() const
{
    return t_;
}

int TensorCipher::p() const
{
    return p_;
}

int TensorCipher::logn() const
{
    return logn_;
}

const Ciphertext &TensorCipher::cipher() const
{
    return cipher_;
}

Ciphertext &TensorCipher::cipher()
{
    return cipher_;
}

void TensorCipher::set_ciphertext(const Ciphertext &cipher)
{
    cipher_ = cipher;
}

void TensorCipher::print_parms(ostream &output) const
{
    output << "k: " << k_ << '\n';
    output << "h: " << h_ << '\n';
    output << "w: " << w_ << '\n';
    output << "c: " << c_ << '\n';
    output << "t: " << t_ << '\n';
    output << "p: " << p_ << '\n';
}

void log_cipher_state(const TensorCipher &tensor, const PoseidonContext &context, ostream &output)
{
    output << tensor_summary(tensor, context) << '\n';
}

void multiplexed_parallel_convolution_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw,
    const vector<double> &data, vector<double> running_var, vector<double> constant_weight,
    double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
    GaloisKeys &gal_keys, vector<Ciphertext> &cipher_pool, ostream &output, Decryptor &decryptor,
    PoseidonContext &context, size_t stage, bool end)
{
    print_stage_banner("conv stage " + to_string(stage), output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_parallel_convolution_seal(cnn_in, cnn_out, co, st, fh, fw, data,
                                          std::move(running_var), std::move(constant_weight),
                                          epsilon, encoder, encryptor, evaluator, gal_keys,
                                          cipher_pool, end);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void multiplexed_parallel_batch_norm_seal_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> bias,
    vector<double> running_mean, vector<double> running_var, vector<double> weight,
    double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
    double B, ostream &output, Decryptor &decryptor, PoseidonContext &context, size_t stage,
    bool end)
{
    print_stage_banner("batchnorm stage " + to_string(stage), output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_parallel_batch_norm_seal(cnn_in, cnn_out, std::move(bias), std::move(running_mean),
                                         std::move(running_var), std::move(weight), epsilon,
                                         encoder, encryptor, evaluator, B, end);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void approx_ReLU_seal_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no,
                            vector<int> deg, long alpha, vector<Tree> &tree, double scaled_val,
                            long scalingfactor, Encryptor &encryptor,
                            EvaluatorCkksBase &evaluator, Decryptor &decryptor,
                            CKKSEncoder &encoder, PublicKey &public_key, SecretKey &secret_key,
                            RelinKeys &relin_keys, double B, ostream &output,
                            PoseidonContext &context, GaloisKeys &gal_keys, size_t stage)
{
    (void)public_key;
    (void)secret_key;
    (void)scalingfactor;
    (void)B;
    (void)gal_keys;

    print_stage_banner("relu stage " + to_string(stage), output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    relu_impl(cnn_in, cnn_out, comp_no, deg, alpha, tree, scaled_val, encryptor, evaluator,
              decryptor, encoder, relin_keys, B, &output, &context);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void bootstrap_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                     PoseidonBootstrapContext &bootstrapper, ostream &output,
                     Decryptor &decryptor, CKKSEncoder &encoder, PoseidonContext &context,
                     size_t stage)
{
    if (!bootstrapper.evaluator || !bootstrapper.encoder || !bootstrapper.relin_keys ||
        !bootstrapper.galois_keys || !bootstrapper.bootstrap_poly)
    {
        throw std::invalid_argument("poseidon bootstrap context is incomplete");
    }

    print_stage_banner("bootstrap stage " + to_string(stage), output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    Ciphertext result = cnn_in.cipher();
    const auto time_start = chrono::high_resolution_clock::now();
    bootstrapper.evaluator->bootstrap(result, result, *bootstrapper.relin_keys,
                                      *bootstrapper.galois_keys, *bootstrapper.encoder,
                                      *bootstrapper.bootstrap_poly);

    output << "  bootstrap real projection: compute (cipher + conjugate(cipher)) / 2\n";
    const double target_scale = result.scale();
    Ciphertext conjugated;
    bootstrapper.evaluator->conjugate(result, *bootstrapper.galois_keys, conjugated);
    Ciphertext real_sum;
    bootstrapper.evaluator->add(result, conjugated, real_sum);
    Ciphertext real_projected;
    bootstrapper.evaluator->multiply_const(real_sum, 0.5,
                                           multiply_plain_scale(real_sum, encoder),
                                           real_projected, encoder);
    bootstrapper.evaluator->rescale_dynamic(real_projected, real_projected, target_scale);
    real_projected.scale() = target_scale;
    result = real_projected;

    const auto time_end = chrono::high_resolution_clock::now();

    cnn_out = TensorCipher(cnn_in.logn(), cnn_in.k(), cnn_in.h(), cnn_in.w(), cnn_in.c(),
                           cnn_in.t(), cnn_in.p(), result);

    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void cipher_add_seal_print(const TensorCipher &cnn1, const TensorCipher &cnn2,
                           TensorCipher &destination, EvaluatorCkksBase &evaluator,
                           ostream &output, Decryptor &decryptor, CKKSEncoder &encoder,
                           PoseidonContext &context)
{
    print_stage_banner("residual add", output);
    cnn_add_seal(cnn1, cnn2, destination, evaluator, encoder);
    log_after_stage(destination, decryptor, encoder, context, output);
}

void multiplexed_parallel_downsampling_seal_print(const TensorCipher &cnn_in,
                                                  TensorCipher &cnn_out,
                                                  EvaluatorCkksBase &evaluator,
                                                  Decryptor &decryptor, CKKSEncoder &encoder,
                                                  PoseidonContext &context,
                                                  GaloisKeys &gal_keys, ostream &output)
{
    print_stage_banner("downsample shortcut", output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_parallel_downsampling_seal(cnn_in, cnn_out, evaluator, gal_keys, encoder);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void averagepooling_seal_scale_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                     EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys, double B,
                                     ostream &output, Decryptor &decryptor,
                                     CKKSEncoder &encoder, PoseidonContext &context)
{
    print_stage_banner("average pool", output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    averagepooling_seal_scale(cnn_in, cnn_out, evaluator, gal_keys, B, encoder, decryptor,
                              output);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void fully_connected_seal_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                vector<double> matrix, vector<double> bias, int q, int r,
                                EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys,
                                ostream &output, Decryptor &decryptor, CKKSEncoder &encoder,
                                PoseidonContext &context)
{
    print_stage_banner("fully connected", output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    matrix_multiplication_seal(cnn_in, cnn_out, std::move(matrix), std::move(bias), q, r,
                               evaluator, gal_keys, encoder);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void multiplexed_parallel_convolution_seal(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw,
    const vector<double> &data, vector<double> running_var, vector<double> constant_weight,
    double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
    GaloisKeys &gal_keys, vector<Ciphertext> &cipher_pool, bool end)
{
    (void)encryptor;
    (void)cipher_pool;

    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();
    int ko = 0;
    int ho = 0;
    int wo = 0;

    if (st != 1 && st != 2)
    {
        throw std::invalid_argument("supported st is only 1 or 2");
    }
    if (static_cast<int>(data.size()) != fh * fw * ci * co)
    {
        throw std::invalid_argument("the size of data vector is not fh*fw*ci*co");
    }
    if (log2_long(ki) == -1)
    {
        throw std::invalid_argument("ki is not power of two");
    }
    if (static_cast<int>(running_var.size()) != co ||
        static_cast<int>(constant_weight.size()) != co)
    {
        throw std::invalid_argument("running_var or constant_weight has invalid size");
    }

    if (st == 1)
    {
        ho = hi;
        wo = wi;
        ko = ki;
    }
    else
    {
        if (hi % 2 != 0 || wi % 2 != 0)
        {
            throw std::invalid_argument("hi and wi should be even when st == 2");
        }
        ho = hi / 2;
        wo = wi / 2;
        ko = 2 * ki;
    }

    const long n = static_cast<long>(slot_count_from_logn(logn));
    const int to = (co + ko * ko - 1) / (ko * ko);
    const int po = pow2(floor_to_int(log(static_cast<double>(n) /
                                         static_cast<double>(ko * ko * ho * wo * to)) /
                                     log(2.0)));
    const int q = (co + pi - 1) / pi;

    if (n % pi != 0 || n % po != 0)
    {
        throw std::out_of_range("slot count is not divisible by tensor packing factor");
    }
    if (ki * ki * hi * wi * ti * pi > n)
    {
        throw std::out_of_range("input tensor packing exceeds slot capacity");
    }
    if (ko * ko * ho * wo * to * po > n)
    {
        throw std::out_of_range("output tensor packing exceeds slot capacity");
    }

    vector<vector<vector<vector<double>>>> weight(
        fh, vector<vector<vector<double>>>(fw, vector<vector<double>>(ci, vector<double>(co, 0.0))));
    vector<vector<vector<vector<double>>>> compact_weight_vec(
        fh, vector<vector<vector<double>>>(fw, vector<vector<double>>(q, vector<double>(n, 0.0))));
    vector<vector<double>> select_one_vec(co, vector<double>(n, 0.0));

    for (int i1 = 0; i1 < fh; ++i1)
    {
        for (int i2 = 0; i2 < fw; ++i2)
        {
            for (int j3 = 0; j3 < ci; ++j3)
            {
                for (int j4 = 0; j4 < co; ++j4)
                {
                    weight[i1][i2][j3][j4] =
                        data[fh * fw * ci * j4 + fh * fw * j3 + fw * i1 + i2];
                }
            }
        }
    }

    for (int i1 = 0; i1 < fh; ++i1)
    {
        for (int i2 = 0; i2 < fw; ++i2)
        {
            for (int i9 = 0; i9 < q; ++i9)
            {
                for (long j8 = 0; j8 < n; ++j8)
                {
                    const int j5 = ((j8 % (n / pi)) % (ki * ki * hi * wi)) / (ki * wi);
                    const int j6 = (j8 % (n / pi)) % (ki * wi);
                    const int i7 = (j8 % (n / pi)) / (ki * ki * hi * wi);
                    const int i8 = j8 / (n / pi);

                    if (j8 % (n / pi) >= ki * ki * hi * wi * ti || i8 + pi * i9 >= co ||
                        ki * ki * i7 + ki * (j5 % ki) + j6 % ki >= ci ||
                        (j6 / ki) - (fw - 1) / 2 + i2 < 0 ||
                        (j6 / ki) - (fw - 1) / 2 + i2 > wi - 1 ||
                        (j5 / ki) - (fh - 1) / 2 + i1 < 0 ||
                        (j5 / ki) - (fh - 1) / 2 + i1 > hi - 1)
                    {
                        compact_weight_vec[i1][i2][i9][j8] = 0.0;
                    }
                    else
                    {
                        compact_weight_vec[i1][i2][i9][j8] =
                            weight[i1][i2][ki * ki * i7 + ki * (j5 % ki) + j6 % ki][i8 + pi * i9];
                    }
                }
            }
        }
    }

    for (int j4 = 0; j4 < co; ++j4)
    {
        for (int v1 = 0; v1 < ko * ho; ++v1)
        {
            for (int v2 = 0; v2 < ko * wo; ++v2)
            {
                for (int u3 = 0; u3 < to; ++u3)
                {
                    const size_t idx = static_cast<size_t>(ko * ko * ho * wo * u3 + ko * wo * v1 + v2);
                    if (ko * ko * u3 + ko * (v1 % ko) + v2 % ko == j4)
                    {
                        select_one_vec[j4][idx] =
                            constant_weight[j4] / sqrt(running_var[j4] + epsilon);
                    }
                }
            }
        }
    }

    Ciphertext ctxt_in = cnn_in.cipher();
    vector<vector<Ciphertext>> ctxt_rot(fh, vector<Ciphertext>(fw, ctxt_in));
    if (fh % 2 == 0 || fw % 2 == 0)
    {
        throw std::invalid_argument("fh and fw should be odd");
    }

    for (int i1 = 0; i1 < fh; ++i1)
    {
        for (int i2 = 0; i2 < fw; ++i2)
        {
            ctxt_rot[i1][i2] = ctxt_in;
            memory_save_rotate(ctxt_rot[i1][i2], ctxt_rot[i1][i2],
                               ki * ki * wi * (i1 - (fh - 1) / 2) + ki * (i2 - (fw - 1) / 2),
                               evaluator, gal_keys);
        }
    }

    Ciphertext total_sum;
    bool has_total_sum = false;
    for (int i9 = 0; i9 < q; ++i9)
    {
        Ciphertext sum;
        bool has_sum = false;
        for (int i1 = 0; i1 < fh; ++i1)
        {
            for (int i2 = 0; i2 < fw; ++i2)
            {
                Ciphertext temp;
                multiply_by_vector(ctxt_rot[i1][i2], compact_weight_vec[i1][i2][i9], temp, encoder,
                                   evaluator);
                if (!has_sum)
                {
                    sum = temp;
                    has_sum = true;
                }
                else
                {
                    add_assign_dynamic(sum, temp, encoder, evaluator);
                }
            }
        }

        Ciphertext var = sum;
        const int d = log2_long(ki);
        const int c = log2_long(ti);

        for (int x = 0; x < d; ++x)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, pow2(x), evaluator, gal_keys);
            add_assign_dynamic(var, temp, encoder, evaluator);
        }
        for (int x = 0; x < d; ++x)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, pow2(x) * ki * wi, evaluator, gal_keys);
            add_assign_dynamic(var, temp, encoder, evaluator);
        }

        if (c == -1)
        {
            Ciphertext grouped;
            bool has_grouped = false;
            for (int x = 0; x < ti; ++x)
            {
                Ciphertext temp = var;
                memory_save_rotate(temp, temp, ki * ki * hi * wi * x, evaluator, gal_keys);
                if (!has_grouped)
                {
                    grouped = temp;
                    has_grouped = true;
                }
                else
                {
                    add_assign_dynamic(grouped, temp, encoder, evaluator);
                }
            }
            var = grouped;
        }
        else
        {
            for (int x = 0; x < c; ++x)
            {
                Ciphertext temp = var;
                memory_save_rotate(temp, temp, pow2(x) * ki * ki * hi * wi, evaluator, gal_keys);
                add_assign_dynamic(var, temp, encoder, evaluator);
            }
        }

        for (int i8 = 0; i8 < pi && pi * i9 + i8 < co; ++i8)
        {
            const int j4 = pi * i9 + i8;
            Ciphertext temp = var;
            memory_save_rotate(temp, temp,
                               (n / pi) * (j4 % pi) - j4 % ko - (j4 / (ko * ko)) * ko * ko * ho * wo -
                                   ((j4 % (ko * ko)) / ko) * ko * wo,
                               evaluator, gal_keys);
            multiply_by_vector_inplace(temp, select_one_vec[j4], encoder, evaluator);
            if (!has_total_sum)
            {
                total_sum = temp;
                has_total_sum = true;
            }
            else
            {
                add_assign_dynamic(total_sum, temp, encoder, evaluator);
            }
        }
    }

    Ciphertext var = total_sum;
    if (!end)
    {
        Ciphertext sum = var;
        for (int u6 = 1; u6 < po; ++u6)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, -u6 * (n / po), evaluator, gal_keys);
            add_assign_dynamic(sum, temp, encoder, evaluator);
        }
        var = sum;
    }

    cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, var);
}

void multiplexed_parallel_batch_norm_seal(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                          vector<double> bias, vector<double> running_mean,
                                          vector<double> running_var, vector<double> weight,
                                          double epsilon, CKKSEncoder &encoder,
                                          Encryptor &encryptor, EvaluatorCkksBase &evaluator,
                                          double B, bool end)
{
    (void)encryptor;
    (void)end;

    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();
    const int ko = ki;
    const int ho = hi;
    const int wo = wi;
    const int co = ci;
    const int to = ti;
    const int po = pi;

    if (static_cast<int>(bias.size()) != ci || static_cast<int>(running_mean.size()) != ci ||
        static_cast<int>(running_var.size()) != ci || static_cast<int>(weight.size()) != ci)
    {
        throw std::invalid_argument("batch norm vectors have invalid size");
    }

    const long n = static_cast<long>(slot_count_from_logn(logn));
    vector<double> g(static_cast<size_t>(n), 0.0);

    if (n % pi != 0)
    {
        throw std::out_of_range("slot count is not divisible by pi");
    }

    for (int v4 = 0; v4 < n; ++v4)
    {
        const int v1 = ((v4 % (n / pi)) % (ki * ki * hi * wi)) / (ki * wi);
        const int v2 = (v4 % (n / pi)) % (ki * wi);
        const int u3 = (v4 % (n / pi)) / (ki * ki * hi * wi);
        if (ki * ki * u3 + ki * (v1 % ki) + v2 % ki >= ci || v4 % (n / pi) >= ki * ki * hi * wi * ti)
        {
            g[v4] = 0.0;
        }
        else
        {
            const int idx = ki * ki * u3 + ki * (v1 % ki) + v2 % ki;
            g[v4] = (bias[idx] -
                     running_mean[idx] * weight[idx] / sqrt(running_var[idx] + epsilon)) /
                    B;
        }
    }

    Plaintext plain;
    encoder.encode(g, cnn_in.cipher().parms_id(), cnn_in.cipher().scale(), plain);
    Ciphertext temp;
    evaluator.add_plain(cnn_in.cipher(), plain, temp);

    cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, temp);
}

void ReLU_seal(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no, vector<int> deg,
               long alpha, vector<Tree> &tree, double scaled_val, long scalingfactor,
               Encryptor &encryptor, EvaluatorCkksBase &evaluator, Decryptor &decryptor,
               CKKSEncoder &encoder, PublicKey &public_key, SecretKey &secret_key,
               RelinKeys &relin_keys, double scale)
{
    (void)scalingfactor;
    (void)public_key;
    (void)secret_key;

    relu_impl(cnn_in, cnn_out, comp_no, deg, alpha, tree, scaled_val, encryptor, evaluator,
              decryptor, encoder, relin_keys, scale, nullptr, nullptr);
}

void cnn_add_seal(const TensorCipher &cnn1, const TensorCipher &cnn2, TensorCipher &destination,
                  EvaluatorCkksBase &evaluator, CKKSEncoder &encoder)
{
    if (cnn1.k() != cnn2.k() || cnn1.h() != cnn2.h() || cnn1.w() != cnn2.w() ||
        cnn1.c() != cnn2.c() || cnn1.t() != cnn2.t() || cnn1.p() != cnn2.p() ||
        cnn1.logn() != cnn2.logn())
    {
        throw std::invalid_argument("the parameters of cnn1 and cnn2 are not the same");
    }

    Ciphertext temp = cnn1.cipher();
    add_lazy_cipher(temp, cnn2.cipher(), evaluator, encoder);
    destination = TensorCipher(cnn1.logn(), cnn1.k(), cnn1.h(), cnn1.w(), cnn1.c(), cnn1.t(),
                               cnn1.p(), temp);
}

void multiplexed_parallel_downsampling_seal(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                            EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys,
                                            CKKSEncoder &encoder)
{
    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int logn = cnn_in.logn();

    const long n = static_cast<long>(slot_count_from_logn(logn));
    const int ko = 2 * ki;
    const int ho = hi / 2;
    const int wo = wi / 2;
    const int to = ti / 2;
    const int co = 2 * ci;
    const int po =
        pow2(floor_to_int(log(static_cast<double>(n) / static_cast<double>(ko * ko * ho * wo * to)) /
                          log(2.0)));

    if (ti % 8 != 0 || hi % 2 != 0 || wi % 2 != 0)
    {
        throw std::invalid_argument("input tensor shape is not valid for packed downsampling");
    }
    if (n % po != 0)
    {
        throw std::out_of_range("slot count is not divisible by po");
    }

    vector<vector<vector<double>>> select_one_vec(
        ki, vector<vector<double>>(ti, vector<double>(n, 0.0)));
    for (int w1 = 0; w1 < ki; ++w1)
    {
        for (int w2 = 0; w2 < ti; ++w2)
        {
            for (int v4 = 0; v4 < n; ++v4)
            {
                const int j5 = (v4 % (ki * ki * hi * wi)) / (ki * wi);
                const int j6 = v4 % (ki * wi);
                const int i7 = v4 / (ki * ki * hi * wi);
                if (v4 < ki * ki * hi * wi * ti && (j5 / ki) % 2 == 0 && (j6 / ki) % 2 == 0 &&
                    (j5 % ki) == w1 && i7 == w2)
                {
                    select_one_vec[w1][w2][v4] = 1.0;
                }
            }
        }
    }

    Ciphertext ct = cnn_in.cipher();
    Ciphertext sum;
    bool has_sum = false;
    for (int w1 = 0; w1 < ki; ++w1)
    {
        for (int w2 = 0; w2 < ti; ++w2)
        {
            Ciphertext temp = ct;
            multiply_by_vector_inplace(temp, select_one_vec[w1][w2], encoder, evaluator);

            const int w3 = ((ki * w2 + w1) % (2 * ko)) / 2;
            const int w4 = (ki * w2 + w1) % 2;
            const int w5 = (ki * w2 + w1) / (2 * ko);
            memory_save_rotate(temp, temp,
                               ki * ki * hi * wi * w2 + ki * wi * w1 - ko * ko * ho * wo * w5 -
                                   ko * wo * w3 - ki * w4 - ko * ko * ho * wo * (ti / 8),
                               evaluator, gal_keys);

            if (!has_sum)
            {
                sum = temp;
                has_sum = true;
            }
            else
            {
                add_assign_dynamic(sum, temp, encoder, evaluator);
            }
        }
    }
    ct = sum;

    sum = ct;
    for (int u6 = 1; u6 < po; ++u6)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, -(n / po) * u6, evaluator, gal_keys);
        add_assign_dynamic(sum, temp, encoder, evaluator);
    }

    cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, sum);
}

void averagepooling_seal_scale(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                               EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys, double B,
                               CKKSEncoder &encoder, Decryptor &decryptor, ostream &output)
{
    (void)decryptor;
    (void)output;

    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int logn = cnn_in.logn();

    if (log2_long(hi) == -1 || log2_long(wi) == -1)
    {
        throw std::invalid_argument("hi and wi should be powers of two");
    }

    Ciphertext ct = cnn_in.cipher();
    for (int x = 0; x < log2_long(wi); ++x)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, pow2(x) * ki, evaluator, gal_keys);
        add_assign_dynamic(ct, temp, encoder, evaluator);
    }
    for (int x = 0; x < log2_long(hi); ++x)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, pow2(x) * ki * ki * wi, evaluator, gal_keys);
        add_assign_dynamic(ct, temp, encoder, evaluator);
    }

    const size_t n = slot_count_from_logn(logn);
    vector<double> select_one(n, 0.0);
    vector<double> zero(n, 0.0);
    Ciphertext sum;
    bool has_sum = false;

    for (int s = 0; s < ki; ++s)
    {
        for (int u = 0; u < ti; ++u)
        {
            const int p = ki * u + s;
            Ciphertext temp = ct;
            memory_save_rotate(temp, temp, -p * ki + ki * ki * hi * wi * u + ki * wi * s,
                               evaluator, gal_keys);
            select_one = zero;
            for (int i = 0; i < ki; ++i)
            {
                select_one[static_cast<size_t>((ki * u + s) * ki + i)] =
                    B / static_cast<double>(hi * wi);
            }

            multiply_by_vector_inplace(temp, select_one, encoder, evaluator);
            if (!has_sum)
            {
                sum = temp;
                has_sum = true;
            }
            else
            {
                add_assign_dynamic(sum, temp, encoder, evaluator);
            }
        }
    }

    cnn_out = TensorCipher(logn, 1, 1, 1, ci, ti, 1, sum);
}

void matrix_multiplication_seal(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                vector<double> matrix, vector<double> bias, int q, int r,
                                EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys,
                                CKKSEncoder &encoder)
{
    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();

    if (static_cast<int>(matrix.size()) != q * r)
    {
        throw std::invalid_argument("the size of matrix is not q*r");
    }
    if (static_cast<int>(bias.size()) != q)
    {
        throw std::invalid_argument("the size of bias is not q");
    }

    const size_t n = slot_count_from_logn(logn);
    vector<vector<double>> W(q + r - 1, vector<double>(n, 0.0));
    vector<double> b(n, 0.0);

    for (int z = 0; z < q; ++z)
    {
        b[z] = bias[z];
    }
    for (int i = 0; i < q; ++i)
    {
        for (int j = 0; j < r; ++j)
        {
            W[i - j + r - 1][i] = matrix[i * r + j];
        }
    }

    Ciphertext ct = cnn_in.cipher();
    Ciphertext sum;
    bool has_sum = false;
    for (int s = 0; s < q + r - 1; ++s)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, r - 1 - s, evaluator, gal_keys);
        multiply_by_vector_inplace(temp, W[s], encoder, evaluator);
        if (!has_sum)
        {
            sum = temp;
            has_sum = true;
        }
        else
        {
            add_assign_dynamic(sum, temp, encoder, evaluator);
        }
    }

    Plaintext bias_plain;
    encoder.encode(b, sum.parms_id(), sum.scale(), bias_plain);
    evaluator.add_plain(sum, bias_plain, sum);

    cnn_out = TensorCipher(logn, ki, hi, wi, ci, ti, pi, sum);
}

void memory_save_rotate(const Ciphertext &cipher_in, Ciphertext &cipher_out, int steps,
                        EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys)
{
    const long n = static_cast<long>(cipher_in.poly_modulus_degree() / 2);
    Ciphertext temp = cipher_in;
    steps = (steps % n + n) % n;
    int first_step = 0;

    if (34 <= steps && steps <= 55)
    {
        first_step = 33;
    }
    else if (57 <= steps && steps <= 61)
    {
        first_step = 33;
    }

    if (steps == 0)
    {
        cipher_out = temp;
        return;
    }

    if (first_step == 0)
    {
        evaluator.rotate(temp, cipher_out, steps, gal_keys);
    }
    else
    {
        evaluator.rotate(temp, temp, first_step, gal_keys);
        evaluator.rotate(temp, cipher_out, steps - first_step, gal_keys);
    }
}

void cipher_add_print(const TensorCipher &lhs, const TensorCipher &rhs, TensorCipher &output,
                      EvaluatorCkksBase &evaluator, const PoseidonContext &context, ostream &log)
{
    CKKSEncoder encoder(context);
    cnn_add_seal(lhs, rhs, output, evaluator, encoder);
    log_cipher_state(output, context, log);
}
