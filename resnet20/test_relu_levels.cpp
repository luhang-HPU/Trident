#include "cnn.h"

#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/parameters_literal.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

using namespace poseidon;
using namespace std;
namespace fs = std::filesystem;

namespace
{

constexpr size_t kPreviewCount = 32;
constexpr long kAlpha = 13;
constexpr double kScaledVal = 1.7;

vector<uint32_t> logq_chain()
{
    return {
        46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 
        46, 46, 46, 46, 46, 46, 46, 46, 46
    };
}

size_t chain_index_or_throw(const PoseidonContext &context, const Ciphertext &cipher)
{
    auto context_data = context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }
    return context_data->chain_index();
}

void print_plain_preview(const string &label, const vector<double> &values)
{
    cout << label;
    const size_t preview_count = min(kPreviewCount, values.size());
    for (size_t i = 0; i < preview_count; ++i)
    {
        cout << ' ' << values[i];
    }
    cout << '\n';
}

void assign_scale(Ciphertext &cipher, double scale)
{
    cipher.scale() = scale;
}

vector<double> decode_real_values(const Ciphertext &cipher, Decryptor &decryptor,
                                  CKKSEncoder &encoder, size_t count)
{
    Plaintext plain;
    decryptor.decrypt(cipher, plain);

    vector<complex<double>> decoded;
    encoder.decode(plain, decoded);

    vector<double> values;
    values.reserve(min(count, decoded.size()));
    for (size_t i = 0; i < min(count, decoded.size()); ++i)
    {
        values.push_back(decoded[i].real());
    }
    return values;
}

void print_cipher_preview(const string &label, const Ciphertext &cipher, Decryptor &decryptor,
                          CKKSEncoder &encoder)
{
    cout << label;
    for (double value : decode_real_values(cipher, decryptor, encoder, kPreviewCount))
    {
        cout << ' ' << value;
    }
    cout << '\n';
}

void print_cipher_state(const string &label, const Ciphertext &cipher,
                        const PoseidonContext &context, Decryptor &decryptor,
                        CKKSEncoder &encoder)
{
    cout << label << '\n';
    cout << "  remaining level : " << chain_index_or_throw(context, cipher) << '\n';
    cout << "  coeff_modulus_size : " << cipher.coeff_modulus_size() << '\n';
    cout << "  scale : " << cipher.scale() << '\n';
    print_cipher_preview("  decrypt preview:", cipher, decryptor, encoder);
}

Ciphertext encrypt_constant_cipher(double value, size_t slot_count, double scale,
                                   Encryptor &encryptor, CKKSEncoder &encoder)
{
    vector<complex<double>> slots(slot_count, {value, 0.0});
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

void eval_t_reference(EvaluatorCkksBase &evaluator, const RelinKeys &relin_keys,
                      CKKSEncoder &encoder, Ciphertext &output, const Ciphertext &tm,
                      const Ciphertext &tn, const Ciphertext &tm_minus_n)
{
    const double target_scale = tm.scale();
    const double lazy_scale = target_scale * target_scale;

    Ciphertext product;
    evaluator.multiply_relin_dynamic(tm, tn, product, relin_keys);
    assign_scale(product, lazy_scale);

    Ciphertext doubled;
    evaluator.add(product, product, doubled);
    assign_scale(doubled, lazy_scale);
    evaluator.rescale(doubled, doubled);
    assign_scale(doubled, target_scale);

    if (doubled.parms_id() == tm_minus_n.parms_id())
    {
        Ciphertext aligned_tm_minus_n = tm_minus_n;
        assign_scale(aligned_tm_minus_n, doubled.scale());
        evaluator.sub(doubled, aligned_tm_minus_n, output);
    }
    else
    {
        evaluator.sub_dynamic(doubled, tm_minus_n, output, encoder);
    }
    assign_scale(output, target_scale);
}

long num_one(long value)
{
    long count = 0;
    while (value > 0)
    {
        if (value & 1L)
        {
            ++count;
        }
        value >>= 1;
    }
    return count;
}

int pow2(int exponent)
{
    return 1 << exponent;
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

vector<vector<double>> load_relu_component_coeffs(const vector<int> &deg, const vector<Tree> &trees)
{
    const fs::path relu_file =
        fs::path(__FILE__).parent_path() / "relu_param" / ("d" + to_string(kAlpha) + ".txt");
    ifstream input(relu_file);
    if (!input.is_open())
    {
        throw runtime_error("failed to open relu parameter file: " + relu_file.string());
    }

    vector<vector<double>> coeffs;
    coeffs.reserve(deg.size());

    for (size_t i = 0; i < deg.size(); ++i)
    {
        const long count = coeff_number(deg[i], trees[i]);
        vector<double> component;
        component.reserve(static_cast<size_t>(count));
        for (long j = 0; j < count; ++j)
        {
            double coeff = 0.0;
            if (!(input >> coeff))
            {
                throw runtime_error("failed to read relu coefficients from: " + relu_file.string());
            }
            component.emplace_back(coeff);
        }
        coeffs.emplace_back(std::move(component));
    }

    for (double &coeff : coeffs[0])
    {
        coeff /= 2.0;
    }
    for (double &coeff : coeffs[1])
    {
        coeff /= kScaledVal;
    }
    for (double &coeff : coeffs[2])
    {
        coeff *= 0.5;
    }
    return coeffs;
}

void multiply_const_reduced_error(const Ciphertext &cipher, double coeff, double target_scale,
                                  Ciphertext &output, EvaluatorCkksBase &evaluator,
                                  CKKSEncoder &encoder)
{
    evaluator.multiply_const(cipher, coeff, target_scale / cipher.scale(), output, encoder);
}

void add_lazy_cipher(Ciphertext &accumulator, const Ciphertext &term, EvaluatorCkksBase &evaluator,
                     CKKSEncoder &encoder)
{
    if (accumulator.parms_id() == term.parms_id())
    {
        Ciphertext aligned_term = term;
        assign_scale(aligned_term, accumulator.scale());
        evaluator.add(accumulator, aligned_term, accumulator);
        return;
    }
    evaluator.add_dynamic(accumulator, term, accumulator, encoder);
}

Ciphertext eval_polynomial_integrate_reference(const Ciphertext &cipher, long degree,
                                               const vector<double> &decomp_coeff, const Tree &tree,
                                               Encryptor &encryptor, EvaluatorCkksBase &evaluator,
                                               CKKSEncoder &encoder, const RelinKeys &relin_keys)
{
    if (tree.type != EvalType::OddBaby)
    {
        throw invalid_argument("test only supports oddbaby tree");
    }

    const double scale = cipher.scale();
    const double lazy_scale = scale * scale;
    const long total_depth =
        static_cast<long>(ceil(log(static_cast<double>(degree + 1)) / log(2.0)));
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
                    add_lazy_cipher(*pt[node], term, evaluator, encoder);
                    coeff_index += 2;
                }
                evaluator.rescale(*pt[node], *pt[node]);
                assign_scale(*pt[node], scale);
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
                assign_scale(*pt[node], lazy_scale);
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
                    assign_scale(term, lazy_scale);
                    add_lazy_cipher(*pt[node], term, evaluator, encoder);
                    walk *= 2;
                }
                evaluator.rescale(*pt[node], *pt[node]);
                assign_scale(*pt[node], scale);
                add_lazy_cipher(*pt[node], *pt[walk], evaluator, encoder);
            }
        }

        if (stage <= tree.m - 1)
        {
            const int cheb_degree = pow2(stage);
            t[cheb_degree] = make_unique<Ciphertext>();
            eval_t_reference(evaluator, relin_keys, encoder, *t[cheb_degree],
                             *t[pow2(stage - 1)], *t[pow2(stage - 1)], *t[0]);
        }
        if (stage <= tree.l)
        {
            for (int cheb_degree = pow2(stage - 1) + 1; cheb_degree <= pow2(stage) - 1;
                 cheb_degree += 2)
            {
                t[cheb_degree] = make_unique<Ciphertext>();
                eval_t_reference(evaluator, relin_keys, encoder, *t[cheb_degree],
                                 *t[pow2(stage - 1)], *t[cheb_degree - pow2(stage - 1)],
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

Ciphertext approximate_sign01_reference(const Ciphertext &input, const vector<int> &deg,
                                        const vector<Tree> &trees, Encryptor &encryptor,
                                        EvaluatorCkksBase &evaluator, CKKSEncoder &encoder,
                                        Decryptor &decryptor, const RelinKeys &relin_keys,
                                        const PoseidonContext &context)
{
    Ciphertext result = input;
    const vector<vector<double>> coeffs = load_relu_component_coeffs(deg, trees);
    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        cout << "component " << (i + 1) << " coeff_count=" << coeffs[i].size() << '\n';
        print_cipher_state("sign poly step " + to_string(i + 1) + " pre-eval state", result,
                           context, decryptor, encoder);
        result = eval_polynomial_integrate_reference(result, deg[i], coeffs[i], trees[i], encryptor,
                                                     evaluator, encoder, relin_keys);
        print_cipher_state("sign poly step " + to_string(i + 1) + " post-eval state", result,
                           context, decryptor, encoder);
    }

    print_cipher_state("sign poly result state", result, context, decryptor, encoder);
    return result;
}

void run_reference_relu_case(const string &label, const vector<double> &message, int target_level,
                             Encryptor &encryptor, Decryptor &decryptor,
                             EvaluatorCkksBase &evaluator, CKKSEncoder &encoder,
                             const RelinKeys &relin_keys, const PoseidonContext &context)
{
    cout << "\n=== " << label << " ===\n";
    print_plain_preview("plaintext source preview:", message);

    TensorCipher input(16, 1, 1, 1, 1, 1, 1, message, encryptor, encoder, 46);
    while (static_cast<int>(chain_index_or_throw(context, input.cipher())) > target_level)
    {
        Ciphertext dropped;
        evaluator.drop_modulus_to_next(input.cipher(), dropped);
        input.set_ciphertext(dropped);
    }

    print_cipher_state("input ciphertext", input.cipher(), context, decryptor, encoder);

    vector<int> deg{15, 15, 27};
    vector<Tree> trees;
    trees.reserve(deg.size());
    for (int degree : deg)
    {
        Tree tree(EvalType::OddBaby);
        upgrade_oddbaby(degree, tree);
        trees.emplace_back(std::move(tree));
    }

    Ciphertext sign_result = approximate_sign01_reference(input.cipher(), deg, trees, encryptor,
                                                          evaluator, encoder, decryptor,
                                                          relin_keys, context);

    Ciphertext mask = sign_result;
    evaluator.add_const(mask, 0.5, mask, encoder);
    print_cipher_state("mask add-const state", mask, context, decryptor, encoder);

    Ciphertext relu_product;
    evaluator.multiply_relin_dynamic(input.cipher(), mask, relu_product, relin_keys);
    print_cipher_state("relu post-multiply state", relu_product, context, decryptor, encoder);

    evaluator.rescale(relu_product, relu_product);
    assign_scale(relu_product, input.cipher().scale());
    print_cipher_state("relu post-rescale state", relu_product, context, decryptor, encoder);

    vector<double> relu_expected = message;
    for (double &value : relu_expected)
    {
        value = max(0.0, value);
    }
    print_plain_preview("plaintext exact relu preview:", relu_expected);
}

} // namespace

int main(int argc, char **argv)
{
    cout << std::unitbuf;

    int target_level = 18;
    if (argc >= 2)
    {
        target_level = stoi(argv[1]);
    }

    ParametersLiteral ckks_param_literal{CKKS, 16, 15, 46, 5, 1, 0, {}, {}};
    ckks_param_literal.set_log_modulus(logq_chain(), {51});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key, secret_key);
    Decryptor decryptor(context, secret_key);

    vector<double> sine_message(encoder.slot_count(), 0.0);
    for (size_t i = 0; i < sine_message.size(); ++i)
    {
        sine_message[i] = sin(static_cast<double>(i) / 32.0);
    }
    run_reference_relu_case("reference HE relu on sine input", sine_message, target_level,
                            encryptor, decryptor, *evaluator, encoder, relin_keys, context);

    vector<double> probe_message(encoder.slot_count(), 0.0);
    for (size_t i = 0; i < kPreviewCount; ++i)
    {
        probe_message[i] =
            -0.30 + 0.60 * static_cast<double>(i) / static_cast<double>(kPreviewCount - 1);
    }
    run_reference_relu_case("reference HE relu on symmetric probe", probe_message, target_level,
                            encryptor, decryptor, *evaluator, encoder, relin_keys, context);

    return 0;
}
