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
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace poseidon;
using namespace std;
namespace
{

constexpr size_t kPreviewCount = 32;
constexpr long kAlpha = 13;
constexpr double kScaledVal = 1.7;

vector<uint32_t> logq_chain()
{
    return vector<uint32_t>(25, 40);
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

void run_reference_relu_case(const string &label, const vector<double> &message, int target_level,
                             Encryptor &encryptor, Decryptor &decryptor,
                             EvaluatorCkksBase &evaluator, CKKSEncoder &encoder,
                             RelinKeys &relin_keys, const PoseidonContext &context)
{
    cout << "\n=== " << label << " ===\n";
    print_plain_preview("plaintext source preview:", message);

    TensorCipher input(16, 1, 1, 1, 1, 1, 1, message, encryptor, encoder, 40);
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

    Ciphertext sign_result = approximate_sign(input.cipher(), deg, kAlpha, trees, kScaledVal,
                                              encryptor, encoder, evaluator, relin_keys);
    print_cipher_state("sign poly result state", sign_result, context, decryptor, encoder);

    Ciphertext mask = sign_result;
    print_cipher_state("ReLU mask state", mask, context, decryptor, encoder);

    Ciphertext relu_product;
    evaluator.multiply_relin_dynamic(input.cipher(), mask, relu_product, relin_keys);
    print_cipher_state("relu post-multiply state", relu_product, context, decryptor, encoder);

    evaluator.rescale(relu_product, relu_product);
    relu_product.scale() = input.cipher().scale();
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

    ParametersLiteral ckks_param_literal{CKKS, 16, 15, 40, 5, 1, 0, {}, {}};
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
