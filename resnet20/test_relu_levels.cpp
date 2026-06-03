#include "poseidon/advance/polynomial_evaluation.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/parameters_literal.h"

#include <cmath>
#include <complex>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace poseidon;
using namespace std;
namespace fs = std::filesystem;

namespace
{

vector<uint32_t> logq_chain()
{
    return {
        46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46,
        46, 46, 46, 46,
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

void print_cipher_state(const string &label, const PoseidonContext &context, const Ciphertext &cipher)
{
    auto context_data = context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }

    cout << label << '\n';
    cout << "  remaining level : " << context_data->chain_index() << '\n';
    cout << "  coeff_modulus_size : " << cipher.coeff_modulus_size() << '\n';
    cout << "  scale : " << cipher.scale() << '\n';
}

PolynomialVector build_polynomial_vector_from_coeffs(const vector<double> &coeffs, int slot_size,
                                                     int max_degree)
{
    vector<int> slots(slot_size);
    for (int i = 0; i < slot_size; ++i)
    {
        slots[i] = i;
    }

    vector<complex<double>> complex_coeffs;
    complex_coeffs.reserve(coeffs.size());
    for (double coeff : coeffs)
    {
        complex_coeffs.emplace_back(coeff, 0.0);
    }

    Polynomial poly(complex_coeffs, 0, 0, max_degree, Monomial);
    poly.lead() = true;
    return PolynomialVector(vector<Polynomial>{poly}, vector<vector<int>>{slots});
}

vector<vector<double>> load_relu_component_coeffs(long alpha, const vector<int> &deg,
                                                  double scaled_val)
{
    const fs::path relu_file =
        fs::path(__FILE__).parent_path() / "relu_param" / ("d" + to_string(alpha) + ".txt");
    ifstream input(relu_file);
    if (!input.is_open())
    {
        throw runtime_error("failed to open relu parameter file: " + relu_file.string());
    }

    vector<vector<double>> coeffs;
    coeffs.reserve(deg.size());
    for (int degree : deg)
    {
        vector<double> component;
        component.reserve(static_cast<size_t>(degree + 1));
        for (int i = 0; i <= degree; ++i)
        {
            double coeff = 0.0;
            if (!(input >> coeff))
            {
                throw runtime_error("failed to read relu coefficients from: " +
                                    relu_file.string());
            }
            component.push_back(coeff);
        }
        coeffs.push_back(std::move(component));
    }

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

    return coeffs;
}

void print_component_coeffs(const vector<vector<double>> &coeffs)
{
    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        cout << "component " << (i + 1) << " coeff_count=" << coeffs[i].size() << '\n';
        cout << "coeffs:";
        for (double coeff : coeffs[i])
        {
            cout << ' ' << coeff;
        }
        cout << '\n';
    }
}

} // namespace

int main(int argc, char **argv)
{
    int target_level = 18;
    if (argc >= 2)
    {
        target_level = stoi(argv[1]);
    }

    ParametersLiteral ckks_param_literal{CKKS, 16, 16 - 1, 46, 5, 1, 0, {}, {}};
    ckks_param_literal.set_log_modulus(logq_chain(), {51});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator kgen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key, kgen.secret_key());
    Decryptor decryptor(context, kgen.secret_key());

    const size_t slot_count = encoder.slot_count();
    vector<complex<double>> message(slot_count, {0.0, 0.0});
    for (size_t i = 0; i < slot_count; ++i)
    {
        message[i] = {sin(static_cast<double>(i) / 32.0), 0.0};
    }

    Plaintext plain;
    encoder.encode(message, ckks_param_literal.scale(), plain);

    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);
    print_cipher_state("fresh ciphertext", context, cipher);

    while (static_cast<int>(chain_index_or_throw(context, cipher)) > target_level)
    {
        ckks_eva->drop_modulus_to_next(cipher, cipher);
    }
    print_cipher_state("input to approximate_sign01", context, cipher);

    const vector<int> deg{15, 15, 27};
    const long alpha = 13;
    const double scaled_val = 1.7;
    const auto coeffs = load_relu_component_coeffs(alpha, deg, scaled_val);
    print_component_coeffs(coeffs);

    Ciphertext result = cipher;
    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        const auto polys =
            build_polynomial_vector_from_coeffs(coeffs[i], static_cast<int>(slot_count), deg[i]);
        print_cipher_state("sign poly step " + to_string(i + 1) + " pre-eval state", context,
                           result);
        ckks_eva->evaluate_poly_vector(result, result, polys, result.scale(), relin_keys, encoder);
        print_cipher_state("sign poly step " + to_string(i + 1) + " post-eval state", context,
                           result);
    }

    ckks_eva->add_const(result, 0.5, result, encoder);
    print_cipher_state("sign poly add-const state", context, result);

    Plaintext plain_out;
    vector<complex<double>> decoded;
    decryptor.decrypt(result, plain_out);
    encoder.decode(plain_out, decoded);

    cout << "preview:";
    for (int i = 0; i < 8; ++i)
    {
        cout << ' ' << decoded[static_cast<size_t>(i)].real();
    }
    cout << '\n';

    return 0;
}
