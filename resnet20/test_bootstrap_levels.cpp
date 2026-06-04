#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/parameters_literal.h"

#include <chrono>
#include <complex>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace poseidon;
using namespace std;

namespace
{

vector<uint32_t> logq_chain()
{
    return {
        46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46,
        51, 51, 51, 51, 51, 51, 51,
        51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51};
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

void print_plain_preview(const string &label, const vector<complex<double>> &values)
{
    cout << label;
    const size_t preview_count = min<size_t>(8, values.size());
    for (size_t i = 0; i < preview_count; ++i)
    {
        cout << ' ' << values[i].real();
    }
    cout << '\n';
}

void print_decrypted_preview(const string &label, const Ciphertext &cipher, Decryptor &decryptor,
                             CKKSEncoder &encoder)
{
    Plaintext plain;
    vector<complex<double>> decoded;
    decryptor.decrypt(cipher, plain);
    encoder.decode(plain, decoded);
    print_plain_preview(label, decoded);
}

} // namespace

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    ParametersLiteral ckks_param_literal{CKKS, 16, 16 - 1, 46, 5, 1, 0, {}, {}};
    ckks_param_literal.set_log_modulus(logq_chain(), {51});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator kgen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys rot_keys;
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(rot_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key, kgen.secret_key());
    Decryptor decryptor(context, kgen.secret_key());

    const size_t slot_count = encoder.slot_count();
    vector<complex<double>> message(slot_count, {0.0, 0.0});
    for (size_t i = 0; i < slot_count; ++i)
    {
        message[i] = {sin(static_cast<double>(i) / 32.0), 0.0};
    }
    print_plain_preview("plaintext source preview:", message);

    Plaintext plain;
    encoder.encode(message, ckks_param_literal.scale(), plain);

    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);
    print_cipher_state("fresh ciphertext", context, cipher);

    while (chain_index_or_throw(context, cipher) > 1)
    {
        ckks_eva->drop_modulus_to_next(cipher, cipher);
    }
    print_cipher_state("after dropping to level 0", context, cipher);

    Ciphertext bootstrap_input = cipher;
    print_cipher_state("bootstrap input", context, bootstrap_input);
    print_decrypted_preview("bootstrap input decrypt preview:", bootstrap_input, decryptor, encoder);

    EvalModPoly eval_mod_poly(context, CosDiscrete, static_cast<uint64_t>(1) << 51, 1, 16, 3,
                              16, 0, 30);

    const size_t level_before = chain_index_or_throw(context, bootstrap_input);
    const auto time_start = chrono::high_resolution_clock::now();
    ckks_eva->bootstrap(bootstrap_input, bootstrap_input, relin_keys, rot_keys, encoder,
                        eval_mod_poly);
    const auto time_end = chrono::high_resolution_clock::now();
    const size_t level_after = chain_index_or_throw(context, bootstrap_input);

    print_cipher_state("bootstrap output", context, bootstrap_input);
    cout << "bootstrap time (ms) : "
         << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    cout << "level delta : " << static_cast<long long>(level_after) - static_cast<long long>(level_before)
         << '\n';

    print_decrypted_preview("bootstrap output decrypt preview:", bootstrap_input, decryptor, encoder);

    return 0;
}
