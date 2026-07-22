#include "encrypted_ops.h"

#include <cmath>
#include <stdexcept>
#include <vector>

using namespace std;
using namespace poseidon;


void relu(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no,
          const vector<int> &deg, long alpha, const vector<Tree> &tree, double scaled_val,
          Encryptor &encryptor, EvaluatorCkksBase &evaluator, CKKSEncoder &encoder,
          RelinKeys &relin_keys, double scale)
{
    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();

    if (comp_no != static_cast<long>(deg.size()) || deg.size() != tree.size())
    {
        throw invalid_argument("relu polynomial component count does not match degree/tree config");
    }
    if (!std::isfinite(cnn_in.cipher().scale()) ||
        std::abs(cnn_in.cipher().scale() / scale - 1.0) > 1.0e-3)
    {
        throw invalid_argument("relu input scale does not match the configured CKKS scale");
    }

    Ciphertext mask = approximate_sign(cnn_in.cipher(), deg, alpha, tree, scaled_val, encryptor,
                                       encoder, evaluator, relin_keys);

    Ciphertext relu_cipher;
    evaluator.multiply_relin_dynamic(cnn_in.cipher(), mask, relu_cipher, relin_keys);

    evaluator.rescale(relu_cipher, relu_cipher);
    assign_scale_for_relu_reference(relu_cipher, scale);

    cnn_out = TensorCipher(logn, ki, hi, wi, ci, ti, pi, relu_cipher);
}

void bootstrap_tensor(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                      PoseidonBootstrapContext &bootstrapper)
{
    if (!bootstrapper.context || !bootstrapper.evaluator || !bootstrapper.encoder ||
        !bootstrapper.relin_keys || !bootstrapper.galois_keys ||
        !bootstrapper.bootstrap_config)
    {
        throw std::invalid_argument("poseidon bootstrap context is incomplete");
    }

    Ciphertext result = cnn_in.cipher();
    bootstrapper.evaluator->bootstrap(result, result, *bootstrapper.relin_keys,
                                      *bootstrapper.galois_keys, *bootstrapper.encoder,
                                      *bootstrapper.bootstrap_config);
    normalize_bootstrap_output_scale(result, bootstrapper);

    cnn_out = TensorCipher(cnn_in.logn(), cnn_in.k(), cnn_in.h(), cnn_in.w(), cnn_in.c(),
                           cnn_in.t(), cnn_in.p(), result);
}

void normalize_bootstrap_output_scale(Ciphertext &cipher,
                                      PoseidonBootstrapContext &bootstrapper)
{
    if (!bootstrapper.context || !bootstrapper.evaluator || !bootstrapper.encoder)
    {
        throw std::invalid_argument("poseidon bootstrap scale context is incomplete");
    }

    const double target_scale = bootstrapper.context->parameters_literal()->scale();
    if (poseidon::util::are_approximate<double>(cipher.scale(), target_scale))
    {
        return;
    }

    auto context_data =
        bootstrapper.context->crt_context()->get_context_data(cipher.parms_id());
    if (!context_data || context_data->coeff_modulus().size() <= 1)
    {
        throw std::invalid_argument(
            "bootstrap output has no level available for scale normalization");
    }

    const double current_scale = cipher.scale();
    const double q_last =
        static_cast<double>(context_data->coeff_modulus().back().value());
    const double plain_scale = target_scale * q_last / current_scale;
    if (!std::isfinite(plain_scale) || plain_scale < 1.0)
    {
        throw std::invalid_argument("invalid bootstrap output scale normalization factor");
    }

    Ciphertext normalized;
    bootstrapper.evaluator->multiply_const(cipher, 1.0, plain_scale, normalized,
                                           *bootstrapper.encoder);
    bootstrapper.evaluator->rescale(normalized, normalized);
    if (!poseidon::util::are_approximate<double>(normalized.scale(), target_scale))
    {
        throw std::runtime_error("failed to normalize bootstrap output scale");
    }
    normalized.scale() = target_scale;
    cipher = std::move(normalized);
}
