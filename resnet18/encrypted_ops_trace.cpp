#include "encrypted_ops.h"

#include "poseidon/plaintext.h"

#include <algorithm>
#include <chrono>
#include <complex>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace poseidon;
using namespace std;

namespace
{

constexpr int kPreviewSlots = 64;

size_t chain_index_or_throw(const PoseidonContext &context, const Ciphertext &cipher)
{
    auto context_data = context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw std::runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }
    return context_data->chain_index();
}

void decode_preview(const Ciphertext &cipher, Decryptor &decryptor, CKKSEncoder &encoder,
                    ostream &output)
{
    Plaintext plain;
    decryptor.decrypt(cipher, plain);

    vector<complex<double>> values;
    encoder.decode(plain, values);

    output << "  cipher decrypt real preview:";
    const size_t preview = min(values.size(), static_cast<size_t>(kPreviewSlots));
    for (size_t i = 0; i < preview; ++i)
    {
        output << ' ' << values[i].real();
    }
    output << '\n';

    output << "  cipher decrypt imag preview:";
    for (size_t i = 0; i < preview; ++i)
    {
        output << ' ' << values[i].imag();
    }
    output << '\n';
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

void log_after_stage(const TensorCipher &tensor, Decryptor &decryptor, CKKSEncoder &encoder,
                     PoseidonContext &context, ostream &output)
{
    output << "  output: " << tensor_summary(tensor, context) << '\n';
    decode_preview(tensor.cipher(), decryptor, encoder, output);
    output << endl;
}

} // namespace

void log_cipher_state(const TensorCipher &tensor, const PoseidonContext &context, ostream &output)
{
    output << tensor_summary(tensor, context) << '\n';
}

void multiplexed_convolution_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw,
    const vector<double> &data, vector<double> running_var, vector<double> constant_weight,
    double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
    GaloisKeys &gal_keys, vector<Ciphertext> &cipher_pool, ostream &output, Decryptor &decryptor,
    PoseidonContext &context, size_t stage, bool end)
{
    print_stage_banner("conv stage " + to_string(stage), output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_convolution(cnn_in, cnn_out, co, st, fh, fw, data,
                                     std::move(running_var), std::move(constant_weight),
                                     epsilon, encoder, encryptor, evaluator, gal_keys,
                                     cipher_pool, end);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void multiplexed_batch_norm_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> bias,
    vector<double> running_mean, vector<double> running_var, vector<double> weight,
    double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
    double B, ostream &output, Decryptor &decryptor, PoseidonContext &context, size_t stage,
    bool end)
{
    print_stage_banner("batchnorm stage " + to_string(stage), output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_batch_norm(cnn_in, cnn_out, std::move(bias), std::move(running_mean),
                                    std::move(running_var), std::move(weight), epsilon,
                                    encoder, encryptor, evaluator, B, end);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void approx_relu_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no,
                       vector<int> deg, long alpha, vector<Tree> &tree, double scaled_val,
                       Encryptor &encryptor, EvaluatorCkksBase &evaluator, Decryptor &decryptor,
                       CKKSEncoder &encoder, RelinKeys &relin_keys, double target_scale,
                       ostream &output, PoseidonContext &context, size_t stage)
{
    print_stage_banner("relu stage " + to_string(stage), output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    relu(cnn_in, cnn_out, comp_no, deg, alpha, tree, scaled_val, encryptor, evaluator,
         encoder, relin_keys, target_scale);
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
    print_stage_banner("bootstrap stage " + to_string(stage), output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    bootstrap_tensor(cnn_in, cnn_out, bootstrapper, encoder);
    const auto time_end = chrono::high_resolution_clock::now();

    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void cipher_add_stage_print(const TensorCipher &cnn1, const TensorCipher &cnn2,
                           TensorCipher &destination, EvaluatorCkksBase &evaluator,
                           ostream &output, Decryptor &decryptor, CKKSEncoder &encoder,
                           PoseidonContext &context)
{
    print_stage_banner("residual add", output);
    cnn_add(cnn1, cnn2, destination, evaluator, encoder);
    log_after_stage(destination, decryptor, encoder, context, output);
}

void multiplexed_downsampling_print(const TensorCipher &cnn_in,
                                             TensorCipher &cnn_out,
                                             EvaluatorCkksBase &evaluator,
                                             Decryptor &decryptor, CKKSEncoder &encoder,
                                             PoseidonContext &context,
                                             GaloisKeys &gal_keys, ostream &output)
{
    print_stage_banner("downsample shortcut", output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_downsampling(cnn_in, cnn_out, evaluator, gal_keys, encoder);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void averagepooling_scale_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys, double B,
                                ostream &output, Decryptor &decryptor,
                                CKKSEncoder &encoder, PoseidonContext &context)
{
    print_stage_banner("average pool", output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    averagepooling_scale(cnn_in, cnn_out, evaluator, gal_keys, B, encoder, decryptor,
                         output);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void fully_connected_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                           vector<double> matrix, vector<double> bias, int q, int r,
                           EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys,
                           ostream &output, Decryptor &decryptor, CKKSEncoder &encoder,
                           PoseidonContext &context)
{
    print_stage_banner("fully connected", output);
    log_labeled_tensor_state("input", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    matrix_multiplication(cnn_in, cnn_out, std::move(matrix), std::move(bias), q, r,
                          evaluator, gal_keys, encoder);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "  time_ms: "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void cipher_add_print(const TensorCipher &lhs, const TensorCipher &rhs, TensorCipher &output,
                      EvaluatorCkksBase &evaluator, const PoseidonContext &context, ostream &log)
{
    CKKSEncoder encoder(context);
    cnn_add(lhs, rhs, output, evaluator, encoder);
    log_cipher_state(output, context, log);
}
