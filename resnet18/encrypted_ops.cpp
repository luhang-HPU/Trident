#include "encrypted_ops.h"

#include "encrypted_inference_timer.h"
#include "parallel_utils.h"
#include "progress_log.h"

#include "poseidon/plaintext.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace poseidon;
using namespace std;

namespace
{

size_t slot_count_from_logn(int logn)
{
    if (logn < 1)
    {
        throw invalid_argument("logn should be positive");
    }
    return static_cast<size_t>(1) << (logn - 1);
}

double multiply_plain_scale(parms_id_type parms_id, const CKKSEncoder &encoder)
{
    auto context_data = encoder.context().crt_context()->get_context_data(parms_id);
    if (!context_data)
    {
        throw runtime_error("failed to locate plaintext parms_id for plain scale selection");
    }
    return pow(2.0, static_cast<double>(context_data->coeff_modulus().back().bit_count()));
}

void rotate_with_direct_key(const Ciphertext &input, Ciphertext &output, int steps,
                            EvaluatorCkksBase &evaluator,
                            const GaloisKeys &galois_keys,
                            const CKKSEncoder &encoder)
{
    const long slot_count = static_cast<long>(input.poly_modulus_degree() / 2);
    steps = static_cast<int>((steps % slot_count + slot_count) % slot_count);

    if (steps == 0)
    {
        output = input;
        return;
    }

    const auto galois_elt =
        encoder.context().crt_context()->galois_tool()->get_elt_from_step(steps);
    if (!galois_keys.has_key(galois_elt))
    {
        throw logic_error("direct fully connected rotation key is missing");
    }

    evaluator.rotate(input, output, steps, galois_keys);
}

void validate_fully_connected_bsgs_shape(int rows, int columns, size_t slot_count)
{
    if (rows <= 0 || columns <= 0)
    {
        throw invalid_argument("fully connected BSGS shape is invalid");
    }
    if (slot_count == 0 || (slot_count & (slot_count - 1)) != 0)
    {
        throw invalid_argument("fully connected BSGS slot count must be a power of two");
    }
    if (static_cast<size_t>(rows) > slot_count ||
        static_cast<size_t>(columns) > slot_count ||
        static_cast<size_t>(rows + columns - 1) > slot_count)
    {
        throw invalid_argument("fully connected BSGS matrix does not fit in the slots");
    }
}

int normalize_fully_connected_step(int step, size_t slot_count)
{
    int normalized = step % static_cast<int>(slot_count);
    if (normalized < 0)
    {
        normalized += static_cast<int>(slot_count);
    }
    return normalized;
}

} // namespace

int fully_connected_bsgs_baby_step(int rows, int columns, size_t slot_count)
{
    validate_fully_connected_bsgs_shape(rows, columns, slot_count);

    int best_baby_step = 1;
    size_t best_rotation_count = numeric_limits<size_t>::max();
    for (size_t candidate = 1; candidate <= slot_count; candidate <<= 1)
    {
        set<int> baby_steps;
        set<int> giant_steps;
        for (int logical_step = -(rows - 1); logical_step <= columns - 1;
             ++logical_step)
        {
            const int normalized =
                normalize_fully_connected_step(logical_step, slot_count);
            const int baby = normalized & (static_cast<int>(candidate) - 1);
            const int giant = normalized - baby;
            if (baby != 0)
            {
                baby_steps.insert(baby);
            }
            if (giant != 0)
            {
                giant_steps.insert(giant);
            }
        }

        const size_t rotation_count = baby_steps.size() + giant_steps.size();
        if (rotation_count < best_rotation_count)
        {
            best_rotation_count = rotation_count;
            best_baby_step = static_cast<int>(candidate);
        }
        if (candidate == slot_count)
        {
            break;
        }
    }
    return best_baby_step;
}

vector<int> fully_connected_bsgs_rotation_steps(int rows, int columns,
                                                size_t slot_count)
{
    const int baby_step =
        fully_connected_bsgs_baby_step(rows, columns, slot_count);
    set<int> steps;
    for (int logical_step = -(rows - 1); logical_step <= columns - 1;
         ++logical_step)
    {
        const int normalized =
            normalize_fully_connected_step(logical_step, slot_count);
        const int baby = normalized & (baby_step - 1);
        const int giant = normalized - baby;
        if (baby != 0)
        {
            steps.insert(baby);
        }
        if (giant != 0)
        {
            steps.insert(giant);
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

void relu(const TensorCipher &input, TensorCipher &output, long component_count,
          const vector<int> &degrees, long alpha, const vector<Tree> &trees,
          double scaled_value, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
          CKKSEncoder &encoder, RelinKeys &relin_keys, double scale)
{
    if (component_count != static_cast<long>(degrees.size()) || degrees.size() != trees.size())
    {
        throw invalid_argument("relu polynomial component count does not match degree/tree config");
    }

    Ciphertext mask = approximate_sign(input.cipher(), degrees, alpha, trees, scaled_value,
                                       encryptor, encoder, evaluator, relin_keys);

    Ciphertext relu_cipher;
    evaluator.multiply_relin_dynamic(input.cipher(), mask, relu_cipher, relin_keys);
    evaluator.rescale(relu_cipher, relu_cipher);
    assign_scale_for_relu_reference(relu_cipher, scale);

    output = TensorCipher(input.logn(), input.k(), input.h(), input.w(), input.c(), input.t(),
                          input.p(), relu_cipher);
}

void bootstrap_tensor(const TensorCipher &input, TensorCipher &output,
                      PoseidonBootstrapContext &bootstrapper)
{
    if (!bootstrapper.context || !bootstrapper.evaluator || !bootstrapper.encoder ||
        !bootstrapper.relin_keys || !bootstrapper.galois_keys ||
        !bootstrapper.bootstrap_config)
    {
        throw invalid_argument("poseidon bootstrap context is incomplete");
    }

    Ciphertext result = input.cipher();
    bootstrapper.evaluator->bootstrap(
        result, result, *bootstrapper.relin_keys, *bootstrapper.galois_keys,
        *bootstrapper.encoder, *bootstrapper.bootstrap_config);
    normalize_bootstrap_output_scale(result, bootstrapper);

    output = TensorCipher(input.logn(), input.k(), input.h(), input.w(), input.c(), input.t(),
                          input.p(), result);
}

void normalize_bootstrap_output_scale(Ciphertext &cipher,
                                      PoseidonBootstrapContext &bootstrapper)
{
    if (!bootstrapper.context || !bootstrapper.evaluator || !bootstrapper.encoder)
    {
        throw invalid_argument("poseidon bootstrap scale context is incomplete");
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
        throw invalid_argument("bootstrap output has no level available for scale normalization");
    }

    const double current_scale = cipher.scale();
    const double q_last = static_cast<double>(context_data->coeff_modulus().back().value());
    const double plain_scale = target_scale * q_last / current_scale;
    if (!isfinite(plain_scale) || plain_scale < 1.0)
    {
        throw invalid_argument("invalid bootstrap output scale normalization factor");
    }

    Ciphertext normalized;
    bootstrapper.evaluator->multiply_const(cipher, 1.0, plain_scale, normalized,
                                           *bootstrapper.encoder);
    bootstrapper.evaluator->rescale(normalized, normalized);
    if (!poseidon::util::are_approximate<double>(normalized.scale(), target_scale))
    {
        throw runtime_error("failed to normalize bootstrap output scale");
    }
    normalized.scale() = target_scale;
    cipher = std::move(normalized);
}

FullyConnectedBsgsPlainPlan prepare_fully_connected_bsgs_plain_plan(
    const vector<double> &matrix, const vector<double> &bias,
    int rows, int columns, int logn, parms_id_type input_parms_id,
    double input_scale, parms_id_type output_parms_id, CKKSEncoder &encoder)
{
    if (static_cast<int>(matrix.size()) != rows * columns)
    {
        throw invalid_argument("the size of matrix is not rows*columns");
    }
    if (static_cast<int>(bias.size()) != rows)
    {
        throw invalid_argument("the size of bias is not rows");
    }

    const size_t slot_count = slot_count_from_logn(logn);
    validate_fully_connected_bsgs_shape(rows, columns, slot_count);
    if (!encoder.context().crt_context()->get_context_data(input_parms_id) ||
        !encoder.context().crt_context()->get_context_data(output_parms_id))
    {
        throw invalid_argument("fully connected BSGS plan parms_id is invalid");
    }

    FullyConnectedBsgsPlainPlan plan;
    plan.rows = rows;
    plan.columns = columns;
    plan.logn = logn;
    plan.baby_step =
        fully_connected_bsgs_baby_step(rows, columns, slot_count);
    plan.input_scale = input_scale;
    plan.input_parms_id = input_parms_id;
    plan.output_parms_id = output_parms_id;

    vector<double> packed_bias(slot_count, 0.0);
    for (int row = 0; row < rows; ++row)
    {
        packed_bias[static_cast<size_t>(row)] = bias[static_cast<size_t>(row)];
    }

    struct PlannedDiagonal
    {
        int logical_step;
        size_t group_index;
        size_t diagonal_index;
    };
    map<int, vector<pair<int, int>>> grouped_diagonals;
    for (int logical_step = -(rows - 1); logical_step <= columns - 1;
         ++logical_step)
    {
        const int normalized =
            normalize_fully_connected_step(logical_step, slot_count);
        const int baby = normalized & (plan.baby_step - 1);
        const int giant = normalized - baby;
        grouped_diagonals[giant].push_back({logical_step, baby});
    }

    vector<PlannedDiagonal> planned_diagonals;
    planned_diagonals.reserve(static_cast<size_t>(rows + columns - 1));
    plan.groups.reserve(grouped_diagonals.size());
    for (auto &group : grouped_diagonals)
    {
        FullyConnectedBsgsPlainGroup plain_group;
        plain_group.giant_step = group.first;
        plain_group.diagonals.resize(group.second.size());
        const size_t group_index = plan.groups.size();
        for (size_t diagonal_index = 0; diagonal_index < group.second.size();
             ++diagonal_index)
        {
            plain_group.diagonals.at(diagonal_index).baby_step =
                group.second.at(diagonal_index).second;
            planned_diagonals.push_back(
                {group.second.at(diagonal_index).first,
                 group_index, diagonal_index});
        }
        plan.groups.emplace_back(std::move(plain_group));
    }

    const double plain_scale = multiply_plain_scale(input_parms_id, encoder);
    resnet18_parallel_for(planned_diagonals.size(), [&](size_t plan_index) {
        const PlannedDiagonal &diagonal = planned_diagonals.at(plan_index);
        const int giant_step = plan.groups.at(diagonal.group_index).giant_step;
        vector<double> rotated_diagonal(slot_count, 0.0);
        for (int row = 0; row < rows; ++row)
        {
            const int column = row + diagonal.logical_step;
            if (column < 0 || column >= columns)
            {
                continue;
            }
            size_t rotated_row = static_cast<size_t>(row) +
                                 static_cast<size_t>(giant_step);
            if (rotated_row >= slot_count)
            {
                rotated_row -= slot_count;
            }
            rotated_diagonal.at(rotated_row) =
                matrix.at(static_cast<size_t>(row * columns + column));
        }
        encoder.encode(
            rotated_diagonal, input_parms_id, plain_scale,
            plan.groups.at(diagonal.group_index)
                .diagonals.at(diagonal.diagonal_index).plaintext);
    });

    encoder.encode(packed_bias, output_parms_id, input_scale, plan.bias);
    plan.encoded_bytes = plan.bias.capacity() * sizeof(uint64_t);
    for (const FullyConnectedBsgsPlainGroup &group : plan.groups)
    {
        for (const FullyConnectedBsgsPlainDiagonal &diagonal : group.diagonals)
        {
            plan.encoded_bytes += diagonal.plaintext.capacity() * sizeof(uint64_t);
        }
    }
    return plan;
}

void matrix_multiplication(const TensorCipher &input, TensorCipher &output,
                           const FullyConnectedBsgsPlainPlan &plan,
                           EvaluatorCkksBase &evaluator, GaloisKeys &galois_keys,
                           CKKSEncoder &encoder)
{
    resnet18_timing::ScopedEncryptedInferenceOperation inference_timer;
    const size_t slot_count = slot_count_from_logn(input.logn());
    if (input.logn() != plan.logn || input.cipher().parms_id() != plan.input_parms_id)
    {
        throw invalid_argument("fully connected BSGS plaintext plan does not match input");
    }
    const int rows = plan.rows;
    const int columns = plan.columns;
    const int baby_step = plan.baby_step;
    const size_t diagonal_count = static_cast<size_t>(rows + columns - 1);

    vector<Ciphertext> baby_rotations(static_cast<size_t>(baby_step));
    resnet18_parallel_for(static_cast<size_t>(baby_step), [&](size_t baby) {
        rotate_with_direct_key(input.cipher(), baby_rotations.at(baby),
                               static_cast<int>(baby), evaluator, galois_keys,
                               encoder);
    });

    const size_t thread_count =
        resnet18_parallel_thread_count(plan.groups.size());
    const size_t groups_per_thread =
        (plan.groups.size() + thread_count - 1) / thread_count;
    vector<Ciphertext> partial_sums(thread_count);
    vector<unsigned char> has_partial_sum(thread_count, 0);

    const vector<int> bsgs_rotation_steps =
        fully_connected_bsgs_rotation_steps(rows, columns, slot_count);
    resnet18_progress_log()
        << "fully connected BSGS: diagonals=" << diagonal_count
        << ", baby_step=" << baby_step
        << ", baby_rotations=" << baby_step - 1
        << ", giant_groups=" << plan.groups.size()
        << ", giant_rotations=" << plan.groups.size() - 1
        << ", total_direct_rotations=" << bsgs_rotation_steps.size()
        << ", rescale_count=1"
        << ", plaintext_plan_bytes=" << plan.encoded_bytes
        << ", threads=" << thread_count << endl;

    resnet18_parallel_for(thread_count, [&](size_t thread_index) {
        const size_t begin = thread_index * groups_per_thread;
        const size_t end = min(plan.groups.size(), begin + groups_per_thread);
        Ciphertext local_sum;
        bool has_local_sum = false;
        for (size_t group_index = begin; group_index < end; ++group_index)
        {
            const FullyConnectedBsgsPlainGroup &group =
                plan.groups.at(group_index);
            const int giant_step = group.giant_step;
            Ciphertext giant_sum;
            bool has_giant_sum = false;
            for (const FullyConnectedBsgsPlainDiagonal &diagonal : group.diagonals)
            {
                Ciphertext term;
                evaluator.multiply_plain(
                    baby_rotations.at(static_cast<size_t>(diagonal.baby_step)),
                    diagonal.plaintext, term);
                if (!has_giant_sum)
                {
                    giant_sum = std::move(term);
                    has_giant_sum = true;
                }
                else
                {
                    evaluator.add(giant_sum, term, giant_sum);
                }
            }
            if (!has_giant_sum)
            {
                continue;
            }

            Ciphertext giant_term;
            rotate_with_direct_key(giant_sum, giant_term, giant_step, evaluator,
                                   galois_keys, encoder);
            if (!has_local_sum)
            {
                local_sum = std::move(giant_term);
                has_local_sum = true;
            }
            else
            {
                evaluator.add(local_sum, giant_term, local_sum);
            }
        }
        if (has_local_sum)
        {
            partial_sums.at(thread_index) = std::move(local_sum);
            has_partial_sum.at(thread_index) = 1;
        }
    });

    Ciphertext sum;
    bool has_sum = false;
    for (size_t thread_index = 0; thread_index < thread_count; ++thread_index)
    {
        if (!has_partial_sum.at(thread_index))
        {
            continue;
        }
        if (!has_sum)
        {
            sum = std::move(partial_sums.at(thread_index));
            has_sum = true;
        }
        else
        {
            evaluator.add(sum, partial_sums.at(thread_index), sum);
        }
    }
    if (!has_sum)
    {
        throw runtime_error("fully connected layer produced no encrypted terms");
    }

    evaluator.rescale_dynamic(sum, sum, input.cipher().scale());
    if (sum.parms_id() != plan.output_parms_id)
    {
        throw runtime_error("fully connected BSGS output level does not match plan");
    }
    evaluator.add_plain(sum, plan.bias, sum);

    output = TensorCipher(input.logn(), input.k(), input.h(), input.w(), input.c(), input.t(),
                          input.p(), sum);
}
