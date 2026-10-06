#include "final_logits.h"
#include "execution_mode.h"
#include "encrypted_inference_timer.h"

#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace
{
void require(bool condition, const char *message)
{
    if (!condition) throw std::runtime_error(message);
}
}

int main()
{
    try
    {
        auto plan = default_poseidon_plan(4, true);
        plan.logN = 13;
        plan.log_slots = 12;
        auto runtime = make_poseidon_runtime(plan, false);
        // All class scores are negative, and padding is larger than every
        // class score. Neither a zero-initialized maximum nor padding may win.
        std::vector<double> values(runtime.slot_count, 20.0);
        for (int i = 0; i < kImageNetClassCount; ++i) values[i] = -3.0;
        values[286] = -0.5;
        poseidon::Plaintext plain;
        runtime.encoder.encode(values, runtime.scale, plain);
        poseidon::Ciphertext cipher;
        runtime.encryptor.encrypt(plain, cipher);
        runtime.evaluator->drop_modulus(cipher, cipher,
            runtime.context.crt_context()->parms_id_map().at(1));
        const auto original_id = cipher.parms_id();
        const auto original_scale = cipher.scale();
        for (bool inference_only : {false, true})
        {
            resnet18_execution::set_inference_only(inference_only);
            resnet18_timing::EncryptedInferenceTimerSession timer;
            const auto correct = validate_final_logits(cipher, runtime, 286);
            const auto incorrect = validate_final_logits(cipher, runtime, 287);
            require(correct.predicted_label == 286 && correct.correct,
                    "final prediction missing or incorrect");
            require(incorrect.predicted_label == 286 && !incorrect.correct,
                    "incorrect classification not reported");
            require(correct.logits.size() == kImageNetClassCount &&
                    std::abs(correct.logits[286].real() + 0.5) < 1e-5,
                    "final logits decoding mismatch");
            require(std::isfinite(correct.verification_time_ms) && correct.verification_time_ms >= 0,
                    "invalid verification timing");
            require(timer.elapsed_milliseconds() == 0 && timer.operation_count() == 0,
                    "final verification was included in encrypted operation time");
            require(resnet18_execution::inference_only() == inference_only,
                    "verification changed the execution mode");
            require(cipher.parms_id() == original_id && cipher.scale() == original_scale,
                    "final verification changed the ciphertext");
            bool rejected_label = false;
            try { (void)validate_final_logits(cipher, runtime, -1); }
            catch (const std::invalid_argument &) { rejected_label = true; }
            require(rejected_label, "invalid true label accepted");
            std::cout << "PASS inference_only=" << inference_only
                      << ", encrypted_pred=286, correct/incorrect checked, verification_ms="
                      << correct.verification_time_ms << ", encrypted_operation_count=0\n";
        }
        resnet18_execution::set_inference_only(false);
        std::vector<std::complex<double>> decoded(kImageNetClassCount, {-2.0, 0.0});
        decoded[5] = decoded[9] = {-1.0, 0.0};
        require(final_logit_argmax(decoded) == 5, "ties must select the first class");
        decoded[1] = {std::numeric_limits<double>::quiet_NaN(), 0.0};
        bool rejected_nan = false;
        try { (void)final_logit_argmax(decoded); }
        catch (const std::runtime_error &) { rejected_nan = true; }
        require(rejected_nan, "NaN logits accepted");
        decoded[1] = {0.0, std::numeric_limits<double>::infinity()};
        bool rejected_inf = false;
        try { (void)final_logit_argmax(decoded); }
        catch (const std::runtime_error &) { rejected_inf = true; }
        require(rejected_inf, "infinite logits accepted");
        bool rejected_short = false;
        try { (void)final_logit_argmax({}); }
        catch (const std::invalid_argument &) { rejected_short = true; }
        require(rejected_short, "missing class logits accepted");
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "Final logits regression failed: " << error.what() << '\n';
        return 1;
    }
}
