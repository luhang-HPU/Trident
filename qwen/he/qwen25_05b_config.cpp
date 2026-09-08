#include "he/qwen25_05b_config.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <stdexcept>
#include <utility>

namespace qwen::he
{
namespace
{

struct PositionRanges
{
    double other_minimum;
    double other_maximum;
    double position_zero_minimum;
    double position_zero_maximum;
};

struct AttentionRange
{
    double difference_bound;
    double shifted_minimum_4;
    double shifted_minimum_8;
    double shifted_minimum_long;
};

struct FeatureInterval
{
    float minimum;
    float maximum;
};

struct FeatureRange
{
    float other_minimum;
    float other_maximum;
    std::array<FeatureInterval, 8> positions;
};

#include "qwen25_05b_silu_feature_ranges.inc"

constexpr std::array<PositionRanges, 24> input_rms_ranges{{
    {0.000116656627, 0.00044775938, 0.000108266295, 0.000354126399},
    {0.0129776126, 0.0990141224, 0.043555831, 0.11297761},
    {0.039904371, 0.165999059, 0.0737248517, 0.17896103},
    {0.0417661715, 0.231050574, 363.416521, 1136.12805},
    {0.0558701107, 0.315815554, 1939.41327, 4621.37186},
    {0.0733023262, 0.429191925, 1943.96244, 4630.91232},
    {0.0997463378, 0.443106629, 2012.55409, 4775.23735},
    {0.106653988, 0.458632237, 2014.21228, 4778.80286},
    {0.127141131, 0.456358539, 2015.40178, 4781.30846},
    {0.123456108, 0.518771566, 2016.87951, 4784.35058},
    {0.14153098, 0.635946723, 2018.37247, 4787.4494},
    {0.154484678, 0.573735141, 2021.72645, 4794.31561},
    {0.1553561, 0.519447175, 2024.23616, 4799.48601},
    {0.183955239, 0.620882764, 2027.01245, 4805.19372},
    {0.175636988, 0.736433448, 2028.33782, 4807.93226},
    {0.202956626, 0.810051628, 2031.33379, 4814.1375},
    {0.209438066, 0.930478375, 2036.00188, 4823.86369},
    {0.296450344, 1.50091335, 2036.23703, 4824.36137},
    {0.456241738, 2.09648721, 2036.55792, 4824.98707},
    {0.666922973, 2.72868423, 2034.27909, 4820.17042},
    {0.960679261, 3.91314383, 2029.16765, 4807.31846},
    {1.72101516, 5.9875854, 2019.49592, 4787.07381},
    {2.82965104, 10.3482829, 2.18326467, 6.86403993},
    {3.51958136, 12.9158545, 2.10112806, 7.77904223},
}};

constexpr std::array<PositionRanges, 24> post_rms_ranges{{
    {0.000177548548, 0.000634120642, 0.000191482738, 0.000437590973},
    {0.0205720407, 0.118385811, 0.0529420562, 0.12867649},
    {0.0415282794, 0.170021365, 0.0782090429, 0.203183295},
    {0.0461569427, 0.230671642, 363.440483, 1136.19436},
    {0.0556969255, 0.271141412, 1939.00789, 4620.50934},
    {0.0695393382, 0.360816681, 1942.198, 4627.24292},
    {0.0976746091, 0.442364164, 2011.54144, 4773.13039},
    {0.111001455, 0.468604541, 2013.08727, 4776.43749},
    {0.134821478, 0.454274792, 2014.84794, 4780.15887},
    {0.130509315, 0.484177537, 2015.88253, 4782.30256},
    {0.131802682, 0.513846106, 2017.19931, 4784.95755},
    {0.142453785, 0.521042681, 2021.16841, 4793.17818},
    {0.141149777, 0.502421095, 2024.20891, 4799.42434},
    {0.154044804, 0.55509796, 2026.5778, 4804.30287},
    {0.150504837, 0.687248516, 2028.24648, 4807.7137},
    {0.193584506, 0.786785342, 2031.72611, 4815.01474},
    {0.21203533, 0.935845997, 2036.1299, 4824.142},
    {0.32022944, 1.60230302, 2038.236, 4828.54176},
    {0.467284628, 2.11432746, 2036.35736, 4824.62029},
    {0.676286249, 2.91918532, 2034.17222, 4819.91679},
    {1.08731622, 4.35120711, 2030.78569, 4810.6442},
    {1.8507975, 7.35834886, 2019.88419, 4787.83082},
    {2.63036146, 10.5227715, 2.11164029, 6.38405972},
    {3.42668707, 13.0899061, 1.61773194, 7.17673366},
}};

constexpr std::array<PositionRanges, 24> silu_ranges{{
    {-6.81823158, 4.62807411, -5.59003603, 4.00497261},
    {-7.6355059, 5.9586552, -9.37480263, 5.97480539},
    {-17.4612185, 5.47595933, -7.03431568, 22.5798768},
    {-7.82247579, 5.37792686, -23.3339878, 32.5894333},
    {-8.6084473, 10.8740598, -6.18993291, 3.4831853},
    {-9.78690332, 6.80719533, -5.8890087, 8.09392227},
    {-7.40143962, 6.24241893, -6.62391901, 3.49269159},
    {-8.30095632, 7.74919399, -3.70808069, 2.69238745},
    {-7.74826114, 5.34941073, -5.28125566, 2.90464754},
    {-7.03599829, 5.88371939, -4.34153452, 3.21287038},
    {-7.91888688, 5.68312042, -3.76660937, 3.6847241},
    {-7.44101276, 4.42058103, -3.85472317, 4.69716017},
    {-7.01223364, 7.30520678, -3.81676876, 3.81395006},
    {-7.768788, 6.34974927, -3.86483415, 3.42233423},
    {-6.89141194, 6.1336691, -2.8715365, 4.40042302},
    {-6.71060393, 6.13058918, -4.12254474, 4.25603957},
    {-7.8337816, 7.49888671, -4.5121479, 4.92817771},
    {-9.6284335, 8.91176206, -6.36666941, 3.73221968},
    {-8.39891136, 7.36893642, -6.93623654, 3.44869301},
    {-10.7170188, 10.0153815, -8.22716371, 24.9234013},
    {-12.3680088, 8.36436106, -6.79395062, 5.90623757},
    {-34.2630517, 8.87470532, -15.7261785, 43.7729304},
    {-14.9315549, 12.520249, -8.51648935, 8.36343278},
    {-12.2228028, 18.6567876, -12.8820415, 19.6377758},
}};

constexpr std::array<AttentionRange, 24> attention_ranges{{
    {2048.0, -20.7619699, -24.2558455, -25.5198062},
    {512.0, -13.9329355, -20.2836166, -20.2836166},
    {256.0, -10.9896266, -14.8578274, -14.8578274},
    {128.0, -23.8793227, -35.3810452, -35.3810452},
    {64.0, -12.3127681, -14.5408387, -14.5408387},
    {32.0, -11.1244653, -13.8095376, -14.6178481},
    {32.0, -11.6863148, -13.0498017, -13.8313712},
    {32.0, -14.8586562, -17.4962545, -17.4962545},
    {2048.0, -32.3749386, -38.8002132, -40.0261355},
    {64.0, -33.6584061, -37.2509173, -37.2509173},
    {32.0, -13.269669, -16.5106687, -18.0465851},
    {64.0, -39.7822416, -39.7822416, -44.779459},
    {32.0, -15.7194845, -19.0659745, -19.3463971},
    {32.0, -19.9439487, -21.1209283, -21.1209283},
    {32.0, -12.4406734, -15.01669, -15.9794237},
    {32.0, -11.8188523, -21.1930928, -21.1930928},
    {32.0, -18.0478871, -21.7771979, -21.7771979},
    {32.0, -11.7480348, -13.0318694, -13.1870643},
    {32.0, -13.5686547, -13.5686547, -13.5686547},
    {32.0, -10.0819545, -12.67875, -15.7849202},
    {32.0, -13.2274271, -14.8248581, -15.1932593},
    {32.0, -14.5465609, -18.6579905, -18.6579905},
    {32.0, -10.0181839, -12.7351799, -12.7351799},
    {64.0, -22.6136331, -22.7723178, -22.7723178},
}};

} // namespace

EncryptedDecoderApproximationConfig
qwen25_05b_layer_approximation(std::size_t layer,
                               std::size_t maximum_tokens)
{
    if (layer >= input_rms_ranges.size() || maximum_tokens == 0)
    {
        throw std::out_of_range(
            "Qwen2.5-0.5B approximation request is out of range");
    }
    const PositionRanges &input = input_rms_ranges[layer];
    const PositionRanges &post = post_rms_ranges[layer];
    const PositionRanges &silu = silu_ranges[layer];
    const AttentionRange &attention = attention_ranges[layer];
    const double shifted_minimum =
        maximum_tokens <= 4
            ? attention.shifted_minimum_4
            : (maximum_tokens <= 8
                   ? attention.shifted_minimum_8
                   : attention.shifted_minimum_long);

    EncryptedDecoderApproximationConfig result;
    // Layer-0 Q/K values reach roughly 80/130 on the official checkpoint.
    // Keep the message inside Poseidon's bootstrap interval and restore the
    // original scale after refresh. Value tensors remain unscaled.
    result.query_key_bootstrap_value_scale = 8.0;
    result.input_inverse_sqrt = {
        input.other_minimum, input.other_maximum, 16};
    result.input_inverse_sqrt_overrides.emplace(
        0, ApproximationConfig{
               input.position_zero_minimum,
               input.position_zero_maximum, 16});
    result.post_attention_inverse_sqrt = {
        post.other_minimum, post.other_maximum, 16};
    result.post_attention_inverse_sqrt_overrides.emplace(
        0, ApproximationConfig{
               post.position_zero_minimum,
               post.position_zero_maximum, 16});

    result.attention = {
        {attention.difference_bound},
        {shifted_minimum, 1.0, 64},
        {0.60, static_cast<double>(maximum_tokens) + 0.50,
         maximum_tokens > 4 ? 64 : 32},
    };
    result.attention.maximum_bootstrap_value_scale =
        std::max(1.0, attention.difference_bound / 16.0);
    result.attention.dual_token_bootstrap_value_scale = std::max(
        1.0,
        (-attention.shifted_minimum_long +
         std::log(std::max(
             1.0, static_cast<double>(maximum_tokens) + 0.5))) /
            16.0);
    result.silu = {
        silu.other_minimum, silu.other_maximum, 32};
    result.silu_overrides.emplace(
        0, ApproximationConfig{
               silu.position_zero_minimum,
               silu.position_zero_maximum, 32});
    constexpr double feature_margin = 10.0;
    constexpr double position_feature_margin = 1.0;
    result.silu_feature_configs.reserve(
        silu_feature_ranges[layer].size());
    for (const FeatureRange &range : silu_feature_ranges[layer])
    {
        result.silu_feature_configs.push_back({
            static_cast<double>(range.other_minimum) - feature_margin,
            static_cast<double>(range.other_maximum) + feature_margin,
            32});
    }
    for (std::size_t position = 0; position < 8; ++position)
    {
        std::vector<ApproximationConfig> position_features;
        position_features.reserve(silu_feature_ranges[layer].size());
        for (const FeatureRange &range : silu_feature_ranges[layer])
        {
            position_features.push_back({
                static_cast<double>(range.positions[position].minimum) -
                    position_feature_margin,
                static_cast<double>(range.positions[position].maximum) +
                    position_feature_margin,
                32});
        }
        result.silu_feature_overrides.emplace(
            position, std::move(position_features));
    }
    result.validate();
    return result;
}

void set_qwen25_05b_calibrated_bootstrap_scales(
    EncryptedDecoderApproximationConfig &config,
    std::size_t layer)
{
    if (layer >= input_rms_ranges.size())
    {
        throw std::out_of_range(
            "Qwen2.5-0.5B bootstrap scale layer is out of range");
    }
    // These scales cover the official checkpoint's calibrated residual
    // ranges. They are independent of the number of logical prompt tokens.
    config.post_attention_bootstrap_value_scale =
        layer < 3 ? 1.0 : 128.0;
    config.output_bootstrap_value_scale =
        layer < 2 ? 1.0 : (layer == 2 ? 32.0 : 128.0);
    config.mlp_input_bootstrap_value_scale =
        layer < 3 ? 1.0 : (layer == 3 ? 128.0 : 4.0);
    // A non-unit output refresh needs one level to scale its input before
    // bootstrap. With the target 46-bit scale, layer 2's RMSNorm + SwiGLU +
    // down-projection path reaches level 0, so refresh the MLP input from
    // layer 2 onward. Later layers also need this boundary for their scaled
    // residual refreshes.
    config.mlp_input_refresh =
        layer < 2 ? RefreshMode::none : RefreshMode::bootstrap;
}

ApproximationConfig qwen25_05b_final_inverse_sqrt_config()
{
    // Degree 31 stays on the reduced-depth Chebyshev evaluator. Degree 63
    // uses Poseidon's generic polynomial-vector path, which is not stable
    // enough for packed final RMSNorm values at the target CKKS scale.
    return {2.5, 55.0, 32};
}

} // namespace qwen::he
