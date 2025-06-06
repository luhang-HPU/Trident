#include "pir.h"
#include "poseidon/src/batchencoder.h"
#include <cassert>
#include <cmath>

namespace poseidon
{
namespace pir
{

std::vector<std::uint64_t> get_dimensions(std::uint64_t num_of_plaintexts, std::uint32_t d)
{

    assert(d > 0);
    assert(num_of_plaintexts > 0);

    std::uint64_t root =
        std::max(static_cast<uint32_t>(2),
                 static_cast<uint32_t>(std::floor(std::pow(num_of_plaintexts, 1.0 / d))));

    std::vector<std::uint64_t> dimensions(d, root);

    for (int i = 0; i < d; i++)
    {
        if (std::accumulate(dimensions.begin(), dimensions.end(), 1, multiplies<uint64_t>()) >
            num_of_plaintexts)
        {
            break;
        }
        dimensions[i] += 1;
    }

    std::uint32_t prod =
        std::accumulate(dimensions.begin(), dimensions.end(), 1, multiplies<uint64_t>());
    assert(prod >= num_of_plaintexts);
    return dimensions;
}

void gen_encryption_params(std::uint32_t N, std::uint32_t logt, ParametersLiteral &enc_params)
{
    enc_params = ParametersLiteralDefault(BFV, N, sec_level_type::tc128);
    enc_params.set_plain_modulus(PlainModulus::Batching(N, logt + 1));
    // the +1 above ensures we get logt bits for each plaintext coefficient.
    // Otherwise the coefficient modulus t will be logt bits, but only floor(t)
    // = logt-1 (whp) will be usable (since we need to ensure that all data in
    // the coefficient is < t).
}

void gen_pir_params(uint64_t ele_num, uint64_t ele_size, uint32_t d,
                    const ParametersLiteral &enc_params, PirParams &pir_params,
                    bool enable_symmetric, bool enable_batching, bool enable_mswitching)
{
    std::uint32_t N = enc_params.degree();
    Modulus t = enc_params.plain_modulus();
    std::uint32_t logt = floor(log2(t.value()));  // # of usable bits
    std::uint64_t elements_per_plaintext;
    std::uint64_t num_of_plaintexts;

    if (enable_batching)
    {
        elements_per_plaintext = elements_per_ptxt(logt, N, ele_size);
        num_of_plaintexts = plaintexts_per_db(logt, N, ele_num, ele_size);
    }
    else
    {
        elements_per_plaintext = 1;
        num_of_plaintexts = ele_num;
    }

    std::vector<uint64_t> nvec = get_dimensions(num_of_plaintexts, d);

    uint32_t expansion_ratio = 0;
    for (uint32_t i = 0; i < enc_params.q().size(); ++i)
    {
        double logqi = log2(enc_params.q()[i].value());
        expansion_ratio += ceil(logqi / logt);
    }
    for (uint32_t i = 0; i < enc_params.p().size(); ++i)
    {
        double logqi = log2(enc_params.p()[i].value());
        expansion_ratio += ceil(logqi / logt);
    }

    pir_params.enable_symmetric = enable_symmetric;
    pir_params.enable_batching = enable_batching;
    pir_params.enable_mswitching = enable_mswitching;
    pir_params.ele_num = ele_num;
    pir_params.ele_size = ele_size;
    pir_params.elements_per_plaintext = elements_per_plaintext;
    pir_params.num_of_plaintexts = num_of_plaintexts;
    pir_params.d = d;
    pir_params.expansion_ratio = expansion_ratio << 1;
    pir_params.nvec = nvec;
    pir_params.slot_count = N;
}

void verify_encryption_params(const ParametersLiteral &enc_params)
{
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(enc_params);
    // TODO
    // if (!context.parameters_set()) {
    //   throw invalid_argument("SEAL parameters not valid.");
    // }
    if (!context.crt_context()->using_keyswitch())
    {
        throw invalid_argument("SEAL parameters do not support key switching.");
    }
    // TODO
    // if (!context.first_context_data()->qualifiers().using_batching) {
    //   throw invalid_argument("SEAL parameters do not support batching.");
    // }

    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    if (slot_count != enc_params.degree())
    {
        throw invalid_argument("Slot count not equal to poly modulus degree - this "
                               "will cause issues downstream.");
    }
}

void print_pir_params(const PirParams &pir_params)
{
    std::uint32_t prod =
        std::accumulate(pir_params.nvec.begin(), pir_params.nvec.end(), 1, multiplies<uint64_t>());

    std::cout << "PIR Parameters" << std::endl;
    std::cout << "number of elements: " << pir_params.ele_num << std::endl;
    std::cout << "element size: " << pir_params.ele_size << std::endl;
    std::cout << "elements per BFV plaintext: " << pir_params.elements_per_plaintext << std::endl;
    std::cout << "dimensions for d-dimensional hyperrectangle: " << pir_params.d << std::endl;
    std::cout << "number of BFV plaintexts (before padding): " << pir_params.num_of_plaintexts
              << std::endl;
    std::cout << "Number of BFV plaintexts after padding (to fill d-dimensional "
                 "hyperrectangle): "
              << prod << std::endl;
    std::cout << "expansion ratio: " << pir_params.expansion_ratio << std::endl;
    std::cout << "Using symmetric encryption: " << pir_params.enable_symmetric << std::endl;
    std::cout << "Using recursive mod switching: " << pir_params.enable_mswitching << std::endl;
    std::cout << "slot count: " << pir_params.slot_count << std::endl;
    std::cout << "==============================" << std::endl;
}

void print_seal_params(const ParametersLiteral &enc_params)
{
    std::uint32_t N = enc_params.degree();
    Modulus t = enc_params.plain_modulus();
    std::uint32_t logt = floor(log2(t.value()));

    std::cout << "SEAL encryption parameters" << std::endl;
    std::cout << "Degree of polynomial modulus (N): " << N << std::endl;
    std::cout << "Size of plaintext modulus (log t):" << logt << std::endl;
    std::cout << "There are " << enc_params.q().size() + enc_params.p().size()
              << " coefficient modulus:" << std::endl;

    uint32_t cnt = 0;
    for (uint32_t i = 0; i < enc_params.q().size(); ++i)
    {
        double logqi = log2(enc_params.q()[i].value());
        std::cout << "Size of coefficient modulus " << cnt << " (log q_" << cnt << "): " << logqi
                  << std::endl;
        ++cnt;
    }
    for (uint32_t i = 0; i < enc_params.p().size(); ++i)
    {
        double logqi = log2(enc_params.p()[i].value());
        std::cout << "Size of coefficient modulus " << cnt << " (log q_" << cnt << "): " << logqi
                  << std::endl;
        ++cnt;
    }
    std::cout << "==============================" << std::endl;
}

// Number of FV plaintexts needed to represent the database
uint64_t plaintexts_per_db(uint32_t logt, uint64_t N, uint64_t ele_num, uint64_t ele_size)
{
    uint64_t ele_per_ptxt = elements_per_ptxt(logt, N, ele_size);
    return std::ceil((double)ele_num / ele_per_ptxt);
}

// Number of database elements that can fit in a single FV plaintext
uint64_t elements_per_ptxt(uint32_t logt, uint64_t N, uint64_t ele_size)
{
    uint64_t coeff_per_ele = coefficients_per_element(logt, ele_size);
    uint64_t ele_per_ptxt = N / coeff_per_ele;
    assert(ele_per_ptxt > 0);
    return ele_per_ptxt;
}

// Number of coefficients needed to represent a database element
uint64_t coefficients_per_element(uint32_t logt, uint64_t ele_size)
{
    return std::ceil(8 * ele_size / (double)logt);
}

std::vector<uint64_t> bytes_to_coeffs(uint32_t limit, const uint8_t *bytes, uint64_t size)
{
    uint64_t size_out = coefficients_per_element(limit, size);
    std::vector<uint64_t> output(size_out);

    uint32_t room = limit;
    uint64_t *target = &output[0];

    for (uint32_t i = 0; i < size; i++)
    {
        uint8_t src = bytes[i];
        uint32_t rest = 8;
        while (rest)
        {
            if (room == 0)
            {
                target++;
                room = limit;
            }
            uint32_t shift = rest;
            if (room < rest)
            {
                shift = room;
            }
            *target = *target << shift;
            *target = *target | (src >> (8 - shift));
            src = src << shift;
            room -= shift;
            rest -= shift;
        }
    }

    *target = *target << room;
    return output;
}

void coeffs_to_bytes(uint32_t limit, const std::vector<uint64_t> &coeffs, uint8_t *output,
                     uint32_t size_out, uint32_t ele_size)
{
    uint32_t room = 8;
    uint32_t j = 0;
    uint8_t *target = output;
    uint32_t bits_left = ele_size * 8;
    for (uint32_t i = 0; i < coeffs.size(); i++)
    {
        if (bits_left == 0)
        {
            bits_left = ele_size * 8;
        }
        uint64_t src = coeffs[i];
        uint32_t rest = min(limit, bits_left);
        while (rest && j < size_out)
        {
            uint32_t shift = rest;
            if (room < rest)
            {
                shift = room;
            }

            target[j] = target[j] << shift;
            target[j] = target[j] | (src >> (limit - shift));
            src = src << shift;
            room -= shift;
            rest -= shift;
            bits_left -= shift;
            if (room == 0)
            {
                j++;
                room = 8;
            }
        }
    }
}

void vector_to_plaintext(const std::vector<uint64_t> &coeffs, Plaintext &plain)
{
    uint32_t coeff_count = coeffs.size();
    plain.resize(coeff_count);
    util::set_uint(coeffs.data(), coeff_count, plain.data());
}

std::vector<uint64_t> compute_indices(uint64_t desiredIndex, std::vector<uint64_t> Nvec)
{
    uint32_t num = Nvec.size();
    uint64_t product = 1;

    for (uint32_t i = 0; i < num; i++)
    {
        product *= Nvec[i];
    }

    uint64_t j = desiredIndex;
    std::vector<uint64_t> result;

    for (uint32_t i = 0; i < num; i++)
    {

        product /= Nvec[i];
        uint64_t ji = j / product;

        result.push_back(ji);
        j -= ji * product;
    }

    return result;
}

uint64_t invert_mod(uint64_t m, const Modulus &mod)
{
    if (mod.uint64_count() > 1)
    {
        std::cout << "Mod too big to invert";
    }
    uint64_t inverse = 0;
    if (!poseidon::util::try_invert_uint_mod(m, mod.value(), inverse))
    {
        std::cout << "Could not invert value";
    }
    return inverse;
}

uint32_t compute_expansion_ratio(ParametersLiteral params)
{
    uint32_t expansion_ratio = 0;
    uint32_t pt_bits_per_coeff = std::log2(params.plain_modulus().value());
    for (size_t i = 0; i < params.p().size(); ++i)
    {
        double coeff_bit_size = std::log2(params.p()[i].value());
        expansion_ratio += std::ceil(coeff_bit_size / pt_bits_per_coeff);
    }
    for (size_t i = 0; i < params.q().size(); ++i)
    {
        double coeff_bit_size = std::log2(params.q()[i].value());
        expansion_ratio += std::ceil(coeff_bit_size / pt_bits_per_coeff);
    }
    return expansion_ratio;
}

std::vector<Plaintext> decompose_to_plaintexts(ParametersLiteral params, const Ciphertext &ct)
{
    const uint32_t pt_bits_per_coeff = std::log2(params.plain_modulus().value());
    const auto coeff_count = params.degree();
    const auto coeff_mod_count = params.q().size() + params.p().size();
    std::vector<Modulus> coeff_modulus;
    for (auto mod : params.q())
    {
        coeff_modulus.push_back(mod);
    }
    for (auto mod : params.p())
    {
        coeff_modulus.push_back(mod);
    }

    const uint64_t pt_bitmask = (1 << pt_bits_per_coeff) - 1;

    std::vector<Plaintext> result(compute_expansion_ratio(params) * ct.size());
    auto pt_iter = result.begin();
    for (size_t poly_index = 0; poly_index < ct.size(); ++poly_index)
    {
        for (size_t coeff_mod_index = 0; coeff_mod_index < coeff_mod_count; ++coeff_mod_index)
        {
            const double coeff_bit_size = std::log2(coeff_modulus[coeff_mod_index].value());
            const size_t local_expansion_ratio = std::ceil(coeff_bit_size / pt_bits_per_coeff);
            size_t shift = 0;
            for (size_t i = 0; i < local_expansion_ratio; ++i)
            {
                pt_iter->resize(coeff_count);
                for (size_t c = 0; c < coeff_count; ++c)
                {
                    (*pt_iter)[c] =
                        (ct.data(poly_index)[coeff_mod_index * coeff_count + c] >> shift) &
                        pt_bitmask;
                }
                ++pt_iter;
                shift += pt_bits_per_coeff;
            }
        }
    }
    return result;
}

void compose_to_ciphertext(ParametersLiteral params, std::vector<Plaintext>::const_iterator pt_iter,
                           const size_t ct_poly_count, Ciphertext &ct)
{
    const uint32_t pt_bits_per_coeff = log2(params.plain_modulus().value());
    const auto coeff_count = params.degree();
    const auto coeff_mod_count = params.q().size() + params.p().size();
    std::vector<Modulus> coeff_modulus;
    for (auto mod : params.q())
    {
        coeff_modulus.push_back(mod);
    }
    for (auto mod : params.p())
    {
        coeff_modulus.push_back(mod);
    }

    ct.resize(ct_poly_count);
    for (size_t poly_index = 0; poly_index < ct_poly_count; ++poly_index)
    {
        for (size_t coeff_mod_index = 0; coeff_mod_index < coeff_mod_count; ++coeff_mod_index)
        {
            const double coeff_bit_size = log2(coeff_modulus[coeff_mod_index].value());
            const size_t local_expansion_ratio = ceil(coeff_bit_size / pt_bits_per_coeff);
            size_t shift = 0;
            for (size_t i = 0; i < local_expansion_ratio; ++i)
            {
                for (size_t c = 0; c < pt_iter->coeff_count(); ++c)
                {
                    if (shift == 0)
                    {
                        ct.data(poly_index)[coeff_mod_index * coeff_count + c] = (*pt_iter)[c];
                    }
                    else
                    {
                        ct.data(poly_index)[coeff_mod_index * coeff_count + c] +=
                            ((*pt_iter)[c] << shift);
                    }
                }
                ++pt_iter;
                shift += pt_bits_per_coeff;
            }
        }
    }
}

void compose_to_ciphertext(ParametersLiteral params, const std::vector<Plaintext> &pts,
                           Ciphertext &ct)
{
    return compose_to_ciphertext(params, pts.begin(), pts.size() / compute_expansion_ratio(params),
                                 ct);
}

// unused
// PirQuery deserialize_query(uint32_t d, uint32_t count, string s,
//                            uint32_t len_ciphertext,
//                            std::shared_ptr<PoseidonContext> context) {
//   std::vector<std::vector<Ciphertext>> q;
//   std::istringstream input(s);

//   for (uint32_t i = 0; i < d; i++) {
//     std::vector<Ciphertext> cs;
//     for (uint32_t i = 0; i < count; i++) {
//       Ciphertext c;
//       c.load(*context, input);
//       cs.push_back(c);
//     }
//     q.push_back(cs);
//   }
//   return q;
// }

std::string serialize_galoiskeys(Serializable<GaloisKeys> g)
{
    std::ostringstream output;
    g.save(output);
    return output.str();
}

GaloisKeys *deserialize_galoiskeys(std::string s, std::shared_ptr<PoseidonContext> context)
{
    GaloisKeys *g = new GaloisKeys();
    std::istringstream input(s);
    g->load(*context, input);
    return g;
}

}  // namespace pir
}  // namespace poseidon
