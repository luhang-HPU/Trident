#include "pir_client.h"
#include <cassert>

using namespace std;

namespace poseidon
{
namespace pir
{

PIRClient::PIRClient(const ParametersLiteral &enc_params, const PirParams &pir_params)
    : enc_params_(enc_params), pir_params_(pir_params)
{
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    context_ = std::make_shared<PoseidonContext>(
        PoseidonFactory::get_instance()->create_poseidon_context(enc_params));

    keygen_ = std::make_unique<KeyGenerator>(*context_);

    PublicKey public_key;
    keygen_->create_public_key(public_key);
    SecretKey secret_key = keygen_->secret_key();

    if (pir_params_.enable_symmetric)
    {
        encryptor_ = std::make_unique<Encryptor>(*context_, secret_key);
    }
    else
    {
        encryptor_ = std::make_unique<Encryptor>(*context_, public_key);
    }

    decryptor_ = std::make_unique<Decryptor>(*context_, secret_key);
    evaluator_ = PoseidonFactory::get_instance()->create_bfv_evaluator(*context_);
    // evaluator_ = std::make_unique<EvaluatorBfvBase>(
    //     PoseidonFactory::get_instance()->create_bfv_evaluator(*context_));
    encoder_ = std::make_unique<BatchEncoder>(*context_);
}

int PIRClient::generate_serialized_query(uint64_t desiredIndex, std::stringstream &stream)
{

    int N = enc_params_.degree();
    int output_size = 0;
    indices_ = compute_indices(desiredIndex, pir_params_.nvec);
    Plaintext pt(enc_params_.degree());

    for (uint32_t i = 0; i < indices_.size(); i++)
    {
        uint32_t num_ptxts = std::ceil((pir_params_.nvec[i] + 0.0) / N);
        // initialize result.
        std::cout << "Client: index " << i + 1 << "/ " << indices_.size() << " = " << indices_[i]
                  << std::endl;
        std::cout << "Client: number of ctxts needed for query = " << num_ptxts << std::endl;

        for (uint32_t j = 0; j < num_ptxts; j++)
        {
            pt.set_zero();
            if (indices_[i] >= N * j && indices_[i] <= N * (j + 1))
            {
                uint64_t real_index = indices_[i] - N * j;
                uint64_t n_i = pir_params_.nvec[i];
                uint64_t total = N;
                if (j == num_ptxts - 1)
                {
                    total = n_i % N;
                }
                uint64_t log_total = std::ceil(log2(total));

                std::cout << "Client: Inverting " << pow(2, log_total) << std::endl;
                pt[real_index] = invert_mod(pow(2, log_total), enc_params_.plain_modulus());
            }

            if (pir_params_.enable_symmetric)
            {
                output_size += encryptor_->encrypt_symmetric(pt).save(stream);
            }
            else
            {
                output_size += encryptor_->encrypt(pt).save(stream);
            }
        }
    }

    return output_size;
}

PirQuery PIRClient::generate_query(uint64_t desiredIndex)
{

    indices_ = compute_indices(desiredIndex, pir_params_.nvec);

    PirQuery result(pir_params_.d);
    int N = enc_params_.degree();

    Plaintext pt(enc_params_.degree());
    for (uint32_t i = 0; i < indices_.size(); i++)
    {
        uint32_t num_ptxts = std::ceil((pir_params_.nvec[i] + 0.0) / N);
        // initialize result.
        std::cout << "Client: index " << i + 1 << "/ " << indices_.size() << " = " << indices_[i]
                  << std::endl;
        std::cout << "Client: number of ctxts needed for query = " << num_ptxts << std::endl;

        for (uint32_t j = 0; j < num_ptxts; j++)
        {
            pt.set_zero();
            if (indices_[i] >= N * j && indices_[i] <= N * (j + 1))
            {
                uint64_t real_index = indices_[i] - N * j;
                uint64_t n_i = pir_params_.nvec[i];
                uint64_t total = N;
                if (j == num_ptxts - 1)
                {
                    total = n_i % N;
                }
                uint64_t log_total = std::ceil(log2(total));

                std::cout << "Client: Inverting " << pow(2, log_total) << std::endl;
                pt[real_index] = invert_mod(pow(2, log_total), enc_params_.plain_modulus());
            }
            Ciphertext dest;
            if (pir_params_.enable_symmetric)
            {
                encryptor_->encrypt_symmetric(pt, dest);
            }
            else
            {
                encryptor_->encrypt(pt, dest);
            }
            result[i].push_back(dest);
        }
    }

#ifdef DEBUG
    for (auto i = 0; i < result.size(); ++i)
    {
        for (auto j = 0; j < result[i].size(); ++j)
        {
            std::cout << "Client: reply noise budget = "
                      << decryptor_->invariant_noise_budget(result[i][j]) << std::endl;
        }
    }
#endif

    return result;
}

uint64_t PIRClient::get_fv_index(uint64_t element_index)
{
    return static_cast<uint64_t>(element_index / pir_params_.elements_per_plaintext);
}

uint64_t PIRClient::get_fv_offset(uint64_t element_index)
{
    return element_index % pir_params_.elements_per_plaintext;
}

Plaintext PIRClient::decrypt(Ciphertext ct)
{
    Plaintext pt;
    decryptor_->decrypt(ct, pt);
    return pt;
}

vector<uint8_t> PIRClient::decode_reply(PirReply &reply, uint64_t offset)
{
    Plaintext result = decode_reply(reply);
    return extract_bytes(result, offset);
}

vector<uint64_t> PIRClient::extract_coeffs(Plaintext pt)
{
    vector<uint64_t> coeffs;
    encoder_->decode(pt, coeffs);
    return coeffs;
}

std::vector<uint64_t> PIRClient::extract_coeffs(Plaintext pt, uint64_t offset)
{
    vector<uint64_t> coeffs;
    encoder_->decode(pt, coeffs);

    uint32_t logt = std::floor(log2(enc_params_.plain_modulus().value()));

    uint64_t coeffs_per_element = coefficients_per_element(logt, pir_params_.ele_size);

    return std::vector<uint64_t>(coeffs.begin() + offset * coeffs_per_element,
                                 coeffs.begin() + (offset + 1) * coeffs_per_element);
}

std::vector<uint8_t> PIRClient::extract_bytes(Plaintext pt, uint64_t offset)
{
    uint32_t N = enc_params_.degree();
    uint32_t logt = std::floor(log2(enc_params_.plain_modulus().value()));
    uint32_t bytes_per_ptxt = pir_params_.elements_per_plaintext * pir_params_.ele_size;

    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(bytes_per_ptxt);
    vector<uint64_t> coeffs;
    encoder_->decode(pt, coeffs);
    coeffs_to_bytes(logt, coeffs, elems.data(), bytes_per_ptxt, pir_params_.ele_size);
    return std::vector<uint8_t>(elems.begin() + offset * pir_params_.ele_size,
                                elems.begin() + (offset + 1) * pir_params_.ele_size);
}

Plaintext PIRClient::decode_reply(PirReply &reply)
{
    ParametersLiteral parms;
    parms_id_type parms_id;
    if (pir_params_.enable_mswitching)
    {
        parms = context_->crt_context()->last_context_data()->parms();
        parms_id = context_->crt_context()->last_parms_id();
    }
    else
    {
        parms = context_->crt_context()->first_context_data()->parms();
        parms_id = context_->crt_context()->first_parms_id();
    }
    uint32_t exp_ratio = compute_expansion_ratio(parms);
    uint32_t recursion_level = pir_params_.d;

    vector<Ciphertext> temp = reply;
    uint32_t ciphertext_size = temp[0].size();

    uint64_t t = enc_params_.plain_modulus().value();

    for (uint32_t i = 0; i < recursion_level; i++)
    {
        std::cout << "Client: " << i + 1 << "/ " << recursion_level
                  << "-th decryption layer started." << std::endl;
        vector<Ciphertext> newtemp;
        vector<Plaintext> tempplain;

        for (uint32_t j = 0; j < temp.size(); j++)
        {
            Plaintext ptxt;
            decryptor_->decrypt(temp[j], ptxt);

#ifdef DEBUG
            std::cout << "Client: reply noise budget = "
                      << decryptor_->invariant_noise_budget(temp[j]) << std::endl;
#endif

            tempplain.push_back(ptxt);

#ifdef DEBUG
            std::cout << "recursion level : " << i << " noise budget :  ";
            std::cout << decryptor_->invariant_noise_budget(temp[j]) << std::endl;
#endif

            if ((j + 1) % (exp_ratio * ciphertext_size) == 0 && j > 0)
            {
                // Combine into one ciphertext.
                Ciphertext combined(*context_, parms_id);
                compose_to_ciphertext(parms, tempplain, combined);
                newtemp.push_back(combined);
                tempplain.clear();
                // std::cout << "Client: const term of ciphertext = " <<
                // combined[0] << std::endl;
            }
        }
        std::cout << "Client: done." << std::endl;
        std::cout << std::endl;
        if (i == recursion_level - 1)
        {
            assert(temp.size() == 1);
            return tempplain[0];
        }
        else
        {
            tempplain.clear();
            temp = newtemp;
        }
    }

    // This should never be called
    assert(0);
    Plaintext fail;
    return fail;
}

GaloisKeys PIRClient::generate_galois_keys()
{
    // Generate the Galois keys needed for coeff_select.
    // vector<uint32_t> galois_elts;
    // int N = enc_params_.degree();
    // int logN = get_power_of_two(N);

    // // std::cout << "printing galois elements...";
    // for (int i = 0; i < logN; i++)
    // {
    //     galois_elts.push_back((N + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    //     //#ifdef DEBUG
    //     // std::cout << galois_elts.back() << ", ";
    //     //#endif
    // }
    GaloisKeys gal_keys;
    keygen_->create_galois_keys(gal_keys);
    return gal_keys;
}

Plaintext PIRClient::replace_element(Plaintext pt, vector<uint64_t> new_element, uint64_t offset)
{
    vector<uint64_t> coeffs = extract_coeffs(pt);

    uint32_t logt = std::floor(log2(enc_params_.plain_modulus().value()));
    uint64_t coeffs_per_element = coefficients_per_element(logt, pir_params_.ele_size);

    assert(new_element.size() == coeffs_per_element);

    for (uint64_t i = 0; i < coeffs_per_element; i++)
    {
        coeffs[i + offset * coeffs_per_element] = new_element[i];
    }

    Plaintext new_pt;

    encoder_->encode(coeffs, new_pt);
    return new_pt;
}

Ciphertext PIRClient::get_one()
{
    Plaintext pt("1");
    Ciphertext ct;
    if (pir_params_.enable_symmetric)
    {
        encryptor_->encrypt_symmetric(pt, ct);
    }
    else
    {
        encryptor_->encrypt(pt, ct);
    }
    return ct;
}

}  // namespace pir
}  // namespace poseidon
