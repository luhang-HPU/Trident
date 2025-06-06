#include <stdexcept>
#include "apsi/log.h"
#include "apsi/psi_params.h"
#include "apsi/query.h"

using namespace std;
using namespace poseidon;

namespace apsi {
    using namespace network;

    namespace sender {
        Query Query::deep_copy() const
        {
            Query result;
            result.relin_keys_ = relin_keys_;
            result.data_ = data_;
            result.sender_db_ = sender_db_;
            result.compr_mode_ = compr_mode_;

            return result;
        }

        Query::Query(QueryRequest query_request, shared_ptr<SenderDB> sender_db)
        {
            if (!sender_db) {
                throw invalid_argument("sender_db cannot be null");
            }
            if (!query_request) {
                throw invalid_argument("query_request cannot be null");
            }

            compr_mode_ = query_request->compr_mode;

            sender_db_ = move(sender_db);
            auto context = sender_db_->get_context();

            // Extract and validate relinearization keys
            if (context->crt_context()->using_keyswitch())
            {
                relin_keys_ = query_request->relin_keys.extract(context);
                // if (!is_valid_for(relin_keys_, *context)) {
                //     APSI_LOG_ERROR("Extracted relinearization keys are invalid for PoseidonContext");
                //     return;
                // }
            }

            // Extract and validate query ciphertexts
            for (auto &q : query_request->data) {
                APSI_LOG_DEBUG(
                    "Extracting " << q.second.size() << " ciphertexts for exponent " << q.first);
                vector<Ciphertext> cts;
                for (auto &ct : q.second) {
                    cts.push_back(ct.extract(context));
                    // if (!is_valid_for(cts.back(), *context)) {
                    //     APSI_LOG_ERROR("Extracted ciphertext is invalid for PoseidonContext");
                    //     return;
                    // }
                }
                data_[q.first] = move(cts);
            }

            // Get the PSIParams
            PSIParams params(sender_db_->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params.query_params().ps_low_degree;
            const set<uint32_t> &query_powers = params.query_params().query_powers;
            set<uint32_t> target_powers = create_powers_set(ps_low_degree, max_items_per_bin);

            // Create the PowersDag
            pd_.configure(query_powers, target_powers);

            // Check that the PowersDag is valid
            if (!pd_.is_configured()) {
                APSI_LOG_ERROR(
                    "Failed to configure PowersDag ("
                    << "source_powers: " << to_string(query_powers) << ", "
                    << "up_to_power: " << to_string(target_powers) << ")");
                return;
            }
            APSI_LOG_DEBUG("Configured PowersDag with depth " << pd_.depth());

            // Check that the query data size matches the PSIParams
            if (data_.size() != query_powers.size()) {
                APSI_LOG_ERROR(
                    "Extracted query data is incompatible with PSI parameters: "
                    "query contains "
                    << data_.size()
                    << " ciphertext powers which does not match with "
                       "the size of query_powers ("
                    << query_powers.size() << ")");
                return;
            }

            for (auto &q : data_) {
                // Check that powers in the query data match source nodes in the PowersDag
                if (q.second.size() != bundle_idx_count) {
                    APSI_LOG_ERROR(
                        "Extracted query data is incompatible with PSI parameters: "
                        "query power "
                        << q.first << " contains " << q.second.size()
                        << " ciphertexts which does not "
                           "match with bundle_idx_count ("
                        << bundle_idx_count << ")");
                    return;
                }
                auto where = find_if(query_powers.cbegin(), query_powers.cend(), [&q](auto n) {
                    return n == q.first;
                });
                if (where == query_powers.cend()) {
                    APSI_LOG_ERROR(
                        "Extracted query data is incompatible with PowersDag: "
                        "query power "
                        << q.first << " does not match with a source node in PowersDag");
                    return;
                }
            }

            // The query is valid
            valid_ = true;
        }
    } // namespace sender
} // namespace apsi
