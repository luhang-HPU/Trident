#include <gtest/gtest.h>

#include "../knn_utils.h"

#include <filesystem>

namespace
{

TEST(KNNTest, Degree32768)
{
    auto options = KNN::make_default_options();
    options.log_degree = 15;
    options.predictions_file = "/tmp/poseidon_knn_test/predictions.jsonl";

    std::filesystem::remove(options.predictions_file);

    EXPECT_EQ(KNN::run_knn(options), 0);
    EXPECT_TRUE(std::filesystem::exists(options.predictions_file));
    EXPECT_GT(std::filesystem::file_size(options.predictions_file), 0);
}

} // namespace
