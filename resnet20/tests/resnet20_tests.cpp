#include <gtest/gtest.h>

#include "../resnet20.h"
#include "../resnet20_plain.h"

#include <algorithm>
#include <cmath>

namespace
{

TEST(ResNet20PlainTest, ToyForwardProducesTenLogits)
{
    const auto weights = ResNet20::make_toy_weights();
    const auto input = ResNet20::make_toy_input();
    const auto logits = ResNet20::forward_plain(input, weights);

    EXPECT_EQ(logits.shape.channels, 10u);
    EXPECT_EQ(logits.shape.height, 1u);
    EXPECT_EQ(logits.shape.width, 1u);
    EXPECT_EQ(logits.values.size(), 10u);

    const bool all_finite = std::all_of(logits.values.begin(), logits.values.end(),
                                        [](double value) { return std::isfinite(value); });
    EXPECT_TRUE(all_finite);
}

TEST(ResNet20PlainTest, ConvKeepsCifarShapeWithPadding)
{
    const auto weights = ResNet20::make_toy_weights();
    const auto input = ResNet20::make_toy_input();
    const auto conv = ResNet20::conv2d_plain(input, weights.conv1);

    EXPECT_EQ(conv.shape.channels, 16u);
    EXPECT_EQ(conv.shape.height, 32u);
    EXPECT_EQ(conv.shape.width, 32u);
}

} // namespace
