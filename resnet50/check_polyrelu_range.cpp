#include "infer_config.h"
#include "relu_approx.h"

#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <vector>

int main()
{
    const ReluConfig config = default_relu_config(default_poseidon_plan());
    std::cout << std::setprecision(10);
    std::cout << "polyrelu config: deg=";
    for (std::size_t i = 0; i < config.deg.size(); ++i)
    {
        if (i != 0)
        {
            std::cout << ',';
        }
        std::cout << config.deg[i];
    }
    std::cout << ", alpha=" << config.alpha << ", scaled_val=" << config.scaled_val << '\n';

    bool saw_nonfinite = false;
    double first_positive_nonfinite = std::numeric_limits<double>::quiet_NaN();
    double last_positive_finite = 0.0;
    for (int i = 0; i <= 22000; ++i)
    {
        const double x = static_cast<double>(i) / 10000.0;
        const double y = approximate_relu_plain(x, config.deg, config.alpha, config.tree,
                                                config.scaled_val);
        if (!std::isfinite(y))
        {
            first_positive_nonfinite = x;
            break;
        }
        last_positive_finite = x;
    }

    double first_negative_nonfinite = std::numeric_limits<double>::quiet_NaN();
    double last_negative_finite = 0.0;
    for (int i = 0; i >= -22000; --i)
    {
        const double x = static_cast<double>(i) / 10000.0;
        const double y = approximate_relu_plain(x, config.deg, config.alpha, config.tree,
                                                config.scaled_val);
        if (!std::isfinite(y))
        {
            first_negative_nonfinite = x;
            break;
        }
        last_negative_finite = x;
    }

    std::cout << "positive finite until x=" << last_positive_finite
              << ", first_nonfinite x=" << first_positive_nonfinite << '\n';
    std::cout << "negative finite until x=" << last_negative_finite
              << ", first_nonfinite x=" << first_negative_nonfinite << '\n';

    double worst_finite_abs = 0.0;
    double worst_finite_x = 0.0;
    for (int i = -22000; i <= 22000; ++i)
    {
        const double x = static_cast<double>(i) / 10000.0;
        const double y = approximate_relu_plain(x, config.deg, config.alpha, config.tree,
                                                config.scaled_val);
        if (!std::isfinite(y))
        {
            if (!saw_nonfinite)
            {
                std::cout << "first_nonfinite x=" << x << ", y=" << y << '\n';
            }
            saw_nonfinite = true;
            continue;
        }
        if (std::abs(y) > worst_finite_abs)
        {
            worst_finite_abs = std::abs(y);
            worst_finite_x = x;
        }
    }

    std::cout << "worst_finite_abs=" << worst_finite_abs
              << " at x=" << worst_finite_x << '\n';

    const std::vector<double> probes = {-2.0, -1.9, -1.8, -1.7, -1.65, -1.62,
                                        -1.6, -1.5, -1.3, -1.25, -1.23, -1.2,
                                        -1.1, -1.0, 0.0, 1.0, 1.1, 1.2,
                                        1.23, 1.25, 1.3, 1.4, 1.5, 1.6,
                                        1.62, 1.65, 1.7, 1.8, 1.9, 2.0};
    for (double x : probes)
    {
        const double y = approximate_relu_plain(x, config.deg, config.alpha, config.tree,
                                                config.scaled_val);
        std::cout << "probe x=" << x << ", y=" << y
                  << ", finite=" << (std::isfinite(y) ? 1 : 0) << '\n';
    }

    return saw_nonfinite ? 2 : 0;
}
