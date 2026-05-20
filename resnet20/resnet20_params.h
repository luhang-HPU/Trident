#ifndef POSEIDON_RESNET20_PARAMS_H
#define POSEIDON_RESNET20_PARAMS_H

#include "resnet20.h"

#include <string>

namespace ResNet20
{

std::vector<float> load_float32_file(const std::string &filename);
bool has_external_parameters(const std::string &parameters_dir);
ResNet20Weights load_weights(const std::string &parameters_dir);
ResNet20Weights load_or_make_weights(const std::string &parameters_dir);

} // namespace ResNet20

#endif
