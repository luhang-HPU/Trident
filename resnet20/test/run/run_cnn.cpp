#include <iostream>
#include "../cnn/infer_poseidon.h"
#include "../cnn/cnn_poseidon.h"
#include <algorithm>

using namespace std;
using namespace poseidon;

int main(int argc, char **argv) {
	int layer = 20;
	int dataset = 10;
	int start = atoi(argv[1]);
	int end = atoi(argv[2]);

	if (start < 0 || start >= 10000) throw std::invalid_argument("start number is not correct");
	if (end < 0 || end >= 10000) throw std::invalid_argument("end number is not correct");
	if (start > end) throw std::invalid_argument("start number is larger than end number");

	cout << "model: ResNet-" << layer << endl;
	cout << "dataset: CIFAR-" << dataset << endl;
	cout << "start image: " << start << endl;
	cout << "end image: " << end << endl;
	if (dataset == 10) 
		ResNet_cifar10_poseidon_sparse(layer, start, end, 45);

	return 0;
}
