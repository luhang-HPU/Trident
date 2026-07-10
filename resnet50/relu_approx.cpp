#include "relu_approx.h"

#include "poseidon/plaintext.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace poseidon;
using namespace std;

namespace fs = std::filesystem;

namespace
{

int pow2_int(int exponent)
{
    if (exponent < 0)
    {
        throw invalid_argument("negative exponent is not supported");
    }
    return 1 << exponent;
}

int pow2(int exponent)
{
    if (exponent < 0)
    {
        throw std::invalid_argument("negative exponent is not supported");
    }
    return 1 << exponent;
}

size_t ceil_to_int(double value)
{
    return static_cast<size_t>(ceil(value) + 0.5);
}

long num_one(long value)
{
    long count = 0;
    while (value > 0)
    {
        count += (value & 1L);
        value >>= 1;
    }
    return count;
}

long coeff_number(long degree, const Tree &tree)
{
    if (tree.tree.empty())
    {
        throw invalid_argument("tree is empty");
    }

    const int tree_size = 1 << (tree.depth + 1);
    vector<long> decomp_deg(static_cast<size_t>(tree_size), -1);
    decomp_deg[1] = degree;
    for (int level = 1; level <= tree.depth; ++level)
    {
        for (int node = 1 << level; node < (1 << (level + 1)); ++node)
        {
            if ((node % 2) == 0)
            {
                decomp_deg[node] = tree.tree[node / 2] - 1;
            }
            else
            {
                decomp_deg[node] = decomp_deg[node / 2] - tree.tree[node / 2];
            }
        }
    }

    long count = 0;
    for (int node = 0; node < tree_size; ++node)
    {
        if (tree.tree[node] == 0)
        {
            count += decomp_deg[node] + 1;
        }
    }
    return count;
}

Ciphertext encrypt_constant_cipher(double value, size_t slot_count, double scale,
                                   Encryptor &encryptor, CKKSEncoder &encoder)
{
    vector<complex<double>> slots(slot_count, complex<double>(value, 0.0));
    Plaintext plain;
    encoder.encode(slots, scale, plain);
    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);
    return cipher;
}

void generate_t0_t1(Encryptor &encryptor, CKKSEncoder &encoder, const Ciphertext &cipher,
                    Ciphertext &t0, Ciphertext &t1)
{
    t0 = encrypt_constant_cipher(1.0, encoder.slot_count(), cipher.scale(), encryptor, encoder);
    t1 = cipher;
}

void multiply_const_reduced_error(const Ciphertext &cipher, double coeff, double target_scale,
                                  Ciphertext &output, EvaluatorCkksBase &evaluator,
                                  CKKSEncoder &encoder)
{
    evaluator.multiply_const(cipher, coeff, target_scale / cipher.scale(), output, encoder);
}

void add_lazy_cipher_for_relu_reference(Ciphertext &accumulator, const Ciphertext &term,
                                        EvaluatorCkksBase &evaluator, CKKSEncoder &encoder)
{
    if (accumulator.parms_id() == term.parms_id())
    {
        Ciphertext aligned_term = term;
        assign_scale_for_relu_reference(aligned_term, accumulator.scale());
        evaluator.add(accumulator, aligned_term, accumulator);
        return;
    }
    evaluator.add_dynamic(accumulator, term, accumulator, encoder);
}

void eval_t_for_relu_reference(EvaluatorCkksBase &evaluator, const RelinKeys &relin_keys,
                               CKKSEncoder &encoder, Ciphertext &output,
                               const Ciphertext &tm, const Ciphertext &tn,
                               const Ciphertext &tm_minus_n)
{
    const double target_scale = tm.scale();
    const double lazy_scale = target_scale * target_scale;

    Ciphertext product;
    evaluator.multiply_relin_dynamic(tm, tn, product, relin_keys);
    assign_scale_for_relu_reference(product, lazy_scale);

    Ciphertext doubled;
    evaluator.add(product, product, doubled);
    assign_scale_for_relu_reference(doubled, lazy_scale);
    evaluator.rescale(doubled, doubled);
    assign_scale_for_relu_reference(doubled, target_scale);

    if (doubled.parms_id() == tm_minus_n.parms_id())
    {
        Ciphertext aligned_tm_minus_n = tm_minus_n;
        assign_scale_for_relu_reference(aligned_tm_minus_n, doubled.scale());
        evaluator.sub(doubled, aligned_tm_minus_n, output);
    }
    else
    {
        evaluator.sub_dynamic(doubled, tm_minus_n, output, encoder);
    }
    assign_scale_for_relu_reference(output, target_scale);
}

Ciphertext eval_polynomial_integrate_for_relu_reference(
    const Ciphertext &cipher, long degree, const vector<double> &decomp_coeff, const Tree &tree,
    Encryptor &encryptor, EvaluatorCkksBase &evaluator, CKKSEncoder &encoder,
    const RelinKeys &relin_keys)
{
    if (tree.type != EvalType::OddBaby)
    {
        throw invalid_argument("relu reference only supports oddbaby tree");
    }

    const double scale = cipher.scale();
    const double lazy_scale = scale * scale;
    const long total_depth =
        static_cast<long>(ceil_to_int(log(static_cast<double>(degree + 1)) / log(2.0)));
    const int tree_size = 1 << (tree.depth + 1);

    vector<long> decomp_deg(static_cast<size_t>(tree_size), -1);
    vector<long> start_index(static_cast<size_t>(tree_size), -1);
    vector<unique_ptr<Ciphertext>> t(128);
    vector<unique_ptr<Ciphertext>> pt(128);

    decomp_deg[1] = degree;
    long temp_index = 1;
    for (int level = 1; level <= tree.depth; ++level)
    {
        for (int node = 1 << level; node < (1 << (level + 1)); ++node)
        {
            if ((node % 2) == 0)
            {
                decomp_deg[node] = tree.tree[node / 2] - 1;
            }
            else
            {
                decomp_deg[node] = decomp_deg[node / 2] - tree.tree[node / 2];
            }
        }
    }
    for (int node = 1; node < tree_size; ++node)
    {
        if (tree.tree[node] == 0)
        {
            start_index[node] = temp_index;
            temp_index += decomp_deg[node] + 1;
        }
    }

    t[0] = make_unique<Ciphertext>();
    t[1] = make_unique<Ciphertext>();
    generate_t0_t1(encryptor, encoder, cipher, *t[0], *t[1]);

    for (int stage = 1; stage <= total_depth; ++stage)
    {
        for (int node = 1; node < tree_size; ++node)
        {
            if (tree.tree[node] == 0 && total_depth + 1 - num_one(node) == stage)
            {
                int coeff_index = static_cast<int>(start_index[node]);
                pt[node] = make_unique<Ciphertext>();
                multiply_const_reduced_error(
                    *t[1], decomp_coeff.at(static_cast<size_t>(coeff_index)), lazy_scale,
                    *pt[node], evaluator, encoder);
                coeff_index += 2;
                for (int cheb_degree = 3; cheb_degree <= decomp_deg[node]; cheb_degree += 2)
                {
                    if (!t[cheb_degree])
                    {
                        throw runtime_error("missing Chebyshev basis ciphertext");
                    }
                    Ciphertext term;
                    multiply_const_reduced_error(
                        *t[cheb_degree], decomp_coeff.at(static_cast<size_t>(coeff_index)),
                        lazy_scale, term, evaluator, encoder);
                    add_lazy_cipher_for_relu_reference(*pt[node], term, evaluator, encoder);
                    coeff_index += 2;
                }
                evaluator.rescale(*pt[node], *pt[node]);
                assign_scale_for_relu_reference(*pt[node], scale);
            }
        }

        for (int node = 1; node < tree_size; ++node)
        {
            if (tree.tree[node] > 0 && total_depth + 1 - num_one(node) == stage &&
                (node % 2) == 1)
            {
                long walk = node;
                pt[node] = make_unique<Ciphertext>();
                evaluator.multiply_relin_dynamic(*t[tree.tree[walk]], *pt[2 * walk + 1],
                                                *pt[node], relin_keys);
                assign_scale_for_relu_reference(*pt[node], lazy_scale);
                walk *= 2;
                while (true)
                {
                    if (tree.tree[walk] == 0)
                    {
                        break;
                    }
                    Ciphertext term;
                    evaluator.multiply_relin_dynamic(*t[tree.tree[walk]], *pt[2 * walk + 1], term,
                                                    relin_keys);
                    assign_scale_for_relu_reference(term, lazy_scale);
                    add_lazy_cipher_for_relu_reference(*pt[node], term, evaluator, encoder);
                    walk *= 2;
                }
                evaluator.rescale(*pt[node], *pt[node]);
                assign_scale_for_relu_reference(*pt[node], scale);
                add_lazy_cipher_for_relu_reference(*pt[node], *pt[walk], evaluator, encoder);
            }
        }

        if (stage <= tree.m - 1)
        {
            const int cheb_degree = pow2(stage);
            t[cheb_degree] = make_unique<Ciphertext>();
            eval_t_for_relu_reference(evaluator, relin_keys, encoder, *t[cheb_degree],
                                      *t[pow2(stage - 1)], *t[pow2(stage - 1)], *t[0]);
        }
        if (stage <= tree.l)
        {
            for (int cheb_degree = pow2(stage - 1) + 1; cheb_degree <= pow2(stage) - 1;
                 cheb_degree += 2)
            {
                t[cheb_degree] = make_unique<Ciphertext>();
                eval_t_for_relu_reference(evaluator, relin_keys, encoder, *t[cheb_degree],
                                          *t[pow2(stage - 1)],
                                          *t[cheb_degree - pow2(stage - 1)],
                                          *t[pow2(stage) - cheb_degree]);
            }
        }
    }

    if (!pt[1])
    {
        throw runtime_error("tree polynomial evaluation failed to produce root ciphertext");
    }
    return *pt[1];
}

double eval_chebyshev_decomposed_plain(double input, long degree,
                                       const vector<double> &decomp_coeff,
                                       const Tree &tree)
{
    if (tree.type != EvalType::OddBaby)
    {
        throw invalid_argument("plain relu reference only supports oddbaby tree");
    }

    const int tree_size = 1 << (tree.depth + 1);
    vector<long> decomp_deg(static_cast<size_t>(tree_size), -1);
    vector<long> start_index(static_cast<size_t>(tree_size), -1);

    decomp_deg[1] = degree;
    long coeff_start = 1;
    for (int level = 1; level <= tree.depth; ++level)
    {
        for (int node = 1 << level; node < (1 << (level + 1)); ++node)
        {
            if ((node % 2) == 0)
            {
                decomp_deg[node] = tree.tree[node / 2] - 1;
            }
            else
            {
                decomp_deg[node] = decomp_deg[node / 2] - tree.tree[node / 2];
            }
        }
    }
    for (int node = 1; node < tree_size; ++node)
    {
        if (tree.tree[node] == 0)
        {
            start_index[node] = coeff_start;
            coeff_start += decomp_deg[node] + 1;
        }
    }

    vector<double> cheb(static_cast<size_t>(degree + 1), 0.0);
    cheb[0] = 1.0;
    if (degree >= 1)
    {
        cheb[1] = input;
    }
    for (long i = 2; i <= degree; ++i)
    {
        cheb[static_cast<size_t>(i)] =
            2.0 * input * cheb[static_cast<size_t>(i - 1)] -
            cheb[static_cast<size_t>(i - 2)];
    }

    function<double(int)> eval_node = [&](int node) -> double {
        if (node <= 0 || node >= tree_size)
        {
            throw invalid_argument("plain relu tree node is out of range");
        }
        if (tree.tree[node] == 0)
        {
            int coeff_index = static_cast<int>(start_index[node]);
            double result =
                cheb[1] * decomp_coeff.at(static_cast<size_t>(coeff_index));
            coeff_index += 2;
            for (int cheb_degree = 3; cheb_degree <= decomp_deg[node];
                 cheb_degree += 2)
            {
                result += cheb[static_cast<size_t>(cheb_degree)] *
                          decomp_coeff.at(static_cast<size_t>(coeff_index));
                coeff_index += 2;
            }
            return result;
        }

        const int split_degree = tree.tree[node];
        return cheb[static_cast<size_t>(split_degree)] * eval_node(2 * node + 1) +
               eval_node(2 * node);
    };

    return eval_node(1);
}

} // namespace

Tree::Tree()
{
    clear();
}

Tree::Tree(EvalType eval_type)
{
    clear();
    type = eval_type;
}

void Tree::clear()
{
    depth = 0;
    type = EvalType::None;
    m = 0;
    l = 0;
    b = 0;
    tree.assign(2, 0);
    tree[0] = -1;
    tree[1] = 0;
}

void Tree::merge(const Tree &lhs, const Tree &rhs, int g)
{
    clear();
    if (lhs.type != rhs.type)
    {
        throw invalid_argument("tree types do not match");
    }

    type = lhs.type;
    depth = max(lhs.depth, rhs.depth) + 1;
    tree.assign(static_cast<size_t>(1U << (depth + 1)), -1);
    tree[0] = -1;
    tree[1] = g;

    for (int i = 1; i <= (1 << (lhs.depth + 1)) - 1; ++i)
    {
        const int offset = 1 << static_cast<int>(log2(static_cast<double>(i)));
        tree[i + offset] = lhs.tree[i];
    }
    for (int i = 1; i <= (1 << (rhs.depth + 1)) - 1; ++i)
    {
        const int offset = 1 << static_cast<int>(log2(static_cast<double>(i)));
        tree[i + 2 * offset] = rhs.tree[i];
    }
}

void upgrade_oddbaby(long degree, Tree &tree)
{
    const long depth = static_cast<long>(ceil(log(static_cast<double>(degree)) / log(2.0)) + 0.5);
    long total_min = 10000;
    long min_m = 0;
    long min_l = 0;
    Tree total_min_tree(EvalType::OddBaby);

    for (long l = 1; pow2_int(static_cast<int>(l)) - 1 <= degree; ++l)
    {
        for (long m = 1; pow2_int(static_cast<int>(m - 1)) < degree; ++m)
        {
            vector<vector<int>> f(static_cast<size_t>(degree + 1),
                                  vector<int>(static_cast<size_t>(depth + 1), 0));
            vector<vector<Tree>> g(static_cast<size_t>(degree + 1),
                                   vector<Tree>(static_cast<size_t>(depth + 1),
                                                Tree(EvalType::OddBaby)));
            f[1][1] = 0;
            for (int i = 3; i <= degree; i += 2)
            {
                f[i][1] = 10000;
            }

            for (int j = 2; j <= depth; ++j)
            {
                for (int i = 1; i <= degree; i += 2)
                {
                    if (i <= pow2_int(static_cast<int>(l)) - 1 && i <= pow2_int(j - 1))
                    {
                        f[i][j] = 0;
                        continue;
                    }

                    int best = 10000;
                    Tree best_tree;
                    for (int k = 1; k <= m - 1 && pow2_int(k) < i && k < j; ++k)
                    {
                        const long split = pow2_int(k);
                        const int candidate = f[i - split][j - 1] + f[split - 1][j] + 1;
                        if (candidate < best)
                        {
                            best = candidate;
                            best_tree.merge(g[split - 1][j], g[i - split][j - 1],
                                            static_cast<int>(split));
                        }
                    }
                    f[i][j] = best;
                    g[i][j] = best_tree;
                }
            }

            const int candidate_total = f[degree][depth] + pow2_int(static_cast<int>(l - 1)) +
                                        static_cast<int>(m) - 2;
            if (candidate_total < total_min)
            {
                total_min = candidate_total;
                total_min_tree = g[degree][depth];
                min_m = m;
                min_l = l;
            }
        }
    }

    tree = total_min_tree;
    tree.type = EvalType::OddBaby;
    tree.m = static_cast<int>(min_m);
    tree.l = static_cast<int>(min_l);
}

void upgrade_baby(long degree, Tree &tree)
{
    const long depth =
        static_cast<long>(ceil(log(static_cast<double>(degree + 1)) / log(2.0)) + 0.5);
    long total_min = 10000;
    long min_m = 0;
    long min_b = 0;
    Tree total_min_tree(EvalType::Baby);

    if (degree == 1)
    {
        tree = Tree(EvalType::Baby);
        tree.m = 1;
        tree.b = 1;
        return;
    }

    for (long b = 1; b <= degree; ++b)
    {
        for (long m = 1; pow2_int(static_cast<int>(m - 1)) * b <= degree; ++m)
        {
            vector<vector<int>> f(static_cast<size_t>(degree + 1),
                                  vector<int>(static_cast<size_t>(depth + 1), 0));
            vector<vector<Tree>> g(static_cast<size_t>(degree + 1),
                                   vector<Tree>(static_cast<size_t>(depth + 1),
                                                Tree(EvalType::Baby)));

            for (int j = 1; j <= depth; ++j)
            {
                for (int i = 1; i <= degree; ++i)
                {
                    if (i + 1 > pow2_int(j))
                    {
                        f[i][j] = 10000;
                        g[i][j] = Tree(EvalType::Baby);
                    }
                    else if (b == 1 && m >= 2 && i <= 2 && i <= pow2_int(j - 1))
                    {
                        f[i][j] = 0;
                        g[i][j] = Tree(EvalType::Baby);
                    }
                    else if (i <= b && i <= pow2_int(j - 1))
                    {
                        f[i][j] = 0;
                        g[i][j] = Tree(EvalType::Baby);
                    }
                    else
                    {
                        int best = 10000;
                        Tree best_tree;
                        for (int k = 2; k <= b; ++k)
                        {
                            const long split = k;
                            if (split <= pow2_int(j - 1) && split < i)
                            {
                                const int candidate =
                                    f[i - split][j - 1] + f[split - 1][j] + 1;
                                if (candidate < best)
                                {
                                    best = candidate;
                                    best_tree.merge(g[split - 1][j], g[i - split][j - 1], k);
                                }
                            }
                        }
                        for (int k = 0; k <= m - 1; ++k)
                        {
                            const long split = pow2_int(k) * b;
                            if (split <= pow2_int(j - 1) && split >= 2 && split < i)
                            {
                                const int candidate =
                                    f[i - split][j - 1] + f[split - 1][j] + 1;
                                if (candidate < best)
                                {
                                    best = candidate;
                                    best_tree.merge(g[split - 1][j], g[i - split][j - 1],
                                                    static_cast<int>(split));
                                }
                            }
                        }
                        f[i][j] = best;
                        g[i][j] = best_tree;
                    }
                }
            }

            const int candidate_total = f[degree][depth] + static_cast<int>(m + b - 2);
            if (candidate_total < total_min)
            {
                total_min = candidate_total;
                total_min_tree = g[degree][depth];
                min_m = m;
                min_b = b;
            }
        }
    }

    tree = total_min_tree;
    tree.type = EvalType::Baby;
    tree.m = static_cast<int>(min_m);
    tree.b = static_cast<int>(min_b);
}

std::vector<std::vector<double>> load_relu_component_coeffs(
    long alpha, const vector<int> &deg, const vector<Tree> &trees, double scaled_val)
{
    const fs::path local_root = fs::path(__FILE__).parent_path() / "relu_param";
    const fs::path fallback_root =
        fs::path(__FILE__).parent_path().parent_path() / "resnet18" / "relu_param";
    const fs::path relu_root = fs::exists(local_root) ? local_root : fallback_root;
    const fs::path relu_file = relu_root / ("d" + to_string(alpha) + ".txt");
    ifstream input(relu_file);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open relu parameter file: " + relu_file.string());
    }

    vector<vector<double>> coeffs;
    coeffs.reserve(deg.size());
    for (size_t component_index = 0; component_index < deg.size(); ++component_index)
    {
        const long component_coeff_count = coeff_number(deg[component_index], trees.at(component_index));
        vector<double> component;
        component.reserve(static_cast<size_t>(component_coeff_count));
        for (long i = 0; i < component_coeff_count; ++i)
        {
            double coeff = 0.0;
            if (!(input >> coeff))
            {
                throw std::runtime_error("failed to read relu coefficients from: " +
                                         relu_file.string());
            }
            component.emplace_back(coeff);
        }
        coeffs.emplace_back(std::move(component));
    }

    if (coeffs.size() >= 3)
    {
        for (double &coeff : coeffs[0])
        {
            coeff /= 2.0;
        }
        for (double &coeff : coeffs[1])
        {
            coeff /= scaled_val;
        }
        for (double &coeff : coeffs[2])
        {
            coeff *= 0.5;
        }
    }

    return coeffs;
}

void log_relu_component_coeffs(const vector<vector<double>> &coeffs, ostream &output)
{
    output << "  sign poly coeff counts:";
    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        output << " c" << (i + 1) << '=' << coeffs[i].size();
    }
    output << '\n';
}

double approximate_step_plain(double input, const vector<int> &deg, long alpha,
                              const vector<Tree> &tree, double scaled_val)
{
    if (deg.size() != tree.size())
    {
        throw invalid_argument("plain relu polynomial component count does not match tree config");
    }

    double result = input;
    static long cached_alpha = -1;
    static vector<int> cached_deg;
    static double cached_scaled_val = 0.0;
    static vector<vector<double>> cached_coeffs;
    if (cached_alpha != alpha || cached_deg != deg ||
        cached_scaled_val != scaled_val || cached_coeffs.empty())
    {
        cached_coeffs = load_relu_component_coeffs(alpha, deg, tree, scaled_val);
        cached_alpha = alpha;
        cached_deg = deg;
        cached_scaled_val = scaled_val;
    }
    for (size_t i = 0; i < cached_coeffs.size(); ++i)
    {
        result = eval_chebyshev_decomposed_plain(
            result, deg.at(i), cached_coeffs.at(i), tree.at(i));
    }
    return result + 0.5;
}

double approximate_relu_plain(double input, const vector<int> &deg, long alpha,
                              const vector<Tree> &tree, double scaled_val)
{
    return input * approximate_step_plain(input, deg, alpha, tree, scaled_val);
}

void assign_scale_for_relu_reference(Ciphertext &cipher, double scale)
{
    cipher.scale() = scale;
}

Ciphertext approximate_sign(const Ciphertext &input, const vector<int> &deg, long alpha,
                            const vector<Tree> &tree, double scaled_val, Encryptor &encryptor,
                            CKKSEncoder &encoder, EvaluatorCkksBase &evaluator,
                            RelinKeys &relin_keys)
{
    Ciphertext result = input;
    const vector<vector<double>> coeffs = load_relu_component_coeffs(alpha, deg, tree, scaled_val);

    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        result = eval_polynomial_integrate_for_relu_reference(
            result, deg.at(i), coeffs[i], tree.at(i), encryptor, evaluator, encoder, relin_keys);
    }

    evaluator.add_const(result, 0.5, result, encoder);

    return result;
}
