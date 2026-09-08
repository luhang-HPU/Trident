# Qwen2.5-0.5B CPU 明文推理架构

本文档说明 `Trident/qwen` 中 C++ CPU 明文推理的完整数据流、张量形状、
算子边界和 KV Cache 生成流程。当前实现使用官方 Qwen2.5-0.5B Base
checkpoint，并已与 Hugging Face Transformers 完成逐层数值验证。

## 1. 整体数据流

```text
Token IDs [T]
   |
   v
Embedding Lookup
   |
   v
Hidden States [T, 896]
   |
   +--> Decoder Layer 0
   +--> Decoder Layer 1
   |        ...
   +--> Decoder Layer 23
   |
   v
Final RMSNorm [T, 896]
   |
   v
取最后一个 Token [1, 896]
   |
   v
LM Head: 896 -> 151936
   |
   v
Logits [1, 151936]
   |
   v
Argmax / Top-K
   |
   v
Next Token
```

其中 `T` 表示本次输入的 token 数量。当前 C++ 推理核心支持单序列推理，
即 `batch_size=1`。

## 2. 模型配置

当前使用的官方 checkpoint 配置如下：

| 参数 | 数值 |
|---|---:|
| 模型 | Qwen2.5-0.5B Base |
| Decoder 层数 | 24 |
| Hidden size | 896 |
| MLP intermediate size | 4864 |
| Query heads | 14 |
| KV heads | 2 |
| Head dimension | 64 |
| GQA 分组大小 | 7 |
| Vocabulary size | 151936 |
| 最大序列长度 | 32768 |
| RMSNorm epsilon | `1e-6` |
| RoPE theta | `1000000` |
| Checkpoint dtype | BF16 |
| Sliding window | 关闭 |
| Embedding/LM Head 权重共享 | 开启 |

GQA 分组大小为：

```text
query_group_size = num_attention_heads / num_key_value_heads
                 = 14 / 2
                 = 7
```

因此每 7 个 Query Head 共享一个 Key/Value Head。

## 3. 权重加载

C++ 首先读取：

```text
config.json
model.safetensors
```

`SafeTensorStore` 支持单文件和分片 checkpoint，并支持以下权重类型：

```text
F64
F32
F16
BF16
```

官方 Qwen2.5-0.5B 权重是 BF16。当前明文基准会在加载时将 BF16 转换为
`double`，之后所有主要 C++ 算子都使用 `Tensor<double>`。

需要加载的主要权重包括：

```text
model.embed_tokens.weight
model.layers.N.input_layernorm.weight
model.layers.N.self_attn.q_proj.weight/bias
model.layers.N.self_attn.k_proj.weight/bias
model.layers.N.self_attn.v_proj.weight/bias
model.layers.N.self_attn.o_proj.weight
model.layers.N.post_attention_layernorm.weight
model.layers.N.mlp.gate_proj.weight
model.layers.N.mlp.up_proj.weight
model.layers.N.mlp.down_proj.weight
model.norm.weight
```

该模型启用了 `tie_word_embeddings`，因此 LM Head 直接复用
`model.embed_tokens.weight`。

## 4. Token Embedding

输入是一维 token ID 数组：

```text
token_ids: [T]
```

Embedding 权重形状：

```text
[151936, 896]
```

对每个 token ID 从 Embedding 表中取出对应的一行：

```text
[T] -> [T, 896]
```

Embedding Lookup 仅进行索引和内存复制，不进行矩阵乘法。

当前 C++ 核心不实现 tokenizer。文本到 token ID 的转换由 Hugging Face
tokenizer 或其他上层组件完成。

## 5. Decoder Layer

每个 Decoder Layer 的完整数据流如下：

```text
input [T, 896]
   |
   v
Input RMSNorm
   |
   v
Q/K/V Linear Projection
   |
   v
Split Heads
   |
   v
RoPE(Q, K)
   |
   v
Causal GQA Attention
   |
   v
Merge Heads + Output Linear
   |
   v
Residual Add
   |
   v
Post-Attention RMSNorm
   |
   +--> Gate Linear --\
   |                  +--> SiLU(Gate) * Up
   +--> Up Linear ----/
                      |
                      v
                 Down Linear
                      |
                      v
                 Residual Add
                      |
                      v
              layer output [T, 896]
```

该结构重复执行 24 次，每层使用不同权重。

## 6. RMSNorm

对每个 token 的 896 个 hidden feature 计算：

```text
variance = mean(x^2)
inverse_rms = 1 / sqrt(variance + epsilon)
output = x * inverse_rms * weight
```

输入输出形状不变：

```text
[T, 896] -> [T, 896]
```

每个 Decoder Layer 包含两个 RMSNorm：

```text
input_layernorm
post_attention_layernorm
```

24 层之后还有一个 Final RMSNorm。

RMSNorm 涉及的基础操作：

```text
逐元素平方
按 hidden 维求和/平均
加 epsilon
平方根
倒数
逐元素乘法
```

## 7. Q/K/V 投影

归一化后的 hidden states 分别乘以 Q、K、V 权重：

```text
Q = X * Wq^T + bq
K = X * Wk^T + bk
V = X * Wv^T + bv
```

具体形状如下：

```text
X:  [T, 896]
Wq: [896, 896]  -> Q: [T, 896]
Wk: [128, 896]  -> K: [T, 128]
Wv: [128, 896]  -> V: [T, 128]
```

然后将最后一维拆成 Attention Head：

```text
Q: [T, 896] -> [T, 14, 64]
K: [T, 128] -> [T,  2, 64]
V: [T, 128] -> [T,  2, 64]
```

## 8. RoPE 位置编码

RoPE 只应用于 Q 和 K，不应用于 V：

```text
Q [T, 14, 64] -> RoPE(Q)
K [T,  2, 64] -> RoPE(K)
```

当前实现使用 Qwen split-half 旋转方式。每个 64 维 Head 被分成两个
32 维部分：

```text
x1' = x1 * cos(angle) - x2 * sin(angle)
x2' = x2 * cos(angle) + x1 * sin(angle)
```

其中：

```text
frequency[i] = theta^(-2i / head_dim)
angle = position * frequency[i]
```

Prefill 时 `position` 从 0 开始。Decode 时从当前 KV Cache 长度继续，
保证新 token 使用正确的位置。

## 9. Causal GQA Attention

每个 Query Head 使用以下 KV Head：

```text
kv_head = query_head / 7
```

Attention 计算为：

```text
score = Q * K^T / sqrt(64)
probability = softmax(score)
attention = probability * V
```

Softmax 使用数值稳定形式：

```text
softmax(x_i) = exp(x_i - max(x)) / sum(exp(x_j - max(x)))
```

因果约束通过可见 token 数量隐式实现：

```text
token 0 只能看到 token 0
token 1 能看到 token 0..1
token 2 能看到 token 0..2
...
```

因此当前实现不需要显式创建完整的 Causal Mask 矩阵。

Attention 输出形状：

```text
[T, 14, 64]
```

合并 Head：

```text
[T, 14, 64] -> [T, 896]
```

再执行输出投影：

```text
attention_output = attention * Wo^T
[T, 896] -> [T, 896]
```

最后执行 Attention 残差连接：

```text
post_attention = input + attention_output
```

## 10. MLP 与 SwiGLU

Attention 残差结果先经过 Post-Attention RMSNorm，然后执行两个并行投影：

```text
gate = X * Wgate^T
up   = X * Wup^T
```

形状为：

```text
X:    [T, 896]
gate: [T, 4864]
up:   [T, 4864]
```

SiLU 激活：

```text
SiLU(x) = x / (1 + exp(-x))
```

SwiGLU：

```text
activated = SiLU(gate) * up
```

Down Projection 将 intermediate size 降回 hidden size：

```text
[T, 4864] -> [T, 896]
```

最后执行 MLP 残差连接：

```text
layer_output = post_attention + mlp_output
```

## 11. Final RMSNorm 与 LM Head

24 个 Decoder Layer 执行完成后：

```text
final_hidden = FinalRMSNorm(hidden)
```

如果需要所有位置的 logits：

```text
[T, 896] -> [T, 151936]
```

生成时只计算最后一个 token：

```text
last_hidden: [1, 896]
lm_head:     [151936, 896]
logits:      [1, 151936]
```

由于 Embedding 和 LM Head 权重共享，实际计算相当于：

```text
logits = last_hidden * embedding_weight^T
```

## 12. Prefill

生成的第一次前向处理完整 Prompt：

```text
Prompt Token IDs [T]
   |
   v
24 层完整前向
   |
   +--> 每层保存 K Cache [T, 2, 64]
   +--> 每层保存 V Cache [T, 2, 64]
   |
   v
最后一个位置的 Logits [1, 151936]
```

这一步称为 Prefill。

## 13. KV Cache Decode

选择下一个 token 后，不再重新计算完整 Prompt，只输入一个新 token：

```text
New Token [1]
   |
   v
Embedding [1, 896]
   |
   v
每层生成新的 Q/K/V
   |
   +--> 新 K 追加到历史 K Cache
   +--> 新 V 追加到历史 V Cache
   |
   v
新 Q 对全部历史 K/V 做 Attention
   |
   v
Next Logits [1, 151936]
```

假设当前 Cache 长度为 `S`：

```text
Q:         [1, 14, 64]
K Cache:   [S,  2, 64]
V Cache:   [S,  2, 64]
```

使用 KV Cache 后，每次 Decode 不需要重新计算前面的 token。

当前 KV Cache 追加会重新分配并复制旧数据，数学结果正确，但长序列性能
还可以通过预分配或分块缓存进一步优化。

## 14. Greedy Generation

当前生成流程使用 Greedy Decoding：

```text
logits
   |
   v
argmax
   |
   v
next_token
   |
   v
使用 KV Cache 计算下一步
```

当前 C++ 核心尚未实现：

```text
temperature
top-p sampling
top-k sampling
repetition penalty
beam search
```

这些属于输出采样策略，不影响 Decoder 数学计算的正确性。

## 15. 基础算子清单

当前明文推理使用的基础操作如下：

| 类型 | 操作 |
|---|---|
| 权重加载 | BF16/F16/F32/F64 转 double |
| 数据访问 | Embedding Lookup |
| 线性代数 | Linear、矩阵向量乘法、点积 |
| 逐元素运算 | Add、Multiply、Bias Add |
| 归约 | Sum、Mean、Max |
| 归一化 | Square、Sqrt、Reciprocal |
| 激活 | Exp、SiLU、SwiGLU |
| Attention | QK、Scale、Softmax、Probability-V |
| 位置编码 | Sin、Cos、RoPE Rotation |
| 数据布局 | Reshape、Split Heads、Merge Heads |
| 缓存 | K/V Append、K/V Read |
| 输出 | Top-K、Argmax |

## 16. CPU 执行方式

当前实现：

```text
只使用 CPU
主要张量类型为 double
Linear 使用连续内存访问
Linear、Attention 和部分逐元素算子使用 OpenMP
不依赖 CUDA
不依赖 GPU
不链接 Poseidon 密文库
```

当前目标是保证算子边界清晰和结果可靠，尚未针对 CPU BLAS、NUMA、
量化或低精度推理做深度优化。

## 17. ExecutionTrace

`ExecutionTrace` 可以记录并导出以下中间节点：

```text
embedding
layer_N.input
layer_N.input_rmsnorm
layer_N.query_projection
layer_N.key_projection
layer_N.value_projection
layer_N.query_rope
layer_N.key_rope
layer_N.attention
layer_N.attention_output
layer_N.post_attention_residual
layer_N.post_attention_rmsnorm
layer_N.mlp_gate
layer_N.mlp_up
layer_N.mlp_swiglu
layer_N.mlp_output
layer_N.output
final_rmsnorm
last_token_logits
```

每个张量可以保存为原始 F64 文件，并在 `manifest.tsv` 中记录名称和形状。
这套节点将作为后续密文实现的逐算子误差参考。

## 18. Hugging Face 对照验证

运行：

```bash
python3 Trident/qwen/tools/validate_hf_checkpoint.py --threads 16
```

验证内容包括：

```text
Embedding
24 个 Decoder Layer 输出
Final RMSNorm
151936 维 Last-Token Logits
Top-5 Logits
8 步 Greedy Generation
Prefill
KV Cache Decode
```

当前官方 Qwen2.5-0.5B 对照结果：

```text
Embedding: 完全一致
Last-token logits 最大绝对误差: 约 1.32e-5
Top-5 token: 完全一致
8 步 Greedy token: 完全一致
整体结果: PASS
```

验证产物位于：

```text
Trident/qwen/validation_output
```

## 19. 明文算子到密文算子的映射

相对容易转换为同态计算的操作：

```text
Linear
Bias Add
Residual Add
明文常数乘法
```

需要重点设计 Packing 和 Ciphertext Rotation 的操作：

```text
矩阵乘法
按 hidden 维归约
Head 拆分与合并
RoPE
GQA 数据布局
KV Cache 布局
```

需要近似或协议配合的非线性操作：

```text
RMSNorm 的 inverse sqrt
SiLU 的 exp 和除法
Softmax 的 max、exp 和除法
Argmax/Top-K 的比较
```

Attention 中还包含：

```text
Encrypted Q x Encrypted K
Encrypted Probability x Encrypted V
```

这些是密文乘法深度、重线性化、Rescale 和 Bootstrap 规划的重点。

## 20. 建议的密文实现顺序

```text
1. 密文 Tensor 和 Packing 方案
2. Ciphertext-Plaintext Linear
3. Bias Add 和 Residual Add
4. RoPE 与 Slot Rotation
5. RMSNorm 多项式近似
6. Gate/Up/Down Linear
7. SiLU/SwiGLU 多项式近似
8. QK^T 与 GQA Attention 布局
9. Softmax 多项式近似
10. 单层 Encrypted Decoder
11. 多层误差和 Level Budget
12. 24 层完整推理
13. Encrypted KV Cache
14. Bootstrap 与长序列优化
```

每完成一个密文节点，都可以与 `ExecutionTrace` 导出的同名明文节点比较：

```text
最大绝对误差
平均绝对误差
RMSE
CKKS level
scale
noise budget
运行时间
```

这样可以在进入完整 24 层推理之前定位算子误差和参数问题。

## 21. 当前多 Token 密文 Softmax

明文参考仍使用第 9 节的标准稳定 Softmax。密文实现按可见 token 数量分三条路径：

```text
1 个 token: softmax 概率恒为 1，直接返回 V
2 个 token: p0 = sigmoid(s0 - s1)，O = V1 + p0 * (V0 - V1)
3 个及以上 token: 在线 logsumexp 递推
```

在线递推维护当前归一化常数 `L` 和加权输出 `O`：

```text
初始: L = s0, O = V0
delta = si - L
p = sigmoid(delta)
O = O + p * (Vi - O)
L = L + softplus(delta)
```

其中：

```text
sigmoid(x) = 1 / (1 + exp(-x))
softplus(x) = log(1 + exp(x))
```

这组递推在实数域与标准 Softmax 完全等价。CKKS 路径使用 Chebyshev 多项式分别近似
`sigmoid` 和 `softplus`，不解密 Q、K、V、分数、概率或 Attention 输出。

同一在线递推 step 的多个 `delta` 会先打包到尽可能少的密文中，再共同执行真实
Bootstrap。Bootstrap 输出为 level 18，拆回单行视图会再消耗 1 个 level；当前
degree-127 的 `sigmoid`/`softplus` 路径随后继续求值。输出聚合每次密文乘法消耗
1 个 level，在 level 不足时按需 Bootstrap。前 3 个 Decoder 层边界仍只保留：

```text
post_attention_refresh
output_refresh
```

后层 residual 的数值范围明显增大，因此 Qwen2.5-0.5B 使用官方 checkpoint 校准得到的
逐层自举幅值缩放。缩放输入会额外消耗 1 个 level，所以从 layer 2 开始还要在
post-Attention RMSNorm 后执行 `mlp_input_refresh`，为 SiLU、SwiGLU 和 Down Projection
以及缩放后的 `output_refresh` 补足深度。该调度同时用于单 token、多 token 和
`target/tc128` 路径。

当前回归覆盖：

```text
2 token 特化公式
4 token 完整因果 Attention
3 token KV-cache prefill/decode
官方 checkpoint 的 3、4、8 token 真实 CKKS 单层
官方 checkpoint 的 4 token 真实 CKKS 多层
官方 checkpoint 的 4 token layer 23 + Final RMSNorm 真实 Bootstrap
```

启用 `--log-file` 后，每个在线 Softmax step 都输出 `batch_step_N.delta_refresh`、
逐行的 `sigmoid`、
`softplus`、`aggregate_update` 以及按需 `aggregate_refresh` 的开始时刻、耗时、
密文数量和输入输出 level。

Final RMSNorm 使用 `[2.5, 55]` 上的 degree-31 inverse-square-root
Chebyshev 多项式。degree-31 会进入低深度 baby-step 求值路径；4-token、方差覆盖
`[6.2, 50]` 的密文回归中，CKKS 相对多项式参考的最大绝对误差约为 `5.6e-7`。

## 22. 多 Token 全模型真实密态运行

从 Poseidon 仓库根目录启动 4-token prefill、24 层 Qwen2.5-0.5B、真实 Bootstrap
和 1-token greedy 输出：

```bash
cd /home/guoshuai/github/poseidon

RUN_ID=$(date +%Y%m%d_%H%M%S)

nohup env OMP_NUM_THREADS=16 ./Trident/build/qwen/qwen_he_generate \
  --model Trident/qwen/pretrained_parameters/Qwen2.5-0.5B \
  --input-ids 9707,11,1246,525 \
  --max-new-tokens 1 \
  --max-layers 24 \
  --he-mode bootstrap \
  --bootstrap-layers 24 \
  --profile target \
  --tokens-per-cipher 4 \
  --log-file Trident/qwen/validation_output/qwen_he_generate_4token_target.log \
  > "Trident/qwen/validation_output/qwen_he_generate_4token_target_nohup_${RUN_ID}.log" \
  2>&1 < /dev/null &

echo $! | tee Trident/qwen/validation_output/qwen_he_generate_4token_target.pid
```

`target` 使用 `logN=16`、`log_slots=15` 和 tc128 参数检查。这里的
`--tokens-per-cipher 4` 只控制逻辑 token packing，不启用 compact/sparse Bootstrap；
每次刷新仍调用 Poseidon 的标准全槽 Bootstrap。

对于 `4/8/32/128` 等整数幅值缩放，自举前的除法仍使用一次高精度 rescale，
自举后的恢复乘法使用 Poseidon `multiply_const_direct`。恢复阶段不再额外消耗 level，
因此缩放后的边界自举稳定返回 level 19。target 的 layer 2 会先执行
`mlp_input_refresh`，避免 MLP 在 level 0 才进入 `output_refresh`。

## 23. 模型权重保密下的生成边界

最终协议要求客户端不能获得 embedding、LM Head 或其他模型参数。因此不能采用
“客户端解密 final hidden，再用明文 LM Head 计算 logits”的部署方式。目标边界固定为：

```text
客户端持有：CKKS 私钥
服务端持有：全部模型权重、CKKS 公钥、评估密钥和 Bootstrap 密钥

服务端：Enc(final hidden) * plaintext LM Head -> Enc(logits)
客户端：decrypt Enc(logits) -> plaintext logits -> argmax/sampling
```

LM Head 是密文与服务端明文权重的 Linear，输出仍在客户端公钥下加密，因此客户端
不需要得到权重，服务端也不能解密 hidden 或 logits。客户端会看到 logits；如果模型
隐私要求只暴露最终 token，还需要把 argmax/sampling 放入安全比较或双方计算协议中。

当前 `qwen_he_generate` 在 Final RMSNorm 后调用 `decrypt_tensor()`，随后执行明文
LM Head 和 `argmax`。这是单进程正确性验证边界，不满足这里定义的最终部署协议。
下一阶段需要增加专用密态 LM Head：

1. 从 packed final hidden 中密态提取最后一个 token；
2. 在服务端用明文 `lm_head` 权重执行密态矩阵乘；
3. 将 151936 个加密 logits 重新打包后交给客户端解密；
4. 客户端只执行 `argmax` 或 sampling，不加载任何模型权重；
5. 服务端继续持有并复用各层密态 KV-cache。

直接沿用 `token_stride=1024` 的通用 Linear 会产生
`ceil(151936 / 1024) = 149` 个 logits 密文，而且预编码全部对角线会占用大量内存。
实现时应增加流式或全槽 logits packing：每次只编码一个输出分块并及时释放临时明文，
或者使用 32768 个 slot 打包 logits，将返回密文数降低到约
`ceil(151936 / 32768) = 5`。这是一项独立的性能工程，不应通过把 LM Head 权重交给
客户端来绕过。

生成下一步还涉及 embedding lookup。若只要求模型权重保密，可以让客户端把选出的
token ID 发回服务端，由服务端查表并用客户端公钥加密 embedding；此方案会向服务端
暴露 token。若同时要求输入和输出 token 对服务端保密，则还需要密态查表、PIR/OT 或
其他安全双方计算协议，不能把 embedding 表复制给客户端。

## 24. 宽 Token Packing 优化

`qwen_he_generate` 支持通过 `--token-stride` 覆盖 profile 的逻辑 token block 宽度。
该参数只改变 CKKS slot 布局，不改变 `logN`、模数链或 tc128 安全检查。

对于 Qwen2.5-0.5B 的 4-token 输入，使用：

```text
slot_count        = 32768
token_stride      = 8192
tokens_per_cipher = 4
```

四个 token block 正好覆盖全部 slots。因为 `intermediate_size=4864 < 8192`，Gate、Up、
SiLU 和 SwiGLU 的布局从：

```text
旧布局：ceil(4864 / 1024) = 5 个密文
宽布局：ceil(4864 / 8192) = 1 个密文
```

Hidden、Q、K、V 和 Attention 输出原本就是一个密文，宽布局下仍保持一个密文。
4-token MLP 中间张量的有效 slot 利用率从约 `11.88%` 提高到 `59.38%`。

真实 target 运行命令在原命令上增加：

```bash
--token-stride 8192 --tokens-per-cipher 4
```

完整示例：

```bash
cd /home/guoshuai/github/poseidon

RUN_ID=$(date +%Y%m%d_%H%M%S)

nohup env OMP_NUM_THREADS=16 ./Trident/build/qwen/qwen_he_generate \
  --model Trident/qwen/pretrained_parameters/Qwen2.5-0.5B \
  --input-ids 9707,11,1246,525 \
  --max-new-tokens 1 \
  --max-layers 24 \
  --he-mode bootstrap \
  --bootstrap-layers 24 \
  --profile target \
  --token-stride 8192 \
  --tokens-per-cipher 4 \
  --log-file Trident/qwen/validation_output/qwen_he_generate_4token_wide.log \
  > "Trident/qwen/validation_output/qwen_he_generate_4token_wide_nohup_${RUN_ID}.log" \
  2>&1 < /dev/null &

echo $! | tee Trident/qwen/validation_output/qwen_he_generate_4token_wide.pid
```

每条 Decoder 和 Attention 操作日志现在还会输出：

```text
active_slots=<逻辑有效元素数>
slot_utilization=<active_slots / (ciphers * slot_count)>
```

例如 MLP Gate 的预期日志由：

```text
tokens=4 features=4864 ciphers=5 slot_utilization=0.11875
```

变为：

```text
tokens=4 features=4864 ciphers=1 slot_utilization=0.59375
```

宽布局已经通过小环 CKKS 的 Linear、SiLU、RoPE、RMSNorm、4-token Attention
数值回归，以及
Qwen2.5-0.5B 真实形状的密文数量检查。完整 24 层 target 宽布局尚未运行，因此实际
CPU 加速比例和长栈误差必须由新的带时间戳日志确认。更进一步的 fused QKV、fused
KV-cache 和 5-cipher LM Head 仍需要独立实现。

## 25. Attention Delta 批量 Bootstrap

4-token causal Attention 的四行分别包含 `0、1、2、3` 个在线更新，旧实现逐行执行：

```text
1 + 2 + 3 = 6 次 delta Bootstrap / layer
```

当前实现改为按 `key_token` 递推轮次调度。每一轮中所有已经可见该 key 的 query row
共享一个 packed delta 密文：

```text
batch step 1: row 1, row 2, row 3
batch step 2: row 2, row 3
batch step 3: row 3
```

在 `tokens_per_cipher=4` 时，4-token Attention 因而只执行：

```text
3 次 packed delta Bootstrap / layer
```

两 token 行仍使用原来的 dual-token sigmoid 配置；三 token 及以上的行仍使用原来的
online sigmoid/softplus 配置。批处理只共享 Bootstrap，不改变各行的 Softmax 公式或
多项式配置。没有启用刷新、只有一个 active row，或者布局只能容纳一个 token 时，
代码自动退回逐行路径。

小环宽布局回归会捕获 operation log，并断言 4-token 路径恰好出现 3 次
`.delta_refresh event=start`。当前回归结果为：

```text
wide_stride_attention delta_refresh_batches=3
wide_stride_attention max_abs约5.2e-7，tolerance=3e-3
```

对单 query 的自回归 decode，在线更新存在前后依赖，缓存长度为 `C` 时仍需要 `C`
个顺序 step；该场景要通过同时批处理多个独立请求来进一步提高 slot 利用率。

## 26. KV-cache 单 Token 无损追加

自回归 decode 每一步只会产生一个新的 K token 和一个新的 V token。旧的通用追加路径
会先把整个 cache 拆成单 token view，再重新打包；每个二值 slot mask 都需要一次
明文乘法和 rescale，因此会无谓消耗 level。

当前单 token 快速路径直接利用新密文未使用 token block 为零这一布局约束：

1. 若最后一个 cache 密文尚未装满，把新密文旋转到下一个 token block，直接执行密文
   加法。
2. 若最后一个 cache 密文已经装满，直接把新密文作为下一组追加。
3. 若新旧密文 level 相同，不执行 mask、rescale 或 Bootstrap；若 level 不同，只把较高
   level 的一方 drop 到共同的最低 level。

以 `tokens_per_cipher=4` 为例：

```text
2 -> 3 tokens: 1 cipher -> 1 cipher，level 不变
4 -> 5 tokens: 1 cipher -> 2 ciphers，level 不变
```

测试同时检查了解密值、cache token 数、密文数量以及 level 保持。prefill 直接写入空
cache，同样没有额外重打包开销。一次批量追加多个 token 的通用兼容路径目前仍使用
拆分和重打包；正常的逐 token decode 不会进入该路径。
