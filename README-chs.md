FrancEnigma是一个实验性的学生代码作品，其为对称加密算法。通过结合第二次世界大战时期德国的加密机器——恩尼格玛（Enigma）的原理与现代计算机的字节与块加密，它实现了一个自制的加密算法。因为只是个人项目，且无性能优化，不建议用于实际加密场景。

# 核心架构
本算法在经典恩尼格玛机“转子-反射器”结构的基础上，融入了现代密码学的安全机制，构建了一个具备完整性校验的混合加密流程：
- 基于 Enigma 的核心流密码。
    - 转子 (Rotors)：动态生成 16 个字节级转子（每个转子包含 0-255 的全排列），使用 Fisher-Yates 洗牌算法和基于 SHA-256/SHAKE-128 的确定性随机数生成器 (`HashRandom`) 进行初始化。
    - 步进机制 (Rotation)：通过可变步长 (`rotation_strength`) 驱动转子转动，并实现了类似于机械恩尼格玛机的进位机制。
    - 反射器/转换 (Conversion)：模拟恩尼格玛机的反射板，在电流折返时进行异或变换。
- 扩散层 (Diffusion)：
    - 在进入 Enigma 核心加密前，对明文进行多轮的扩散操作，包括位置置换、动态模加和异或链。这一步极大增强了算法对明文微小变化的雪崩效应。
- 现代密钥派生：
    - 使用`PBKDF2-HMAC-SHA256`（迭代 1 000 000 次）将用户提供的密钥和随机盐扩展为加密密钥 (Cryption Key) 和认证密钥 (MAC Key)。
- 消息认证码 (MAC)：
    - 采用 Encrypt-then-MAC 架构，利用`HMAC-SHA3-512`和`SHAKE-256`对密文生成 16 字节的认证标签，确保数据在传输或存储过程中未被篡改。

# 加密流程
加密过程如下：
1. **生成随机盐**：获取 16 字节随机盐。
2. **派生子密钥**：`PBKDF2(UserKey + Version, Salt)` -> `Cryption Key` & `MAC Key`。
3. **明文扩散**：`Diffusion(Plaintext, Cryption Key)` 进行混淆与扩散。
4. **Enigma 加密**：`FrancEnigma(Cryption Key)` 对扩散后的数据进行流加密。
5. **生成 MAC**：`MAC(Encrypted Data, MAC Key)` 生成认证标签。
6. **输出**：`Salt` + `Encrypted Data` + `MAC`。

# 技术信息
在Python 3.9+版本中运行。此程序仅依赖 Python 标准库，无需安装第三方库。
