# Decrypt Cypher Strings in malicious kemon.sys

kemon.sys 是 "双枪木马" 传播环节中的一个恶意驱动文件。其中用到的 100+ 字串都进行了自定义加密处理，以至于在 IDA 中无法静态分析。参考：
[“双枪”木马的基础设施更新及相应传播方式的分析](https://mp.weixin.qq.com/s/KHa5GyCvbZwXruv0uK6weA)

这里提供两个 IDAPython 脚本，以不同的姿势在 IDA 中将这批字符串批量解密：
1. 用 Python 实现解密算法，批量解密 ——> decrypt_drv_str.py；
2. 基于 [Flare-Emu](https://github.com/fireeye/flare-emu) 来用指令模拟的方式批量解密字符串 --> decrypt_drv_str_by_falre-emu.py。

