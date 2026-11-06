# DSH 金丝雀判决证据

作者 / 维护者：He Fangsheng (贺方升 / 贺去病; also known as Dosen)· [hequbing.com](https://www.hequbing.com)

离线、确定性地复核一份金丝雀发布清单：其中记录的 `promote`、`abort` 或 `pause` 是否必然由同一份显式、仅含哈希的策略与证据推出。

本插件**不执行发布、不查询线上指标、不认证回执、不授予权限、不证明统计显著性，也不证明用户结果正确**。证据缺失、陈旧、错绑、样本不足、暴露流量超限或时间顺序错误时，一律失败闭合到 `pause`。

它与相邻项目互补：`dsh-ankh-guard` 会监督实例、跑健康 canary 并自动回滚，本插件不操作实例；`dsh-artifact-promotion-proof` 证明晋级链，本插件复算晋级前判决；`dsh-deployment-rollback-proof` 证明事故后恢复收敛，本插件只判断当前证据应晋级、终止还是暂停；Argo Rollouts 是线上控制器，本插件是控制器无关的离线证据核验器。

清单固定 canary/baseline 制品摘要、环境、rollout/policy 回执、精确窗口、最大 canary 流量、最短窗口、观察者阈值、新鲜度和指标规则。每个指标在每个窗口都必须同时有 baseline 与 canary 固定点整数值及样本量。报告只含哈希、计数、时间、比较和判决。

```bash
npm test
node bin/dsh-canary-decision-proof.mjs verify examples/promote.json
```

DSH 工具为 `dsh_canary_decision_inspect` 和 `dsh_canary_decision_verify`；独立 MCP stdio 工具为 `canary_decision_inspect` 和 `canary_decision_verify`。写入仅限显式工作区相对 `artifactDir`，拒绝路径逃逸与符号链接，并执行内容寻址和写后回读验证。

