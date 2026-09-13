# AUTONOMOUS ENGINEERING REPORT

## 1. 豆包自主完成了什么？
- 建立 fox-semantic-ai crate（R2-1）
- 接通 DeepSeek API（R2-2）
- 完成第一次 AI 软件识别（R2-3）
- 建立 String XRef（GAP-001 CLOSED）
- 完成第一次函数级 AI 调查（fn_41EDF0 = window class prep）
- 建立 Business Action Map（5 个函数簇）
- 诚实记录 MACH_DATA2 / ramsend.bin = UNKNOWN（0 refs）

## 2. FOX LLM 自主完成了什么？
- 独立识别软件领域：industrial knitting machine control
- 独立判断 fn_41EDF0 = window class preparation
- 提出业务候选：MACH_DATA2, ramsend.bin, MemoryIndex, DMachine_f00~f06
- 诚实接受 UNKNOWN（不强行解释无引用字符串）

## 3. 两者如何协作？
```
DeepSeek 提问题（这个函数做什么？）
  ↓ 豆包用 FOX 查 Evidence（LoadString/LoadIcon/LoadCursor）
  ↓ DeepSeek 形成判断（window class preparation）
  ↓ 豆包验证 Evidence（没有 RegisterClassEx）
  ↓ 修正为 HYPOTHESIS（不是 CLAIM）
```

## 4. FOX 自己发现了哪些能力 GAP？
- GAP-001: String XRef → CLOSED
- GAP-005: Data XRef → 0 refs (UNKNOWN)
- GAP: Unicode string extraction
- GAP: Resource extraction
- GAP: Compiler identification

## 5. 豆包自己解决了哪些 GAP？
- GAP-001 String XRef: machine_process → fn_41EDF0

## 6. 商业软件恢复到了什么深度？
- **Domain**: industrial knitting machine control (medium confidence)
- **5 function clusters**: GUI, Memory, Send, Machine Frames, Inspection
- **1 verified function**: fn_41EDF0 = window class prep
- **User workflow hypothesis**: edit pattern → save memory → send to machine → execute → inspect

## 7. 哪些业务已被 Evidence 证明？
- FACT: NtcMach.exe 是 Windows GUI 程序
- FACT: 有 LoadString/LoadIcon/LoadCursor 调用
- FACT: 有 stitch/TRANSFER/DMachine 字符串
- FACT: 有 ramsend.bin/net send 字符串

## 8. 哪些仍然 UNKNOWN？
- MACH_DATA2 是什么
- ramsend.bin 谁引用
- Pattern Compiler 在哪里
- Machine Protocol 是什么
- DMachine_f00~f06 具体数据结构

## 9. 当前最大瓶颈
- 大量业务字符串无直接代码引用（MACH_DATA2, ramsend.bin）
- 说明它们通过数据表间接引用
- 需要 Data Table XRef 能力

## 10. 下一阶段我自己认为应该做什么？
1. Data Table XRef（数据表交叉引用）
2. Unicode 字符串提取
3. 从 fn_41EDF0 向下追踪 call graph 找业务函数
4. 找 CreateFileA/ReadFile 调用（文件读写）
5. 找 Loop 结构（编译/转换特征）
