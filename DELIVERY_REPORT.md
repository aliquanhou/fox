# FOX 制版软件反编译交付报告

## 一、交付内容
- 14/14 PE 完整反编译 C 代码（约 16MB）
- MSVC cl /c 0 编译错误
- AI 语义分析报告
- 业务动作地图
- 自主工程报告

## 二、软件识别
**软件**: 工业针织机控制软件
**证据**: stitch, TRANSFER, DMachine_f00~f06, machine_process, ramsend.bin
**置信度**: medium

## 三、已恢复的业务模块
1. **GUI/Window** - fn_41EDF0 (LoadString/LoadIcon/LoadCursor)
2. **File I/O** - fn_41A870 (CreateFileA, ReadFile)
3. **Memory Management** - MemoryIndex, IsMemorySave
4. **Data Send** - ramsend.bin, net send
5. **Machine Frames** - DMachine_f00~f06
6. **Stitch Inspection** - chk_cams.bmp, chk_yarn.bmp

## 四、已知 UNKNOWN
- Pattern Compiler 具体实现
- Machine Protocol 协议格式
- 文件格式 (FSZ/BMZ/TBL/DAT)
- DMachine_f00~f06 数据结构
- MACH_DATA2 含义

## 五、FOX 能力状态
- PE Loader ✅
- CFG ✅
- SSA ✅
- CallGraph ✅
- DataFlow ✅
- C 反编译 ✅
- 14/14 PE 可编译 ✅
- AI 语义分析 ✅
- String XRef ✅
