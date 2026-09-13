# Batch Function Semantic Analysis
## NtcMach.exe - Top 7 Functions

| Function | Lines | Role | Confidence |
|---|---|---|---|
| fn_40A590 | 1322 | **Main control/command dispatcher** (UI message handler, state machine driving knitting operations, error dialogs, inter-window messaging) | medium |
| fn_42CC50 | 966 | **Pattern file processing / knitting program execution** (core data processing, likely pattern loading/interpretation) | low |
| fn_402B30 | 675 | **Core initialization / configuration** (machine parameters, hardware setup) | low |
| fn_401390 | 615 | **Startup / main application initialization** (early app setup, resource management) | low |
| fn_432290 | 380 | **Communication / serial-port handling** (handle-based I/O, supporting subsystem) | low |
| fn_41EDF0 | ~20 | **Window class registration/preparation** (WNDCLASSEX setup: string, icon, cursor) | high |
| fn_41A870 | ~20 | **File open/access helper** (open pattern/config/log file) | high |

## Key Insights
1. fn_40A590 是最大的函数，包含 MessageBoxA + SendMessageA → 主命令调度器
2. fn_42CC50 是第二大的，可能是 Pattern 处理核心
3. fn_401390 在低地址 → 启动/初始化
4. fn_41EDF0 和 fn_41A870 是小函数，但置信度高

## Next Steps
- [ ] Deep dive fn_40A590 (main dispatcher)
- [ ] Deep dive fn_42CC50 (pattern processing)
- [ ] Trace call graph from fn_40A590 to find business functions
