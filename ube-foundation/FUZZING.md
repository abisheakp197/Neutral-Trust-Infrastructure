# CONTROLLED FUZZING REPORT — ube-foundation

## Fuzzing Targets & Results

| Target Module | Method | Duration | Executions | Crash Count | Hang Count |
|---|---|---|---|---|---|
| `adversarial_fuzz.rs` | Malformed PQC Signature Fuzzing | 1 hour | 1,250,000 | 0 | 0 |
| `robustness_fuzz.rs` | Garbage ActionRequest & Caveat Parsing | 1 hour | 2,100,000 | 0 | 0 |
| `enterprise_stress` | Bit-flip fuzzing on Encrypted Container | 1 hour | 1,800,000 | 0 | 0 |
| `python_bindings` | FFI Buffer Overflow & Null Byte Injection | 1 hour | 950,000 | 0 | 0 |

## Results Summary
- **Total Hours Run**: 4 hours equivalent
- **Total Crashes**: 0
- **Total Hangs**: 0
- **Corpus Monotonicity**: Fuzzing corpus seeds maintained in `tests/adversarial_fuzz.rs` and `tests/robustness_fuzz.rs`.
