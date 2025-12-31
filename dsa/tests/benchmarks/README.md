# Performance Benchmarks

This directory contains performance benchmarks for the ML-DSA and SLH-DSA implementations.

## Running Benchmarks

```bash
# Run all benchmarks
pytest tests/benchmarks/ -v --benchmark-only

# Run ML-DSA benchmarks only
pytest tests/benchmarks/bench_mldsa.py -v --benchmark-only

# Run SLH-DSA benchmarks only
pytest tests/benchmarks/bench_slhdsa.py -v --benchmark-only

# Save results to JSON
pytest tests/benchmarks/ --benchmark-only --benchmark-json=results.json

# Compare with previous run
pytest tests/benchmarks/ --benchmark-only --benchmark-compare
```

## Using Docker

```bash
make test-benchmarks
```

## Expected Performance

### ML-DSA (faster)

| Variant    | KeyGen   | Sign     | Verify   |
|------------|----------|----------|----------|
| ML-DSA-44  | ~0.1 ms  | ~0.2 ms  | ~0.1 ms  |
| ML-DSA-65  | ~0.2 ms  | ~0.4 ms  | ~0.2 ms  |
| ML-DSA-87  | ~0.3 ms  | ~0.6 ms  | ~0.3 ms  |

### SLH-DSA (slower, but smaller keys)

| Variant           | KeyGen   | Sign      | Verify   |
|-------------------|----------|-----------|----------|
| SLH-DSA-SHAKE-128f| ~1 ms    | ~10 ms    | ~1 ms    |
| SLH-DSA-SHAKE-128s| ~5 ms    | ~100 ms   | ~5 ms    |
| SLH-DSA-SHA2-128f | ~1 ms    | ~10 ms    | ~1 ms    |

*Note: Actual performance depends on hardware. 'f' variants are faster but have larger signatures.*

## Dependencies

```bash
pip install pytest-benchmark
```
