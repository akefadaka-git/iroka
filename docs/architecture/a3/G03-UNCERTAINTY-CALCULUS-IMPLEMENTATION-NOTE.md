# A3 G03 Uncertainty-Calculus Implementation Note

- Gene: `g03.uncertainty-calculus`
- Additive schema version: v1.1.0
- Method: registered weighted log-odds v1

## Implemented controls

1. Requires an exact registered calibration profile digest, validated status, calibration dataset digest, calibrator identity and current profile validity.
2. Binds inference ID, premise-set digest, profile digest, calculation method and method version in version-bound evidence.
3. Accepts only source-backed fact evidence for calibrated updates. Assumptions, hypotheses and unknown evidence remain unresolved and do not affect the posterior.
4. Checks source digest, provenance reference, canonical UTC observation time, future dating and validity interval.
5. Weight and reliability are finite and bounded to [0,1]. Support and refutation evidence are both retained; conflict is explicit.
6. Uses weighted log-odds with registered support/refutation likelihood ratios and profile probability bounds.
7. Reports normalized binary entropy as a mathematical uncertainty measure; it does not imply certainty or an autonomous decision.
8. Produces independent per-hypothesis estimates. Probabilities are not normalized across hypotheses and must not be interpreted as a mutually exclusive distribution.
9. No posterior is emitted when there is no informative valid fact evidence.
10. Every evidence item is either used or represented as unresolved; the calculation digest is reproducible.

## Calibration boundary

A profile is accepted only when its digest matches the policy registry and it is marked validated. This increment does not train or independently validate a calibration profile. Profile governance, calibration dataset provenance and independent statistical validation remain external policy/evidence responsibilities.
