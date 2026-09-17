import pkg/metrics
import ../timestamps

declareGauge(promethei_proofs_per_period, "promethei proofs per period")

type SalesMetrics* = object
  currentPeriod: ProofPeriod
  proofsPerPeriod: int64

proc increaseNumberOfProofs*(metrics: var SalesMetrics, period: ProofPeriod) =
  if period > metrics.currentPeriod:
    if metrics.currentPeriod > 0'ProofPeriod:
      promethei_proofs_per_period.set(metrics.proofsPerPeriod)
    metrics.currentPeriod = period
    metrics.proofsPerPeriod = 0
  inc metrics.proofsPerPeriod
