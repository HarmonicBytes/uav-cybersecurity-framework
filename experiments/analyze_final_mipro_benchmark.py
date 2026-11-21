"""Analyze 30-trial UAV cybersecurity pipeline CSV; generate paper-ready figures.

Usage (from repository root):
    python experiments/analyze_final_mipro_benchmark.py --input results/final_end_to_end_30_trials.csv

Outputs results/final_mipro_analysis/{summary.md,metrics.json,figure_*.png,figure_*.svg}
Requires: matplotlib, numpy (already typical in the research environment).
"""
import argparse
import csv
import json
import math
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

STAGES = {
    'AI inference': 'ai_inference_ms',
    'Authentication': 'authentication_ms',
    'PBFT consensus': 'consensus_stage_ms',
    'Central persistence': 'ledger_ms',
    'GCS replication': 'replication_ms',
    'Simulated response': 'response_ms',
}


def descriptives(data):
    a = np.asarray(data, dtype=float)
    if not np.all(np.isfinite(a)):
        raise ValueError('Non-finite values in timings')
    return {
        'n': int(a.size),
        'mean_ms': float(np.mean(a)),
        'median_ms': float(np.median(a)),
        'std_ms': float(np.std(a, ddof=1)) if a.size > 1 else None,
        'min_ms': float(np.min(a)),
        'max_ms': float(np.max(a)),
        'p95_ms': float(np.percentile(a, 95)),
    }


def finish_figure(fig, target, stem):
    fig.savefig(target / f'{stem}.png', dpi=300, bbox_inches='tight')
    fig.savefig(target / f'{stem}.svg', bbox_inches='tight')
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='results/final_end_to_end_30_trials.csv')
    parser.add_argument('--out', default='results/final_mipro_analysis')
    args = parser.parse_args()
    target = Path(args.out)
    target.mkdir(parents=True, exist_ok=True)
    with Path(args.input).open(newline='', encoding='utf-8-sig') as file:
        rows = list(csv.DictReader(file))
    if not rows:
        raise SystemExit('ERROR: CSV has no data rows')
    required = ['trial', 'status', 'total_pipeline_ms', 'replicated_validators', 'replicated_block_index', *STAGES.values()]
    missing = [c for c in required if c not in rows[0]]
    if missing:
        raise SystemExit('ERROR: Missing CSV columns: ' + ', '.join(missing))
    trials = np.array([int(r['trial']) for r in rows], dtype=int)
    if len(set(trials)) != len(trials):
        raise SystemExit('ERROR: Duplicate trial IDs')
    order = np.argsort(trials)
    trials = trials[order]
    rows = [rows[int(i)] for i in order]
    values = {}
    for name, column in [('Total pipeline', 'total_pipeline_ms'), *STAGES.items()]:
        values[name] = np.array([float(r[column]) for r in rows])
    success = sum(r['status'].upper() == 'SUCCESS' for r in rows)
    replicas = np.array([int(r['replicated_validators']) for r in rows])
    height = np.array([int(r['replicated_block_index']) for r in rows])
    stats = {name: descriptives(a) for name, a in values.items()}
    stats['trial_count'] = len(rows)
    stats['success_count'] = success
    stats['success_rate'] = success / len(rows)
    stats['all_four_replicas'] = bool(np.all(replicas == 4))
    stats['ledger_height_first'] = int(height[0])
    stats['ledger_height_last'] = int(height[-1])
    stats['replication_share_of_mean_total_pct'] = float(100 * stats['GCS replication']['mean_ms'] / stats['Total pipeline']['mean_ms'])

    # Trial-level figure; stages share axis in ms, enabling easy comparison.
    fig, ax = plt.subplots(figsize=(7.0, 3.4))
    for name in ('Total pipeline', 'GCS replication', 'PBFT consensus'):
        ax.plot(trials, values[name], marker='o', markersize=2.5, linewidth=1.3, label=name)
    ax.set(xlabel='Trial', ylabel='Latency (ms)', title='End-to-end latency across 30 trials')
    ax.legend(frameon=False, fontsize=8)
    ax.grid(alpha=0.25)
    finish_figure(fig, target, 'figure_1_trial_latencies')

    # Distribution figure.
    fig, ax = plt.subplots(figsize=(6.6, 3.3))
    ax.hist(values['Total pipeline'], bins='auto', edgecolor='black', linewidth=0.6)
    ax.axvline(np.median(values['Total pipeline']), linestyle='--', linewidth=1.5,
               label=f"Median {np.median(values['Total pipeline']):.1f} ms")
    ax.set(xlabel='End-to-end latency (ms)', ylabel='Trial count', title='Pipeline latency distribution')
    ax.legend(frameon=False, fontsize=8)
    finish_figure(fig, target, 'figure_2_latency_distribution')

    # Stage mean bars (distinct from total; stages may not sum exactly due to instrumentation).
    labels = list(STAGES.keys())
    means = [stats[label]['mean_ms'] for label in labels]
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    y = np.arange(len(labels))
    ax.barh(y, means, edgecolor='black', linewidth=0.4)
    ax.set_yticks(y, labels=labels)
    ax.invert_yaxis()
    ax.set(xlabel='Mean stage latency (ms)', title='Mean pipeline-stage latency')
    for idx, v in enumerate(means):
        ax.text(v + max(means) * 0.012, idx, f'{v:.1f}', va='center', fontsize=8)
    ax.set_xlim(0, max(means) * 1.18)
    finish_figure(fig, target, 'figure_3_stage_means')

    # Replication latency against increasing chain height.
    fig, ax = plt.subplots(figsize=(6.6, 3.3))
    ax.scatter(height, values['GCS replication'], s=22)
    if len(np.unique(height)) > 1:
        slope, intercept = np.polyfit(height, values['GCS replication'], 1)
        xx = np.linspace(height.min(), height.max(), 100)
        ax.plot(xx, slope * xx + intercept, linestyle='--', linewidth=1.2, label='Exploratory linear trend')
        ax.legend(frameon=False, fontsize=8)
        stats['replication_height_trend_ms_per_block'] = float(slope)
    ax.set(xlabel='Replicated block index', ylabel='Replication latency (ms)',
           title='Replication latency versus ledger height')
    ax.grid(alpha=0.25)
    finish_figure(fig, target, 'figure_4_ledger_growth')

    def cell(name):
        d = stats[name]
        return f"| {name} | {d['mean_ms']:.2f} | {d['median_ms']:.2f} | {d['std_ms']:.2f} | {d['p95_ms']:.2f} | {d['min_ms']:.2f} | {d['max_ms']:.2f} |"

    report = [
        '# Final end-to-end benchmark statistics', '',
        f"Source: `{args.input}`", '',
        f"Trials: {len(rows)}; successful: {success}; observed success rate: {100*success/len(rows):.1f}%.",
        f"Four replicas in every trial: {'yes' if stats['all_four_replicas'] else 'no'}.",
        f"Replicated block indices: {height[0]}–{height[-1]}.", '',
        '| Metric | Mean (ms) | Median (ms) | SD (ms) | P95 (ms) | Min (ms) | Max (ms) |',
        '|---|---:|---:|---:|---:|---:|---:|',
        *[cell(name) for name in values], '',
        f"Replication as percentage of mean total latency: {stats['replication_share_of_mean_total_pct']:.1f}%.",
        '', '## Figures', '',
        '1. `figure_1_trial_latencies` — trial-by-trial pipeline, replication and consensus latency.',
        '2. `figure_2_latency_distribution` — observed end-to-end latency distribution.',
        '3. `figure_3_stage_means` — per-stage means.',
        '4. `figure_4_ledger_growth` — exploratory ledger-height relationship.', '',
        '## Interpretation and limitations', '',
        '- The trials use a synthetic telemetry-driven anomaly, not a live UAV flight.',
        '- Network timing is a local four-process prototype; do not generalize to geographic GCS deployment.',
        '- Defensive actions are simulated; no UAV actuator or on-chain smart contract execution is demonstrated.',
        '- A 30/30 success result does not imply fault-free operation or a 100% population success probability.',
        '- The regression test count is separate from the end-to-end trial count.',
        '- Trial number and ledger height both increase; the exploratory height slope is not a causal estimate.',
        '- Startup/model initialization is excluded from total pipeline latency.',
        '- Results depend on the hardware, process load, ledger height, and test configuration.',
    ]
    (target / 'summary.md').write_text('\n'.join(report) + '\n', encoding='utf-8')
    (target / 'metrics.json').write_text(json.dumps(stats, indent=2) + '\n', encoding='utf-8')
    print('\n'.join(report[:18]))
    print(f'\nCreated figures, stats and manuscript summary in {target.resolve()}')


if __name__ == '__main__':
    main()
