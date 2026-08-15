#!/usr/bin/env python3
"""Run the five-configuration eval on the built-in demo tasks and print the report."""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from callosum.eval import demo_tasks, run_eval

base = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="callosum_eval_")
report = run_eval(base, demo_tasks())
print(json.dumps(report["summary"], indent=2))
print(f"\nfull report: {base}/eval_report.json")
