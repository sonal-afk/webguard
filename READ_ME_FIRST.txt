WebGuard - source code
======================

Start with README.md (setup) and DEMO.md (a 3-4 minute walkthrough).

Left out of this zip on purpose:
- Python virtual environments (install with requirements.txt / requirements-ml.txt)
- the fine-tuned CodeBERT weights (webguard/web_vuln_model, several hundred MB).
  Without them the rule engine still works; recreate them with
  webguard/train_web_model.py on benchmark/training_corpus.csv
- webguard/.env (copy webguard/.env.example and fill in your own values)
- the local SQLite database and logs

Benchmark: python benchmark/run_benchmark.py and python benchmark/realistic_set.py
Design decisions and evaluation notes: benchmark/DEFENSE.md
