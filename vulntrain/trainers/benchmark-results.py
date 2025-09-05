import json
from pathlib import Path

results_dir = Path("results")

print("\n===== Benchmark Results =====\n")

for model_dir in results_dir.iterdir():
    metrics_file = model_dir / "metrics.json"
    if metrics_file.exists():
        with open(metrics_file) as f:
            metrics = json.load(f)
        model_name = model_dir.name
        accuracy = metrics.get("accuracy", 0)
        f1 = metrics.get("f1", 0)
        print(f"Model: {model_name}")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Macro F1 : {f1:.4f}\n")
