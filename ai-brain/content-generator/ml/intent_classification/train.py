from __future__ import annotations

import argparse

from .evaluation import format_report
from .pipeline import DEFAULT_MODEL_TYPE, METADATA_PATH, MODEL_PATH, MODEL_TYPES, train_and_persist


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the attacker intent classifier and report how it scores")
    parser.add_argument(
        "--model-type",
        choices=MODEL_TYPES,
        default=DEFAULT_MODEL_TYPE,
        help="Classifier backend",
    )
    args = parser.parse_args()

    artifact = train_and_persist(model_type=args.model_type)
    print(f"Trained {artifact['model_name']} on {artifact['training_samples']} windows -> {MODEL_PATH}")
    print(f"Metadata -> {METADATA_PATH}\n")
    for reports in artifact["evaluation"].values():
        for report in reports.values():
            print(format_report(report))
            print()


if __name__ == "__main__":
    main()
