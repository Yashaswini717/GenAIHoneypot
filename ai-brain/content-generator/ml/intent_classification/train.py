from __future__ import annotations

import argparse

from .pipeline import METADATA_PATH, MODEL_PATH, train_and_persist


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Phase 3 attacker intent classifier")
    parser.add_argument(
        "--model-type",
        choices=["random_forest", "xgboost"],
        default="random_forest",
        help="Classifier backend",
    )
    args = parser.parse_args()

    artifact = train_and_persist(model_type=args.model_type)
    print(f"Trained {artifact['model_name']} and saved model to {MODEL_PATH}")
    print(f"Metadata saved to {METADATA_PATH}")


if __name__ == "__main__":
    main()
