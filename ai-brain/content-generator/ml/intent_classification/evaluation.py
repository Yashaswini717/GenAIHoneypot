"""Scores intent classifiers against the hand-labelled transcripts.

Every number this module reports is measured on `eval_transcripts.py`, never on
generated data: the training generator can only ever be as right as itself,
which is why the first version of this classifier scored 1.000 in
cross-validation while doing much worse on a real session.

Windows are built the way the sidecar builds them (brain_courier.py): the last
three commands, never fewer than two, carrying Cowrie-style timestamps at a
human or bot tempo. A window's label is the stage at its newest command.

Run from ai-brain/content-generator:

    python -m ml.intent_classification.evaluation
"""

from __future__ import annotations

import math
import random
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Optional

from core.intent_taxonomy import INTENT_CLASSES

from .eval_transcripts import TRANSCRIPTS, Transcript, resolved_labels

#: Commands per window. Mirrors CLASSIFY_WINDOW in the sidecar.
WINDOW = 3
#: The sidecar never classifies fewer than CLASSIFY_EVERY commands.
MIN_WINDOW = 2
#: ...and classifies again every CLASSIFY_EVERY commands, so the previous
#: classification a window can be told about is the one this many commands back.
CLASSIFY_EVERY = 2

#: Seconds between commands, by tempo.
_GAPS = {"bot": (0.3, 1.5), "human": (3.0, 30.0)}


@dataclass(frozen=True)
class Window:
    transcript: str
    split: str
    activity: dict
    label: str
    #: False when every command in the window is neutral, so its contents say
    #: nothing about the stage and no classifier could get it right on merit.
    informative: bool
    #: How many commands of the transcript the window reaches (its newest one).
    end: int = 0
    #: How many captured sessions the window's transcript stands for.
    weight: int = 1


def _timestamps(transcript: Transcript) -> list[str]:
    """The captured timestamps, or deterministic Cowrie-formatted ones at the transcript's tempo."""
    if transcript.stamps:
        return list(transcript.stamps)
    rng = random.Random(zlib.crc32(transcript.name.encode("utf-8")))
    low, high = _GAPS[transcript.tempo]
    moment = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc) + timedelta(minutes=rng.randint(0, 600))
    stamps = []
    for _ in transcript.steps:
        stamps.append(moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        moment += timedelta(seconds=rng.uniform(low, high))
    return stamps


def iter_windows(
    transcripts: Iterable[Transcript] = TRANSCRIPTS,
    split: Optional[str] = None,
) -> list[Window]:
    """Every window the sidecar would classify, across the chosen transcripts."""
    windows: list[Window] = []
    for transcript in transcripts:
        if split and transcript.split != split:
            continue
        commands = [command for command, _ in transcript.steps]
        neutral = [label is None for _, label in transcript.steps]
        labels = resolved_labels(transcript.steps)
        stamps = _timestamps(transcript)
        for end in range(MIN_WINDOW, len(commands) + 1):
            start = max(0, end - WINDOW)
            windows.append(
                Window(
                    transcript=transcript.name,
                    split=transcript.split,
                    activity={
                        "commands": commands[start:end],
                        "event_timestamps": stamps[start:end],
                    },
                    label=labels[end - 1],
                    informative=not all(neutral[start:end]),
                    end=end,
                    weight=transcript.weight,
                )
            )
    return windows


def wilson_interval(correct: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for an accuracy of correct/total.

    Reported beside every accuracy because the sets are small: 27 of 32 is
    0.844, but anything from about 0.68 to 0.93 is consistent with it, and a
    single window moves the point estimate by three points.
    """
    if total == 0:
        return 0.0, 0.0
    p = correct / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return max(0.0, centre - half), min(1.0, centre + half)


@dataclass
class Report:
    name: str
    labels: list[str] = field(default_factory=list)
    predictions: list[Optional[str]] = field(default_factory=list)
    informative: list[bool] = field(default_factory=list)
    weights: list[int] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.labels)

    @property
    def correct(self) -> int:
        return sum(p == y for p, y in zip(self.predictions, self.labels))

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    @property
    def coverage(self) -> float:
        """Share of windows the classifier answered at all (rules may abstain)."""
        return sum(p is not None for p in self.predictions) / self.total if self.total else 0.0

    @property
    def weighted_accuracy(self) -> Optional[float]:
        """Accuracy with each window counted once per captured session its
        script stands for: what live traffic would see, where one bot can be
        most of it. None when every window counts once anyway."""
        if all(weight == 1 for weight in self.weights):
            return None
        hits = sum(w for p, y, w in zip(self.predictions, self.labels, self.weights) if p == y)
        return hits / sum(self.weights)

    @property
    def informative_accuracy(self) -> float:
        pairs = [(p, y) for p, y, i in zip(self.predictions, self.labels, self.informative) if i]
        return sum(p == y for p, y in pairs) / len(pairs) if pairs else 0.0

    def per_class(self) -> dict[str, dict[str, float]]:
        """Precision, recall and F1 per intent. An abstention counts against recall."""
        stats: dict[str, dict[str, float]] = {}
        for intent in INTENT_CLASSES:
            tp = sum(p == intent and y == intent for p, y in zip(self.predictions, self.labels))
            predicted = sum(p == intent for p in self.predictions)
            actual = sum(y == intent for y in self.labels)
            precision = tp / predicted if predicted else 0.0
            recall = tp / actual if actual else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            stats[intent] = {"precision": precision, "recall": recall, "f1": f1, "support": actual}
        return stats

    @property
    def macro_f1(self) -> float:
        rows = [row for row in self.per_class().values() if row["support"]]
        return sum(row["f1"] for row in rows) / len(rows) if rows else 0.0

    def summary(self) -> dict[str, float]:
        low, high = wilson_interval(self.correct, self.total)
        summary = {
            "windows": self.total,
            "accuracy": round(self.accuracy, 3),
            "accuracy_ci95": [round(low, 3), round(high, 3)],
            "informative_accuracy": round(self.informative_accuracy, 3),
            "macro_f1": round(self.macro_f1, 3),
            "coverage": round(self.coverage, 3),
        }
        if self.weighted_accuracy is not None:
            summary["traffic_weighted_accuracy"] = round(self.weighted_accuracy, 3)
        return summary


def evaluate(
    predict: Callable[[dict], Optional[str]],
    windows: list[Window],
    name: str,
) -> Report:
    """Run `predict` over the windows. `predict` may return None to abstain."""
    report = Report(name=name)
    for window in windows:
        report.labels.append(window.label)
        report.predictions.append(predict(window.activity))
        report.informative.append(window.informative)
        report.weights.append(window.weight)
    return report


_SHORT = {
    "reconnaissance": "recon",
    "privilege_escalation": "privesc",
    "persistence": "persist",
    "lateral_movement": "lateral",
    "data_exfiltration": "exfil",
}


def format_report(report: Report) -> str:
    s = report.summary()
    low, high = s["accuracy_ci95"]
    lines = [
        f"{report.name}: accuracy {s['accuracy']:.3f} ({report.correct}/{report.total}, "
        f"95% CI {low:.2f}-{high:.2f}), informative-only {s['informative_accuracy']:.3f}, "
        f"macro-F1 {s['macro_f1']:.3f}, coverage {s['coverage']:.3f}"
        + (f", traffic-weighted {s['traffic_weighted_accuracy']:.3f}" if "traffic_weighted_accuracy" in s else ""),
        f"    {'intent':<9}{'prec':>6}{'recall':>8}{'f1':>6}{'n':>5}",
    ]
    for intent, row in report.per_class().items():
        lines.append(
            f"    {_SHORT[intent]:<9}{row['precision']:>6.2f}{row['recall']:>8.2f}"
            f"{row['f1']:>6.2f}{row['support']:>5}"
        )
    return "\n".join(lines)


def standard_predictors(classifier=None) -> dict[str, Callable[[dict], Optional[str]]]:
    """The three views worth comparing: rules alone, model alone, and the hybrid."""
    from .predict import get_intent_classifier, predict_intent_realtime
    from .rules import detect_intent_by_rules

    model = classifier or get_intent_classifier()

    def rules(activity: dict) -> Optional[str]:
        match = detect_intent_by_rules(activity)
        return match.intent if match else None

    def ml(activity: dict) -> Optional[str]:
        return model.predict(activity).predicted_intent

    def hybrid(activity: dict) -> Optional[str]:
        if classifier is None:
            return predict_intent_realtime(activity).intent
        match = detect_intent_by_rules(activity)
        return match.intent if match else model.predict(activity).predicted_intent

    return {"rules": rules, "ml": ml, "hybrid": hybrid}


def evaluate_with_session(
    predict: Callable[[dict, Optional[str]], Optional[str]],
    windows: list[Window],
    name: str,
) -> Report:
    """Like `evaluate`, but each window is told the intent predicted for its session before.

    That is the window CLASSIFY_EVERY commands back -- the classification the
    sidecar actually has in hand when it sends the next one -- and it is the
    *prediction*, right or wrong, so a mistake carries forward here exactly as
    it would live. Windows must arrive in transcript order, as iter_windows
    yields them.
    """
    report = Report(name=name)
    predicted: dict[tuple[str, int], Optional[str]] = {}
    for window in windows:
        previous = predicted.get((window.transcript, window.end - CLASSIFY_EVERY))
        prediction = predict(window.activity, previous)
        predicted[(window.transcript, window.end)] = prediction
        report.labels.append(window.label)
        report.predictions.append(prediction)
        report.informative.append(window.informative)
        report.weights.append(window.weight)
    return report


def session_predictor(classifier=None) -> Callable[[dict, Optional[str]], Optional[str]]:
    """The hybrid as deployed with the sidecar: rules, then the model given the previous intent."""
    from .predict import predict_intent_realtime
    from .rules import detect_intent_by_rules

    if classifier is None:
        return lambda activity, previous: predict_intent_realtime({**activity, "previous_intent": previous}).intent

    def predict(activity: dict, previous: Optional[str]) -> Optional[str]:
        match = detect_intent_by_rules(activity)
        if match:
            return match.intent
        return classifier.predict({**activity, "previous_intent": previous}).predicted_intent

    return predict


def run(classifier=None, splits: tuple[str, ...] = ("dev", "test", "holdout")) -> dict[str, dict[str, Report]]:
    """Evaluate every standard predictor, and the session-aware hybrid, on every split."""
    predictors = standard_predictors(classifier)
    session = session_predictor(classifier)
    results: dict[str, dict[str, Report]] = {}
    for split in splits:
        windows = iter_windows(split=split)
        if not windows:
            continue  # a split with no transcripts (between holdouts) would report 0/0
        reports = {name: evaluate(fn, windows, f"{split}/{name}") for name, fn in predictors.items()}
        reports["session"] = evaluate_with_session(session, windows, f"{split}/session")
        results[split] = reports
    return results


if __name__ == "__main__":  # pragma: no cover - manual report
    for split_reports in run().values():
        for report in split_reports.values():
            print(format_report(report))
            print()
