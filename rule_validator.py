"""
rule_validator.py

Two jobs:
  1. Syntax-validate a generated YARA rule (does it compile?).
  2. Evaluate detection performance by running the rule against a folder of
     known-malicious samples and a folder of known-benign files, then reporting
     precision, recall, F1, accuracy and false-positive rate.

Usage:
    # syntax check only
    python rule_validator.py --rule ./eval_shell.yar

    # full evaluation
    python rule_validator.py --rule ./eval_shell.yar \
        --malicious ./datasets/malicious \
        --benign ./datasets/benign
"""

import os
import argparse
import yara


def validate_rule(rule_path):
    """Compile the rule to confirm it is syntactically valid.
    Returns the compiled rules object on success, or None on failure."""
    try:
        rules = yara.compile(filepath=rule_path)
        print("SYNTAX VALID: Rule compiled successfully")
        return rules
    except yara.SyntaxError as e:
        print("SYNTAX ERROR:", e)
        return None


def _iter_files(folder):
    """Yield every file path under a folder (recursively)."""
    for root, _dirs, files in os.walk(folder):
        for name in files:
            yield os.path.join(root, name)


def _count_hits(rules, folder):
    """Run the compiled rule against every file in a folder.
    Returns (matched, total) where matched = files the rule flagged."""
    matched = 0
    total = 0
    for path in _iter_files(folder):
        total += 1
        try:
            if rules.match(path):
                matched += 1
        except yara.Error as e:
            print(f"  [skip] could not scan {path}: {e}")
    return matched, total


def evaluate_rule(rules, malicious_dir, benign_dir):
    """Score a compiled rule against malicious (positive) and benign (negative)
    datasets and print a full confusion matrix + metrics."""
    # Malicious folder: a match is a True Positive, a miss is a False Negative.
    tp, n_malicious = _count_hits(rules, malicious_dir)
    fn = n_malicious - tp

    # Benign folder: a match is a False Positive, a miss is a True Negative.
    fp, n_benign = _count_hits(rules, benign_dir)
    tn = n_benign - fp

    # Metrics (guard against divide-by-zero).
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    accuracy = ((tp + tn) / (tp + tn + fp + fn)
                if (tp + tn + fp + fn) else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print("\n=== Confusion Matrix ===")
    print(f"  Malicious samples: {n_malicious}  |  Benign samples: {n_benign}")
    print(f"  True Positives (TP):  {tp}")
    print(f"  False Negatives (FN): {fn}   <- malicious files the rule missed")
    print(f"  False Positives (FP): {fp}   <- benign files the rule wrongly flagged")
    print(f"  True Negatives (TN):  {tn}")

    print("\n=== Metrics ===")
    print(f"  Precision:            {precision:.3f}")
    print(f"  Recall:               {recall:.3f}")
    print(f"  F1-Score:             {f1:.3f}")
    print(f"  Accuracy:             {accuracy:.3f}")
    print(f"  False Positive Rate:  {fpr:.3f}")

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": f1, "accuracy": accuracy, "fpr": fpr,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate and evaluate an LLM-generated YARA rule.")
    parser.add_argument("--rule", default="./eval_shell.yar",
                        help="Path to the YARA rule file.")
    parser.add_argument("--malicious",
                        help="Folder of known-malicious samples (positive set).")
    parser.add_argument("--benign",
                        help="Folder of known-benign files (negative set).")
    args = parser.parse_args()

    # Step 1: always syntax-check first.
    rules = validate_rule(args.rule)
    if rules is None:
        return  # bad syntax -> nothing to evaluate

    # Step 2: if both datasets are given, run the full evaluation.
    if args.malicious and args.benign:
        evaluate_rule(rules, args.malicious, args.benign)
    else:
        print("\n(No --malicious/--benign folders given; syntax check only.)")


if __name__ == "__main__":
    main()
