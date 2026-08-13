"""Prompt Injection Defense Benchmark Evaluator for AI-Vault."""

import json
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.guardrails import PromptInjectionDetector


def run_benchmark() -> None:
    payloads_file = Path(__file__).resolve().parent / "payloads.json"
    if not payloads_file.exists():
        print(f"Error: {payloads_file} not found.")
        return

    with payloads_file.open("r", encoding="utf-8") as f:
        test_cases = json.load(f)

    detector = PromptInjectionDetector()

    total = len(test_cases)
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    print("=" * 75)
    print("        AI-VAULT PROMPT INJECTION DEFENSE BENCHMARK (OWASP LLM01)")
    print("=" * 75)
    print(f"{'ID':<10} {'Type':<26} {'Expected':<10} {'Detected':<10} {'Result'}")
    print("-" * 75)

    for case in test_cases:
        cid = case["id"]
        category = case["category"]
        prompt = case["prompt"]
        is_attack = case["is_attack"]

        detected = detector.is_injection(prompt)

        if is_attack and detected:
            true_positives += 1
            status = "PASS (Blocked)"
        elif not is_attack and not detected:
            true_negatives += 1
            status = "PASS (Allowed)"
        elif is_attack and not detected:
            false_negatives += 1
            status = "FAIL (Missed Attack)"
        else:
            false_positives += 1
            status = "FAIL (False Positive)"

        expected_str = "Attack" if is_attack else "Clean"
        detected_str = "Attack" if detected else "Clean"
        print(f"{cid:<10} {category:<26} {expected_str:<10} {detected_str:<10} {status}")

    print("=" * 75)
    total_attacks = true_positives + false_negatives
    total_clean = true_negatives + false_positives

    attack_block_rate = (true_positives / total_attacks * 100) if total_attacks else 0
    clean_pass_rate = (true_negatives / total_clean * 100) if total_clean else 0
    accuracy = ((true_positives + true_negatives) / total * 100) if total else 0

    print(f"Total Test Cases Evaluated:   {total}")
    print(f"Attack Detection Rate (TPR):  {attack_block_rate:.1f}% ({true_positives}/{total_attacks})")
    print(f"Clean Prompt Pass Rate:       {clean_pass_rate:.1f}% ({true_negatives}/{total_clean})")
    print(f"Overall Gateway Accuracy:     {accuracy:.1f}%")
    print("=" * 75)


if __name__ == "__main__":
    run_benchmark()
