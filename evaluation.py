"""
ChatPhishDetector - Evaluation & Benchmark Subsystem (Module 6)
Reproduces the experimental evaluation framework from Section IV and Section V of the IEEE paper:
  - Metrics: Precision, Recall, Accuracy, F-measure, TP, TN, FP, FN
  - Baselines: dnstwist, PhishStorm, Simple Mode (URL-only)
  - Comparison across models: GPT-4V, GPT-4, GPT-3.5, Gemini Pro, Llama
  - Dataset loader and automated test benchmark runner
"""

import argparse
import json
import os
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd

from detector import PhishingDetector, DetectionResult
from processor import simplify_html
from ocr_engine import OCRTextBlock
from security import extract_domain


# Paper's published benchmark results (Table 1 & Table 2) for historical comparison
PAPER_BENCHMARK_RESULTS = [
    {
        "System": "ChatPhishDetector",
        "Mode": "Vision",
        "Model": "GPT-4V",
        "Precision": 98.7,
        "Recall": 99.6,
        "Accuracy": 99.2,
        "F-measure": 99.2,
        "TP": 991,
        "TN": 986,
        "FP": 13,
        "FN": 4,
    },
    {
        "System": "ChatPhishDetector",
        "Mode": "Vision",
        "Model": "Gemini Pro 1.0 Vision",
        "Precision": 78.9,
        "Recall": 99.1,
        "Accuracy": 89.1,
        "F-measure": 87.9,
        "TP": 789,
        "TN": 993,
        "FP": 7,
        "FN": 211,
    },
    {
        "System": "ChatPhishDetector",
        "Mode": "Normal",
        "Model": "GPT-4",
        "Precision": 98.3,
        "Recall": 98.4,
        "Accuracy": 98.4,
        "F-measure": 98.4,
        "TP": 984,
        "TN": 983,
        "FP": 17,
        "FN": 16,
    },
    {
        "System": "ChatPhishDetector",
        "Mode": "Normal",
        "Model": "GPT-3.5",
        "Precision": 98.3,
        "Recall": 86.7,
        "Accuracy": 92.6,
        "F-measure": 92.1,
        "TP": 867,
        "TN": 985,
        "FP": 15,
        "FN": 133,
    },
    {
        "System": "ChatPhishDetector",
        "Mode": "Normal",
        "Model": "Llama 2 70B",
        "Precision": 78.4,
        "Recall": 66.4,
        "Accuracy": 74.1,
        "F-measure": 71.9,
        "TP": 664,
        "TN": 817,
        "FP": 183,
        "FN": 336,
    },
    {
        "System": "ChatPhishDetector",
        "Mode": "Normal",
        "Model": "Gemini Pro 1.0",
        "Precision": 90.5,
        "Recall": 95.6,
        "Accuracy": 93.2,
        "F-measure": 93.0,
        "TP": 905,
        "TN": 958,
        "FP": 42,
        "FN": 95,
    },
    {
        "System": "ChatPhishDetector",
        "Mode": "Simple",
        "Model": "GPT-4",
        "Precision": 98.4,
        "Recall": 75.5,
        "Accuracy": 87.2,
        "F-measure": 85.5,
        "TP": 755,
        "TN": 988,
        "FP": 12,
        "FN": 245,
    },
    {
        "System": "ChatPhishDetector",
        "Mode": "Simple",
        "Model": "GPT-3.5",
        "Precision": 98.6,
        "Recall": 77.5,
        "Accuracy": 88.2,
        "F-measure": 86.8,
        "TP": 775,
        "TN": 989,
        "FP": 11,
        "FN": 225,
    },
    {
        "System": "dnstwist",
        "Mode": "Baseline",
        "Model": "dnstwist [33]",
        "Precision": 31.3,
        "Recall": None,
        "Accuracy": None,
        "F-measure": None,
        "TP": None,
        "TN": None,
        "FP": None,
        "FN": None,
    },
    {
        "System": "Phishpedia",
        "Mode": "Baseline",
        "Model": "Phishpedia [15]",
        "Precision": 26.0,
        "Recall": None,
        "Accuracy": None,
        "F-measure": None,
        "TP": None,
        "TN": None,
        "FP": None,
        "FN": None,
    },
    {
        "System": "PhishStorm",
        "Mode": "Baseline",
        "Model": "PhishStorm [49]",
        "Precision": 52.0,
        "Recall": 75.1,
        "Accuracy": 52.8,
        "F-measure": 61.4,
        "TP": None,
        "TN": None,
        "FP": None,
        "FN": None,
    },
]


@dataclass
class EvaluationSample:
    """A test sample with ground truth for benchmarking."""
    url: str
    ground_truth: int  # 1 for phishing, 0 for legitimate
    brand: Optional[str]
    category: str
    html: str
    ocr_text: str = ""


# Curated representative dataset reflecting Section IV categories
SAMPLE_BENCHMARK_DATASET: List[EvaluationSample] = [
    # 1. Phishing: Brand Impersonation + Fake Account Urgency (PayPal)
    EvaluationSample(
        url="https://paypal-verify-user.security-update.com/login",
        ground_truth=1,
        brand="PayPal",
        category="Fake Account Issue",
        html="""<html><head><title>PayPal - Account Suspension</title></head>
        <body><h1>Your PayPal Account Is Temporarily Locked!</h1>
        <p>Unusual activity detected. Confirm your credit card number and password now to restore access.</p>
        <form action="/steal"><input type="password" /><input type="text" /></form></body></html>""",
        ocr_text="PayPal Security Alert: Confirm credentials to unlock your account immediately.",
    ),
    # 2. Phishing: Fake Virus Infection Warning (Microsoft Defender scam)
    EvaluationSample(
        url="https://landiingpages-alert.beauty/scan",
        ground_truth=1,
        brand="Microsoft",
        category="Fake Security Warning",
        html="""<html><head><title>Windows Defender Security Warning</title></head>
        <body><h1>(Threat found) - Trojan Spyware App</h1>
        <p>Access to this PC is blocked for security reasons. Call Microsoft Technical Support now at +1-800-FAKE.</p>
        </body></html>""",
        ocr_text="Access to this PC is blocked for security reasons. Threat found: Trojan.Spyware",
    ),
    # 3. Phishing: Fake Reward / Lottery Scam (Amazon)
    EvaluationSample(
        url="https://amazon-winner-giftcard.xyz/claim",
        ground_truth=1,
        brand="Amazon",
        category="Fake Reward",
        html="""<html><head><title>Amazon Loyalty Reward</title></head>
        <body><h1>Congratulations Amazon Shopper!</h1>
        <p>You have won a $1,000 Amazon Gift Card! Enter your card details to pay $1 shipping.</p>
        <input type="text" placeholder="Card number" /></body></html>""",
        ocr_text="Amazon Gift Card Winner: Claim your $1000 prize now!",
    ),
    # 4. Phishing: Urgent Parcel Fee / Payment Scam (DHL)
    EvaluationSample(
        url="https://dhl-parcel-tracking.delivery-fees.top/track",
        ground_truth=1,
        brand="DHL",
        category="Urgent Payment Request",
        html="""<html><head><title>DHL Express - Delivery Notice</title></head>
        <body><h1>Interrupted delivery: Additional charges required</h1>
        <p>Your package is held due to unpaid customs fee of $2.99. Pay immediately to avoid package return.</p>
        </body></html>""",
        ocr_text="DHL Express: Delivery fee outstanding. Pay online now.",
    ),
    # 5. Phishing: Credential / 2FA SMS Code Phishing (Bank of America)
    EvaluationSample(
        url="https://bankofamerica-auth-code.com/2fa",
        ground_truth=1,
        brand="Bank of America",
        category="Authentication Request",
        html="""<html><head><title>Bank of America - Verification</title></head>
        <body><h1>One-Time Passcode Verification</h1>
        <p>Please enter the 6-digit SMS code sent to your mobile phone to approve transaction.</p>
        <input type="text" name="otp" /></body></html>""",
        ocr_text="Bank of America: Enter one-time SMS verification code.",
    ),
    # 6. Legitimate: Tranco Benign Domain (Example Domain)
    EvaluationSample(
        url="https://example.com",
        ground_truth=0,
        brand=None,
        category="Benign Tranco Site",
        html="""<html><head><title>Example Domain</title></head>
        <body><h1>Example Domain</h1>
        <p>This domain is for use in illustrative examples in documents. You may use this domain in literature.</p>
        </body></html>""",
        ocr_text="Example Domain: Illustrative examples in documents.",
    ),
    # 7. Legitimate: Wikipedia Article
    EvaluationSample(
        url="https://en.wikipedia.org/wiki/Phishing",
        ground_truth=0,
        brand=None,
        category="Benign Information Site",
        html="""<html><head><title>Phishing - Wikipedia</title></head>
        <body><h1>Phishing</h1>
        <p>Phishing is a form of social engineering where an attacker attempts to fraudulently acquire sensitive information.</p>
        </body></html>""",
        ocr_text="Phishing - From Wikipedia, the free encyclopedia.",
    ),
    # 8. Legitimate: Official Python Homepage
    EvaluationSample(
        url="https://www.python.org",
        ground_truth=0,
        brand=None,
        category="Benign Technology Site",
        html="""<html><head><title>Welcome to Python.org</title></head>
        <body><h1>Python Programming Language</h1>
        <p>Python is a programming language that lets you work quickly and integrate systems more effectively.</p>
        </body></html>""",
        ocr_text="Python: Lets you work quickly and integrate systems.",
    ),
    # 9. Legitimate: Official PayPal Login
    EvaluationSample(
        url="https://www.paypal.com/signin",
        ground_truth=0,
        brand="PayPal",
        category="Legitimate Brand Login",
        html="""<html><head><title>Log in to your PayPal account</title></head>
        <body><h1>Log in to PayPal</h1>
        <form><input type="email" /><input type="password" /></form>
        </body></html>""",
        ocr_text="PayPal: Log in to your account.",
    ),
    # 10. Legitimate: GitHub Documentation
    EvaluationSample(
        url="https://github.com",
        ground_truth=0,
        brand=None,
        category="Benign Developer Site",
        html="""<html><head><title>GitHub: Let's build from here</title></head>
        <body><h1>Where the world builds software</h1>
        <p>Over 100 million developers shape the future of software, together.</p></body></html>""",
        ocr_text="GitHub: Where the world builds software.",
    ),
]


def calculate_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    """
    Computes Precision, Recall, Accuracy, and F-measure matching paper Section V-B1 formulas:
      Precision = TP / (TP + FP)
      Recall = TP / (TP + FN)
      Accuracy = (TP + TN) / (TP + TN + FP + FN)
      F-measure = 2 * (Precision * Recall) / (Precision + Recall)
    """
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f_measure = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "Accuracy": round(accuracy * 100, 2),
        "Precision": round(precision * 100, 2),
        "Recall": round(recall * 100, 2),
        "F-measure": round(f_measure * 100, 2),
    }


def evaluate_chatphishdetector(
    dataset: List[EvaluationSample] = SAMPLE_BENCHMARK_DATASET,
    mode: str = "normal",
    model: str = "gpt-4",
) -> Tuple[Dict[str, float], List[Dict[str, Any]]]:
    """
    Runs automated evaluation across test samples and computes evaluation metrics.
    """
    detector = PhishingDetector(default_model=model)
    y_true = []
    y_pred = []
    detailed_results = []

    for sample in dataset:
        y_true.append(sample.ground_truth)

        # Run mode detection
        if mode == "normal":
            ocr_blocks = [OCRTextBlock(text=sample.ocr_text, font_size=20.0)] if sample.ocr_text else []
            res = detector.detect_normal_mode(
                url=sample.url,
                raw_html=sample.html,
                ocr_blocks=ocr_blocks,
                model=model,
            )
        elif mode == "simple":
            res = detector.detect_simple_mode(
                url=sample.url,
                model=model,
            )
        else:
            # Fallback for vision
            res = detector.detect_normal_mode(
                url=sample.url,
                raw_html=sample.html,
                ocr_blocks=[],
                model=model,
            )

        predicted_class = 1 if res.is_phishing else 0
        y_pred.append(predicted_class)

        detailed_results.append({
            "url": sample.url,
            "category": sample.category,
            "ground_truth": "Phishing" if sample.ground_truth == 1 else "Legitimate",
            "prediction": "Phishing" if predicted_class == 1 else "Legitimate",
            "correct": (sample.ground_truth == predicted_class),
            "phishing_score": res.phishing_score,
            "brands": res.brands,
            "reasoning": res.reasoning,
        })

    metrics = calculate_metrics(y_true, y_pred)
    return metrics, detailed_results


def get_paper_benchmark_dataframe() -> pd.DataFrame:
    """Returns the IEEE paper's Table 1 & Table 2 metrics as a DataFrame."""
    return pd.DataFrame(PAPER_BENCHMARK_RESULTS)


def main():
    parser = argparse.ArgumentParser(description="ChatPhishDetector Evaluation Harness")
    parser.add_argument("--mode", choices=["normal", "simple"], default="normal", help="Evaluation mode")
    parser.add_argument("--model", default="gpt-4", help="Model name")
    args = parser.parse_args()

    print("=" * 75)
    print(" ChatPhishDetector: Research Paper Evaluation & Baseline Comparison")
    print("=" * 75)
    print(f"[*] Mode  : {args.mode}")
    print(f"[*] Model : {args.model}")
    print(f"[*] Samples Tested: {len(SAMPLE_BENCHMARK_DATASET)}")
    print("-" * 75)

    metrics, details = evaluate_chatphishdetector(mode=args.mode, model=args.model)

    print("\n--- Evaluation Metrics on Test Suite ---")
    print(f"Accuracy   : {metrics['Accuracy']}%")
    print(f"Precision  : {metrics['Precision']}%")
    print(f"Recall     : {metrics['Recall']}%")
    print(f"F-measure  : {metrics['F-measure']}%")
    print(f"Matrix     : TP={metrics['TP']}, TN={metrics['TN']}, FP={metrics['FP']}, FN={metrics['FN']}")
    print("-" * 75)

    print("\nSample Predictions:")
    for d in details:
        mark = "[PASS]" if d["correct"] else "[FAIL]"
        print(f" {mark} URL: {d['url']}")
        print(f"        Truth: {d['ground_truth']} | Prediction: {d['prediction']} | Score: {d['phishing_score']}/10 | Brand: {d['brands']}")

    print("\n" + "=" * 75)
    print(" IEEE Paper Reported Benchmark Comparison (Table 1 & 2):")
    print("=" * 75)
    df = get_paper_benchmark_dataframe()
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
