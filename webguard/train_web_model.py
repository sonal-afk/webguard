# ============================================================
# train_web_model.py
# Fine-tune CodeBERT for WEBSITE vulnerability detection
# Detects: SQLi, XSS, SSRF, Open Redirect, IDOR, Auth Bypass,
#          Path Traversal, Command Injection, XXE, CSRF, etc.
#
# Dataset format (CSV from Kaggle):
#   - payload / url / request / code column  → input text
#   - label column                            → 0=safe, 1=vulnerable
#
# Compatible datasets (download from Kaggle):
#   • Web Application Attacks Dataset
#   • OWASP Top 10 Payloads
#   • SQL Injection / XSS payload datasets
#   • Network Intrusion / Web Attack (CICIDS)
# ============================================================

import os
import re
import json
import time
import random
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

import torch
from torch import nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from torch.cuda.amp import GradScaler, autocast

from transformers import (
    RobertaTokenizer,
    RobertaForSequenceClassification,
    get_linear_schedule_with_warmup,
    get_cosine_schedule_with_warmup,
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score,
)
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore")

# ============================================================
# CONFIG
# ============================================================

CONFIG = {
    # Model
    "base_model": "microsoft/codebert-base",       # CodeBERT backbone
    "output_dir": "./web_vuln_model",               # Where to save fine-tuned model
    "max_length": 256,                              # Token limit (web payloads are shorter than code)

    # Training
    "epochs": 5,
    "batch_size": 16,
    "eval_batch_size": 32,
    "learning_rate": 2e-5,
    "weight_decay": 0.01,
    "warmup_ratio": 0.1,
    "gradient_clip": 1.0,
    "scheduler": "cosine",                         # "linear" or "cosine"
    "seed": 42,

    # Class imbalance handling
    "use_class_weights": True,                     # Real datasets are often imbalanced
    "oversample_minority": False,                  # Alternative to class weights

    # Data
    "test_size": 0.15,
    "val_size": 0.10,
    "label_column": "label",                       # Column name for ground truth
    "text_column": None,                           # Auto-detected if None

    # Logging
    "log_every_n_steps": 50,
    "eval_every_epoch": True,
    "save_best_model": True,
    "metric_for_best": "f1",                       # "f1", "accuracy", "auc"

    # Mixed precision
    "fp16": True,
}

# ============================================================
# VULNERABILITY CATEGORIES (reference)
# ============================================================

WEB_VULN_TYPES = {
    "sqli":       {"cwe": "CWE-89",  "severity": "CRITICAL"},
    "xss":        {"cwe": "CWE-79",  "severity": "HIGH"},
    "ssrf":       {"cwe": "CWE-918", "severity": "HIGH"},
    "idor":       {"cwe": "CWE-639", "severity": "HIGH"},
    "lfi":        {"cwe": "CWE-22",  "severity": "HIGH"},
    "rfi":        {"cwe": "CWE-98",  "severity": "CRITICAL"},
    "cmdi":       {"cwe": "CWE-78",  "severity": "CRITICAL"},
    "xxe":        {"cwe": "CWE-611", "severity": "HIGH"},
    "csrf":       {"cwe": "CWE-352", "severity": "MEDIUM"},
    "auth_bypass":{"cwe": "CWE-287", "severity": "CRITICAL"},
    "redirect":   {"cwe": "CWE-601", "severity": "MEDIUM"},
    "ssti":       {"cwe": "CWE-94",  "severity": "HIGH"},
    "nosqli":     {"cwe": "CWE-943", "severity": "HIGH"},
    "xpath":      {"cwe": "CWE-643", "severity": "MEDIUM"},
    "header_inj": {"cwe": "CWE-113", "severity": "MEDIUM"},
}

# ============================================================
# SEED
# ============================================================

def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


# ============================================================
# DATA LOADER — handles multiple Kaggle dataset formats
# ============================================================

COLUMN_ALIASES = {
    "text_column": [
        "payload", "Payload", "PAYLOAD",
        "url", "URL", "Url",
        "request", "Request", "REQUEST",
        "query", "Query", "QUERY",
        "input", "Input", "INPUT",
        "code", "Code", "CODE",
        "sentence", "Sentence",
        "text", "Text", "TEXT",
        "data", "Data", "DATA",
        "http_request", "raw", "Raw",
        "attack", "Attack",
    ],
    "label_column": [
        "label", "Label", "LABEL",
        "vulnerable", "Vulnerable", "VULNERABLE",
        "is_vulnerable", "Is_Vulnerable",
        "target", "Target", "TARGET",
        "class", "Class", "CLASS",
        "attack_type", "Attack_Type",
        "vuln", "Vuln",
        "y", "Y",
        "malicious", "Malicious",
        "result", "Result",
    ],
}


def auto_detect_columns(df):
    text_col = None
    label_col = None

    for alias in COLUMN_ALIASES["text_column"]:
        if alias in df.columns:
            text_col = alias
            break

    for alias in COLUMN_ALIASES["label_column"]:
        if alias in df.columns:
            label_col = alias
            break

    if text_col is None:
        str_cols = df.select_dtypes(include="object").columns
        if len(str_cols):
            text_col = str_cols[0]

    if label_col is None:
        int_cols = df.select_dtypes(include=["int", "bool", "float"]).columns
        if len(int_cols):
            label_col = int_cols[0]

    if text_col is None or label_col is None:
        raise ValueError(
            f"Could not auto-detect columns.\n"
            f"Available: {list(df.columns)}\n"
            f"Set --text_column and --label_column manually."
        )

    print(f"   Auto-detected  text_col='{text_col}'  label_col='{label_col}'")
    return text_col, label_col


def normalize_labels(series):
    if pd.api.types.is_numeric_dtype(series):
        vals = set(series.dropna().unique())
        if vals.issubset({0, 1, 0.0, 1.0, True, False}):
            return series.astype(int)
        safe_vals = {"0", "normal", "benign", "safe", "legitimate", "clean"}
        return series.apply(lambda x: 0 if str(x).lower() in safe_vals else 1)

    safe_words = {"0", "safe", "benign", "normal", "legitimate", "clean", "ham", "negative"}
    return series.apply(lambda x: 0 if str(x).strip().lower() in safe_words else 1)


def load_dataset_from_csv(path, text_col=None, label_col=None):
    print(f"\n   Loading: {path}")
    df = pd.read_csv(path, low_memory=False)
    print(f"   Raw shape: {df.shape}")

    if text_col is None or label_col is None:
        text_col, label_col = auto_detect_columns(df)

    df = df[[text_col, label_col]].copy()
    df.columns = ["text", "label"]
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = normalize_labels(df["label"])
    df = df[df["text"].str.len() > 2]

    lc = df["label"].value_counts()
    print(f"   Clean shape: {df.shape}  |  Safe={lc.get(0,0)}  Vulnerable={lc.get(1,0)}")
    return df


def load_all_datasets(csv_paths, text_col=None, label_col=None):
    frames = []
    
    possible_dirs = [
        Path("."),
        Path("../datasets"),
        Path("../../datasets"),
        Path(__file__).parent.parent / "datasets"
    ]
    
    for path in csv_paths:
        file_path = None
        for d in possible_dirs:
            p = d / path
            if p.exists():
                file_path = p
                break
                
        if file_path is None:
            print(f"   Skipping {path}: File not found in typical dataset directories.")
            continue
            
        try:
            frames.append(load_dataset_from_csv(file_path, text_col, label_col))
        except Exception as e:
            print(f"   Skipping {file_path}: {e}")

    if not frames:
        raise RuntimeError("No datasets loaded. Check your CSV paths.")

    combined = pd.concat(frames, ignore_index=True).drop_duplicates(subset=["text"])
    print(f"\n   Total combined samples: {len(combined)}")
    return combined


# ============================================================
# PREPROCESSING
# ============================================================

def preprocess_web_input(text):
    """Normalize web request / payload text before tokenization."""
    text = text.replace("%20", " ").replace("%27", "'").replace("%22", '"')
    text = text.replace("%3C", "<").replace("%3E", ">").replace("%2F", "/")
    text = text.replace("%3D", "=").replace("%26", "&").replace("%3B", ";")
    text = text.replace("&#x27;", "'").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("\\u003c", "<").replace("\\u003e", ">")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:2000]


# ============================================================
# PYTORCH DATASET
# ============================================================

class WebVulnDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        enc = self.tokenizer(
            preprocess_web_input(self.texts[idx]),
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        return {
            "input_ids":      enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "label":          torch.tensor(self.labels[idx], dtype=torch.long),
        }


# ============================================================
# METRICS
# ============================================================

def compute_metrics(preds, labels, probs=None):
    metrics = {
        "accuracy":  accuracy_score(labels, preds),
        "f1":        f1_score(labels, preds, average="binary", zero_division=0),
        "precision": precision_score(labels, preds, average="binary", zero_division=0),
        "recall":    recall_score(labels, preds, average="binary", zero_division=0),
    }
    if probs is not None:
        try:
            metrics["auc"] = roc_auc_score(labels, probs)
        except Exception:
            metrics["auc"] = 0.0
    return metrics


def print_metrics(metrics, prefix=""):
    bar = "-" * 50
    print(f"\n{bar}")
    print(f"  {prefix}Results")
    print(bar)
    for k, v in metrics.items():
        print(f"  {k:<12}: {v:.4f}")
    print(bar)


# ============================================================
# TRAINING LOOP
# ============================================================

def train_epoch(model, loader, optimizer, scheduler, scaler, device, config, epoch):
    model.train()
    total_loss = 0.0
    all_preds, all_labels = [], []

    progress = tqdm(loader, desc=f"Epoch {epoch} [Train]", leave=False)
    for step, batch in enumerate(progress):
        input_ids      = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels         = batch["label"].to(device)

        optimizer.zero_grad()
        with autocast(enabled=config["fp16"]):
            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss

        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), config["gradient_clip"])
        scaler.step(optimizer)
        scaler.update()
        scheduler.step()

        total_loss += loss.item()
        preds = outputs.logits.argmax(dim=-1).cpu().numpy()
        all_preds.extend(preds)
        all_labels.extend(labels.cpu().numpy())

        if step % config["log_every_n_steps"] == 0:
            progress.set_postfix(loss=f"{total_loss/(step+1):.4f}")

    metrics = compute_metrics(np.array(all_preds), np.array(all_labels))
    metrics["loss"] = total_loss / len(loader)
    return metrics


@torch.no_grad()
def eval_epoch(model, loader, device, config):
    model.eval()
    total_loss = 0.0
    all_preds, all_labels, all_probs = [], [], []

    for batch in tqdm(loader, desc="Evaluating", leave=False):
        input_ids      = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels         = batch["label"].to(device)

        with autocast(enabled=config["fp16"]):
            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)

        total_loss += outputs.loss.item()
        probs = torch.softmax(outputs.logits, dim=-1)[:, 1].cpu().numpy()
        preds = outputs.logits.argmax(dim=-1).cpu().numpy()

        all_preds.extend(preds)
        all_labels.extend(labels.cpu().numpy())
        all_probs.extend(probs)

    metrics = compute_metrics(np.array(all_preds), np.array(all_labels), np.array(all_probs))
    metrics["loss"] = total_loss / len(loader)
    return metrics, np.array(all_preds), np.array(all_labels)


# ============================================================
# MAIN TRAINING FUNCTION
# ============================================================

def train(csv_paths, config, text_col=None, label_col=None):
    set_seed(config["seed"])
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n   Device: {device}")

    # Load data
    print("\n" + "="*60)
    print("LOADING DATASETS")
    print("="*60)
    df = load_all_datasets(csv_paths, text_col, label_col)

    texts  = df["text"].tolist()
    labels = df["label"].tolist()

    # Check if we can stratify
    unique_labels, counts = np.unique(labels, return_counts=True)
    can_stratify = len(unique_labels) > 1 and all(c >= 2 for c in counts)
    stratify_arg = labels if can_stratify else None

    if not can_stratify:
        print("   Warning: Extremely imbalanced data or single class. Disabling stratified split.")

    X_train, X_tmp, y_train, y_tmp = train_test_split(
        texts, labels,
        test_size=config["test_size"] + config["val_size"],
        stratify=stratify_arg,
        random_state=config["seed"],
    )
    
    val_ratio = config["val_size"] / (config["test_size"] + config["val_size"])
    
    # Check stratify for val/test split
    unique_labels_tmp, counts_tmp = np.unique(y_tmp, return_counts=True)
    can_stratify_tmp = len(unique_labels_tmp) > 1 and all(c >= 2 for c in counts_tmp)
    stratify_arg_tmp = y_tmp if can_stratify_tmp else None

    X_val, X_test, y_val, y_test = train_test_split(
        X_tmp, y_tmp,
        test_size=1 - val_ratio,
        stratify=stratify_arg_tmp,
        random_state=config["seed"],
    )
    print(f"\n   Train: {len(X_train)}  |  Val: {len(X_val)}  |  Test: {len(X_test)}")

    # Tokenizer + Datasets
    print(f"\n   Loading tokenizer: {config['base_model']}")
    tokenizer = RobertaTokenizer.from_pretrained(config["base_model"])

    train_ds = WebVulnDataset(X_train, y_train, tokenizer, config["max_length"])
    val_ds   = WebVulnDataset(X_val,   y_val,   tokenizer, config["max_length"])
    test_ds  = WebVulnDataset(X_test,  y_test,  tokenizer, config["max_length"])

    train_loader = DataLoader(train_ds, batch_size=config["batch_size"],      shuffle=True,  num_workers=2, pin_memory=True)
    val_loader   = DataLoader(val_ds,   batch_size=config["eval_batch_size"], shuffle=False, num_workers=2, pin_memory=True)
    test_loader  = DataLoader(test_ds,  batch_size=config["eval_batch_size"], shuffle=False, num_workers=2, pin_memory=True)

    # Model
    print(f"\n   Loading model: {config['base_model']}")
    model = RobertaForSequenceClassification.from_pretrained(
        config["base_model"], num_labels=2,
        hidden_dropout_prob=0.1, attention_probs_dropout_prob=0.1,
    ).to(device)

    # Class weights for imbalanced datasets
    if config["use_class_weights"]:
        n_safe = y_train.count(0)
        n_vuln = y_train.count(1)
        total  = len(y_train)
        w_safe = total / (2 * n_safe)  if n_safe else 1.0
        w_vuln = total / (2 * n_vuln) if n_vuln else 1.0
        cw = torch.tensor([w_safe, w_vuln], dtype=torch.float).to(device)
        print(f"\n   Class weights  safe={w_safe:.3f}  vulnerable={w_vuln:.3f}")

        orig_fwd = model.forward
        def weighted_fwd(*args, **kwargs):
            out = orig_fwd(*args, **kwargs)
            if kwargs.get("labels") is not None:
                out.loss = nn.CrossEntropyLoss(weight=cw)(
                    out.logits.view(-1, 2), kwargs["labels"].view(-1)
                )
            return out
        model.forward = weighted_fwd

    # Optimizer
    no_decay = ["bias", "LayerNorm.weight"]
    opt_groups = [
        {"params": [p for n,p in model.named_parameters() if not any(nd in n for nd in no_decay)], "weight_decay": config["weight_decay"]},
        {"params": [p for n,p in model.named_parameters() if     any(nd in n for nd in no_decay)], "weight_decay": 0.0},
    ]
    optimizer     = AdamW(opt_groups, lr=config["learning_rate"])
    total_steps   = len(train_loader) * config["epochs"]
    warmup_steps  = int(total_steps * config["warmup_ratio"])
    scheduler     = (get_cosine_schedule_with_warmup if config["scheduler"] == "cosine"
                     else get_linear_schedule_with_warmup)(optimizer, warmup_steps, total_steps)
    scaler        = GradScaler(enabled=config["fp16"])

    # Training loop
    print("\n" + "="*60)
    print("TRAINING")
    print("="*60)

    best_score = -1.0
    history    = []
    output_dir = Path(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    for epoch in range(1, config["epochs"] + 1):
        t0 = time.time()
        train_m = train_epoch(model, train_loader, optimizer, scheduler, scaler, device, config, epoch)
        val_m, _, _ = eval_epoch(model, val_loader, device, config)

        print(f"\nEpoch {epoch}/{config['epochs']}  ({time.time()-t0:.0f}s)")
        print_metrics(train_m, "Train ")
        print_metrics(val_m,   "Val   ")

        score = val_m[config["metric_for_best"]]
        history.append({"epoch": epoch, "train": train_m, "val": val_m})

        if config["save_best_model"] and score > best_score:
            best_score = score
            model.save_pretrained(str(output_dir))
            tokenizer.save_pretrained(str(output_dir))
            print(f"   Saved best model  ({config['metric_for_best']}={best_score:.4f})")

    # Test evaluation
    print("\n" + "="*60)
    print("FINAL TEST EVALUATION")
    print("="*60)
    best_model = RobertaForSequenceClassification.from_pretrained(str(output_dir)).to(device)
    test_m, test_preds, test_labels = eval_epoch(best_model, test_loader, device, config)
    print_metrics(test_m, "Test  ")

    print("\nClassification Report:")
    print(classification_report(test_labels, test_preds, target_names=["Safe", "Vulnerable"]))
    cm = confusion_matrix(test_labels, test_preds)
    print(f"Confusion Matrix:  TN={cm[0,0]}  FP={cm[0,1]}  FN={cm[1,0]}  TP={cm[1,1]}")

    # Save artifacts
    with open(output_dir / "training_history.json", "w") as f: json.dump(history, f, indent=2)
    with open(output_dir / "label_map.json",        "w") as f: json.dump({"0":"SAFE","1":"VULNERABLE"}, f, indent=2)
    with open(output_dir / "train_config.json",     "w") as f: json.dump(config, f, indent=2)

    print(f"\n   All artifacts saved to: {output_dir}")
    print(f"   Best val {config['metric_for_best']}: {best_score:.4f}")
    print(f"   Test F1:  {test_m['f1']:.4f}  |  AUC: {test_m.get('auc',0):.4f}")
    return best_score, test_m


# ============================================================
# QUICK INFERENCE HELPER
# ============================================================

def predict_web_input(text, model_dir="./web_vuln_model"):
    """Predict whether a URL / HTTP payload / request is vulnerable."""
    tokenizer = RobertaTokenizer.from_pretrained(model_dir)
    model     = RobertaForSequenceClassification.from_pretrained(model_dir)
    model.eval()

    enc = tokenizer(preprocess_web_input(text), max_length=256,
                    padding="max_length", truncation=True, return_tensors="pt")
    with torch.no_grad():
        probs = torch.softmax(model(**enc).logits, dim=-1)[0]
    pred = probs.argmax().item()
    return {
        "input":      text[:100] + ("..." if len(text) > 100 else ""),
        "prediction": "VULNERABLE" if pred == 1 else "SAFE",
        "confidence": round(probs[pred].item(), 4),
        "prob_safe":  round(probs[0].item(), 4),
        "prob_vuln":  round(probs[1].item(), 4),
    }


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fine-tune CodeBERT for website vulnerability detection"
    )
    parser.add_argument("datasets",     nargs="*", help="CSV file paths (Kaggle). If empty, reads all from ../datasets or datasets.")
    parser.add_argument("--text_column",  default=None,               help="Payload/URL column (auto-detected)")
    parser.add_argument("--label_column", default=None,               help="Label column 0/1 (auto-detected)")
    parser.add_argument("--output_dir",   default="./web_vuln_model", help="Where to save the model")
    parser.add_argument("--epochs",       type=int,   default=5)
    parser.add_argument("--batch_size",   type=int,   default=16)
    parser.add_argument("--lr",           type=float, default=2e-5)
    parser.add_argument("--max_length",   type=int,   default=256)
    parser.add_argument("--no_fp16",      action="store_true")
    parser.add_argument("--test",         action="store_true", help="Run demo inference after training")
    args = parser.parse_args()

    CONFIG.update({
        "output_dir":    args.output_dir,
        "epochs":        args.epochs,
        "batch_size":    args.batch_size,
        "learning_rate": args.lr,
        "max_length":    args.max_length,
        "fp16":          not args.no_fp16,
    })

    datasets_to_use = args.datasets
    if not datasets_to_use:
        # Auto-discover datasets
        base_dir = Path(os.path.abspath(__file__)).parent
        possible_dirs = [
            Path("datasets"), 
            Path("../datasets"), 
            base_dir / "datasets",
            base_dir.parent / "datasets"
        ]
        
        for d in possible_dirs:
            if d.resolve().exists() and d.resolve().is_dir():
                found_files = [str(f.resolve()) for f in d.resolve().glob("*.csv")]
                if found_files:
                    datasets_to_use = found_files
                    print(f"Auto-discovered {len(found_files)} datasets in {d.resolve()}")
                    break
        
        if not datasets_to_use:
             print("Error: No datasets provided and none found in 'datasets' directories.")
             exit(1)

    print("\n" + "="*60)
    print("WEB VULNERABILITY DETECTOR  CodeBERT Fine-Tuner")
    print("="*60)
    print(f"   Datasets : {datasets_to_use}")
    print(f"   Epochs   : {CONFIG['epochs']}  |  LR: {CONFIG['learning_rate']}")
    print(f"   Output   : {CONFIG['output_dir']}")

    train(datasets_to_use, CONFIG, args.text_column, args.label_column)

    if args.test:
        print("\n" + "="*60)
        print("DEMO INFERENCE")
        print("="*60)
        samples = [
            "https://example.com/search?q=hello+world",
            "https://example.com/login?id=1' OR '1'='1",
            "<script>alert(document.cookie)</script>",
            "https://example.com/file?path=../../../../etc/passwd",
            "cmd=ls;cat /etc/passwd",
            "https://example.com/redirect?url=https://evil.com",
            "SELECT * FROM users WHERE id='1' AND SLEEP(5)--",
            "https://example.com/api/user/profile",
        ]
        for s in samples:
            r = predict_web_input(s, args.output_dir)
            icon = "VULNERABLE" if r["prediction"] == "VULNERABLE" else "SAFE"
            print(f"\n[{icon}] ({r['confidence']*100:.1f}%) {r['input']}")

    print(f"""
Done! Model saved to: {CONFIG['output_dir']}

Usage:
  # Single dataset
  python train_web_model.py sqli_dataset.csv --epochs 5 --test

  # Multiple Kaggle datasets merged together
  python train_web_model.py sqli.csv xss.csv cmdi.csv --epochs 5 --batch_size 16

  # Explicit column names
  python train_web_model.py attacks.csv --text_column payload --label_column label

  # Point backend.py at the new model
  # Change model path in backend.py to: ./web_vuln_model
""")