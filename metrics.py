#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
metrics.py - расчёт Accuracy, Precision, Recall, F1.
"""

def calculate_metrics(history):
    """
    history: list of (pred_label, true_label), where 1=succes, 0=no.
    output data (accuracy, precision, recall, f1).
    """
    tp = fp = fn = tn = 0
    for (pred, true) in history:
        if pred == 1 and true == 1:
            tp += 1
        elif pred == 1 and true == 0:
            fp += 1
        elif pred == 0 and true == 1:
            fn += 1
        else:
            tn += 1

    total = tp + fp + fn + tn + 1e-9
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp + 1e-9)
    recall = tp / (tp + fn + 1e-9)
    f1 = 2 * precision * recall / (precision + recall + 1e-9)
    return accuracy, precision, recall, f1
