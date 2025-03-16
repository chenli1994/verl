# -*- coding: utf-8 -*-
"""
Author  : chenli2
Time    : 2025/3/16 9:39
Desc    :
"""


def compute_score(solution_str: str, ground_truth, format_score=0., score=1.):
    if ground_truth in solution_str:
        return score
    else:
        return format_score

