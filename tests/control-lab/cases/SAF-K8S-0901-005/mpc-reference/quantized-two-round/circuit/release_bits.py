"""Unsigned two-bit median and per-bit randomized response for MP-SPDZ."""

from Compiler.GC.types import sbit


def less_than_u2(left, right):
    left_low, left_high = left
    right_low, right_high = right
    high_less = (~left_high) & right_high
    high_equal = ~(left_high ^ right_high)
    low_less = (~left_low) & right_low
    return high_less | (high_equal & low_less)


def compare_swap_u2(left, right):
    choose_left = less_than_u2(left, right)
    low_min = choose_left.if_else(left[0], right[0])
    high_min = choose_left.if_else(left[1], right[1])
    low_max = choose_left.if_else(right[0], left[0])
    high_max = choose_left.if_else(right[1], left[1])
    return (low_min, high_min), (low_max, high_max)


def median3_u2(first, second, third):
    first, second = compare_swap_u2(first, second)
    second, third = compare_swap_u2(second, third)
    first, second = compare_swap_u2(first, second)
    return second


def randomized_response_bit(value):
    coin_a = sbit.get_random_bit()
    coin_b = sbit.get_random_bit()
    return randomized_response_with_coins(value, coin_a, coin_b)


def randomized_response_with_coins(value, coin_a, coin_b):
    return value ^ (coin_a & coin_b)
