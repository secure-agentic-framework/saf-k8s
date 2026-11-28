"""One-bit federated aggregation with randomized response."""

def majority(first, second, third):
    return (first & second) ^ ((first ^ second) & third)


def randomized_response(aggregate, first_coin, second_coin):
    return aggregate ^ (first_coin & second_coin)
