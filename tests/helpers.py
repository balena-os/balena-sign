def without(request, field):
    return {k: v for k, v in request.items() if k != field}


def but(request, **fields):
    return dict(request, **fields)
