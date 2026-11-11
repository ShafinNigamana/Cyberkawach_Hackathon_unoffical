import pytest
from backend.utils.rate_limiter import get_rate_limiter

@pytest.fixture(autouse=True)
def reset_rate_limiter_for_test(request):
    """
    Ensure rate limiter test isolation across the full test suite so preceding
    test runs don't inadvertently trigger 429 Too Many Requests in unrelated tests.
    """
    if "test_16_rate_limit" in request.node.name or "test_rate_limiter" in request.node.name:
        # Let rate limiter unit tests test default limits
        limiter = get_rate_limiter(anon_limit=15, auth_limit=120)
        limiter.reset()
        yield
        limiter = get_rate_limiter(rate_limit=1000)
        limiter.reset()
        return

    limiter = get_rate_limiter(rate_limit=1000)
    limiter.reset()
    yield
    limiter.reset()
