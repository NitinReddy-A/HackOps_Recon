"""Representative application source for the demo target (what a --repo review would see).

This is the code path behind GET /api/orders/{id}. It fetches an order by id and returns it
*without an object-level ownership check* — the CWE-639 / BOLA defect Rampart proves at runtime
and then localizes here. (The runtime harness is ``vulnerable_app.py``; this file stands in for
the application's own source so the source-correlation + advisory-patch flow is realistic.)
"""


class NotFound(Exception):
    pass


class Forbidden(Exception):
    pass


class OrdersService:
    def __init__(self, repo):
        self.repo = repo

    def get_order(self, order_id, principal):
        order = self.repo.get(order_id)
        if order is None:
            raise NotFound()
        return order
