"""Reading, from the code, which route serves one row of a table."""

from tainted.static.routes import route_for_table

REPO = "tests/fixtures/vulnerable_routes"


def test_each_framework_s_route_is_found_by_its_table():
    found = {t: route_for_table(REPO, t)[0].path for t in ("invoices", "orders", "tickets", "documents")}
    assert found == {
        "invoices": "/api/invoices/[id]",
        "orders": "/orders/:orderId",  # Prisma names the model `order`
        "tickets": "/tickets/{ticket_id}",  # SQLAlchemy names it `Ticket`
        "documents": "/documents/<int:doc_id>",
    }


def test_two_equal_routes_are_refused_rather_than_picked(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n"
        "@app.route('/a/<item_id>')\ndef a(item_id):\n    return Item.query.get(item_id)\n\n"
        "@app.route('/b/<item_id>')\ndef b(item_id):\n    return Item.query.get(item_id)\n",
        encoding="utf-8",
    )
    route, why = route_for_table(str(tmp_path), "items")
    assert route is None and "several routes" in why
