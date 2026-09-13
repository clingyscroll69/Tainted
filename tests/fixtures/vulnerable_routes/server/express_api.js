const express = require("express");
const app = express();

// VULNERABLE: :orderId is fetched with no ownership predicate at all.
app.get("/orders/:orderId", async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.orderId } });
  res.json(order);
});

// SAFE: the where clause carries the caller's id alongside the record id.
app.get("/carts/:cartId", async (req, res) => {
  const cart = await prisma.cart.findFirst({
    where: { id: req.params.cartId, userId: req.user.id },
  });
  res.json(cart);
});

// SAFE: no database read at all — a route with nothing to leak.
app.get("/healthz", (req, res) => res.json({ ok: true }));

module.exports = app;
