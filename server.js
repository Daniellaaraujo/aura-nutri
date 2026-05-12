require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/criar-checkout', async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'gbp',
            product_data: {
              name: 'Coenzima Q10 Premium — Aura Nutri',
              description: '200mg · 60 cápsulas · 2 meses de uso',
            },
            unit_amount: 1900,
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: process.env.BASE_URL + '/sucesso.html',
      cancel_url: process.env.BASE_URL + '/',
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Servidor rodando na porta ' + PORT));
