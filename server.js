require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');
const { Resend } = require('resend');
const { google } = require('googleapis');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(express.static(path.join(__dirname, 'public')));
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

async function gerarNumeroPedido() {
  const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS_JSON);
  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
  });
  const sheets = google.sheets({ version: 'v4', auth });
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: process.env.GOOGLE_SHEET_ID,
    range: 'Sheet1!A:A',
  });
  const rows = res.data.values || [];
  const total = rows.length; // inclui cabeçalho
  const numero = total; // primeira linha = cabeçalho, pedido 1 = linha 2
  const ano = new Date().getFullYear();
  return `AUR-${ano}-${String(numero).padStart(4, '0')}`;
}

async function salvarPedido(dados) {
  const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS_JSON);
  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
  });
  const sheets = google.sheets({ version: 'v4', auth });
  await sheets.spreadsheets.values.append({
    spreadsheetId: process.env.GOOGLE_SHEET_ID,
    range: 'Sheet1!A:H',
    valueInputOption: 'RAW',
    resource: {
      values: [[
        dados.numeroPedido, dados.data, dados.nome, dados.email,
        dados.endereco, dados.valor, dados.status, dados.rastreio || '',
      ]],
    },
  });
}

async function emailCliente(email, nome, endereco, numeroPedido) {
  await resend.emails.send({
    from: 'Aura Nutri <onboarding@resend.dev>',
    to: email,
    subject: `✅ Pedido ${numeroPedido} confirmado — Aura Nutri`,
    html: `
      <div style="font-family:sans-serif;max-width:500px;margin:0 auto;">
        <h2 style="color:#1A1714;">Obrigada pelo seu pedido, ${nome}!</h2>
        <p><strong>Número do pedido:</strong> ${numeroPedido}</p>
        <p>Recebemos o seu pagamento com sucesso.</p>
        <p><strong>Produto:</strong> Coenzima Q10 Premium — 200mg · 60 cápsulas</p>
        <p><strong>Endereço de entrega:</strong> ${endereco}</p>
        <p>Seu pedido será enviado em até 2 dias úteis. Você receberá o código de rastreio por email.</p>
        <br>
        <p style="color:#8A827A;font-size:0.85rem;">Aura Nutri — Suplementos Premium</p>
      </div>
    `,
  });
}

async function emailAdmin(nome, email, endereco, valor, numeroPedido) {
  await resend.emails.send({
    from: 'Aura Nutri <onboarding@resend.dev>',
    to: process.env.ADMIN_EMAIL,
    subject: `🛒 Novo pedido ${numeroPedido} — Aura Nutri`,
    html: `
      <div style="font-family:sans-serif;max-width:500px;margin:0 auto;">
        <h2 style="color:#1A1714;">Novo pedido!</h2>
        <p><strong>Número do pedido:</strong> ${numeroPedido}</p>
        <p><strong>Nome:</strong> ${nome}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Endereço:</strong> ${endereco}</p>
        <p><strong>Valor:</strong> £${valor}</p>
      </div>
    `,
  });
}

app.post('/criar-checkout', async (req, res) => {
  try {
    const numeroPedido = await gerarNumeroPedido();
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'gbp',
          product_data: {
            name: 'Coenzima Q10 Premium — Aura Nutri',
            description: `200mg · 60 cápsulas · 2 meses de uso · Pedido ${numeroPedido}`,
          },
          unit_amount: 1900,
        },
        quantity: 1,
      }],
      mode: 'payment',
      metadata: { numeroPedido },
      shipping_address_collection: {
        allowed_countries: ['GB', 'PT', 'BR', 'US'],
      },
      shipping_options: [{
        shipping_rate_data: {
          type: 'fixed_amount',
          fixed_amount: { amount: 0, currency: 'gbp' },
          display_name: 'Frete incluso',
          delivery_estimate: {
            minimum: { unit: 'business_day', value: 3 },
            maximum: { unit: 'business_day', value: 5 },
          },
        },
      }],
      success_url: process.env.BASE_URL + '/sucesso.html',
      cancel_url: process.env.BASE_URL + '/',
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const numeroPedido = session.metadata?.numeroPedido || 'N/A';
    const nome = session.shipping_details?.name || 'Cliente';
    const email = session.customer_details?.email || '';
    const endereco = session.shipping_details?.address
      ? `${session.shipping_details.address.line1}, ${session.shipping_details.address.city}, ${session.shipping_details.address.country}`
      : 'Não informado';
    const valor = (session.amount_total / 100).toFixed(2);

    try {
      await salvarPedido({
        numeroPedido, data: new Date().toLocaleString('pt-BR'),
        nome, email, endereco, valor, status: 'Pago',
      });
      await emailCliente(email, nome, endereco, numeroPedido);
      await emailAdmin(nome, email, endereco, valor, numeroPedido);
    } catch (err) {
      console.error('Erro no webhook:', err);
    }
  }

  res.json({ received: true });
});

app.post('/enviar-rastreio', async (req, res) => {
  const { email, nome, codigo } = req.body;
  try {
    await resend.emails.send({
      from: 'Aura Nutri <onboarding@resend.dev>',
      to: email,
      subject: '📦 Seu pedido foi enviado — Aura Nutri',
      html: `
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto;">
          <h2 style="color:#1A1714;">Seu pedido está a caminho, ${nome}!</h2>
          <p>Código de rastreio: <strong>${codigo}</strong></p>
          <p>Prazo estimado: 3 a 5 dias úteis.</p>
          <br>
          <p style="color:#8A827A;font-size:0.85rem;">Aura Nutri — Suplementos Premium</p>
        </div>
      `,
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Servidor rodando na porta ' + PORT));
