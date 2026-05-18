require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');
const { Resend } = require('resend');
const { google } = require('googleapis');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// ─── CONEXÃO COM POSTGRESQL ──────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ─── MIDDLEWARES ─────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ─── MIDDLEWARE DE AUTENTICAÇÃO ──────────────────────────
// Verifica se o cliente está logado antes de acessar rotas protegidas
function autenticar(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // formato: "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ erro: 'Acesso negado. Faça login primeiro.' });
  }

  try {
    const dados = jwt.verify(token, process.env.JWT_SECRET);
    req.cliente = dados; // salva os dados do cliente na requisição
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido ou expirado. Faça login novamente.' });
  }
}

// ─── ROTAS DE CLIENTE ────────────────────────────────────

// CADASTRO — cria novo cliente
app.post('/api/cadastro', async (req, res) => {
  try {
    const { nome, email, senha, telefone, cpf } = req.body;

    // Valida campos obrigatórios
    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: 'Nome, email e senha são obrigatórios.' });
    }

    // Criptografa a senha antes de salvar
    const senha_hash = await bcrypt.hash(senha, 10);

    const resultado = await pool.query(
      `INSERT INTO clientes (nome, email, senha_hash, telefone, cpf)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, nome, email`,
      [nome, email, senha_hash, telefone || null, cpf || null]
    );

    res.status(201).json({
      mensagem: 'Cadastro realizado com sucesso!',
      cliente: resultado.rows[0]
    });

  } catch (erro) {
    if (erro.code === '23505') {
      return res.status(400).json({ erro: 'Este e-mail já está cadastrado.' });
    }
    console.error('Erro no cadastro:', erro);
    res.status(500).json({ erro: 'Erro ao cadastrar. Tente novamente.' });
  }
});

// LOGIN — autentica cliente e retorna token
app.post('/api/login', async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({ erro: 'Email e senha são obrigatórios.' });
    }

    // Busca cliente pelo email
    const resultado = await pool.query(
      'SELECT * FROM clientes WHERE email = $1',
      [email]
    );

    if (resultado.rows.length === 0) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const cliente = resultado.rows[0];

    // Compara senha digitada com a senha criptografada no banco
    const senhaCorreta = await bcrypt.compare(senha, cliente.senha_hash);
    if (!senhaCorreta) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }

    // Gera token JWT válido por 7 dias
    const token = jwt.sign(
      { id: cliente.id, email: cliente.email, nome: cliente.nome },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      mensagem: 'Login realizado com sucesso!',
      token,
      cliente: {
        id: cliente.id,
        nome: cliente.nome,
        email: cliente.email
      }
    });

  } catch (erro) {
    console.error('Erro no login:', erro);
    res.status(500).json({ erro: 'Erro ao fazer login. Tente novamente.' });
  }
});

// PERFIL — retorna dados do cliente logado (rota protegida)
app.get('/api/perfil', autenticar, async (req, res) => {
  try {
    const resultado = await pool.query(
      'SELECT id, nome, email, telefone, cpf FROM clientes WHERE id = $1',
      [req.cliente.id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: 'Cliente não encontrado.' });
    }

    res.json(resultado.rows[0]);

  } catch (erro) {
    console.error('Erro ao buscar perfil:', erro);
    res.status(500).json({ erro: 'Erro ao buscar perfil.' });
  }
});

// ─── ROTAS DE ENDEREÇO ───────────────────────────────────

// SALVAR ENDEREÇO (rota protegida)
app.post('/api/endereco', autenticar, async (req, res) => {
  try {
    const { rua, numero, complemento, bairro, cidade, estado, cep, principal } = req.body;
    const cliente_id = req.cliente.id; // pega o id do cliente pelo token

    if (!rua || !numero || !cidade || !estado || !cep) {
      return res.status(400).json({ erro: 'Preencha todos os campos obrigatórios do endereço.' });
    }

    // Se esse endereço for marcado como principal,
    // remove o principal dos outros endereços do cliente
    if (principal) {
      await pool.query(
        'UPDATE enderecos SET principal = false WHERE cliente_id = $1',
        [cliente_id]
      );
    }

    const resultado = await pool.query(
      `INSERT INTO enderecos (cliente_id, rua, numero, complemento, bairro, cidade, estado, cep, principal)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [cliente_id, rua, numero, complemento || null, bairro || null, cidade, estado, cep, principal || false]
    );

    res.status(201).json({
      mensagem: 'Endereço salvo com sucesso!',
      endereco: resultado.rows[0]
    });

  } catch (erro) {
    console.error('Erro ao salvar endereço:', erro);
    res.status(500).json({ erro: 'Erro ao salvar endereço.' });
  }
});

// LISTAR ENDEREÇOS DO CLIENTE (rota protegida)
app.get('/api/enderecos', autenticar, async (req, res) => {
  try {
    const resultado = await pool.query(
      'SELECT * FROM enderecos WHERE cliente_id = $1 ORDER BY principal DESC, id DESC',
      [req.cliente.id]
    );
    res.json(resultado.rows);
  } catch (erro) {
    console.error('Erro ao buscar endereços:', erro);
    res.status(500).json({ erro: 'Erro ao buscar endereços.' });
  }
});

// ─── ROTAS DE PEDIDOS ────────────────────────────────────

// LISTAR PEDIDOS DO CLIENTE (rota protegida)
app.get('/api/pedidos', autenticar, async (req, res) => {
  try {
    // Busca pedidos com os itens e informações de pagamento
    const resultado = await pool.query(
      `SELECT 
        p.id,
        p.status,
        p.total,
        p.frete,
        p.codigo_rastreio,
        p.criado_em,
        p.atualizado_em,
        e.rua, e.numero, e.cidade, e.estado, e.cep,
        json_agg(json_build_object(
          'produto', pr.nome,
          'quantidade', ip.quantidade,
          'preco', ip.preco_unit
        )) AS itens,
        pg.metodo AS metodo_pagamento,
        pg.status AS status_pagamento
       FROM pedidos p
       LEFT JOIN enderecos e ON p.endereco_id = e.id
       LEFT JOIN itens_pedido ip ON ip.pedido_id = p.id
       LEFT JOIN produtos pr ON pr.id = ip.produto_id
       LEFT JOIN pagamentos pg ON pg.pedido_id = p.id
       WHERE p.cliente_id = $1
       GROUP BY p.id, e.id, pg.id
       ORDER BY p.criado_em DESC`,
      [req.cliente.id]
    );

    res.json(resultado.rows);

  } catch (erro) {
    console.error('Erro ao buscar pedidos:', erro);
    res.status(500).json({ erro: 'Erro ao buscar pedidos.' });
  }
});

// ─── GOOGLE SHEETS ───────────────────────────────────────

async function gerarNumeroPedido() {
  try {
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
    const total = rows.length;
    const ano = new Date().getFullYear();
    return `AUR-${ano}-${String(total).padStart(4, '0')}`;
  } catch (erro) {
    // Se o Google Sheets falhar, gera um número pelo timestamp
    console.error('Erro ao gerar número pelo Sheets:', erro);
    return `AUR-${Date.now()}`;
  }
}

async function salvarNoPlanilha(dados) {
  try {
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
          dados.numeroPedido,
          dados.data,
          dados.nome,
          dados.email,
          dados.endereco,
          dados.valor,
          dados.status,
          dados.rastreio || '',
        ]],
      },
    });
  } catch (erro) {
    console.error('Erro ao salvar no Google Sheets:', erro);
    // Não interrompe o fluxo se o Sheets falhar
  }
}

// ─── EMAILS ──────────────────────────────────────────────

async function emailConfirmacaoPedido(email, nome, endereco, numeroPedido, total) {
  try {
    await resend.emails.send({
      from: 'Aura Nutri <onboarding@resend.dev>',
      to: email,
      subject: `✅ Pedido ${numeroPedido} confirmado — Aura Nutri`,
      html: `
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:20px;">
          <h2 style="color:#1A1714;">Obrigada pelo seu pedido, ${nome}!</h2>
          <p><strong>Número do pedido:</strong> ${numeroPedido}</p>
          <p><strong>Total:</strong> R$ ${total}</p>
          <p><strong>Endereço de entrega:</strong> ${endereco}</p>
          <p>Seu pedido será enviado em até 2 dias úteis.</p>
          <br>
          <p style="color:#8A827A;font-size:0.85rem;">Aura Nutri — Suplementos Premium</p>
        </div>
      `,
    });
  } catch (erro) {
    console.error('Erro ao enviar email para cliente:', erro);
  }
}

async function emailAdmin(nome, email, endereco, valor, numeroPedido) {
  try {
    await resend.emails.send({
      from: 'Aura Nutri <onboarding@resend.dev>',
      to: process.env.ADMIN_EMAIL,
      subject: `🛒 Novo pedido ${numeroPedido} — Aura Nutri`,
      html: `
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:20px;">
          <h2 style="color:#1A1714;">Novo pedido recebido!</h2>
          <p><strong>Número:</strong> ${numeroPedido}</p>
          <p><strong>Cliente:</strong> ${nome}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Endereço:</strong> ${endereco}</p>
          <p><strong>Valor:</strong> R$ ${valor}</p>
        </div>
      `,
    });
  } catch (erro) {
    console.error('Erro ao enviar email para admin:', erro);
  }
}

// ─── STRIPE ──────────────────────────────────────────────

// CRIAR SESSÃO DE CHECKOUT
app.post('/criar-checkout', async (req, res) => {
  try {
    // Pega os dados do carrinho enviados pelo frontend
    const { itens, cliente_id, endereco_id, frete } = req.body;

    const numeroPedido = await gerarNumeroPedido();

    // Monta os itens do checkout para o Stripe
    const lineItems = itens ? itens.map(item => ({
      price_data: {
        currency: 'brl',
        product_data: { name: item.nome },
        unit_amount: Math.round(item.preco * 100), // Stripe usa centavos
      },
      quantity: item.quantidade,
    })) : [{
      // Produto padrão se não vier itens
      price_data: {
        currency: 'brl',
        product_data: {
          name: 'Coenzima Q10 Premium — Aura Nutri',
          description: `200mg · 60 cápsulas · Pedido ${numeroPedido}`,
        },
        unit_amount: 19000, // R$ 190,00
      },
      quantity: 1,
    }];

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: lineItems,
      mode: 'payment',
      metadata: {
        numeroPedido,
        cliente_id: cliente_id || '',
        endereco_id: endereco_id || '',
      },
      shipping_address_collection: {
        allowed_countries: ['BR', 'PT', 'GB', 'US'],
      },
      shipping_options: [{
        shipping_rate_data: {
          type: 'fixed_amount',
          fixed_amount: { amount: Math.round((frete || 0) * 100), currency: 'brl' },
          display_name: 'Frete incluso',
          delivery_estimate: {
            minimum: { unit: 'business_day', value: 3 },
            maximum: { unit: 'business_day', value: 7 },
          },
        },
      }],
      success_url: process.env.BASE_URL + '/sucesso.html',
      cancel_url: process.env.BASE_URL + '/',
    });

    res.json({ url: session.url });

  } catch (erro) {
    console.error('Erro ao criar checkout:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// WEBHOOK — chamado pelo Stripe quando pagamento é confirmado
app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  // Verifica se o webhook realmente veio do Stripe
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (erro) {
    console.error('Webhook inválido:', erro.message);
    return res.status(400).send(`Webhook Error: ${erro.message}`);
  }

  // Processa apenas quando pagamento for confirmado
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    const numeroPedido = session.metadata?.numeroPedido || 'N/A';
    const cliente_id = session.metadata?.cliente_id || null;
    const endereco_id = session.metadata?.endereco_id || null;
    const nome = session.shipping_details?.name || session.customer_details?.name || 'Cliente';
    const email = session.customer_details?.email || '';
    const endereco = session.shipping_details?.address
      ? `${session.shipping_details.address.line1}, ${session.shipping_details.address.city}, ${session.shipping_details.address.country}`
      : 'Não informado';
    const total = (session.amount_total / 100).toFixed(2);
    const data = new Date().toLocaleString('pt-BR');

    try {
      // 1. Salva o pedido na tabela pedidos
      const pedidoResult = await pool.query(
        `INSERT INTO pedidos (cliente_id, endereco_id, status, total, frete)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [
          cliente_id || null,
          endereco_id || null,
          'pago',
          parseFloat(total),
          parseFloat(frete || 0)
        ]
      );
      const pedido_id = pedidoResult.rows[0].id;

      // 2. Salva o pagamento na tabela pagamentos
      await pool.query(
        `INSERT INTO pagamentos (pedido_id, metodo, status, valor, id_externo)
         VALUES ($1, $2, $3, $4, $5)`,
        [pedido_id, 'cartao', 'aprovado', parseFloat(total), session.payment_intent]
      );

      // 3. Salva também na tabela pedidos_aura (para manter histórico)
      await pool.query(
        `INSERT INTO pedidos_aura (numero_pedido, nome, email, endereco, valor, status, data)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (numero_pedido) DO NOTHING`,
        [numeroPedido, nome, email, endereco, total, 'Pago', data]
      );

      // 4. Salva no Google Sheets
      await salvarNoPlanilha({ numeroPedido, data, nome, email, endereco, valor: total, status: 'Pago' });

      // 5. Envia emails
      await emailConfirmacaoPedido(email, nome, endereco, numeroPedido, total);
      await emailAdmin(nome, email, endereco, total, numeroPedido);

      console.log(`✅ Pedido ${numeroPedido} processado com sucesso!`);

    } catch (erro) {
      console.error('Erro ao processar webhook:', erro);
    }
  }

  res.json({ received: true });
});

// ENVIAR CÓDIGO DE RASTREIO
app.post('/enviar-rastreio', async (req, res) => {
  const { email, nome, codigo, pedido_id } = req.body;

  try {
    // Atualiza o código de rastreio no banco
    if (pedido_id) {
      await pool.query(
        'UPDATE pedidos SET codigo_rastreio = $1, status = $2 WHERE id = $3',
        [codigo, 'enviado', pedido_id]
      );
    }

    // Envia email com o rastreio
    await resend.emails.send({
      from: 'Aura Nutri <onboarding@resend.dev>',
      to: email,
      subject: '📦 Seu pedido foi enviado — Aura Nutri',
      html: `
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:20px;">
          <h2 style="color:#1A1714;">Seu pedido está a caminho, ${nome}!</h2>
          <p>Código de rastreio: <strong>${codigo}</strong></p>
          <p>Prazo estimado: 3 a 7 dias úteis.</p>
          <br>
          <p style="color:#8A827A;font-size:0.85rem;">Aura Nutri — Suplementos Premium</p>
        </div>
      `,
    });

    res.json({ ok: true, mensagem: 'Rastreio enviado com sucesso!' });

  } catch (erro) {
    console.error('Erro ao enviar rastreio:', erro);
    res.status(500).json({ erro: erro.message });
  }
});

// ─── INICIAR SERVIDOR ────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor Aura Nutri rodando na porta ${PORT}`);
});