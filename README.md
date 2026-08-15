# Studio de Telas — com login e biblioteca na nuvem

Editor visual de telas de celular (loading, atualização, verificação facial, contagem
regressiva) com:

- **Login protegendo o site inteiro** — a senha fica só no servidor, não dá pra burlar pelo navegador.
- **Biblioteca de modelos na nuvem** — o que um salva, todo o time enxerga e usa.
- **Exportação de HTML** pronto pra colar no WebView do app.

---

## 1. Criar o banco grátis (MongoDB Atlas)

Os modelos compartilhados ficam guardados aqui. É grátis e leva uns 5 minutos.

1. Acesse **mongodb.com/cloud/atlas** e crie uma conta.
2. Crie um cluster gratuito (**M0**, plano Free). Escolha a região mais perto (ex: São Paulo).
3. Em **Database Access**, crie um usuário com senha (anote os dois).
4. Em **Network Access**, clique **Add IP Address → Allow access from anywhere** (`0.0.0.0/0`).
   (O Render usa IPs variáveis; pra uso interno isso está ok.)
5. Em **Database → Connect → Drivers**, copie a *connection string*. Fica assim:

   ```
   mongodb+srv://SEU_USUARIO:SUA_SENHA@cluster0.xxxx.mongodb.net/?retryWrites=true&w=majority
   ```

   Troque `SUA_SENHA` pela senha real do usuário do banco. Guarde essa string — é o `MONGODB_URI`.

---

## 2. Subir no Render (Web Service)

> **Atenção:** agora é **Web Service**, não Static Site. E use um **repositório novo/separado**
> pra não mexer no site que já está no ar.

1. Suba estes arquivos num repositório do GitHub (sem a pasta `node_modules`):

   ```
   server.js
   package.json
   render.yaml
   .gitignore
   public/index.html
   public/login.html
   ```

2. No Render: **New → Web Service**, aponte pro repositório.
3. Configuração (o `render.yaml` já preenche quase tudo):
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - **Plan:** Free
4. Em **Environment**, adicione as variáveis:

   | Variável | Valor |
   |---|---|
   | `ADMIN_USER` | `admin` |
   | `ADMIN_PASSWORD` | `mercenario` (troque quando quiser) |
   | `MONGODB_URI` | a string que você copiou do Atlas |
   | `SESSION_SECRET` | uma frase longa e aleatória (qualquer coisa comprida) |
   | `DB_NAME` | `studio_telas` |
   | `NODE_ENV` | `production` |

5. **Create Web Service.** Em um ou dois minutos o Render te dá a URL.

> No plano Free o serviço "dorme" após uns minutos sem uso e demora ~30s pra acordar no
> primeiro acesso. Os modelos **não** se perdem — eles ficam no MongoDB, não no Render.

---

## 3. Usar

- Abra a URL → cai na **tela de login**. Entre com `admin` / `mercenario`.
- Monte a tela arrastando elementos.
- **☁ Salvar na nuvem** guarda o modelo pra todo o time.
- **Modelos** mostra primeiro os da equipe (nuvem), com botão **×** pra apagar, e depois os prontos.
- **Exportar HTML** gera o arquivo final transparente pro app.
- **Sair** encerra a sessão.

---

## Como funciona a segurança (à prova de burla)

- A senha **nunca** vai pro navegador. O login é validado no servidor, com comparação em
  tempo constante (não dá pra descobrir a senha medindo o tempo de resposta).
- A sessão é um **cookie assinado com HMAC**. Se alguém tentar forjar ou editar o cookie,
  a assinatura não bate e o acesso é negado (testado: cookie falso retorna 401).
- O cookie é `httpOnly` (o JavaScript da página não lê) e `sameSite=strict` (não vaza pra outros sites).
- **6 tentativas erradas** de login travam aquele IP por 5 minutos.
- Todas as rotas da biblioteca (`/api/modelos`) exigem sessão válida. O próprio editor
  (`index.html`) só é entregue pra quem está logado.
- Trocar a senha é só mudar `ADMIN_PASSWORD` no painel do Render e salvar.

---

## Rodar na sua máquina (opcional)

```bash
npm install
cp .env.example .env      # edite o .env com sua senha e o MONGODB_URI
node server.js            # abre em http://localhost:3000
```

Sem `MONGODB_URI`, ele cai num arquivo local (`data/modelos.json`) só pra testar — nesse
modo os modelos não são compartilhados nem persistem em produção.

---

## Estrutura

```
server.js           servidor Express: login, sessão, API da biblioteca
package.json        dependências (express, cookie-parser, mongodb)
render.yaml         configuração pronta do Render
public/
  index.html        o editor (todo o app num arquivo)
  login.html        tela de login
```

O editor e o HTML exportado usam o mesmo motor de animação, então preview e resultado são idênticos.
