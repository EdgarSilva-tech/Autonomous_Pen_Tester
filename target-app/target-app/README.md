# Target App — Pentest Challenge

Aplicação FastAPI que serve de **alvo** para o desafio técnico do agente
autónomo. Expõe um conjunto mínimo de endpoints de autenticação para o teu
agente interagir.

> Não modifiques esta aplicação. O teu trabalho é construir o agente que
> interage com ela — trata-a como uma "caixa preta" cujo contrato está
> documentado abaixo.

---

## Como executar

```bash
docker compose up --build
```

A API fica disponível em `http://localhost:8000`.
Documentação interactiva (Swagger UI) em `http://localhost:8000/docs`.

Para parar:

```bash
docker compose down
```

---

## Utilizadores pré-criados

| username | password    |
| -------- | ----------- |
| `alice`  | `Alice#2025` |
| `bob`    | `Bob#2025`   |

---

## Contrato da API

### `GET /health`

Healthcheck simples. Devolve `200 {"message": "ok"}`.

### `POST /login`

**Request body:**

```json
{ "username": "alice", "password": "Alice#2025" }
```

**Respostas:**

- `200` — `{"token": "<opaque>", "expires_in": 300}`
- `401` — credenciais inválidas (`{"detail": "Invalid credentials"}`)
- `429` — conta bloqueada após múltiplas falhas
  (`{"detail": "Account locked. Retry in <N>s"}`)
- `503` — falha transitória (ver secção **Falhas transitórias**)

O token devolvido deve ser usado no header
`Authorization: Bearer <token>` nos endpoints autenticados.

### `POST /change-password`

Requer header `Authorization: Bearer <token>`.

**Request body:**

```json
{ "current_password": "Alice#2025", "new_password": "NovaPass#2025" }
```

**Regras da nova password:**

- Mínimo 8 caracteres.
- Pelo menos uma letra maiúscula e uma minúscula.
- Pelo menos um dígito.
- Não pode ser igual à actual.

**Respostas:**

- `200` — `{"message": "Password changed successfully"}`
- `400` — nova password não cumpre os requisitos.
- `401` — token em falta, inválido ou expirado.
- `403` — `current_password` incorrecta.
- `503` — falha transitória.

> ⚠️ **Importante:** após uma alteração de password bem-sucedida, **todas
> as sessões activas do utilizador são invalidadas**. O agente terá de
> voltar a fazer login com a nova password.

### `POST /logout`

Requer header `Authorization: Bearer <token>`. Invalida o token actual.

**Respostas:**

- `200` — `{"message": "Logged out"}`
- `401` — token em falta, inválido ou expirado.
- `503` — falha transitória.

### `GET /me`

Requer header `Authorization: Bearer <token>`. Devolve informação do
utilizador autenticado — útil para validares se uma sessão está activa.

**Respostas:**

- `200` — `{"username": "alice"}`
- `401` — token em falta, inválido ou expirado.

### `POST /_admin/reset`

Repõe o estado da aplicação para os valores iniciais (utilizadores e
passwords originais, sem sessões). **Útil durante o desenvolvimento e nos
testes.** Não requer autenticação.

---

## Configuração

Variáveis de ambiente (definidas no `docker-compose.yml`):

| Variável             | Default | Descrição                                              |
| -------------------- | ------- | ------------------------------------------------------ |
| `TOKEN_TTL_SECONDS`  | `300`   | Tempo de vida do token, em segundos.                   |
| `MAX_FAILED_LOGINS`  | `3`     | Tentativas falhadas antes de bloquear o utilizador.    |
| `LOCKOUT_SECONDS`    | `30`    | Duração do bloqueio após exceder `MAX_FAILED_LOGINS`.  |
| `FLAKY_RATE`         | `0.0`   | Probabilidade (0.0–1.0) de cada request devolver 503.  |

### Falhas transitórias

Para testares o comportamento do teu agente perante falhas intermitentes,
arranca a aplicação com `FLAKY_RATE` > 0:

```bash
FLAKY_RATE=0.2 docker compose up --build
```

Cerca de 20% dos requests irão devolver `503 Service Unavailable`. Um bom
agente deve detectar este caso e fazer retry com backoff em vez de abortar.

---

## Smoke test rápido

```bash
# Login
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice#2025"}'

# Reset (caso queiras voltar ao estado inicial)
curl -s -X POST http://localhost:8000/_admin/reset
```
