# Plano de implementação – 4 fases

Roadmap para melhorar a visualização e as conversões do painel Tracking Core.

---

## Fase 1 – Sidebar + Dashboard base

**Objetivo:** Reorganizar o menu lateral e tornar a área principal um dashboard com números e blocos de informação.

### 1.1 Sidebar em duas seções
- [x] **Seção "Pixel"** no menu: link para página/área só de conexão de pixels (listar, conectar, editar).
- [x] **Seção "Projetos"** no menu: link para lista/criação/edição de projetos (como hoje, mas separado do Pixel).
- [x] Ajustar rotas e layout para que "Dashboard" seja a página inicial ao entrar no painel; Pixel e Projetos sejam itens do menu que levam a suas próprias views.

### 1.2 Dashboard como página principal
- [x] Área principal = **Dashboard** por padrão (resumo geral, não só “Resumo” atual).
- [x] Blocos de **números/KPIs**: total de eventos, compras, valor no período, conversões (quando existirem).
- [x] Tabelas ou cards resumidos: projetos com mais eventos, últimas conversões, alertas (ex.: vendas não trackeadas).
- [x] Manter filtro de período (1d, 7d, 30d, todo) no dashboard.
- [x] Links rápidos para “Ver eventos”, “Editar projeto” etc. a partir do dashboard.

**Entregável Fase 1:** Menu com Pixel + Projetos + Dashboard; área principal = dashboard com KPIs e resumos.

---

## Fase 2 – Novas conversões + Scroll

**Objetivo:** Ampliar eventos rastreados e adicionar conversão por scroll.

### 2.1 Eventos padrão (Meta-like)
- [x] **ViewContent** – visualização de conteúdo/página.
- [x] **InitiateCheckout** – início do checkout.
- [x] **AddToCart** – adicionar ao carrinho.
- [x] **Purchase** – já existe; manter e garantir consistência com Meta.
- [x] Backend e SDK: aceitar e persistir esses `event_name` em `normalized_events` (e raw); enviar para Meta quando pixel estiver configurado.

### 2.2 Conversão por scroll
- [x] Definir eventos: ex. `scroll_25`, `scroll_75`, `scroll_100` (ou % configurável).
- [x] **Snippet** (código) que o usuário cola na página ou em uma seção: ao rolar até X% daquele elemento, dispara o evento.
- [x] Documentar: “cole no botão ou na seção; ao rolar até 25%/75%/100% dispara o evento”.
- [x] Backend: aceitar e salvar esses eventos; opcional: enviar como evento customizado ao Meta se fizer sentido.

### 2.3 Outros eventos úteis
- [x] Avaliar e, se fizer sentido, adicionar: **Lead**, **Contact**, **Subscribe** (e outros que combinem com o produto).
- [x] Manter lista de eventos documentada no painel ou no README.

**Entregável Fase 2:** Novos eventos disponíveis no SDK/API; snippet de scroll funcionando; backend e (se aplicável) Meta recebendo os eventos.

---

## Fase 3 – Fluxo projeto + pixel + seleção de conversões

**Objetivo:** Ao criar/editar projeto, associar pixel e escolher quais conversões rastrear; gerar códigos por conversão (ou um único script organizado).

### 3.1 Projeto associado ao pixel
- [x] Na criação/edição de projeto: campo ou seleção para **associar um pixel** (já conectado na seção Pixel) ao projeto.
- [x] Persistir essa associação (ex.: em `integrations_meta` ou tabela de projeto já existente).
- [x] Listar no projeto qual pixel está vinculado.

### 3.2 Catálogo de conversões
- [x] Lista fixa de conversões disponíveis: ViewContent, InitiateCheckout, AddToCart, Purchase, scroll 25/75/100, Lead, etc.
- [x] Na tela do projeto (ou em “Configurar rastreamento”): **checkboxes** ou lista para **escolher quais conversões** aquele projeto vai usar.

### 3.3 Geração de códigos
- [ ] Após selecionar as conversões: botão tipo **“Gerar códigos”** ou seção “Códigos de rastreamento”.
- [x] Exibir os **snippets por conversão** (um bloco por evento), com opção de copiar.
- [x] Opcional: **um único script** que já inclua todas as conversões selecionadas (mais organizado para quem prefere um bloco só).
- [x] Texto curto de ajuda em cada bloco (onde colar, o que o evento faz).

**Entregável Fase 3:** Fluxo “criar/editar projeto → associar pixel → escolher conversões → ver/copiar códigos” funcionando e visível no painel.

---

## Fase 4 – Visual “estilo game”

**Objetivo:** Deixar a interface com identidade visual de jogo (cores, formas, feedbacks).

### 4.1 Tema e componentes
- [x] Paleta e variáveis CSS em estilo gaming (cores vibrantes, contraste, gradientes se fizer sentido).
- [x] Bordas, cantos, sombras e ícones que lembrem UI de jogos (badges, cards “level”, barras de progresso).
- [x] Tipografia: fonte com personalidade (ex.: títulos mais marcantes), mantendo legibilidade.

### 4.2 Elementos de “game”
- [x] Onde fizer sentido: **badges** (ex.: “Pixel ativo”, “X conversões”), **níveis** ou **progress bars** (ex.: meta de eventos no mês).
- [x] Feedback visual em ações: sucesso ao salvar, ao copiar código (toast ou animação leve).
- [x] Sidebar e header alinhados ao novo tema (ícones, cores, estados hover/active).

### 4.3 Consistência
- [x] Aplicar o tema em todas as páginas do painel: Dashboard, Pixel, Projetos, eventos, configurações.
- [x] Garantir acessibilidade (contraste, foco) mesmo com o visual mais “game”.

**Entregável Fase 4:** Painel com identidade visual de jogo aplicada de forma consistente em todo o sistema.

---

## Ordem sugerida e dependências

| Fase | Depende de        | Permite depois                    |
|------|-------------------|-----------------------------------|
| 1    | —                 | Dashboard pronto para receber gráficos e KPIs |
| 2    | —                 | Ter eventos para mostrar no dashboard e nos códigos |
| 3    | Fase 1 (estrutura de páginas) e Fase 2 (eventos) | Usuário configurar e copiar códigos por projeto |
| 4    | Fases 1–3         | Aplicar visual sem refazer estrutura |

Recomendação: implementar **1 → 2 → 3 → 4**. Fases 1 e 2 podem ter partes em paralelo (ex.: sidebar + dashboard em 1; eventos e scroll em 2).

---

## Resumo por fase

| Fase | Nome curto              | Foco principal                                      |
|------|--------------------------|-----------------------------------------------------|
| 1    | Sidebar + Dashboard      | Menu Pixel/Projetos; área principal = dashboard com KPIs |
| 2    | Conversões + Scroll     | ViewContent, Checkout, AddToCart, scroll %, backend/SDK |
| 3    | Projeto + Pixel + Códigos | Associar pixel ao projeto; escolher conversões; gerar snippets |
| 4    | Visual gaming           | Tema, componentes e identidade visual de jogo       |

Quando quiser começar, podemos pegar a **Fase 1** e quebrar em tarefas de código (arquivos, rotas, componentes) e ir implementando passo a passo.
