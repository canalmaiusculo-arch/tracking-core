# Estudo: Gateways de pagamento, valor da venda, upsell e atribuição (campanha/conjunto/anúncio)

## 1. Como as gateways enviam a informação de venda

### 1.1 Kiwify

- **Formato:** Webhook POST em JSON para a URL configurada (ex.: `/webhooks/kiwify?project_key=sk_...`).
- **Eventos:** `compra_aprovada`, `compra_recusada`, `compra_reembolsada`, `boleto_gerado`, `pix_gerado`, `carrinho_abandonado`, `chargeback`, eventos de assinatura.
- **Estrutura do payload (espelho da API de vendas):**
  - **Identificação:** `id` (UUID do pedido), `reference` (ex.: "iYJwhMP").
  - **Valor:** Valores monetários vêm em **centavos** nos objetos `payment`:
    - `payment.charge_amount` – valor cobrado (ex.: 10388 = R$ 103,88).
    - `payment.product_base_price` – preço base do produto (ex.: 60037 = R$ 600,37).
    - `payment.net_amount` – líquido (após taxas).
    - `net_amount` no nível da venda também em centavos.
  - **Upsell:** Campo **`parent_order_id`**:
    - Se **`parent_order_id` é `null`** → venda do **produto principal** (checkout).
    - Se **`parent_order_id` tem valor** → venda é **upsell** (1-click); o ID é o pedido da compra principal.
  - **Rastreio:** Objeto **`tracking`** com UTM e afiliado:
    - `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`, `utm_term`
    - `s1`, `s2`, `s3` (subs de afiliado).
  - **Cliente:** `customer.email`, `customer.name`, etc.
  - **Produto:** `product.id`, `product.name`.

**Resumo:** Para saber “quem é comprador” vs “quem é comprador + upsell”, usar `parent_order_id`: ausente = principal, presente = upsell. Valor: usar `payment.charge_amount` ou `payment.product_base_price` e **dividir por 100** (centavos → reais).

---

### 1.2 Hotmart

- Webhook (Postback) em JSON; eventos como compra aprovada, reembolsada, assinatura cancelada, etc.
- Payload traz detalhes da transação, status e **valores da venda**.
- Pode ser configurado por produto (um ou todos). Para distinguir produto principal de upsell/oferta secundária, é preciso ver na documentação ou no payload se existe campo equivalente a “parent order” ou “product type”; na prática costuma haver identificador de produto ou tipo de oferta.

---

### 1.3 Outras (Eduzz, Perfect Pay, Ticto)

- Em geral: webhook POST em JSON com evento (ex.: venda aprovada), ID do pedido, valor (às vezes em centavos), cliente, e às vezes UTM ou campos de rastreio.
- Upsell: quando a plataforma tem upsell, costuma haver um segundo webhook por transação ou um campo que indica oferta principal vs secundária; varia por gateway.

---

## 2. Valor da venda

- **Kiwify:** Valores em **centavos** em `payment.charge_amount`, `payment.product_base_price`, `net_amount`. Converter para reais: **valor / 100**.
- **Hotmart / outras:** Verificar na documentação ou no payload se o valor vem em reais ou centavos (muito comum ser em centavos em APIs de pagamento).
- No **tracking-core:** ao mapear o payload da Kiwify (e de outras que usem centavos), normalizar para reais antes de gravar em `normalized_events.value`.

---

## 3. Público comprador vs comprador + upsell

- **Definição operacional:**
  - **Comprador (só principal):** toda venda onde não há upsell associado, ou onde consideramos apenas o evento da **primeira compra** (order principal).
  - **Comprador + upsell:** mesma pessoa que comprou o principal e depois aceitou pelo menos um upsell (outro evento de compra com `parent_order_id` apontando para o principal).
- **Implementação (ex.: Kiwify):**
  - Guardar em cada evento de compra um indicador **`is_upsell`** (ex.: `true` quando `parent_order_id` está preenchido) e opcionalmente **`parent_order_id`**.
  - No painel/relatórios: filtrar ou segmentar por “apenas principal” vs “principal + upsell” usando esse campo (e, se quiser, valor somando só principal ou principal + upsell).

---

## 4. Campanha, conjunto e anúncio: o que realmente chega na página

### 4.1 O que NÃO vem decodificado na URL

- **Meta (Facebook/Instagram):** Ao clicar em anúncio, a URL de destino ganha o parâmetro **`fbclid`** (Facebook Click ID). Esse ID é **opaco**: a Meta usa internamente para atribuição (campanha, conjunto, anúncio), mas **não é possível decodificar** no seu servidor para obter nome de campanha, conjunto ou anúncio. Ou seja: **não existe “pegada” na URL com nome de campanha/conjunto/anúncio**; só o click ID.
- **Google Ads:** O parâmetro **`gclid`** (Google Click ID) funciona de forma análoga: identifica o clique para o Google atribuir conversões a campanha, ad group e criativo, mas **não traz** nomes de campanha/conjunto/anúncio na URL para você decodificar.

Conclusão: **as plataformas não enviam “qual campanha/conjunto/anúncio” em texto na URL**. Elas enviam um **identificador de clique** (fbclid, gclid) que só elas interpretam.

### 4.2 O que podemos fazer no nosso lado

1. **Capturar e guardar os click IDs**
   - **`fbclid`** (Meta): ao aterrissar na página, ler da query string; opcionalmente montar o cookie **`_fbc`** no formato que a Meta recomenda e enviar **`fbc`** (e **`fbp`**) na Conversions API para melhorar atribuição e match.
   - **`gclid`** (Google): capturar da URL e guardar no contexto do evento (e, se houver integração com Google, enviar no servidor).
   - Assim mantemos a “pegada” do clique (quem veio de anúncio Meta/Google) e melhoramos atribuição no lado deles; **não** temos como exibir “nome da campanha/conjunto/anúncio” só com isso.

2. **UTM e parâmetros manuais**
   - Se na **URL de destino do anúncio** forem colocados **UTM** (ex.: `utm_campaign=BlackFriday`, `utm_content=ad_set_1`, `utm_term=anuncio_a`), esses sim chegam na página e podem ser lidos e armazenados. Aí conseguimos mostrar no painel “veio da campanha X” no sentido do que o próprio anunciante nomeou nos UTMs.
   - Boas práticas: configurar as URLs dos anúncios (Meta, Google, etc.) já com `utm_source`, `utm_medium`, `utm_campaign` e, se quiser granularidade de conjunto/criativo, usar `utm_content` / `utm_term`.

3. **Relatórios nas plataformas**
   - Para ver **na plataforma** desempenho por campanha, conjunto e anúncio (com números oficiais de atribuição), é necessário usar:
     - **Meta:** Meta Ads Manager (ou integração via Marketing API, como a que temos no painel Meta Ads).
     - **Google:** Google Ads + possivelmente GA4. O envio de conversões (ex.: via Measurement Protocol) com **gclid** ajuda o Google a atribuir no relatório deles.

### 4.3 Resumo atribuição

- **Na sua página:** você consegue ter com precisão:
  - **UTM** (se configurados na campanha) → “campanha” no sentido do seu rótulo.
  - **fbclid / gclid** → “veio de clique em anúncio Meta/Google” e melhor atribuição nas plataformas; **não** → nome de campanha/conjunto/anúncio.
- **Campanha/conjunto/anúncio com nome:** só dentro das ferramentas das plataformas (ou via API delas), não “decodificando” a URL do lead.

---

## 5. Recomendações para o tracking-core

1. **Webhook Kiwify (e similares):**
   - Mapear **valor em reais** (centavos → /100 quando aplicável).
   - Preencher **`context.is_upsell`** e **`context.parent_order_id`** a partir de `parent_order_id`.
   - Repassar **UTM** do objeto `tracking` para o contexto do evento normalizado.

2. **SDK / página:**
   - Capturar **`fbclid`** e **`gclid`** da URL e enviar no contexto dos eventos (e, no caso do Meta, enviar **fbc**/fbp na Conversions API quando disponíveis).

3. **Painel:**
   - Exibir e filtrar por **“Venda principal” vs “Upsell”** usando `context.is_upsell`.
   - Manter relatório por **UTM** (já existente) como “campanha” do seu lado; deixar claro que “campanha/conjunto/anúncio” com nome oficial é na integração Meta Ads (e futuramente Google, se houver).

4. **Documentação:**
   - Orientar o usuário a configurar **UTM nas URLs dos anúncios** para conseguir ver no painel de qual “campanha” (e, se quiser, conjunto/anúncio via utm_content/utm_term) veio o lead/compra.

Este documento pode ser atualizado quando houver novos gateways ou novas descobertas da documentação oficial (Kiwify, Hotmart, etc.).
