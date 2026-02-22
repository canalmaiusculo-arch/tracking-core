# Conversões e eventos – Tracking Core

Eventos suportados pelo SDK e enviados ao Meta (quando o pixel estiver configurado no projeto).

---

## Eventos padrão (Meta)

| Evento | Método SDK | Uso |
|--------|------------|-----|
| **PageView** | `trackPageView()` | Visualização de página (disparo automático no carregamento). |
| **ViewContent** | `trackViewContent(properties)` | Visualização de conteúdo/produto. |
| **AddToCart** | `trackAddToCart(properties)` | Adicionar ao carrinho. |
| **InitiateCheckout** | `trackInitiateCheckout(properties)` | Início do checkout. |
| **Purchase** | `trackPurchase(data)` | Compra concluída (order_id, value, currency). |
| **Lead** | `trackLead(properties)` | Lead (formulário, cadastro). |
| **Contact** | `trackContact(properties)` | Contato (formulário, chat). |

### Exemplo de uso (depois de criar o tracker)

```html
<script src="https://SEU-DOMINIO/sdk/browser-tracker.js"></script>
<script>
  var t = TrackingCore.createTracker({
    endpoint: 'https://SEU-DOMINIO/events',
    apiKey: 'SUA_CHAVE_PUBLICA'
  });
  t.trackPageView();

  // Em botão ou após carregar oferta
  t.trackViewContent({ content_name: 'Oferta X' });

  // Ao clicar em "Adicionar ao carrinho"
  t.trackAddToCart({ value: 97.00, currency: 'BRL' });

  // Ao abrir a página de checkout
  t.trackInitiateCheckout({ value: 97.00 });

  // Após conclusão da compra (geralmente no thank-you page)
  t.trackPurchase({ order_id: 'PED-123', value: 97.00, currency: 'BRL' });

  // Ao enviar formulário de lead
  t.trackLead({ content_name: 'Landing Page' });

  // Ao enviar formulário de contato
  t.trackContact();
</script>
```

---

## Scroll (profundidade de leitura)

Eventos **scroll_25**, **scroll_75** e **scroll_100** são disparados quando o usuário atinge 25%, 75% e 100% da área rolável (página ou um elemento). Útil para ver onde as pessoas param de ler.

### Scroll na página inteira

```html
<script src="https://SEU-DOMINIO/sdk/browser-tracker.js"></script>
<script>
  var t = TrackingCore.createTracker({
    endpoint: 'https://SEU-DOMINIO/events',
    apiKey: 'SUA_CHAVE_PUBLICA'
  });
  t.trackPageView();
  // Dispara scroll_25, scroll_75, scroll_100 ao rolar a página
  t.trackScrollDepth({ percentMarks: [25, 75, 100] });
</script>
```

### Scroll em uma seção específica

Cole o script e use um **seletor CSS** para o elemento que tem scroll próprio (ex.: div com altura fixa e `overflow: auto`):

```html
<script>
  var t = TrackingCore.createTracker({
    endpoint: 'https://SEU-DOMINIO/events',
    apiKey: 'SUA_CHAVE_PUBLICA'
  });
  // Quando o usuário rolar dentro de #minha-secao até 25%, 75%, 100%
  t.trackScrollDepth({
    element: '#minha-secao',
    percentMarks: [25, 75, 100]
  });
</script>
```

### Marcas customizadas

```javascript
t.trackScrollDepth({ percentMarks: [50, 100] }); // só 50% e 100%
```

---

## Evento genérico

Para qualquer outro nome de evento:

```javascript
t.track('NomeDoEvento', { prop1: 'valor', prop2: 123 });
```

---

## Resumo dos eventos de scroll

| Evento     | Quando dispara        |
|------------|------------------------|
| **scroll_25**  | Usuário rolou 25% da área.  |
| **scroll_75**  | Usuário rolou 75% da área.  |
| **scroll_100** | Usuário rolou 100% da área. |

Cada marca é enviada **uma vez por sessão** (não repete ao rolar de volta).
