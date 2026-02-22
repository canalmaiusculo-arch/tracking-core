(function (window) {
  const DEFAULT_ENDPOINT = 'http://localhost:4100/events';

  function createTracker(config) {
    const endpoint = config.endpoint || DEFAULT_ENDPOINT;
    const projectKey = config.apiKey || null;

    function baseEvent(eventName, properties) {
      return {
        event_name: eventName,
        event_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        user: {
          user_agent: navigator.userAgent,
          email: config.email || undefined
        },
        context: {
          url: window.location.href,
          referrer: document.referrer,
          utm_source: getParam('utm_source'),
          utm_medium: getParam('utm_medium'),
          utm_campaign: getParam('utm_campaign'),
          utm_content: getParam('utm_content'),
          utm_term: getParam('utm_term')
        },
        properties: properties || {}
      };
    }

    function getParam(name) {
      const params = new URLSearchParams(window.location.search);
      return params.get(name);
    }

    async function send(event) {
      const headers = { 'Content-Type': 'application/json' };
      if (projectKey) headers['X-API-Key'] = projectKey;

      try {
        await fetch(endpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify(event)
        });
      } catch (e) {
        console.warn('[tracking-core] Falha ao enviar evento', e);
      }
    }

    // Dispara eventos de scroll (25%, 75%, 100%) uma vez por marca
    function trackScrollDepth(options) {
      const opts = options || {};
      const el = typeof opts.element === 'string'
        ? document.querySelector(opts.element)
        : opts.element || null;
      const container = el || (document.scrollingElement || document.documentElement);
      const percentMarks = opts.percentMarks || [25, 75, 100];
      const sent = {};

      function getScrollPercent() {
        if (container === document.scrollingElement || container === document.documentElement) {
          const doc = document.documentElement;
          const scrollTop = window.pageYOffset || doc.scrollTop;
          const scrollHeight = Math.max(doc.scrollHeight, doc.body.scrollHeight) - window.innerHeight;
          return scrollHeight <= 0 ? 100 : (scrollTop / scrollHeight) * 100;
        }
        const scrollTop = container.scrollTop;
        const scrollHeight = container.scrollHeight - container.clientHeight;
        return scrollHeight <= 0 ? 100 : (scrollTop / scrollHeight) * 100;
      }

      function onScroll() {
        const pct = getScrollPercent();
        percentMarks.forEach(function (mark) {
          if (pct >= mark && !sent[mark]) {
            sent[mark] = true;
            send(baseEvent('scroll_' + mark, { percent: mark, scroll_percent: pct }));
          }
        });
      }

      if (container === document.scrollingElement || container === document.documentElement) {
        window.addEventListener('scroll', onScroll, { passive: true });
      } else {
        container.addEventListener('scroll', onScroll, { passive: true });
      }
      onScroll();
    }

    return {
      trackPageView() {
        send(baseEvent('PageView', {}));
      },
      trackViewContent(properties) {
        send(baseEvent('ViewContent', properties || {}));
      },
      trackInitiateCheckout(properties) {
        send(baseEvent('InitiateCheckout', properties || {}));
      },
      trackAddToCart(properties) {
        send(baseEvent('AddToCart', properties || {}));
      },
      trackPurchase(data) {
        const props = data || {};
        send(
          baseEvent('Purchase', {
            order_id: props.order_id,
            value: props.value,
            currency: props.currency || 'BRL',
            items: props.items || []
          })
        );
      },
      trackLead(properties) {
        send(baseEvent('Lead', properties || {}));
      },
      trackContact(properties) {
        send(baseEvent('Contact', properties || {}));
      },
      trackScrollDepth: trackScrollDepth,
      track(eventName, properties) {
        send(baseEvent(eventName, properties || {}));
      }
    };
  }

  window.TrackingCore = { createTracker };
})(window);

