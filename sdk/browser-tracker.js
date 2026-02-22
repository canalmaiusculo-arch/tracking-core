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

    return {
      trackPageView() {
        send(baseEvent('PageView', {}));
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
      track(eventName, properties) {
        send(baseEvent(eventName, properties || {}));
      }
    };
  }

  window.TrackingCore = { createTracker };
})(window);

