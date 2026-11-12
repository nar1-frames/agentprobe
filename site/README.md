# Landing page

Static pages for ordering an AgentProbe scan. No build step: open any page
directly from disk (`file://`) to preview it.

| File | What it is |
|---|---|
| `index.html` | The landing page: the $199 scan and report, the free open-source tool, and the $2,500 full assessment. CSS and script are inline; fonts load from Google Fonts. The sample-report image is embedded in the page. |
| `model.webp` | The animated 3D model shown in the "49 probes, one agent" section of `index.html`. |
| `privacy.html` | Privacy policy for the paid services. Marked as a draft until reviewed. |
| `terms.html` | Terms of service for the paid services. Marked as a draft until reviewed. |
| `order-received.html` | Where Stripe sends buyers after payment. It collects the agent details and the written authorization, and prepares them as an email to send. |

## Checkout

The three order buttons in `index.html` carry a `data-checkout` attribute.
Near the top of the page's script is one setting:

```js
var CHECKOUT_URL = "";
```

Paste the Stripe Payment Link between the quotes. While it is empty, the order
buttons stay on the page (they jump to the pricing section) and a "Draft" notice
shows at the top. Once it is set, every order button opens the Payment Link and
the notice hides. In Stripe, set the Payment Link's confirmation page to
redirect to `order-received.html` on the published site.

## Publishing

`.github/workflows/pages.yml` publishes every file in this folder except this
README to GitHub Pages, on every push to `main` that touches `site/`,
`examples/sample-report/`, or `examples/sample-retest/`. It also copies the
sample report to `sample-report/` and the sample retest to `sample-retest/`
beside the pages (`scripts/check_links.py` maps those paths to the repository
copies).

The deploy step runs only when GitHub Pages is enabled for the repository
(Settings, then Pages, with "GitHub Actions" as the source). Until then the
workflow builds the site and skips publishing.

`tests/test_site.py` checks that every local link and file reference in the
four pages resolves, that no contact placeholder is left, that `index.html` has
the `CHECKOUT_URL` setting and three order buttons, and that it links the
privacy policy and terms.
