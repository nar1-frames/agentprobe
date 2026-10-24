# Landing page

`index.html` is the assessment landing page: a single static file with inline
CSS, no scripts, and no external fonts or assets. Open it directly from disk
(`file://`) to preview it. It follows the system light or dark theme.

`.github/workflows/pages.yml` publishes it to GitHub Pages on every push to
`main` that touches `site/` or `examples/sample-report/`. The workflow copies
the sample report to `sample-report/` beside the page. That one "web version"
link works only on the deployed site. The other proof links point at
github.com.

Before the first deploy:

1. Replace `CONTACT_EMAIL@example.com` in `index.html` (it appears twice) with
   the address that should receive scoping-call requests.
2. In the repository settings, under Pages, set the source to "GitHub Actions".

`tests/test_site.py` checks that the page stays self-contained and that its
in-page links resolve.
