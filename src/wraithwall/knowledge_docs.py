"""Public knowledge base routes — CC BY 4.0 field handbooks (no auth)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from flask import Blueprint, abort, render_template

knowledge_bp = Blueprint('knowledge', __name__)

ROOT = Path(__file__).resolve().parent
ARTICLES = ROOT / 'docs' / 'knowledge-pipeline' / 'articles'
MANIFEST = ROOT / 'docs' / 'knowledge-pipeline' / 'manifest.json'

def _published_slugs() -> dict[str, dict]:
    if not MANIFEST.is_file():
        return {}
    data = json.loads(MANIFEST.read_text())
    out = {}
    for pub in data.get('publications', []):
        if pub.get('status') == 'PUBLISHED' and pub.get('slug'):
            out[pub['slug']] = pub
    return out

def _strip_front_matter(text: str) -> str:
    if text.startswith('---'):
        parts = text.split('---', 2)
        if len(parts) >= 3:
            return parts[2].lstrip('\n')
    return text

def _md_to_html(md: str) -> str:
    import markdown

    return markdown.markdown(
        md,
        extensions=['tables', 'fenced_code', 'sane_lists', 'toc'],
    )

def _enrich_callouts(html: str) -> str:
    """Style blockquote callouts for Security warning / Operational note / Common mistake."""
    for label, css in (
        ('Security warning', 'kw-callout kw-warn'),
        ('Operational note', 'kw-callout kw-note'),
        ('Common mistake', 'kw-callout kw-mistake'),
    ):
        html = re.sub(
            rf'<blockquote>\s*<p><strong>{label}:</strong>\s*(.*?)</p>\s*</blockquote>',
            rf'<div class="{css}"><strong>{label}:</strong> \1</div>',
            html,
            flags=re.DOTALL | re.IGNORECASE,
        )
    return html

@knowledge_bp.route('/docs/knowledge/<slug>')
def knowledge_article(slug: str):
    published = _published_slugs()
    if slug not in published:
        abort(404)
    meta_path = ARTICLES / slug / 'meta.json'
    website_path = ARTICLES / slug / 'website.md'
    if not meta_path.is_file() or not website_path.is_file():
        abort(404)
    meta = json.loads(meta_path.read_text())
    body = _strip_front_matter(website_path.read_text())
    content = _enrich_callouts(_md_to_html(body))
    pair = meta.get('pair_guide')
    pair_title = None
    if pair and pair in published:
        pair_title = published[pair].get('title')
    return render_template(
        'knowledge_article.html',
        meta=meta,
        content=content,
        pair_guide=pair,
        pair_title=pair_title,
    )

def knowledge_sitemap_entries(base_url: str) -> list[tuple[str, str]]:
    """Return (loc, lastmod) for published knowledge articles."""
    entries = []
    for slug, pub in _published_slugs().items():
        src = ARTICLES / slug / 'website.md'
        lastmod = ''
        if src.is_file():
            from datetime import datetime
            lastmod = datetime.utcfromtimestamp(src.stat().st_mtime).strftime('%Y-%m-%d')
        entries.append((f'{base_url}/docs/knowledge/{slug}', lastmod))
    return entries

def register_knowledge_routes(app) -> None:
    app.register_blueprint(knowledge_bp)