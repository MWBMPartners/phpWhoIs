<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:atom="http://www.w3.org/2005/Atom">
<xsl:output method="html" doctype-system="about:legacy-compat" encoding="UTF-8" indent="yes"/>

<xsl:template match="/">
<html lang="en" data-theme="auto">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title><xsl:value-of select="/rss/channel/title"/> — RSS Feed</title>
    <style>
        /* ─── Light theme (default) ─── */
        :root, [data-theme="light"] {
            --bg: #f8f9fa;
            --card-bg: #fff;
            --text: #212529;
            --muted: #6c757d;
            --accent: #0d6efd;
            --border: #dee2e6;
            --banner-bg: #0d6efd;
            --toggle-bg: rgba(0,0,0,0.08);
            --toggle-hover: rgba(0,0,0,0.12);
            --toggle-text: #212529;
        }

        /* ─── Dark theme ─── */
        [data-theme="dark"] {
            --bg: #212529;
            --card-bg: #2b3035;
            --text: #dee2e6;
            --muted: #8b949e;
            --accent: #6ea8fe;
            --border: #495057;
            --banner-bg: #1a5276;
            --toggle-bg: rgba(255,255,255,0.1);
            --toggle-hover: rgba(255,255,255,0.15);
            --toggle-text: #dee2e6;
        }

        /* ─── Colourblind-safe theme ─── */
        [data-theme="colourblind"] {
            --bg: #f5f3ee;
            --card-bg: #fff;
            --text: #212529;
            --muted: #595347;
            --accent: #0077BB;
            --border: #bbb5a6;
            --banner-bg: #0077BB;
            --toggle-bg: rgba(0,0,0,0.08);
            --toggle-hover: rgba(0,0,0,0.12);
            --toggle-text: #212529;
        }

        /* ─── Auto theme: follow system preference ─── */
        @media (prefers-color-scheme: dark) {
            [data-theme="auto"] {
                --bg: #212529;
                --card-bg: #2b3035;
                --text: #dee2e6;
                --muted: #8b949e;
                --accent: #6ea8fe;
                --border: #495057;
                --banner-bg: #1a5276;
                --toggle-bg: rgba(255,255,255,0.1);
                --toggle-hover: rgba(255,255,255,0.15);
                --toggle-text: #dee2e6;
            }
        }

        /* ─── Base styles ─── */
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem 1rem;
            transition: background 0.2s, color 0.2s;
        }
        .container { max-width: 700px; margin: 0 auto; }

        /* ─── Header row ─── */
        .header-row {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 0.25rem;
        }

        /* ─── Theme toggle ─── */
        .theme-toggle {
            position: relative;
            flex-shrink: 0;
        }
        .theme-toggle-btn {
            background: var(--toggle-bg);
            border: 1px solid var(--border);
            border-radius: 0.375rem;
            padding: 0.35rem 0.65rem;
            font-size: 0.85rem;
            color: var(--toggle-text);
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.35rem;
            transition: background 0.15s;
        }
        .theme-toggle-btn:hover { background: var(--toggle-hover); }
        .theme-menu {
            display: none;
            position: absolute;
            right: 0;
            top: 100%;
            margin-top: 0.25rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.375rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            min-width: 150px;
            z-index: 10;
            padding: 0.25rem 0;
        }
        .theme-menu.open { display: block; }
        .theme-menu button {
            display: block;
            width: 100%;
            text-align: left;
            background: none;
            border: none;
            padding: 0.45rem 0.85rem;
            font-size: 0.88rem;
            color: var(--text);
            cursor: pointer;
        }
        .theme-menu button:hover { background: var(--toggle-bg); }
        .theme-menu button.active { font-weight: 600; color: var(--accent); }

        /* ─── Banner ─── */
        .banner {
            background: var(--banner-bg);
            color: #fff;
            padding: 1rem 1.25rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
            font-size: 0.9rem;
        }
        .banner strong { display: block; font-size: 1.1rem; margin-bottom: 0.25rem; }
        .banner a { color: #fff; }

        /* ─── Content ─── */
        h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
        .subtitle { color: var(--muted); margin-bottom: 2rem; }
        .item {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 1.25rem;
            margin-bottom: 1rem;
            transition: background 0.2s, border-color 0.2s;
        }
        .item-title {
            font-size: 1.05rem;
            font-weight: 600;
            margin-bottom: 0.35rem;
        }
        .item-title a { color: var(--accent); text-decoration: none; }
        .item-title a:hover { text-decoration: underline; }
        .item-date { font-size: 0.85rem; color: var(--muted); margin-bottom: 0.5rem; }
        .item-desc { font-size: 0.92rem; color: var(--muted); }
        footer {
            text-align: center;
            margin-top: 2rem;
            font-size: 0.85rem;
            color: var(--muted);
        }
        footer a { color: var(--accent); text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="banner">
            <strong>This is an RSS feed</strong>
            Copy the URL into your favourite feed reader to subscribe to updates.
        </div>

        <div class="header-row">
            <div>
                <h1><xsl:value-of select="/rss/channel/title"/></h1>
                <p class="subtitle"><xsl:value-of select="/rss/channel/description"/></p>
            </div>
            <div class="theme-toggle">
                <button class="theme-toggle-btn" id="themeBtn" type="button" aria-label="Change theme" title="Change theme">
                    <span id="themeIcon">&#9681;</span>
                    <span>&#9662;</span>
                </button>
                <div class="theme-menu" id="themeMenu">
                    <button type="button" data-theme="auto">&#9681; Auto</button>
                    <button type="button" data-theme="light">&#9728; Light</button>
                    <button type="button" data-theme="dark">&#9790; Dark</button>
                    <button type="button" data-theme="colourblind">&#9673; Colourblind</button>
                </div>
            </div>
        </div>

        <xsl:for-each select="/rss/channel/item">
            <div class="item">
                <div class="item-title">
                    <a>
                        <xsl:attribute name="href"><xsl:value-of select="link"/></xsl:attribute>
                        <xsl:value-of select="title"/>
                    </a>
                </div>
                <div class="item-date"><xsl:value-of select="pubDate"/></div>
                <div class="item-desc"><xsl:value-of select="description" disable-output-escaping="yes"/></div>
            </div>
        </xsl:for-each>

        <footer>
            <a>
                <xsl:attribute name="href"><xsl:value-of select="/rss/channel/link"/></xsl:attribute>
                Visit <xsl:value-of select="/rss/channel/title"/>
            </a>
        </footer>
    </div>

    <script>
    (function() {
        var icons = {auto:'\u25D1', light:'\u2600', dark:'\u263E', colourblind:'\u25C9'};
        var stored = localStorage.getItem('feed-theme') || 'auto';
        var root = document.documentElement;
        var btn = document.getElementById('themeBtn');
        var menu = document.getElementById('themeMenu');
        var iconEl = document.getElementById('themeIcon');

        function apply(t) {
            root.setAttribute('data-theme', t);
            iconEl.textContent = icons[t] || icons.auto;
            var btns = menu.querySelectorAll('button');
            for (var i = 0; i &lt; btns.length; i++) {
                if (btns[i].getAttribute('data-theme') === t) {
                    btns[i].classList.add('active');
                } else {
                    btns[i].classList.remove('active');
                }
            }
            localStorage.setItem('feed-theme', t);
        }

        apply(stored);

        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            menu.classList.toggle('open');
        });

        var items = menu.querySelectorAll('button');
        for (var i = 0; i &lt; items.length; i++) {
            items[i].addEventListener('click', function() {
                apply(this.getAttribute('data-theme'));
                menu.classList.remove('open');
            });
        }

        document.addEventListener('click', function() {
            menu.classList.remove('open');
        });
    })();
    </script>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
