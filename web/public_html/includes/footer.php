<?php
/**
 * Shared footer — included by all pages.
 * Expects $app array and $appName to be set by the calling page.
 */

// Load config if not already available (needed for portfolio_enabled check)
if (!isset($config)) {
    $config = [];
    $_configPath = __DIR__ . DIRECTORY_SEPARATOR . 'config.php';
    if (file_exists($_configPath)) {
        require_once $_configPath;
    }
}

// Copyright helper
if (isset($app["Application"]["Copyright"]["Year"]["Start"])
    && is_numeric($app["Application"]["Copyright"]["Year"]["Start"])
    && $app["Application"]["Copyright"]["Year"]["Start"] < date("Y")) {
    $_footerCopyrightYear = $app["Application"]["Copyright"]["Year"]["Start"] . "-" . date("Y");
} else {
    $_footerCopyrightYear = date("Y");
}

if (isset($app["Application"]["Vendor"]["Parent"]["Name"]) && $app["Application"]["Vendor"]["Parent"]["Name"]) {
    $_footerCopyrightOwner = $app["Application"]["Vendor"]["Parent"]["Name"];
} elseif (isset($app["Application"]["Vendor"]["Name"]) && $app["Application"]["Vendor"]["Name"]) {
    $_footerCopyrightOwner = $app["Application"]["Vendor"]["Name"];
} elseif (isset($appName) && $appName) {
    $_footerCopyrightOwner = $appName;
} else {
    $_footerCopyrightOwner = null;
}

$_footerTitle = isset($appName) ? $appName : 'WHOIS Lookup';

// ── Conditional footer link visibility ──
// Both flags below depend on the user account system (Issue #163).
// Until #163 is implemented, $_SESSION['logged_in'] and $_SESSION['is_developer']
// are never set, so these links stay hidden for all visitors.

// Portfolio: requires config enabled + logged in + watched domains in localStorage (Issue #171)
$_showPortfolio = !empty($config['portfolio_enabled'])
    && !empty($_SESSION['logged_in']);

// API Documentation: requires logged in + developer account (Issue #172)
// A developer account is a prerequisite for API key issuance.
$_showApiDocs = !empty($_SESSION['logged_in'])
    && !empty($_SESSION['is_developer']);
?>
    <footer class="footer">
        <div class="footer-row">
            <div class="footer-left">
                <?php if ($_showApiDocs): ?><a href="docs" class="footer-link">API Documentation</a> | <?php endif; ?><?php if ($_showPortfolio): ?><span id="footerPortfolioLink" style="display:none;"><a href="portfolio" class="footer-link">Portfolio</a> | </span><?php endif; ?><span id="footerWatchlistFeed" style="display:none;"><a href="feed-watchlist" class="footer-link" title="Watched Domains RSS Feed"><i class="bi bi-rss" aria-hidden="true"></i> Watchlist Feed</a> | </span>
                <a href="privacy" class="footer-link">Privacy Policy</a> | <a href="terms" class="footer-link">Terms of Service</a>
            </div>
            <div class="footer-right">
                <?php
                    echo htmlspecialchars($_footerTitle);

                    if (isset($app["Application"]["Version"]["Number"]) && $app["Application"]["Version"]["Number"]){
                        echo ' <a href="feed" class="footer-link" title="Changelog RSS Feed" target="_blank" rel="noopener noreferrer">v' . htmlspecialchars($app["Application"]["Version"]["Number"]) . '</a>';

                        if (!empty($app["Application"]["Version"]["Repo"]["Commit"]["SHA"]["Short"])){
                            echo ' <span style="font-size: 0.8em">(<a href="' . htmlspecialchars($app["Application"]["Version"]["Repo"]["Commit"]["URL"]) . '" target="_blank" rel="noopener noreferrer" class="footer-commit">';
                            echo htmlspecialchars($app["Application"]["Version"]["Repo"]["Commit"]["SHA"]["Short"]);
                            echo '</a>';

                            if (!empty($app["Application"]["Version"]["Repo"]["Commit"]["Date"])){
                                echo ' ' . htmlspecialchars($app["Application"]["Version"]["Repo"]["Commit"]["Date"]);
                            }

                            echo ")</span><br>";
                        }
                    }
                ?>
                &copy; <?php echo htmlspecialchars("$_footerCopyrightYear $_footerCopyrightOwner"); ?>. All Rights Reserved
            </div>
        </div>
    </footer>
    <script>
    (function () {
        try {
            var w = JSON.parse(localStorage.getItem('watchedDomains') || '[]');
            if (w.length) {
<?php if ($_showPortfolio): ?>
                var fl = document.getElementById('footerPortfolioLink');
                if (fl) {
                    fl.style.display = '';
                }
                var hl = document.getElementById('historyPortfolioLink');
                if (hl) {
                    hl.style.display = '';
                }
<?php endif; ?>
                var wf = document.getElementById('footerWatchlistFeed');
                if (wf) {
                    wf.style.display = '';
                }
                var hwf = document.getElementById('historyWatchlistFeed');
                if (hwf) {
                    hwf.style.display = '';
                }
            }
        } catch (e) {}
    })();
    </script>
