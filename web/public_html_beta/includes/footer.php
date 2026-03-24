<?php
/**
 * Shared footer — included by all pages.
 * Expects $app array and $appName to be set by the calling page.
 */

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
?>
    <footer class="footer">
        <div class="footer-row">
            <div class="footer-left">
                <a href="docs" class="footer-link">API Documentation</a> | <a href="portfolio" class="footer-link">Portfolio</a> | <a href="feed" class="footer-link" title="RSS Feed"><i class="bi bi-rss" aria-hidden="true"></i> RSS</a><br>
                <a href="privacy" class="footer-link">Privacy Policy</a> | <a href="terms" class="footer-link">Terms of Service</a>
            </div>
            <div class="footer-right">
                <?php
                    echo htmlspecialchars($_footerTitle);

                    if (isset($app["Application"]["Version"]["Number"]) && $app["Application"]["Version"]["Number"]){
                        echo " v" . htmlspecialchars($app["Application"]["Version"]["Number"]);

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
