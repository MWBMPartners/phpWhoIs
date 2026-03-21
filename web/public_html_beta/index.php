<?php //https://chatgpt.com/share/66ed46d1-c1a4-800b-bc0a-93663c3084dd ?><?php
	#########################################
	#			WhoIs Lookup Tool			#
	#										#
	# version: v0.3.000						#
	#										#
	#########################################
	#		(C) 2024 MWservices.it			#
	#########################################

	##Domain Name Whois Lookup Tool
	##	BASED ON //https://chatgpt.com/share/66ed46d1-c1a4-800b-bc0a-93663c3084dd

	// Session hardening & CSRF (replaces protectSessionInjection)
	ini_set('session.use_strict_mode', 1);
	ini_set('session.use_only_cookies', 1);
	ini_set('session.cookie_httponly', 1);
	ini_set('session.cookie_samesite', 'Strict');
	if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
		ini_set('session.cookie_secure', 1);
	}
	session_start();
	// Regenerate session ID periodically to prevent fixation
	if (!isset($_SESSION['_created'])) {
		$_SESSION['_created'] = time();
	} elseif (time() - $_SESSION['_created'] > 1800) {
		session_regenerate_id(true);
		$_SESSION['_created'] = time();
	}
	// Generate CSRF token
	if (empty($_SESSION['csrf_token'])) {
		$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
	}
	$csrfToken = $_SESSION['csrf_token'];

	//Case Insensitive GET Params
	//	https://stackoverflow.com/a/4211432/1954972
		$_lowerGET = array_change_key_case($_GET, CASE_LOWER);

	//////////////////////////////////////////////////////////////////////////////
	//			START of Integration of WebMS Shared/Global Resources			//
	//////////////////////////////////////////////////////////////////////////////
		//Check loading status
			//Dev
				if (isset($_lowerGET['dev']) or isset($_GET['dev'])){
					$modeDev = TRUE;
				
					//Debug
						if (isset($_lowerGET['debug']) or isset($_GET['debug'])){
							$modeDebug = TRUE;
						}
						else{
							$modeDebug = FALSE;
						}
				}
				else{
					$modeDev = FALSE;
					$modeDebug = FALSE;
				}
				
				if (isset($modeDebug) && $modeDebug === TRUE){
					echo nl2br("modeDev: ". $modeDev." (FILE: ".__FILE__."; LINE: ".__LINE__.")". PHP_EOL . PHP_EOL);
					echo nl2br("modeDebug: ". $modeDebug." (FILE: ".__FILE__."; LINE: ".__LINE__.")". PHP_EOL . PHP_EOL);
				}
			
		//Enable Error Reporting if accessed in Debug mode
			if (isset($modeDebug) && $modeDebug === TRUE){
				if (isset($_lowerGET['debug']) or isset($debug) or $debug or isset($_lowerGET['dev']) or isset($dev) or $dev){
					ini_set('display_errors',1);
					error_reporting(E_ALL);
				}
			}

		$countError = 0;

		//melaS WebMS Shared Components
			//Define & Initialise WebMS Shared Components
				//Define Host Root Directory
					if (!isset($pathHostRoot) or empty($pathHostRoot) or !file_exists($pathHostRoot)){
						if (file_exists(dirname(dirname(dirname(dirname(dirname(dirname(__FILE__)))))))){
							$pathHostRoot = dirname(dirname(dirname(dirname(dirname(dirname(__FILE__))))));
						}
						else{
							if (function_exists("webmsStatus")){
								webmsStatus("Host Root directory not defined", __FILE__, __LINE__);
							}
						}
					}

					if (isset($pathHostRoot) && $pathHostRoot){
						//Directory to WebMS Functions
							if (!isset($pathFunctions) or empty($pathFunctions) or !file_exists($pathFunctions. DIRECTORY_SEPARATOR ."all.php")){
								if (file_exists($pathHostRoot. DIRECTORY_SEPARATOR ."_functions")){
									$pathFunctions = $pathHostRoot. DIRECTORY_SEPARATOR ."_functions";

									//Add Support for WebMS Shared Functions
										require_once ($pathFunctions. DIRECTORY_SEPARATOR ."all.php");
								}
								elseif (file_exists(dirname(__FILE__))){
									$pathFunctions = dirname(__FILE__);

									//Add Support for WebMS Shared Functions
										require_once ($pathFunctions. DIRECTORY_SEPARATOR ."all.php");
								}
								else{
									if (function_exists("webmsStatus")){
										webmsStatus("WebMS shared functions directory not found", __FILE__, __LINE__);
									}
								}
							}

						//Directory to WebMS Shared Libraries
							if (!isset($pathLibraries) or empty($pathLibraries) or !file_exists($pathLibraries)){
								if (file_exists($pathHostRoot. DIRECTORY_SEPARATOR ."_libraries")){
									$pathLibraries = $pathHostRoot. DIRECTORY_SEPARATOR ."_libraries";
								}
								else{
									if (function_exists("webmsStatus")){
										webmsStatus("WebMS shared libraries directory not found", __FILE__, __LINE__);
									}
								}
							}

						//Directory to WebMS Error Pages
							if (!isset($pathErrors) or empty($pathErrors) or !file_exists($pathErrors)){
								if (file_exists($pathHostRoot. DIRECTORY_SEPARATOR ."_errors")){
									$pathErrors = $pathHostRoot. DIRECTORY_SEPARATOR ."_errors";
								}
								else{
									if (function_exists("webmsStatus")){
										webmsStatus("WebMS shared errors directory not found", __FILE__, __LINE__);
									}
								}
							}

						//Directory to SysCheck
						/*	if (!isset($pathSysCheck) or empty($pathSysCheck) or !file_exists($pathSysCheck)){
								if (file_exists($pathHostRoot. DIRECTORY_SEPARATOR ."_syscheck")){
									$pathSysCheck = $pathHostRoot. DIRECTORY_SEPARATOR ."_syscheck";
								}
								else{
									if (function_exists("webmsStatus")){
										webmsStatus("SysCheck directory not found", __FILE__, __LINE__);
									}
								}
							}	*/
					}

			//Define & Initialise App Specific Components
				//Define App Root Directory
					if (!isset($pathAppRoot) or empty($pathAppRoot) or !file_exists($pathAppRoot)){
					/*	if (file_exists(dirname(dirname(__FILE__)))){
							$pathAppRoot = dirname(dirname(__FILE__));
						}   */
						if (file_exists(dirname(__FILE__))){
							$pathAppRoot = dirname(__FILE__);
						}
						else{
							if (function_exists("webmsStatus")){
								webmsStatus("Application root directory (pathAppRoot) not specified", __FILE__, __LINE__);
							}
						}
					}

					if (isset($pathAppRoot) && !empty($pathAppRoot)){
						//App Functions Directory
							if (!isset($pathAppFunctions) or empty($pathAppFunctions) or !file_exists($pathAppFunctions)){
								if (file_exists($pathAppRoot. DIRECTORY_SEPARATOR ."_functions")){
									$pathAppFunctions = $pathAppRoot. DIRECTORY_SEPARATOR ."_functions";

									//Declare all App Specific Functions
										if (file_exists($pathAppFunctions. DIRECTORY_SEPARATOR ."all.php")){
											require_once ($pathAppFunctions. DIRECTORY_SEPARATOR ."all.php");
										}

								//		require_once ($pathAppFunctions. DIRECTORY_SEPARATOR ."dbFunctions.php");
								}
								else{
									if (function_exists("webmsStatus")){
										webmsStatus("Application functions directory not found", __FILE__, __LINE__);
									}
								}
							}

						//App Libraries Directory
							if (!isset($pathAppLibraries) or empty($pathAppLibraries) or !file_exists($pathAppLibraries)){
								if (file_exists($pathAppRoot. DIRECTORY_SEPARATOR ."_libraries")){
									$pathAppLibraries = $pathAppRoot. DIRECTORY_SEPARATOR ."_libraries";
								}
								else{
									if (function_exists("webmsStatus")){
										webmsStatus("Application functions directory not found", __FILE__, __LINE__);
									}
								}
							}

						//App Configuration Directory
							if (!isset($pathAppConfig) or empty($pathAppConfig) or !file_exists($pathAppConfig)){
								if (file_exists($pathAppRoot. DIRECTORY_SEPARATOR ."_config")){
									$pathAppConfig = $pathAppRoot. DIRECTORY_SEPARATOR ."_config";
								}
								else{
									//COMING SOON
										$countError = $countError+1;

										$streamLoadData["Response"]["Status"]["Error"][$countError]["Code"] = "AppConfigDirFail";
										$streamLoadData["Response"]["Status"]["Error"][$countError]["Severity"] = "WARNING";
										$streamLoadData["Response"]["Status"]["Error"][$countError]["ErrorDescription"] = "App specific config folder not found (this is not necessarily a problem)";

										if (isset($modeDebug) && $modeDebug === TRUE){
											$streamLoadData["Response"]["Status"]["Error"][$countError]["Backtrace"] = var_dump(debug_backtrace());
										}

								/*	if (function_exists("webmsStatus")){
										webmsStatus("Application configuration data directory not found", __FILE__, __LINE__);
									}	*/
								}
							}

						//App Templates Directory
							if (!isset($pathAppTemplates) or empty($pathAppTemplates) or !file_exists($pathAppTemplates)){
								if (file_exists($pathAppRoot. DIRECTORY_SEPARATOR ."_templates")){
									$pathAppTemplates = $pathAppRoot. DIRECTORY_SEPARATOR ."_templates";
								}
								else{
									//COMING SOON
										$countError = $countError+1;

										$streamLoadData["Response"]["Status"]["Error"][$countError]["Code"] = "AppTemplatesDirFail";
										$streamLoadData["Response"]["Status"]["Error"][$countError]["Severity"] = "WARNING";
										$streamLoadData["Response"]["Status"]["Error"][$countError]["ErrorDescription"] = "App templates folder not found (this is not necessarily an issue)";

										if (isset($modeDebug) && $modeDebug === TRUE){
											$streamLoadData["Response"]["Status"]["Error"][$countError]["Backtrace"] = var_dump(debug_backtrace());
										}

								/*	if (function_exists("webmsStatus")){
										webmsStatus("Application templates directory not found", __FILE__, __LINE__);
									}	*/
								}
							}
					}

			// Session injection protection handled at top of file (replaces legacy protectSessionInjection)

			//Run SysCheck
			/*	if (function_exists("defineSysCheck")){
					$pathSysCheck = defineSysCheck(NULL, NULL, NULL, TRUE);
				}
				else{
					if (function_exists("webmsStatus")){
						webmsStatus("SysCheck not loaded", __FILE__, __LINE__);
					}
				}	*/

			//Allow for viewing of PHP Source Code
				if (function_exists("allowViewSourceCode")){
					allowViewSourceCode();
				}

			//phpGlobalVars - Sets common PHP variables
				if (function_exists("phpGlobalVars")){
					$phpCommonVars = phpGlobalVars();
				}
				else{
					echo "no GlobalVars";
				}

			//Retrieve/Initialise WebMS Global Variables
				if (function_exists("getParams")){
					getParams();
				}
				else{
					if (function_exists("webmsStatus")){
						webmsStatus("Parameters not collected, function (getParams()) not found", __FILE__, __LINE__);
					}
				}

			//////////////////////////////////////////////////////////
			//														//
			// When "debug" variable is used, extra debugging info	//
			// is displayed, such as hidden variables set, etc. To 	//
			// be used be developers only.				 			//
			//														//
			// NOTE: This variable does NOT need to have a value. 	//
			// 		 It just needs to be present.					//
			//														//
			//////////////////////////////////////////////////////////
				if (function_exists("paramDebug")){
					paramDebug();
				}

			//////////////////////////////////////////////////////////
			//  When "stealth" variable is used, website visitor	//
			//  monitoring & statistics gathering (analytics) is	//
			//				disabled.								//
			//														//
			// NOTE: This variable does NOT need to have a value. 	//
			// 	   It just needs to be present.						//
			//////////////////////////////////////////////////////////
				if (function_exists("getPrivacyMode")){
					getPrivacyMode();
				}

			//////////////////////////////////////////////////////////
			// When "textselect" variable is used, it allows the  	//
			// user to select text on the website which can then  	//
			//  be copied to the clipboard. Failure to use this   	//
			//   variable disables the selection of text. This is 	//
			//	 done to prevent source code viewing/copying		//
			//													  	//
			// NOTE: This variable does NOT need to have a value. 	//
			// 	   It just needs to be present.						//
			//////////////////////////////////////////////////////////
				if (function_exists("paramAllowTextSelect")){
					paramAllowTextSelect();
				}

	//////////////////////////////////////////////////////////////////////////////
	//			END of Integration of WebMS Shared/Global Resources				//
	//////////////////////////////////////////////////////////////////////////////

    if (file_exists($pathAppRoot. DIRECTORY_SEPARATOR ."infoAppVer.php")){
        require_once ($pathAppRoot. DIRECTORY_SEPARATOR ."infoAppVer.php");
    }
    else{
        if (function_exists("webmsStatus")){
            webmsStatus("Application Version Info not loaded", __FILE__, __LINE__);
        }
    }
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Whois Lookup</title>

    <!-- Bootstrap 5 CSS (Issue #8) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Header -->
    <div class="header-form">
        <div class="d-flex justify-content-between align-items-center mb-2">
            <h1 class="mb-0">Whois Lookup</h1>
            <button class="btn btn-sm btn-outline-secondary" id="darkModeToggle" title="Toggle dark mode">
                <i class="bi bi-moon-fill" id="darkModeIcon"></i>
            </button>
        </div>

        <!-- Lookup mode tabs (Issue #5) -->
        <ul class="nav nav-tabs mb-3" id="lookupModeTabs">
            <li class="nav-item">
                <a class="nav-link active" href="#" data-mode="single">Single Lookup</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="#" data-mode="bulk">Bulk Lookup</a>
            </li>
        </ul>

        <!-- Single domain form -->
        <form id="whoisForm" class="form-container">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
            <div class="form-group flex-grow-1">
                <label for="domain" class="visually-hidden">Domain or URL</label>
                <input type="text" class="form-control" id="domain" name="domain"
                    title="Please enter a valid domain name, e.g., example.com"
                    placeholder="example.com" required autocomplete="off">
            </div>
            <button type="submit" class="btn btn-primary submit-btn">Lookup</button>
        </form>

        <!-- Bulk domain form (Issue #5) -->
        <form id="bulkWhoisForm" class="form-container" style="display:none;">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
            <div class="form-group flex-grow-1">
                <label for="bulkDomains" class="visually-hidden">Domains (one per line)</label>
                <textarea class="form-control" id="bulkDomains" name="domains" rows="4"
                    placeholder="example.com&#10;example.org&#10;example.net" required></textarea>
            </div>
            <button type="submit" class="btn btn-primary submit-btn">Lookup All</button>
        </form>

        <!-- Recent lookups (Issue #4) -->
        <div id="historyContainer" class="mt-2" style="display:none;">
            <div class="d-flex align-items-center gap-2">
                <small class="text-muted">Recent:</small>
                <div id="historyList" class="d-flex flex-wrap gap-1"></div>
                <button class="btn btn-sm btn-link text-muted p-0" id="clearHistory" title="Clear history">
                    <i class="bi bi-x-circle"></i>
                </button>
            </div>
        </div>
    </div>

    <!-- Result section -->
    <div class="result-container" id="resultContainer">
        <!-- Loading spinner (Issue #2) -->
        <div id="loadingSpinner" class="text-center py-5" style="display:none;">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2 text-muted">Looking up domain information...</p>
        </div>

        <!-- Availability badge (Issue #3) -->
        <div id="availabilityBadge" style="display:none;" class="mb-3"></div>

        <!-- Data source indicator (Issue #12) -->
        <div id="dataSourceBadge" style="display:none;" class="mb-2"></div>

        <!-- Structured fields card (Issue #9) -->
        <div id="parsedFields" style="display:none;" class="mb-3"></div>

        <!-- Tab navigation for WHOIS / DNS (Issue #6) -->
        <ul class="nav nav-pills mb-3" id="resultTabs" style="display:none;">
            <li class="nav-item">
                <a class="nav-link active" href="#" data-tab="whois">WHOIS</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="#" data-tab="dns">DNS Records</a>
            </li>
        </ul>

        <!-- WHOIS result -->
        <div id="whoisResultPane">
            <div id="result"></div>
        </div>

        <!-- DNS records pane (Issue #6) -->
        <div id="dnsResultPane" style="display:none;"></div>

        <!-- Action buttons -->
        <div id="actionButtons" class="mt-2 d-flex gap-2 flex-wrap" style="display:none !important;">
            <button class="btn btn-secondary btn-sm toggle-btn" id="toggleViewBtn">Show Raw Whois</button>
            <button class="btn btn-outline-secondary btn-sm" id="copyBtn" title="Copy to clipboard">
                <i class="bi bi-clipboard"></i> Copy
            </button>
            <button class="btn btn-outline-secondary btn-sm" id="downloadBtn" title="Download as text file">
                <i class="bi bi-download"></i> Download
            </button>
        </div>

        <!-- Bulk results accordion (Issue #5) -->
        <div id="bulkResults" class="accordion mt-3" style="display:none;"></div>
    </div>

    <!-- Footer -->
    <div class="footer">
        <?php
        if (isset($appYearStart)){
            if (isset($appVendor)){
                if (isset($appVendorParent)){
                    if ($appYearStart < date("Y")) {
                        echo "&copy; ". $appYearStart ." - ". date("Y") ." ". $appVendorParent ."(t/a) ". $appVendor .". All Rights Reserved";
                    }
                    else {
                        echo "&copy; ". $appYearStart ." ". $appVendorParent ."(t/a) ". $appVendor .". All Rights Reserved";
                    }
                }
                else{
                    if ($appYearStart < date("Y")) {
                        echo "&copy; ". $appYearStart ." - ". date("Y") ." ". $appVendor .". All Rights Reserved";
                    }
                    else {
                        echo "&copy; ". $appYearStart ." Whois Lookup Tool. All Rights Reserved";
                    }
                }
            }
            else{
                if (isset($appVendorParent)){
                    if ($appYearStart < date("Y")) {
                        echo "&copy; ". $appYearStart ." - ". date("Y") ." ". $appVendorParent .". All Rights Reserved";
                    }
                    else {
                        echo "&copy; ". $appYearStart ." ". $appVendorParent .". All Rights Reserved";
                    }
                }
                else{
                    if ($appYearStart < date("Y")) {
                        echo "&copy; ". $appYearStart ." - ". date("Y") ." Whois Lookup Tool. All Rights Reserved";
                    }
                    else {
                        echo "&copy; ". $appYearStart ." Whois Lookup Tool. All Rights Reserved";
                    }
                }
            }
        }
        else{
            if (isset($appVendor)){
                if (isset($appVendorParent)){
                    echo "&copy; ". date("Y") ." ". $appVendorParent ."(t/a) ". $appVendor .". All Rights Reserved";
                }
                else{
                    echo "&copy; ". date("Y") ." ". $appVendor .". All Rights Reserved";
                }
            }
            else{
                if (isset($appVendorParent)){
                    echo "&copy; ". date("Y") ." ". $appVendorParent .". All Rights Reserved";
                }
                else{
                    echo "&copy; ". date("Y") ." Whois Lookup Tool. All Rights Reserved";
                }
            }
        }
        ?>
    </div>

    <!-- Bootstrap 5 JS bundle (Issue #8) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var csrfToken = '<?php echo htmlspecialchars($csrfToken); ?>';
        let formattedResult = '';
        let rawWhoisText = '';
        let isRawView = false;
        let currentDomain = '';

        // ---- Dark mode (Issue #8) ----
        const darkModeToggle = document.getElementById('darkModeToggle');
        const darkModeIcon = document.getElementById('darkModeIcon');
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-bs-theme', savedTheme);
        updateDarkModeIcon(savedTheme);

        darkModeToggle.addEventListener('click', function () {
            const current = document.documentElement.getAttribute('data-bs-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-bs-theme', next);
            localStorage.setItem('theme', next);
            updateDarkModeIcon(next);
        });

        function updateDarkModeIcon(theme) {
            darkModeIcon.className = theme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
        }

        // ---- Lookup mode tabs (Issue #5) ----
        document.querySelectorAll('#lookupModeTabs .nav-link').forEach(function (tab) {
            tab.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelectorAll('#lookupModeTabs .nav-link').forEach(function (t) { t.classList.remove('active'); });
                this.classList.add('active');
                var mode = this.dataset.mode;
                document.getElementById('whoisForm').style.display = mode === 'single' ? '' : 'none';
                document.getElementById('bulkWhoisForm').style.display = mode === 'bulk' ? '' : 'none';
            });
        });

        // ---- History (Issue #4) ----
        function getHistory() {
            try { return JSON.parse(localStorage.getItem('whoisHistory') || '[]'); } catch (e) { return []; }
        }
        function saveToHistory(domain) {
            var history = getHistory().filter(function (h) { return h.domain !== domain; });
            history.unshift({ domain: domain, timestamp: Date.now() });
            if (history.length > 10) history = history.slice(0, 10);
            localStorage.setItem('whoisHistory', JSON.stringify(history));
            renderHistory();
        }
        function renderHistory() {
            var history = getHistory();
            var container = document.getElementById('historyContainer');
            var list = document.getElementById('historyList');
            if (history.length === 0) { container.style.display = 'none'; return; }
            container.style.display = '';
            list.innerHTML = history.map(function (h) {
                return '<button class="btn btn-sm btn-outline-primary history-item" data-domain="' + h.domain + '">' + h.domain + '</button>';
            }).join('');
            list.querySelectorAll('.history-item').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    document.getElementById('domain').value = this.dataset.domain;
                    triggerWhoisLookup(this.dataset.domain);
                    updateURL(this.dataset.domain);
                });
            });
        }
        document.getElementById('clearHistory').addEventListener('click', function () {
            localStorage.removeItem('whoisHistory');
            renderHistory();
        });
        renderHistory();

        // ---- URL param auto-lookup ----
        var urlParams = new URLSearchParams(window.location.search);
        var initialDomain = urlParams.get('domain');
        if (initialDomain) {
            document.getElementById('domain').value = initialDomain;
            triggerWhoisLookup(initialDomain);
        }

        // ---- Single form submit ----
        document.getElementById('whoisForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var domain = document.getElementById('domain').value.trim();
            if (!domain) return;
            triggerWhoisLookup(domain);
            updateURL(domain);
        });

        // ---- Bulk form submit (Issue #5) ----
        document.getElementById('bulkWhoisForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var text = document.getElementById('bulkDomains').value.trim();
            if (!text) return;
            var domains = text.split(/[\n,]+/).map(function (d) { return d.trim(); }).filter(function (d) { return d; });
            if (domains.length === 0) return;
            triggerBulkLookup(domains);
        });

        // ---- Main WHOIS lookup ----
        function triggerWhoisLookup(domain) {
            currentDomain = domain;
            showLoading(true);
            hideResults();

            var formData = new FormData();
            formData.append('domain', domain);
            formData.append('csrf_token', csrfToken);

            fetch('lookup.php?nocache=' + Date.now(), { method: 'POST', body: formData })
                .then(function (res) {
                    if (!res.ok) throw new Error('Server error: ' + res.status);
                    return res.json();
                })
                .then(function (data) {
                    showLoading(false);
                    if (data.error) {
                        showError(data.error);
                        return;
                    }
                    rawWhoisText = data.whois || '';
                    displayResults(data);
                    saveToHistory(domain);
                })
                .catch(function (err) {
                    showLoading(false);
                    showError('Lookup failed: ' + err.message + '. Please try again.');
                });
        }

        // ---- Bulk lookup (Issue #5) ----
        function triggerBulkLookup(domains) {
            showLoading(true);
            hideResults();
            var accordion = document.getElementById('bulkResults');
            accordion.innerHTML = '';
            accordion.style.display = '';
            var completed = 0;

            domains.forEach(function (domain, index) {
                setTimeout(function () {
                    var formData = new FormData();
                    formData.append('domain', domain);
                    formData.append('csrf_token', csrfToken);

                    fetch('lookup.php?nocache=' + Date.now(), { method: 'POST', body: formData })
                        .then(function (r) { return r.json(); })
                        .then(function (data) {
                            var item = document.createElement('div');
                            item.className = 'accordion-item';
                            var badgeClass = data.availability === 'available' ? 'bg-success' : 'bg-info';
                            var badgeText = data.availability === 'available' ? 'Available' : 'Registered';
                            var bulkRegisterBtn = '';
                            if (data.availability === 'available') {
                                var bulkRegUrl = 'https://store.mwservices.it/cart.php?a=add&domain=register&query=' + encodeURIComponent(domain);
                                bulkRegisterBtn = ' <a href="' + bulkRegUrl + '" target="_blank" rel="noopener" class="btn btn-success btn-sm ms-2"><i class="bi bi-cart-plus me-1"></i>Register</a>';
                            }
                            item.innerHTML =
                                '<h2 class="accordion-header">' +
                                '<button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#bulk-' + index + '">' +
                                domain + ' <span class="badge ' + badgeClass + ' ms-2">' + badgeText + '</span>' + bulkRegisterBtn +
                                '</button></h2>' +
                                '<div id="bulk-' + index + '" class="accordion-collapse collapse">' +
                                '<div class="accordion-body"><pre>' + (data.whois || data.error || 'No data') + '</pre></div></div>';
                            accordion.appendChild(item);
                            completed++;
                            if (completed === domains.length) showLoading(false);
                        })
                        .catch(function () {
                            completed++;
                            if (completed === domains.length) showLoading(false);
                        });
                }, index * 1000);
            });
        }

        // ---- Display results ----
        function displayResults(data) {
            // Availability badge (Issue #3)
            var avBadge = document.getElementById('availabilityBadge');
            if (data.availability === 'available') {
                var registerUrl = 'https://store.mwservices.it/cart.php?a=add&domain=register&query=' + encodeURIComponent(currentDomain);
                avBadge.innerHTML = '<div class="alert alert-success d-flex align-items-center justify-content-between flex-wrap gap-2">' +
                    '<div><i class="bi bi-check-circle-fill me-2"></i> <strong>' + currentDomain + '</strong>&nbsp;appears to be available!</div>' +
                    '<a href="' + registerUrl + '" target="_blank" rel="noopener" class="btn btn-success btn-sm"><i class="bi bi-cart-plus me-1"></i>Register this domain</a>' +
                    '</div>';
            } else if (data.availability === 'registered') {
                avBadge.innerHTML = '<div class="alert alert-info d-flex align-items-center"><i class="bi bi-info-circle-fill me-2"></i> <strong>' + currentDomain + '</strong>&nbsp;is registered.</div>';
            }
            avBadge.style.display = '';

            // Data source (Issue #12)
            var dsBadge = document.getElementById('dataSourceBadge');
            var src = (data.data_source || 'whois').toUpperCase();
            var cached = data.cached ? ' (cached)' : '';
            dsBadge.innerHTML = '<span class="badge bg-secondary">Source: ' + src + cached + '</span>';
            dsBadge.style.display = '';

            // Parsed fields card (Issue #9)
            if (data.parsed && Object.keys(data.parsed).length > 0) {
                var pf = document.getElementById('parsedFields');
                var html = '<div class="card"><div class="card-header"><strong>Domain Summary</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                for (var key in data.parsed) {
                    var val = data.parsed[key];
                    var display = Array.isArray(val) ? val.join(', ') : val;
                    var rowClass = '';
                    if (key === 'Expires In') {
                        var days = parseInt(val);
                        if (days <= 30) rowClass = ' class="table-danger"';
                        else if (days <= 90) rowClass = ' class="table-warning"';
                    }
                    html += '<tr' + rowClass + '><td class="fw-bold">' + key + '</td><td>' + display + '</td></tr>';
                }
                html += '</table></div></div>';
                pf.innerHTML = html;
                pf.style.display = '';
            }

            // WHOIS formatted result
            formatWhoisData(data.whois || '');

            // DNS records (Issue #6)
            if (data.dns && data.dns.length > 0) {
                document.getElementById('resultTabs').style.display = '';
                var dnsHtml = '<table class="table table-striped table-sm"><thead><tr><th>Type</th><th>Value</th><th>Priority</th></tr></thead><tbody>';
                data.dns.forEach(function (rec) {
                    dnsHtml += '<tr><td><span class="badge bg-secondary">' + rec.type + '</span></td><td>' + rec.value + '</td><td>' + (rec.priority || '') + '</td></tr>';
                });
                dnsHtml += '</tbody></table>';
                document.getElementById('dnsResultPane').innerHTML = dnsHtml;
            }

            // Show action buttons
            document.getElementById('actionButtons').style.display = '';
            document.getElementById('actionButtons').style.cssText = '';
            isRawView = false;
            updateToggleButtonText();
        }

        // ---- Result tabs (Issue #6) ----
        document.querySelectorAll('#resultTabs .nav-link').forEach(function (tab) {
            tab.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelectorAll('#resultTabs .nav-link').forEach(function (t) { t.classList.remove('active'); });
                this.classList.add('active');
                var target = this.dataset.tab;
                document.getElementById('whoisResultPane').style.display = target === 'whois' ? '' : 'none';
                document.getElementById('dnsResultPane').style.display = target === 'dns' ? '' : 'none';
            });
        });

        // ---- Format WHOIS data ----
        function formatWhoisData(whoisHtml) {
            formattedResult = whoisHtml.split('\n').map(function (line) {
                var colonIndex = line.indexOf(':');
                if (colonIndex !== -1) {
                    var label = line.substring(0, colonIndex + 1);
                    var value = line.substring(colonIndex + 1).trim();
                    return '<span class="whois-label">' + label + '</span><div class="whois-value">' + value + '</div>';
                }
                return '<span class="whois-value">' + line + '</span>';
            }).join('');
            document.getElementById('result').innerHTML = formattedResult;
        }

        // ---- Toggle raw/formatted ----
        document.getElementById('toggleViewBtn').addEventListener('click', function () {
            isRawView = !isRawView;
            if (isRawView) {
                document.getElementById('result').innerHTML = '<pre>' + rawWhoisText + '</pre>';
            } else {
                document.getElementById('result').innerHTML = formattedResult;
            }
            updateToggleButtonText();
        });

        function updateToggleButtonText() {
            document.getElementById('toggleViewBtn').textContent = isRawView ? 'Show Formatted Whois' : 'Show Raw Whois';
        }

        // ---- Copy to clipboard (Issue #7) ----
        document.getElementById('copyBtn').addEventListener('click', function () {
            var text = rawWhoisText.replace(/<[^>]*>/g, '');
            navigator.clipboard.writeText(text).then(function () {
                var btn = document.getElementById('copyBtn');
                btn.innerHTML = '<i class="bi bi-check"></i> Copied!';
                setTimeout(function () { btn.innerHTML = '<i class="bi bi-clipboard"></i> Copy'; }, 2000);
            });
        });

        // ---- Download as text (Issue #7) ----
        document.getElementById('downloadBtn').addEventListener('click', function () {
            var text = rawWhoisText.replace(/<[^>]*>/g, '');
            var blob = new Blob([text], { type: 'text/plain' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = currentDomain + '-whois.txt';
            a.click();
            URL.revokeObjectURL(a.href);
        });

        // ---- Helpers ----
        function showLoading(show) {
            document.getElementById('loadingSpinner').style.display = show ? '' : 'none';
        }

        function hideResults() {
            document.getElementById('availabilityBadge').style.display = 'none';
            document.getElementById('dataSourceBadge').style.display = 'none';
            document.getElementById('parsedFields').style.display = 'none';
            document.getElementById('resultTabs').style.display = 'none';
            document.getElementById('dnsResultPane').style.display = 'none';
            document.getElementById('whoisResultPane').style.display = '';
            document.getElementById('result').innerHTML = '';
            document.getElementById('actionButtons').style.display = 'none';
            document.getElementById('actionButtons').style.cssText = 'display:none !important';
            document.getElementById('bulkResults').style.display = 'none';
        }

        function showError(message) {
            document.getElementById('result').innerHTML = '<div class="alert alert-danger"><i class="bi bi-exclamation-triangle-fill me-2"></i>' + message + '</div>';
        }

        function updateURL(domain) {
            var newUrl = window.location.origin + window.location.pathname + '?domain=' + encodeURIComponent(domain);
            history.pushState({ path: newUrl }, '', newUrl);
        }
    });
    </script>
</body>
</html>