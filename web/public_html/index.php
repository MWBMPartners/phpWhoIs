<?php //https://chatgpt.com/share/66ed46d1-c1a4-800b-bc0a-93663c3084dd ?><?php
	#########################################
	#			WhoIs Lookup Tool			#
	#										#
	# version: v0.2.350						#
	#										#
	#########################################
	#		(C) 2024 MWservices.it			#
	#########################################

	##Domain Name Whois Lookup Tool
	##	BASED ON //https://chatgpt.com/share/66ed46d1-c1a4-800b-bc0a-93663c3084dd
	
	
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
						if (file_exists(dirname(dirname(__FILE__)))){
							$pathAppRoot = dirname(dirname(__FILE__));
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

			//Prevent Session Injections (//www.php.net/manual/en/reserved.variables.session.php#94676)
				if (function_exists("protectSessionInjection")){
					protectSessionInjection();
				}

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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Whois Lookup</title>

    <!-- Bootstrap CSS for responsive design and default styling of buttons, forms, etc.
         Documentation: https://getbootstrap.com/docs/4.5/getting-started/introduction/ -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    
    <!-- Link to external CSS file for custom styles specific to this project -->
    <link rel="stylesheet" href="style.css">
</head>
<body>

    <!-- Header section for the form and page title 
         - The header includes a title and an input form where the user can enter a domain name
         - It is styled to be positioned at the top and separated from the rest of the content -->
    <div class="header-form">
        <h1>Whois Lookup</h1> <!-- Main title of the page displayed at the top -->
        
        <!-- Form section: The form allows users to input a domain name and submit it 
             - Uses the Bootstrap grid system to structure the form responsively
             - The form uses POST method and is submitted via AJAX -->
        <form id="whoisForm" class="form-container">
            <!-- Form group for the domain input field 
                 - The input is designed to accept valid domain names and uses HTML5 pattern validation -->
            <div class="form-group">
                <label for="domain" class="sr-only">Domain or URL</label> <!-- Screen reader only label for accessibility -->
                <input type="text" class="form-control" id="domain" name="domain" 
                    pattern="^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+(?:[a-zA-Z]{2,})$"
                    title="Please enter a valid domain name, e.g., example.com" 
                    placeholder="example.com" required> <!-- Placeholder and required attributes for user guidance -->
            </div>

            <!-- Submit button to trigger the Whois lookup via AJAX -->
            <button type="submit" class="btn btn-primary submit-btn">Lookup</button>
        </form>
    </div>

    <!-- Result section where the WHOIS lookup result will be displayed 
         - It uses a scrollable container to allow long WHOIS responses to be viewed without scrolling the whole page -->
    <div class="result-container" id="resultContainer">
        <div id="result"></div> <!-- The result from the WHOIS lookup will be dynamically inserted here -->

        <!-- Toggle button to switch between formatted and raw WHOIS result views 
             - This button is hidden by default and will be shown after the first lookup -->
        <button class="btn btn-secondary toggle-btn" id="toggleViewBtn" style="display:none;">Show Raw Whois</button>
    </div>

    <!-- Footer section that stays fixed at the bottom of the viewport 
         - Used to display copyright or any important footer information -->
    <div class="footer">
        &copy; 2024 Whois Lookup Tool - All Rights Reserved
    </div>

    <!-- jQuery for handling form submission and AJAX requests 
         Documentation: https://api.jquery.com/jquery.ajax/ -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>

    <!-- JavaScript for handling WHOIS lookups and formatting of the result 
         The script handles the form submission via AJAX, processes the WHOIS result, and adds the toggle functionality -->
    <script>
        $(document).ready(function () {
            let formattedResult = ""; // Store formatted WHOIS result
            let rawResult = ""; // Store raw WHOIS result
            let isRawView = false; // Track if raw view is currently shown

            // Check if a domain is passed via the URL (e.g., ?domain=example.com) and automatically trigger the lookup
            const urlParams = new URLSearchParams(window.location.search);
            const initialDomain = urlParams.get('domain');
            if (initialDomain) {
                $('#domain').val(initialDomain); // Pre-fill the input with the domain from the URL
                triggerWhoisLookup(initialDomain); // Trigger the whois lookup automatically
            }

            // Handle form submission via AJAX when the user submits the form
            $("#whoisForm").on("submit", function (event) {
                event.preventDefault(); // Prevent the form from submitting in the traditional way (page reload)
                var domain = $("#domain").val(); // Get the domain name entered by the user
                triggerWhoisLookup(domain); // Perform the WHOIS lookup
                updateURL(domain); // Update the URL with the domain name for sharing/bookmarking
            });

            // Function to perform the WHOIS lookup via an AJAX request to the backend (lookup.php)
            function triggerWhoisLookup(domain) {
                $.ajax({
                    type: "POST",
                    url: "lookup.php?nocache=" + new Date().getTime(),  // Prevent caching by appending a timestamp
                    data: { domain: domain }, // Send the domain as POST data to the server
                    success: function (response) {
                        rawResult = response; // Store the raw WHOIS result
                        formatWhoisData(); // Format the raw result for better readability
                        $('#toggleViewBtn').show(); // Show the toggle button after the first lookup
                        isRawView = false; // Default to showing the formatted view
                        updateToggleButtonText(); // Update the toggle button text based on the current view
                    }
                });
            }

            // Function to update the browser URL with the domain name (allows bookmarking/sharing)
            function updateURL(domain) {
                const newUrl = window.location.origin + window.location.pathname + '?domain=' + domain;
                history.pushState({ path: newUrl }, '', newUrl); // Modify the URL without reloading the page
            }

            // Function to format the raw WHOIS data into a more readable format
            // It splits the WHOIS response line by line and makes labels bold, with values indented on new lines
            function formatWhoisData() {
                let whoisText = rawResult; // Use the raw WHOIS data for processing

                // Split the WHOIS data into lines and process each line
                formattedResult = whoisText.split('\n').map(line => {
                    let colonIndex = line.indexOf(':'); // Find the first colon in the line
                    if (colonIndex !== -1) {
                        // Split the line into label (before colon) and value (after colon)
                        let label = line.substring(0, colonIndex + 1); // Include the colon as part of the label
                        let value = line.substring(colonIndex + 1).trim(); // Trim extra spaces from the value
                        // Format the label and value: label bolded, value indented on a new line
                        return `<span class="whois-label">${label}</span><div class="whois-value">${value}</div>`;
                    } else {
                        // If no colon is found, treat the entire line as a value (not bolded)
                        return `<span class="whois-value">${line}</span>`;
                    }
                }).join(''); // Join the formatted lines back together

                $("#result").html(formattedResult); // Insert the formatted result into the result container
            }

            // Function to toggle between the raw and formatted views of the WHOIS result
            $("#toggleViewBtn").on("click", function () {
                isRawView = !isRawView; // Toggle the state
                if (isRawView) {
                    $("#result").html(`<pre>${rawResult}</pre>`); // Show the raw WHOIS result
                } else {
                    $("#result").html(formattedResult); // Show the formatted WHOIS result
                }
                updateToggleButtonText(); // Update the text of the toggle button
            });

            // Function to update the toggle button text based on the current view (raw/formatted)
            function updateToggleButtonText() {
                if (isRawView) {
                    $("#toggleViewBtn").text("Show Formatted Whois"); // Text to switch to formatted view
                } else {
                    $("#toggleViewBtn").text("Show Raw Whois"); // Text to switch to raw view
                }
            }
        });
    </script>
</body>
</html>