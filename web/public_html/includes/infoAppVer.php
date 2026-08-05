<?php
	//Application
		$app["Application"]["ID"] = "Ltd.MWBMPartners.DomainCheckr";
		$app["Application"]["Bundle"]["ID"] = "Ltd.MWBMPartners.DomainCheckr";
		$app["Application"]["Name"] = "DomainCheckr";
		$app["Application"]["Website"]["URL"] = NULL;
		$app["Application"]["Description"]["Synopsis"] = "Free domain name checker and s WHOIS and RDAP lookup tool. Check domain registration, availability, DNS records, expiry dates, and registrar information.";
		$app["Application"]["Description"]["Keywords"] = "Domain name, Domain name registration, Whois, RDAP, DNS Records, Domain availability, Registrar information, Expiry date, Name servers, Contact information, IP address lookup, Bulk domain lookup, Domain history, Domain ownership, Domain status, Free whois lookup, Online whois tool";

		if (!isset($app["Application"]["ID"]) OR empty($app["Application"]["ID"])){
			if (isset($app["Application"]["Bundle"]["ID"]) && $app["Application"]["Bundle"]["ID"]){
				$app["Application"]["ID"] = $app["Application"]["Bundle"]["ID"];
			}
			elseif (isset($app["Application"]["Name"]) && $app["Application"]["Name"]){
				$app["Application"]["ID"] = $app["Application"]["Name"];
			}
			elseif (isset($app["Application"]["Website"]["URL"]) && $app["Application"]["Website"]["URL"]){
				$app["Application"]["ID"] = $app["Application"]["Website"]["URL"];
			}
			else{
				$app["Application"]["ID"] = NULL;
			}
		}

		//Version
			$app["Application"]["Version"]["Number"] = "1.50.4";
			$app["Application"]["Version"]["Name"] = NULL;
			
			// Environment-based override (failsafe)
			// Single-source deploy model (#204): every branch deploys from the
			// same web/public_html/ source, so the old folder-name check
			// (public_html_beta / public_html_dev) can no longer distinguish
			// channels. Read the CI/CD-injected web/public_html/.env-channel
			// file instead (written by deploy.yml on every deploy: "live",
			// "beta", or "alpha"). Absent locally (no deploy has run) -> NULL.
				$app["Application"]["Version"]["Development"]["Status"] = NULL;
				$envChannelFile = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.env-channel';
				if (is_file($envChannelFile)){
					$envChannel = trim((string) file_get_contents($envChannelFile));
					if ($envChannel === 'alpha'){
						$app["Application"]["Version"]["Development"]["Status"] = "Alpha";
					}
					elseif ($envChannel === 'beta'){
						$app["Application"]["Version"]["Development"]["Status"] = "Beta";
					}
				}

			//Repo Build (populated by GitHub Actions deploy)
			$app["Application"]["Version"]["Repo"]["Commit"]["SHA"]["Full"] = NULL;
			$app["Application"]["Version"]["Repo"]["Commit"]["SHA"]["Short"] = NULL;
			$app["Application"]["Version"]["Repo"]["Commit"]["Date"] = NULL;
			$app["Application"]["Version"]["Repo"]["Commit"]["URL"] = NULL;

	//Vendor
			$app["Application"]["Vendor"]["Name"] = "MWservices";
			$app["Application"]["Vendor"]["Website"]["URL"] = "https://www.MWservices.it";
		
		//Parent Vendor
			$app["Application"]["Vendor"]["Parent"]["Name"] = "MWBM Partners Ltd";
			$app["Application"]["Vendor"]["Parent"]["Website"]["URL"] = "https://www.MWBMpartners.Ltd";
	
		//Copyright
			$app["Application"]["Copyright"]["Year"]["Start"] = "2024";
			$app["Application"]["Copyright"]["RightsStatement"] = "All Rights Reserved";
	
		//License	
			$app["Application"]["License"]["Developer"]["Type"] = NULL;
			$app["Application"]["License"]["Developer"]["Cost"] = NULL;
			$app["Application"]["License"]["Developer"]["Agreement"]["URL"] = NULL;
			$app["Application"]["License"]["Developer"]["ToSURL"] = NULL;

			$app["Application"]["License"]["User"]["Type"] = "Freeware";
			$app["Application"]["License"]["User"]["Cost"] = "Free";
			$app["Application"]["License"]["User"]["Agreement"]["URL"] = NULL;
			$app["Application"]["License"]["User"]["ToSURL"] = NULL;
?>
