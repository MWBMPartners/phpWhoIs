<?php
	//Application
		$app["Application"]["ID"] = "Ltd.MWBMPartners.DomainCheckr";
		$app["Application"]["Name"] = "DomainCheckr";
		$app["Application"]["Website"]["URL"] = NULL;
		$app["Application"]["Description"]["Synopsis"] = "Free domain name checker and s WHOIS and RDAP lookup tool. Check domain registration, availability, DNS records, expiry dates, and registrar information.";
		$app["Application"]["Description"]["Keywords"] = "Domain name, Domain name registration, Whois, RDAP, DNS Records, Domain availability, Registrar information, Expiry date, Name servers, Contact information, IP address lookup, Bulk domain lookup, Domain history, Domain ownership, Domain status, Free whois lookup, Online whois tool";

		//Version
			$app["Application"]["Version"]["Number"] = "1.29.1";
			$app["Application"]["Version"]["Name"] = NULL;
			
			// Environment-based override (failsafe)
			//If running from a non-beta directory, clear the dev status
				if (str_contains(__DIR__, 'public_html_dev')){
					$app["Application"]["Version"]["Development"]["Status"] = "Alpha";
				}
				elseif (str_contains(__DIR__, 'public_html_beta')){
					$app["Application"]["Version"]["Development"]["Status"] = "Beta";
				}
				else{
					$app["Application"]["Version"]["Development"]["Status"] = NULL;
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
