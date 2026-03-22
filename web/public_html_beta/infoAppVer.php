<?php
	//Application
		$app["Application"]["ID"] = "Ltd.MWBMPartners.Whois";
		$app["Application"]["Name"] = "WHOIS Lookup";
		$app["Application"]["Website"]["URL"] = NULL;

		//Version
			$app["Application"]["Version"]["Version"] = "1.11.0";
			$app["Application"]["Version"]["Name"] = NULL;
			
			// Environment-based override (failsafe)
			//If running from a non-beta directory, clear the dev status
				if (strpos(__DIR__, 'public_html_dev') !== false){
					$app["Application"]["Version"]["Development"]["Status"] = "Alpha";
				}
				elseif (strpos(__DIR__, 'public_html_beta') !== false){
					$app["Application"]["Version"]["Development"]["Status"] = "Beta";
				}
				else{
					$app["Application"]["Version"]["Development"]["Status"] = NULL;
				}

			//Repo Build (populated by GitHub Actions deploy)
			$app["Application"]["Version"]["Repo"]["Commit"]["SHA"] = NULL;
			$app["Application"]["Version"]["Repo"]["Commit"]["Short"] = NULL;
			$app["Application"]["Version"]["Repo"]["Commit"]["Date"] = NULL;
			$app["Application"]["Version"]["Repo"]["Commit"]["URL"] = NULL;

	//Vendor
			$app["Application"]["Vendor"]["Name"] = "MWservices";
			$app["Application"]["Vendor"]["Website"]["URL"] = NULL;
		
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
