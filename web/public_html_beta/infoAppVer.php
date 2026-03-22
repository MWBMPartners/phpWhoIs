<?php
	//Application
		$app["Application"]["ID"] = "Ltd.MWBMPartners.Whois";
		$app["Application"]["Name"] = "WHOIS Lookup";
		$app["Application"]["Website"]["URL"] = NULL;

		//Version
			$app["Application"]["Version"]["Version"] = "1.1.1";
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
			$app["Application"]["License"]["Type"] = "Freeware";
			$app["Application"]["License"]["Cost"] = "Free";
			$app["Application"]["License"]["Agreement"]["URL"] = NULL;
			$app["Application"]["License"]["ToSURL"] = NULL;
?>
