<?php

// Increase memory limit to allow for large streams
ini_set('memory_limit', '350M');

/*
// Terminate if this launches without a valid session
session_start();
if (!(isset($_SESSION['sLogin']) && $_SESSION['sLogin'] != '')) {
    header ("Location: session.php?id=0");
    exit();
}
*/

require_once 'functions.php';

// record starting time so we can see how long the callback takes
$time0 = microtime(true);

// check for data
if (!isset($_REQUEST['d'])) { 
    exit;
} else { 
    $d = $_REQUEST['d'];
}

// pull the individual values out
$d = explode("-", $d);

function cleanUp($string) {
    if (get_magic_quotes_gpc()) {
        $string = stripslashes($string);
    }
    $string = mysql_real_escape_string($string);
    return $string;
}

// If any input validation fails, return error and exit immediately
function invalidCallback($string) {
	$result = array("tx"  => "",
                  "dbg" => "",
                  "err" => "$string");

	$theJSON = json_encode($result);
	echo $theJSON;
	exit;
}

// cliscript requests the pcap/transcript from sguild
function cliscript($cmd, $pwd) {
    $descspec = array(
                 0 => array("pipe", "r"),
                 1 => array("pipe", "w"),
                 2 => array("pipe", "w")
    );
    $proc = proc_open($cmd, $descspec, $pipes);
    $debug = "Process execution failed";
    $_raw = "";
    if (is_resource($proc)) {
        fwrite($pipes[0], $pwd);
        fclose($pipes[0]);
        $_raw = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $debug = fgets($pipes[2]);
        fclose($pipes[2]);
    }
    return explode("\n", $_raw);
}

// Authenticate with Splunk and return a session key, the session key will be used
// with subsequent searches.  The user and password that is logged into Security Onion's
// web needs to be a Splunk user with the User role.
function splunk_authenticate($splunk_host, $splunkd_port, $usr, $pwd) {
	$ch = curl_init();
	$url = "https://$splunk_host:$splunkd_port/services/auth/login?output_mode=json";
	$loginInfo = "username=$usr&password=$pwd";

	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $loginInfo);
	curl_setopt($ch, CURLOPT_POST, 1);

	$headers = array();
	$headers[] = "Cache-Control: no-cache";
	$headers[] = "Content-Type: application/x-www-form-urlencoded";
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	$result = curl_exec($ch);
	if (curl_errno($ch)) {
		echo 'Error:' . curl_error($ch);
	}

	curl_close($ch);
	//Decode the json data
	$result_object = json_decode($result, true);
	$session_key = $result_object['sessionKey'];
	// Return object
	return $session_key;
}

//Send the inital search to Splunk
function splunk_search($splunk_host, $splunkd_port, $splunk_sessionKey, $query, $usr){
	$ch = curl_init();
	$url = "https://$splunk_host:$splunkd_port/servicesNS/$usr/securityonion/search/jobs?output_mode=json";
	
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $query);
	curl_setopt($ch, CURLOPT_POST, 1);

	$headers = array();
	$headers[] = "Authorization: Splunk $splunk_sessionKey";
	$headers[] = "Cache-Control: no-cache";
	$headers[] = "Content-Type: application/x-www-form-urlencoded";
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	$result = curl_exec($ch);
	if (curl_errno($ch)) {
	    echo 'Error:' . curl_error($ch);
	}
	curl_close ($ch);
	//Decode the json data
	$result_object = json_decode($result, true);
	$searchID = $result_object['sid'];
	// Return object
	return $searchID;
}

// Get the conn.log UID
function conn_search($splunk_host, $splunkd_port, $splunk_sessionKey, $query, $st, $et, $usr){
	$ch = curl_init();
	$url = "https://$splunk_host:$splunkd_port/servicesNS/$usr/securityonion/search/jobs?earliest_time=$st&latest_time=$et&output_mode=json";
	
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $query);
	curl_setopt($ch, CURLOPT_POST, 1);

	$headers = array();
	$headers[] = "Authorization: Splunk $splunk_sessionKey";
	$headers[] = "Cache-Control: no-cache";
	$headers[] = "Content-Type: application/x-www-form-urlencoded";
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	$result = curl_exec($ch);
	if (curl_errno($ch)) {
	    echo 'Error:' . curl_error($ch);
	}
	curl_close ($ch);
	//Decode the json data
	$result_object = json_decode($result, true);
	$searchID = $result_object['sid'];
	// Return object
	return $searchID;
}



//Check to see if the search is done
function splunk_check_status($splunk_host, $splunkd_port, $splunk_sessionKey, $searchID, $usr){

	do {
		$ch = curl_init();
		$url = "https://$splunk_host:$splunkd_port/servicesNS/$usr/securityonion/search/jobs/$searchID?output_mode=json";
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");


		$headers = array();
		$headers[] = "Authorization: Splunk $splunk_sessionKey";
		$headers[] = "Cache-Control: no-cache";
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

		$result = curl_exec($ch);
		if (curl_errno($ch)) {
		    echo 'Error:' . curl_error($ch);
		}
		$result_object = json_decode($result, true);
		$status = $result_object['entry'][0]['content']['isDone'];
		$failed = $result_object['entry'][0]['content']['isFailed'];
		if($failed == true){
			$type = $result_object['entry'][0]['content']['messages'][0]['type'];
			$text = $result_object['entry'][0]['content']['messages'][0]['text'];
			$reason =  $typ . ':' . $text;
			return "$reason";
		}

	} while( $status != true);
	
	curl_close ($ch);

	return "finished";
}

//Get the results back
function splunk_get_results($splunk_host, $splunkd_port, $splunk_sessionKey, $searchID, $usr){
	$ch = curl_init();
	$url = "https://$splunk_host:$splunkd_port/servicesNS/$usr/securityonion/search/jobs/$searchID/results?output_mode=json&count=0";

	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");


	$headers = array();
	$headers[] = "Authorization: Splunk $splunk_sessionKey";
	$headers[] = "Cache-Control: no-cache";
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	$result = curl_exec($ch);

	if (curl_errno($ch)) {
	    echo 'Error:' . curl_error($ch);
	}
	curl_close ($ch);
	//Decode the json data
	$result_object = json_decode($result, true);
	// Return object
	$result_object = $result_object['results'];
	return $result_object;

}

// Validate user input - Splunk ID (numbers, letters)
$spid	= h2s($d[0]);
if(!ctype_alnum($spid)) { 
	invalidCallback("Invalid Splunk ID.");
} 

// Validate user input - start time
// must be greater than 5 years ago and less than 5 years from today
$mintime=time() - 5 * 365 * 24 * 60 * 60;
$maxtime=time() + 5 * 365 * 24 * 60 * 60;
$stime= h2s($d[1]);
if (filter_var($stime, FILTER_VALIDATE_INT, array("options" => array("min_range"=>$mintime, "max_range"=>$maxtime))) === false) {
	invalidCallback($stime);
}

// Validate user input - Splunk Sourcetype (numbers, letters, underscores, hyphens)
$stype	= h2s($d[2]); 
$aValid = array('-', '_'); 
if(!ctype_alnum(str_replace($aValid, '', $stype))) { 
	invalidCallback("Invalid Splunk Sourcetype.");
} 

// Validate user input - maxtxbytes
// must be an integer between 1000 and 100000000
$maxtranscriptbytes	= h2s($d[3]);
if (filter_var($maxtranscriptbytes, FILTER_VALIDATE_INT, array("options" => array("min_range"=>1000, "max_range"=>100000000))) === false) {
	invalidCallback("Invalid maximum transcript bytes.");
}

// Validate user input - sidsrc
// splunk is the only valid value
$sidsrc = h2s($d[4]);
if ( $sidsrc != 'splunk' ) {
	invalidCallback("Invalid sidsrc.");
}

// Validate user input - xscript
// valid values are: auto, tcpflow, bro, and pcap
$xscript = h2s($d[5]);
if (!( $xscript == 'auto' || $xscript == 'tcpflow' || $xscript == 'bro' || $xscript == 'pcap' )) {
	invalidCallback("Invalid xscript.");
}

// Defaults
$err = 0;
$bro_query = $st = $et = $fmtd = $debug = $errMsg = $errMsgSplunk = '';
$sensor = '';

if ($sidsrc == "splunk") {

	$sp_array = file("/etc/nsm/securityonion.conf");
	
	// Define the strings we are looking for
	$splunk_host = "SPLUNK_HOST";
	$splunkd_port = "SPLUNKD_PORT";
	$usr     = $_SERVER['PHP_AUTH_USER'];
    $pwd     = $_SERVER['PHP_AUTH_PW'];

	
	foreach($sp_array as $line) {
		// If we find a match, retrieve only the value and clean it up
		if(strpos($line, $splunk_host) !== false) {
			list(, $new_str) = explode("=", $line);
			$rm_whitespace = trim($new_str);
			$splunk_host = trim($rm_whitespace, '"');
		}
		if(strpos($line, $splunkd_port) !== false) {
			list(, $new_str) = explode("=", $line);
			$rm_whitespace = trim($new_str);
			$splunkd_port = trim($rm_whitespace, '"');
		}
	}
	
	// Inital query
	$query = "search=search sourcetype=$stype spid=$spid earliest_time=$stime | table *";
	$splunk_sessionKey = splunk_authenticate($splunk_host, $splunkd_port, $usr, $pwd);
	$searchID = splunk_search($splunk_host, $splunkd_port, $splunk_sessionKey, $query, $usr);
	$status = splunk_check_status($splunk_host, $splunkd_port, $splunk_sessionKey, $searchID, $usr);
	if($status == "finished") {
		$search_results = splunk_get_results($splunk_host, $splunkd_port, $splunk_sessionKey, $searchID, $usr);
	} else {
		$errMsgSplunk = $status;
	}
	
	if ( ! isset($search_results) ) {
		$errMsgSplunk = "Initial Splunk query didn't return anything.";
	} elseif ( empty($search_results)) {
		$errMsgSplunk = "Inital Splunk query couldn't find this ID.";
	
	} else {

		if (isset($search_results[0]['uid'])){
			$uid = $search_results[0]["uid"];
			if (is_array($uid)) {
					$uid = $search_results[0]['uid'][0];
			}
				// A Bro CID should be alphanumeric and begin with the letter C
			if (ctype_alnum($uid)) {
				if (substr($uid,0,1)=="C") {
					$type = "bro_conn";
					$bro_query = $uid;
				}
			}
		}elseif (isset($search_results[0]['id']) ) {
			$id = $search_results[0]['id'];
			if (ctype_alnum($id)) {
		        if (substr($id,0,1)=="F") {
	                $type = "bro_files";
					$bro_query = $id;
		        }
			}
		} elseif (isset($search_results[0]['fuid']) ) {
			$uid = $search_results[0]["uid"];
			if (is_array($uid)) {
					$uid = $search_results[0]['uid'][0];
			}
				// A Bro CID should be alphanumeric and begin with the letter C
			if (ctype_alnum($uid)) {
				if (substr($uid,0,1)=="C") {
					$type = "bro_conn";
					$bro_query = $uid;
				}
			}
		}
	

		if (isset($search_results[0]['sid']) ) {
			$rule_sid = $search_results[0]['sid'];
			if ( $rule_sid > 0 && $rule_sid < 9999999) {
				$rule_command = "grep -h sid:$rule_sid\; /etc/nsm/rules/*.rules |head -1";
				$rule = shell_exec($rule_command);
			}
		}

		$message = $search_results[0]['_raw'];
		if ( $bro_query == "" ) {
			// source_ip
			if (isset($search_results[0]["src"])) {
				$sip = $search_results[0]["src"];
				if (!filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
					if (filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
						$errMsgSplunk = "Source IP is IPV6!  CapMe currently only supports IPV4.";
					} else {
						$errMsgSplunk = "Invalid source IP.";
					}
				}
			} else {
				$search_results = "Missing source IP.";
			}

			// src_port
			if (isset($search_results[0]["src_port"])) {
				$spt = $search_results[0]["src_port"];
				if (filter_var($spt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
				        $errMsgSplunk = "Invalid source port.";
				}
			} else {
				$errMsgSplunk = "Missing source port.";
			}

			// dest
			if (isset($search_results[0]["dest"])) {
				$dip = $search_results[0]["dest"];
				if (!filter_var($dip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
					if (filter_var($dip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                                                $errMsgSplunk = "Destination IP is IPV6!  CapMe currently only supports IPV4.";
                                        } else {
                                                $errMsgSplunk = "Invalid destination IP.";
                                        }
				}
			} else {
				$errMsgSplunk = "Missing destination IP.";
			}

			// dest_port
			if (isset($search_results[0]["dest_port"])) {
				$dpt = $search_results[0]["dest_port"];
				if (filter_var($dpt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
				        $errMsgSplunk = "Invalid destination port.";
				}
			} else {
				$errMsgSplunk = "Missing destination port.";
			}

			// If all four of those fields looked OK, then build a query to send to Splunk
			if ($errMsgSplunk == "") {
				$type = "bro_conn";
				$bro_query = "$sip AND $spt AND $dip AND $dpt";
			}
		}



		$timestamp_epoch = $search_results[0]["epochTime"];


		$mintime=time() - 50 * 365 * 24 * 60 * 60;
		$maxtime=time() + 5 * 365 * 24 * 60 * 60;
		if (filter_var($timestamp_epoch, FILTER_VALIDATE_INT, array("options" => array("min_range"=>$mintime, "max_range"=>$maxtime))) === false) {
		        $errMsgSplunk = "Invalid start time.";
		}
		// Set a start time and end time for the search to allow for a little bit of clock drift amongst different log sources
		$st = $timestamp_epoch - 1800;
		$et = $timestamp_epoch + 1800;
		
		// If bro_files, we need to query Splunk and get the log
		if ($errMsgSplunk == "" && $type == "bro_files") {

			$query = "search=search sourcetype=$type $bro_query | table sourcetype, epochTime, src, src_port, dest, dest_port, proto";
			$searchID = conn_search($splunk_host, $splunkd_port, $splunk_sessionKey, $query, $st, $et, $usr);
			$status = splunk_check_status($splunk_host, $splunkd_port, $splunk_sessionKey, $sid, $usr);
			if($status == "finished") {
				$search_results = splunk_get_results($splunk_host, $splunkd_port, $splunk_sessionKey, $sid, $usr);
			} else {
				$errMsgSplunk = $status;
			}
			// Check for common error conditions.

			if ( ! isset($search_results) ) {
				$errMsgSplunk = "Second Splunk query didn't return anything.";
			} elseif ( empty($search_results)) {
				$errMsgSplunk = "Second Splunk query couldn't find this ID.";
	
			} else {
                // If we received a bro_files record back, we need to grab the CID and get ready to query ES again
                if ($search_results[0]["sourcetype"] == "bro_files") {
                	$uid = $search_results[0]["uid"];
					if (is_array($uid)) {
						$uid = $search_results[0]['uid'][0];
					}
				// A Bro CID should be alphanumeric and begin with the letter C
					if (ctype_alnum($uid)) {
						if (substr($uid,0,1)=="C") {
							$type = "bro_conn";
							$bro_query = $uid;
						}	
					}
                }
				
			}
		}

		// Now we to send those parameters back to Splunk to see if we can find a matching bro_conn log
		if ($errMsgSplunk == "") {
			
			$query = "search=search sourcetype=$type $bro_query | table epochTime, src, src_port, dest, dest_port, proto, sensorname";
			$searchID = conn_search($splunk_host, $splunkd_port, $splunk_sessionKey, $query, $st, $et, $usr);
			$status = splunk_check_status($splunk_host, $splunkd_port, $splunk_sessionKey, $searchID, $usr);
			if($status == "finished") {
				$search_results = splunk_get_results($splunk_host, $splunkd_port, $splunk_sessionKey, $searchID, $usr);
			} else {
				$errMsgSplunk = $status;
			}
			// Check for common error conditions.
			if ( ! isset($search_results) ) {
				$errMsgSplunk = "Second Splunk query didn't return anything.";
			} elseif ( empty($search_results)) {
				$errMsgSplunk = "Second Splunk query couldn't find this ID.";
			
			} else {
				// Check to see how many hits we got back from our query
				$num_records = count($search_results);
				$delta_arr = array();

				// For each hit, we need to compare its timestamp to the timestamp of our original record (from which we pivoted).
				for ( $i =0 ; $i < $num_records; $i++) {
                    $record_ts = $search_results[$i]["epochTime"];
                    if ($timestamp_epoch > $record_ts){
                    	$delta = $timestamp_epoch - $record_ts;
					} elseif ($timestamp_epoch < $record_ts){
                        $delta = $record_ts - $timestamp_epoch;
                    } else {
						$delta = 0;
					}

                    $delta_arr[$i] = $delta;
				}
				// Start Editing here
				// Get the key for the hit with the smallest delta
				$min_val = min($delta_arr);
				$key = array_search($min_val, $delta_arr);
				if (!isset($search_results[$key]["proto"])){
					$errMsgSplunk = "Second Splunk query didn't return a protocol field.";
				} elseif (!in_array($search_results[$key]["proto"], array('tcp','udp'), TRUE)) {
					$errMsgSplunk = "CapMe currently only supports TCP and UDP.";
				}

				// src
				if (isset($search_results[$key]["src"])) {
					$sip = $search_results[$key]["src"];
					if (!filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
						if (filter_var($sip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        	$errMsgSplunk = "Source IP is IPV6!  CapMe currently only supports IPV4.";
                        } else {
                            $errMsgSplunk = "Invalid source IP.";
                        }
					}
				} else {
					$errMsgSplunk = "Missing source IP.";
				}

				// src_port
				if (isset($search_results[$key]["src_port"])) {
					$spt = $search_results[$key]["src_port"];
					if (filter_var($spt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
					    $errMsgSplunk = "Invalid source port.";
					}
				} else {
					$errMsgSplunk = "Missing source port.";
				}

				// dest
				if (isset($search_results[$key]["dest"])) {
					$dip = $search_results[$key]["dest"];
					if (!filter_var($dip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
						if (filter_var($dip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
							$errMsgSplunk = "Destination IP is IPV6!  CapMe currently only supports IPV4.";
						} else {
							$errMsgSplunk = "Invalid destination IP.";
						}
					}
				} else {
					$errMsgSplunk = "Missing destination IP.";
				}
	
				// dest_port
				if (isset($search_results[$key]["dest_port"])) {
					$dpt = $search_results[$key]["dest_port"];
					if (filter_var($dpt, FILTER_VALIDATE_INT, array("options" => array("min_range"=>0, "max_range"=>65535))) === false) {
					        $errMsgSplunk = "Invalid destination port.";
					}
				} else {
					$errMsgSplunk = "Missing destination port.";
				}

				// Convert the timestamp to "Y-m-d H:i:s format"
				$sensor = $search_results[$key]["sensorname"];
				$timestamp = $search_results[$key]["epochTime"];
				$st = date("Y-m-d H:i:s", $timestamp);
				

			} 
		}
	}

	if ($errMsgSplunk != "") {
	    $err = 1;
	    $errMsg = $errMsgSplunk;
	} else {
		// Query the Sguil database.
		$query = "SELECT sid FROM sensor WHERE hostname='$sensor' AND agent_type='pcap' LIMIT 1";
		$response = mysqli_query($db,$query);
		if (!$response) {
	    	$err = 1;
	    	$errMsg = "Error: The query failed, please verify database connectivity";
	    	$debug = $query;
		} else if (mysqli_num_rows($response) == 0) {
	    	$err = 1;
	    	$debug = $query;
	    	$errMsg = "Failed to find a matching sid. " . $errMsgSplunk;

	    	// Check for possible error condition: no pcap_agent.
	    	$response = mysql_query("select * from sensor where agent_type='pcap' and active='Y';");
	    	if (mysql_num_rows($response) == 0) {
			    $errMsg = "Error: No pcap_agent found";
	    	}
		} else {
	    	$row = mysqli_fetch_assoc($response);
	    	$sid    = $row["sid"];
	    	$err = 0;
		}
	}

		
	if ($err == 1) {
    $result = array("tx"  => "0",
                    "dbg" => "$debug",
                    "err" => "$errMsg");
	} else {

	    // We passed all error checks, so let's get ready to request the transcript.

	    // Apache is handling authentication and passing username and password through
	    $usr     = $_SERVER['PHP_AUTH_USER'];
	    $pwd     = $_SERVER['PHP_AUTH_PW'];

	    $time1 = microtime(true);

	    // The original cliscript.tcl assumes TCP (proto 6).
	    $script = "cliscript.tcl";
	    $proto=6;
	    $cmdusr 	= escapeshellarg($usr);
	    $cmdsensor 	= escapeshellarg($sensor);
	    $cmdst	= escapeshellarg($st);
	    $cmdsid 	= escapeshellarg($sid);
	    $cmdsip 	= escapeshellarg($sip);
	    $cmddip 	= escapeshellarg($dip);
	    $cmdspt 	= escapeshellarg($spt);
	    $cmddpt 	= escapeshellarg($dpt);
	    $cmd = "../.scripts/$script $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt";

	    // Check to see if the event is UDP.
	    if ($search_results[$key]["proto"] == "udp") {
		$proto=17;
	    }

	    // If the traffic is UDP or the user chose the Bro transcript, change to cliscriptbro.tcl.
	    if ($xscript == "bro" || $proto == "17" ) {
		$script = "cliscriptbro.tcl";
	    	$cmdproto 	= escapeshellarg($proto);
		$cmd = "../.scripts/$script $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt $cmdproto";

	    }

	    // Request the transcript.
	    $raw = cliscript($cmd, $pwd);
	    $time2 = microtime(true);

	    // Check for errors or signs of gzip encoding.
	    $foundgzip=0;
	    foreach ($raw as $line) {
		if (preg_match("/^ERROR: Connection failed$/", $line)) {
			invalidCallback("ERROR: Connection to sguild failed!");
		}
		if (preg_match("/^DEBUG: $/", $line)) {
			invalidCallback("ERROR: No data was returned. Check pcap_agent service.");
		}
	    	if ($xscript == "auto") {
			if (preg_match("/^DST: Content-Encoding: gzip/i", $line)) {
				$foundgzip=1;
				break;
			}
		}
	    }
	    $time3 = microtime(true);

	    # Insert message so user can see the full message of the log they pivoted from
	    $fmtd .= "<span class=txtext_hdr>Log entry:</span>";
	    $fmtd .= "<span class=txtext_hdr>" . htmlspecialchars($message) . "</span>";

	    # If NIDS alert, show rule that generated the alert
	    if (isset($rule) && isset($rule_sid)) {
		$fmtd .= "<span class=txtext_hdr><br></span>";
		$fmtd .= "<span class=txtext_hdr>IDS rule:</span>";
		$fmtd .= "<span class=txtext_hdr>" . htmlspecialchars($rule) . "</span>";
	    }

	    $fmtd .= "<span class=txtext_hdr><br></span>";

	    // If we found gzip encoding, then switch to Bro transcript.
	    if ($foundgzip==1) {
	    	$cmdproto 	= escapeshellarg($proto);
	        $cmd = "../.scripts/cliscriptbro.tcl $cmdusr $cmdsensor $cmdst $cmdsid $cmdsip $cmddip $cmdspt $cmddpt $cmdproto";
		$fmtd .= "<span class=txtext_hdr>CAPME: <b>Detected gzip encoding.</b></span>";
		$fmtd .= "<span class=txtext_hdr>CAPME: <b>Automatically switched to Bro transcript.</b></span>";
	    }

	    // Always request pcap/transcript a second time to ensure consistent DEBUG output.
	    $raw = cliscript($cmd, $pwd);
	    $time4 = microtime(true);

	    // Initialize $transcriptbytes so we can count the number of bytes in the transcript.
	    $transcriptbytes=0;

	    // Check for errors and format as necessary.
	    foreach ($raw as $line) {
		if (preg_match("/^ERROR: Connection failed$/", $line)) {
			invalidCallback("ERROR: Connection to sguild failed!");
		}
		if (preg_match("/^DEBUG: $/", $line)) {
			invalidCallback("ERROR: No data was returned. Check pcap_agent service.");
		}
	    	// To handle large pcaps more gracefully, we only render the first $maxtranscriptbytes.
		$transcriptbytes += strlen($line);
		if ($transcriptbytes <= $maxtranscriptbytes) {
		        $line = htmlspecialchars($line);
	        	$type = substr($line, 0,3);
		        switch ($type) {
	        	    case "DEB": $debug .= preg_replace('/^DEBUG:.*$/', "<span class=txtext_dbg>$0</span>", $line) . "<br>"; $line = ''; break;
		            case "HDR": $line = preg_replace('/(^HDR:)(.*$)/', "<span class=txtext_hdr>$2</span>", $line); break;
	        	    case "DST": $line = preg_replace('/^DST:.*$/', "<span class=txtext_dst>$0</span>", $line); break;
		            case "SRC": $line = preg_replace('/^SRC:.*$/', "<span class=txtext_src>$0</span>", $line); break;
	        	}

	        	if (strlen($line) > 0) {
		            $fmtd  .= $line . "<br>";
			}
	        }
	    }


	    // Default to sending transcript.
	    $mytx = $fmtd;

	    /*

	    On the first pcap request, $debug would have looked like this (although it may have been split up and mislabeled):

	    DEBUG: Raw data request sent to doug-virtual-machine-eth1.
	    DEBUG: Making a list of local log files.
	    DEBUG: Looking in /nsm/sensor_data/doug-virtual-machine-eth1/dailylogs/2013-11-08.
	    DEBUG: Making a list of local log files in /nsm/sensor_data/doug-virtual-machine-eth1/dailylogs/2013-11-08.
	    DEBUG: Available log files:
	    DEBUG: 1383910121
	    DEBUG: Creating unique data file: /usr/sbin/tcpdump -r /nsm/sensor_data/doug-virtual-machine-eth1/dailylogs/2013-11-08/snort.log.1383910121 -w /tmp/10.0.2.15:1066_192.168.56.50:80-6.raw (ip and host 10.0.2.15 and host 192.168.56.50 and port 1066 and port 80 and proto 6) or (vlan and host 10.0.2.15 and host 192.168.56.50 and port 1066 and port 80 and proto 6)
	    DEBUG: Receiving raw file from sensor.

	    Since we now request the pcap twice, $debug SHOULD look like this:

	    DEBUG: Using archived data: /nsm/server_data/securityonion/archive/2013-11-08/doug-virtual-machine-eth1/10.0.2.15:1066_192.168.56.50:80-6.raw

	    */

	    // Find pcap file.
	    $archive = '/DEBUG: Using archived data.*/';
	    $unique = '/DEBUG: Creating unique data file.*/';
	    $found_pcap = 0;
	    if (preg_match($archive, $debug, $matches)) {
	    	$found_pcap = 1;
		$match = str_replace("</span><br>", "", $matches[0]);
	    	$pieces = explode(" ", $match);
	    	$full_filename = $pieces[4];
	    	$pieces = explode("/", $full_filename);
	    	$filename = $pieces[7];
	    } else if (preg_match($unique, $debug, $matches)) {
	    	$found_pcap = 1;
		$match = str_replace("</span><br>", "", $matches[0]);
	    	$pieces = explode(" ", $match);
	    	$sensor_filename = $pieces[7];
	    	$server_filename = $pieces[9];
	    	$pieces = explode("/", $sensor_filename);
	    	$sensorname = $pieces[3];
	    	$dailylog = $pieces[5];
	    	$pieces = explode("/", $server_filename);
	    	$filename = $pieces[2];
	    	$full_filename = "/nsm/server_data/securityonion/archive/$dailylog/$sensorname/$filename";
	    }	

	    // Add query and timer information to debug section.
	    $debug = "<br>" . $debug;
	    $debug .= "<span class=txtext_qry>QUERY: " . $query . "</span>";
	    $time5 = microtime(true);
	    $alltimes  = number_format(($time1 - $time0), 2) . " ";
	    $alltimes .= number_format(($time2 - $time1), 2) . " ";
	    $alltimes .= number_format(($time3 - $time2), 2) . " ";
	    $alltimes .= number_format(($time4 - $time3), 2) . " ";
	    $alltimes .= number_format(($time5 - $time4), 2);
	    $debug .= "<span class=txtext_dbg>CAPME: Processed transcript in " . number_format(($time5 - $time0), 2) . " seconds: " . $alltimes . "</span><br>";

	    // If we exceeded $maxtranscriptbytes, notify the user and recommend downloading the pcap.
	    if ($transcriptbytes > $maxtranscriptbytes) {
		$debug .= "<span class=txtext_dbg>CAPME: <b>Only showing the first " . number_format($maxtranscriptbytes) . " bytes of transcript output.</b></span><br>";
		$debug .= "<span class=txtext_dbg>CAPME: <b>This transcript has a total of " . number_format($transcriptbytes) . " bytes.</b></span><br>";
		$debug .= "<span class=txtext_dbg>CAPME: <b>To see the entire stream, you can either:</b></span><br>";
		$debug .= "<span class=txtext_dbg>CAPME: <b>- click the 'close' button, increase Max Xscript Bytes, and resubmit (may take a while)</b></span><br>";
		$debug .= "<span class=txtext_dbg>CAPME: <b>OR</b></span><br>";
		$debug .= "<span class=txtext_dbg>CAPME: <b>- you can download the pcap using the link below.</b></span><br>";
	    }

	    // if we found the pcap, create a symlink in /var/www/so/capme/pcap/
	    // and then create a hyperlink to that symlink.
	    if ($found_pcap == 1) {
	      	$tmpstring = rand();
		$filename_random = str_replace(".raw", "", "$filename-$tmpstring");
		$filename_download = "$filename_random.pcap";
		$link = "/var/www/so/capme/pcap/$filename_download";
		symlink($full_filename, $link);
		$debug .= "<br><br><a href=\"/capme/pcap/$filename_download\">$filename_download</a>";
		$mytx = "<a href=\"/capme/pcap/$filename_download\">$filename_download</a><br><br>$mytx";
		// if the user requested pcap, send the pcap instead of the transcript
		if ($xscript == "pcap") {
		    	$mytx = $filename_download;
		}
	    } else {
	        $debug .= "<br>WARNING: Unable to find pcap.";
	    }

	    // Pack the output into an array.
	    $result = array("tx"  => "$mytx",
	                    "dbg" => "$debug",
	                    "err" => "$errMsg");
	}
}
// Encode the array and send it to the browser.
$theJSON = json_encode($result);
echo $theJSON;
?>
