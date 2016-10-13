<?php

if(!defined("IN_MYBB")) {
    die("You cannot access this file directly. Please make sure IN_MYBB is defined.");
}

$plugins->add_hook('parse_message_end', 'parse_img');
$plugins->add_hook('global_start', 'upgrade_insecure_requests');

function ssl_proxy_info() {
	return array(
		"name"  		=> "SSL Proxy",
		"description"	=> "Makes all images in posts get requested by the server instead of by the client and upgrades all insecure requests.",
		"website"       => "http://forums.woodnet.net",
		"author"        => "kloddant",
		"authorsite"    => "http://forums.woodnet.net",
		"version"       => "1.0",
		"guid"          => "",
		"compatibility" => "18*"
	);
}

function ssl_proxy_activate() {
	global $db;

	create_file();

	$ssl_proxy_group = array(
        'gid'         => 'NULL',
        'name'  	  => 'ssl_proxy',
        'title'       => 'SSL Proxy',
        'description' => 'Makes all images in posts get requested by the server instead of by the client and upgrades all insecure requests.',
        'disporder'   => "1",
        'isdefault'   => "0",
    );

    $db->insert_query('settinggroups', $ssl_proxy_group);
 	$gid = $db->insert_id();

 	$ssl_proxy_setting = array(
        'sid'            => 'NULL',
        'name'        => 'ssl_proxy_enable',
        'title'            => 'Do you want to enable SSL Proxy?',
        'description'    => 'If you set this option to yes, this plugin will route all incoming image requests through your server to the client and will send a content security policy header to upgrade all insecure requests.',
        'optionscode'    => 'yesno',
        'value'        => '1',
        'disporder'        => 1,
        'gid'            => intval($gid),
    );

    $db->insert_query('settings', $ssl_proxy_setting);
	rebuild_settings();
}

function ssl_proxy_deactivate() {
	global $db;

	if (!unlink(MYBB_ROOT."ssl_proxy.php")) {
		exit("Error: Cannot delete ssl_proxy.php.  It is either not writeable or does not exist.");
	}

 	$db->query("
 		DELETE FROM ".TABLE_PREFIX."settings 
 		WHERE name IN ('ssl_proxy_enable')
 	");
    $db->query("
    	DELETE FROM ".TABLE_PREFIX."settinggroups 
    	WHERE name='ssl_proxy'
    ");

	rebuild_settings();
} 

function create_file() {
	$contents = '
		<?php

		$url = $_GET["url"];
		$url = strip_tags($url);
		
		$url_pieces = parse_url($url);
		if (!isset($url_pieces["path"])) {
			exit;
		}
		$scheme = (isset($url_pieces["scheme"]) ? $url_pieces["scheme"]."://" : "");
		$host = (isset($url_pieces["host"]) ? $url_pieces["host"] : "");
		$path = $url_pieces["path"];
		$file = basename($path);

		$path = urldecode($path);
		$path = implode("/", array_map("rawurlencode", explode("/", $path)));
		$url = $scheme.$host.$path;
		
		$url = filter_var($url, FILTER_SANITIZE_URL);

		if (filter_var($url, FILTER_VALIDATE_URL) === false) {
			exit;
		}
		
		$curl_options = array(
			CURLOPT_FAILONERROR => true,
			CURLOPT_FOLLOWLOCATION => false,
			CURLOPT_RETURNTRANSFER => false,
			CURLOPT_SSL_VERIFYHOST => false,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_HTTPGET => true,
			CURLOPT_HEADER => false,
			CURLOPT_VERBOSE => true,
			CURLOPT_BINARYTRANSFER => true,
			CURLOPT_TIMEOUT => 900,
			CURLOPT_USERAGENT => "Mozilla/5.0 (Windows NT x.y; WOW64; rv:10.0) Gecko/20100101 Firefox/10.0",
		);

		$curl = curl_init($url);
		curl_setopt_array($curl, $curl_options); 
		header("Content-Type: ".curl_getinfo($curl, CURLINFO_CONTENT_TYPE)); 
		header("Content-Disposition: filename=\'".$file."\'"); 
		$result = curl_exec($curl);
		if(curl_error($curl)) {
		    echo "error:" . curl_error($curl);
		}
		curl_close($curl);

		?>
	';
	if (!file_put_contents(MYBB_ROOT."ssl_proxy.php", trim($contents))) {
		exit("Error: Cannot create ssl_proxy.php.  Your main MyBB directory is probably not writeable.");
	}
	chmod(MYBB_ROOT."ssl_proxy.php", 0755);
}

function parse_img($message) {
	global $mybb;
	if (!$mybb->settings['ssl_proxy_enable']) {
		return $message;
	}
	// Parse all image tags so that they retrieve their images through the ssl proxy file.
	$message = preg_replace("/<img(\s*)?src=[\'\"]((?:(?!\/ssl_proxy\.php)[^\'\"])*)[\'\"](\s*)?(?:\/?>|><\/img>)/i", "<img $1 src='/ssl_proxy.php?url=$2' $3 />", $message);
	return $message;
}

function upgrade_insecure_requests() {
	global $mybb;
	if (!$mybb->settings['ssl_proxy_enable']) {
		return;
	}
	header('Content-Security-Policy: upgrade-insecure-requests');
}

?>