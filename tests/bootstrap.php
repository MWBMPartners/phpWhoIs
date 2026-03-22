<?php
/**
 * PHPUnit bootstrap — loads functions from lookup.php without executing the main handler.
 * We extract functions into a separate includable file for testing.
 */

// Define constants that lookup.php needs
if (!defined('CACHE_DIR')) {
    define('CACHE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_test_cache');
}
if (!defined('CACHE_TTL')) {
    define('CACHE_TTL', 900);
}
if (!defined('RATE_LIMIT_MAX')) {
    define('RATE_LIMIT_MAX', 30);
}
if (!defined('RATE_LIMIT_WINDOW')) {
    define('RATE_LIMIT_WINDOW', 60);
}
if (!defined('MAX_DOMAIN_LENGTH')) {
    define('MAX_DOMAIN_LENGTH', 253);
}
if (!defined('MAX_POST_SIZE')) {
    define('MAX_POST_SIZE', 1024);
}
if (!defined('IANA_TLD_URL')) {
    define('IANA_TLD_URL', 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt');
}
if (!defined('IANA_TLD_PATH')) {
    define('IANA_TLD_PATH', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_tlds.txt');
}
if (!defined('PSL_ICANN_URL')) {
    define('PSL_ICANN_URL', 'https://publicsuffix.org/list/public_suffix_list.dat');
}
if (!defined('SL_SUFFIXES_PATH')) {
    define('SL_SUFFIXES_PATH', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_suffixes.txt');
}
if (!defined('TLD_META_PATH')) {
    define('TLD_META_PATH', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_tld_meta.json');
}

// Load the functions file
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'web' . DIRECTORY_SEPARATOR . 'public_html_beta' . DIRECTORY_SEPARATOR . 'functions.php';
