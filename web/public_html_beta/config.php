<?php
/**
 * Application configuration.
 * Edit these values to customise the application behaviour.
 */

$config = [

    // Domain registration provider
    'registration' => [
        // Set to false to hide the "Register this domain" button entirely
        'enabled' => true,

        // URL template — {domain} will be replaced with the searched domain name
        'url_template' => 'https://store.mwservices.it/cart.php?a=add&domain=register&query={domain}',

        // Button text shown to the user
        'button_text' => 'Register this domain',

        // Open the registration link in a new browser tab
        'open_in_new_tab' => true,
    ],

];
