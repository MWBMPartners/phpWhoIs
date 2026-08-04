<?php
/**
 * Shared cache-busting helper for static asset URLs (Issue #218).
 *
 * Several pages append "?v=<filemtime>" to assets/css/style.css so browsers
 * pick up a fresh copy after a deploy. Calling filemtime() directly is
 * unguarded — if the file is ever missing or unreadable it returns false,
 * which would render as "?v=" (or emit a PHP warning). Centralise it here
 * so every page fails safe the same way.
 */

if (!function_exists('assetVersion')) {
    /**
     * Return a cache-busting version string for a static asset path.
     * Falls back to '1' if the file's mtime can't be read.
     */
    function assetVersion(string $path): string {
        $mtime = @filemtime($path);
        return $mtime !== false ? (string) $mtime : '1';
    }
}
