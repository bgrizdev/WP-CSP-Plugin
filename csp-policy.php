<?php 

/*
Plugin Name: CSP Policy
Description: Custom plugin to support, create, and generate a Content Security Policy
Version: 1.0
Author: Ben G 
*/

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

// Settings → CSP Settings
add_action('admin_menu', function () {
    add_options_page('CSP Settings', 'CSP Settings', 'manage_options', 'csp-settings', 'csp_settings_page');
});

add_action('admin_init', function () {

    $group = 'csp_settings';
    $page  = 'csp-settings';

    register_setting($group, 'csp_report_mode', [
        'type' => 'string',
        'sanitize_callback' => function ($v) {
            return in_array($v, ['report', 'enforce'], true) ? $v : 'enforce';
        },
        'default' => 'report',
    ]);

    add_settings_section('csp_report_section', 'Report Mode', '__return_false', $page);

    add_settings_field(
        'csp_report_mode',
        'Mode',
        function () {
            $mode = get_option('csp_report_mode', 'enforce'); ?>
            <span>Select the enforcement mode. Keep in report while testing and adding violations to directives.</span><br>
            <label>
                <input type="radio" name="csp_report_mode" value="enforce" <?php checked($mode, 'enforce'); ?>>
                Enforce (<code>Content-Security-Policy</code>)
            </label><br>
            <label>
                <input type="radio" name="csp_report_mode" value="report" <?php checked($mode, 'report'); ?>>
                Report-Only (<code>Content-Security-Policy-Report-Only</code>)
            </label>
        <?php },
        $page,
        'csp_report_section'
    );

    add_settings_section('csp_section', 'Directives', '__return_false', $page);

    $directives = [
        'frame-ancestors',
        'script-src',
        'style-src',
        'img-src',
        'font-src',
        'connect-src',
        'frame-src',
    ];

    foreach ($directives as $dir) {
        $option = 'csp_' . str_replace('-', '_', $dir);

        register_setting($group, $option, [
            'type' => 'string',
            'sanitize_callback' => 'sanitize_textarea_field', 
        ]);

        add_settings_field(
            $option,
            $dir,
            function () use ($option) {
                $val = get_option($option, '');
                echo '<span>Separate URLs with a space.</span><br><textarea name="' . esc_attr($option) . '" rows="5" class="large-text code">' .
                     esc_textarea($val) . '</textarea>';
            },
            $page,
            'csp_section'
        );
    }
});

function csp_settings_page() {
    if (!current_user_can('manage_options')) return; ?>
    <div class="wrap">
        <h1>CSP Settings</h1>
        <span>When adding URLs to the directives only use the base domain and not the full URL.</span>
        <form method="post" action="options.php">
            <?php
            settings_fields('csp_settings');
            do_settings_sections('csp-settings');
            submit_button('Save Changes');
            ?>
        </form>
    </div>
    <?php
}

// create global hash for scripts 
add_action('init', function () {
    $GLOBALS['csp_nonce'] = base64_encode(random_bytes(16));
});

// nonce external scripts
add_filter('script_loader_tag', function ($tag) {
    $n = esc_attr($GLOBALS['csp_nonce']);
    return (strpos($tag, ' nonce=') !== false) ? $tag : str_replace('<script ', "<script nonce=\"$n\" ", $tag);
}, 10, 1);

// nonce external stylesheets
add_filter('style_loader_tag', function ($html) {
    $n = esc_attr($GLOBALS['csp_nonce']);
    return (strpos($html, ' nonce=') !== false) ? $html : str_replace("<link rel='stylesheet'", "<link rel='stylesheet' nonce=\"$n\"", $html);
}, 10, 1);

// nonce inline styles
add_filter('wp_inline_style_attributes', function ($atts) {
    $n = isset($GLOBALS['csp_nonce']) ? $GLOBALS['csp_nonce'] : '';
    if ($n) {
        $atts['nonce'] = $n;
    }
    return $atts;
});

// run JS script early to add nonce to any scripts and style 
add_action('wp_head', function () {
    $n = esc_attr($GLOBALS['csp_nonce']);
    ?>
    <script nonce="<?= $n; ?>">
      window.CSP_NONCE = "<?= esc_js($n); ?>";
      (function(n){
        if(!n) return;
        const needsNonce = el =>
          (el.tagName === 'SCRIPT' || el.tagName === 'STYLE') && !el.nonce;

        const origCreate = Document.prototype.createElement;
        Document.prototype.createElement = function(tag){
          const el = origCreate.call(this, tag);
          if (needsNonce(el)) el.setAttribute('nonce', n);
          return el;
        };

        const patch = (proto, method) => {
          const orig = proto[method];
          proto[method] = function(node){
            if (node && needsNonce(node)) node.setAttribute('nonce', n);
            return orig.apply(this, arguments);
          };
        };
        patch(Node.prototype, 'appendChild');
        patch(Node.prototype, 'insertBefore');
      })(window.CSP_NONCE);
    </script>
    <?php
}, 0);


add_action('wp_head', function () {
    $n = esc_attr($GLOBALS['csp_nonce'] ?? '');
    if (!$n) return; ?>
    <script nonce="<?= $n ?>">
    // Log CSP violations with source info
    window.addEventListener('securitypolicyviolation', function (e) {
      if (e.violatedDirective && e.violatedDirective.indexOf('script-src') === 0) {
        console.warn('[CSP]', e.violatedDirective,
          'at', e.sourceFile + ':' + e.lineNumber + ':' + e.columnNumber,
          'blocked:', e.blockedURI || '(eval/new Function)', 
          'sample:', e.sample || '');
      }
    }, {capture: true});
    </script>
    <?php
}, 0);

// additional catch for inline <style> and <script>

add_action('template_redirect', function () {

    ob_start(function ($buffer) {
        $n = isset($GLOBALS['csp_nonce']) ? $GLOBALS['csp_nonce'] : '';
        if (!$n) return $buffer;

        // <script> without src
        $buffer = preg_replace_callback(
            '#<script(?![^>]*\bsrc=)([^>]*)>#i',
            fn($m) => (strpos($m[1], 'nonce=') !== false) ? $m[0] : "<script{$m[1]} nonce=\"$n\">",
            $buffer
        );

        // <style> blocks
        $buffer = preg_replace_callback(
            '#<style([^>]*)>#i',
            fn($m) => (strpos($m[1], 'nonce=') !== false) ? $m[0] : "<style{$m[1]} nonce=\"$n\">",
            $buffer
        );

        return $buffer;
    });
}, 0);

// send header
add_action('send_headers', function () {
    if (headers_sent()) { return; }

    $n = esc_attr($GLOBALS['csp_nonce']);

    $mode                   = get_option('csp_report_mode', 'report');
    $csp_frame_ancestors    = get_option('csp_frame_ancestors');
    $csp_script_src         = get_option('csp_script_src');
    $csp_style_src          = get_option('csp_style_src');
    $csp_img_src            = get_option('csp_img_src');
    $csp_font_src           = get_option('csp_font_src');
    $csp_connect_src        = get_option('csp_connect_src');
    $csp_frame_src          = get_option('csp_frame_src');

    $header = ($mode === 'report') ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';

    header(
        "{$header}: " .
        "default-src 'self'; " .

        // Defines which external sources are allowed to embed
        "frame-ancestors 'self' {$csp_frame_ancestors}; " .

        // Scripts
        "script-src 'self' 'nonce-{$n}' {$csp_script_src}; " .

        // address blobs
        "worker-src 'self' blob:; " .
        "child-src 'self' blob:; " .

        // Fallback for older browsers
        "style-src 'self' {$csp_style_src}; " .
        // CSP3 splits
        "style-src-elem 'self' 'nonce-{$n}' {$csp_style_src}  'unsafe-hashes'; " .
        "style-src-attr 'unsafe-inline'; " .

        // Images
        "img-src 'self' {$csp_img_src} data:; " .

        // Fonts
        "font-src 'self' {$csp_font_src} data:; " .

        // XHR / fetch / beacons
        "connect-src 'self' {$csp_connect_src} ; " .

        // Frames
        "frame-src {$csp_frame_src} ; " .

        "object-src 'none'; base-uri 'self'; form-action 'self';"
    );
});