<?php
/*
Plugin Name: 6caner - PHP Malcode Scanner
Plugin URI: https://github.com/6ickzone/6caner
Description: 6caner is a lightweight PHP scanner for detecting common malware patterns such as eval(base64_decode()), system(), shell_exec(), etc.
Version: 1.0
Author:Michael Stowe,0x6ick (6ickZone)
License: GPL-2.0
*/

/*
╔═╗┬ ┬┌─┐┌─┐┌┬┐┌─┐┌─┐
║  ├─┤├┤ ├─┤ │ ├┤ └─┐
╚═╝┴ ┴└  ┴ ┴ ┴ └─┘└─┘
Coded by 0x6ick (based on open mod by Michael Stowe, now supercharged)
*/

define('SEND_EMAIL_ALERTS_TO', 'youremail@example.com'); // Optional: change if you want email alert
define('LOG_FILE', 'infected.log'); // Log file

class SixCaner {
    public $infected_files = [];
    private $scanned_files = [];

    function __construct($start = '.') {
        $this->scan($start);
        $this->sendAlert();
    }

    function scan($dir) {
        $this->scanned_files[] = $dir;
        $files = scandir($dir);
        if (!is_array($files)) return;

        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;
            $path = $dir . '/' . $file;

            if (is_dir($path)) {
                $this->scan($path);
            } elseif (is_file($path) && pathinfo($path, PATHINFO_EXTENSION) === 'php') {
                if (!in_array($path, $this->scanned_files)) {
                    $this->check(file_get_contents($path), $path);
                }
            }
        }
    }

    function check($contents, $file) {
        $this->scanned_files[] = $file;

        $patterns = [
            '/eval\s*\s*base64_decode/i',
            '/eval\s*\s*gzuncompress/i',
            '/eval\s*\s*gzinflate/i',
            '/preg_replace\s*.*\/e.*/i',
            '/assert\s*/i',
            '/system\s*/i',
            '/exec\s*/i',
            '/shell_exec\s*/i',
            '/passthru\s*/i',
            '/popen\s*/i',
            '/proc_open\s*/i',
            '/create_function\s*/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $contents, $matches)) {
                $this->infected_files[] = $file;
                $snippet = substr($contents, stripos($contents, $matches[0]) - 20, 100);
                $this->log("[!] Suspicious: $file\n    >> " . trim($matches[0]) . "\n    Snippet: " . trim($snippet) . "\n");
                break;
            }
        }
    }

    function log($message) {
        file_put_contents(LOG_FILE, $message . "\n", FILE_APPEND);
        echo $message . "\n";
    }

    function sendAlert() {
        if (!empty($this->infected_files)) {
            $message = "6caner Alert - Malicious Code Detected:\n\n";
            foreach ($this->infected_files as $inf) {
                $message .= " - $inf\n";
            }

            // Email if needed
            if (SEND_EMAIL_ALERTS_TO !== 'youremail@example.com') {
                @mail(SEND_EMAIL_ALERTS_TO, '6caner Malware Alert', $message, "From: scanner@localhost");
            }
        }
    }
}

// CLI support
$scan_path = isset($argv[1]) ? $argv[1] : getcwd();

ini_set('memory_limit', '-1');
new SixCaner($scan_path);

?>
