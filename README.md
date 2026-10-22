# PHPCheck
A simple Python tool to check the PHP version of a website.

## Usage
python phpcheck.py URL [options]

## Options
URL: The target website URL to check.
--deep: Enable deep scanning.
--insecure: Skip SSL certificate verification.
--timeout [1~60]: Set the request timeout in seconds.
--json: Output results in JSON format.
--show-headers: Display HTTP response headers.
