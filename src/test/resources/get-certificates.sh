#!/bin/bash

_script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cat "$_script_dir/https-server" | while read server
do
    echo "get HTTPS certificate of $server"
    echo | openssl s_client -servername $server -connect $server:443 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "$_script_dir/certificates/$server.crt"
done
