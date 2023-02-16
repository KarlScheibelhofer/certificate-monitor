#!/bin/bash

shopt -s nullglob

_script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

_url="http://localhost:8080/certificates"
_cert_files=(${_script_dir}/certificates/*.crt)

for file in "${_cert_files[@]}"
do
    echo -n "processing ${file} - status code "
    curl --url "${_url}" --request POST --data-binary @${file} --output /dev/null --silent --write-out "%{http_code}"
    echo
done
