#!/usr/bin/env bash

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -s)
    SUBJECT="$2"
    shift # past argument
    shift # past value
    ;;
    -i)
    ISSUER="$2"
    shift # past argument
    shift # past value
    ;;
    -p)
    KEYPATH="$2"
    shift # past argument
    shift # past value
    ;;
esac
done
set -- "${POSITIONAL[@]}"

java -jar kube.auth.jar ${SUBJECT} ${ISSUER} ${KEYPATH}