#!/usr/bin/env bash

echo "start content tests"

SECRET_CONF_PATH=$(cat secret_conf_path)

CONF_PATH="./Tests/conf.json"

USERNAME=$(cat $SECRET_CONF_PATH | jq '.username')
# remove quotes
temp="${USERNAME%\"}"
temp="${temp#\"}"
USERNAME=$temp

SERVER_URL=$(cat $SECRET_CONF_PATH | jq '.url')
# remove quotes
temp="${SERVER_URL%\"}"
temp="${temp#\"}"
SERVER_URL=$temp

PASS=$(cat $SECRET_CONF_PATH | jq '.userPassword')
# remove quotes
temp="${PASS%\"}"
temp="${temp#\"}"
PASS=$temp

[ -n "${NIGHTLY}" ] && IS_NIGHTLY=true || IS_NIGHTLY=false

echo "Starts tests with server url - $SERVER_URL"
python ./Tests/test_content.py -s "$SERVER_URL" -u "$USERNAME" -p "$PASS" -c "$CONF_PATH" -e "$SECRET_CONF_PATH" -n $IS_NIGHTLY -t "$SLACK_TOKEN" -a "$CIRCLECI_TOKEN" -b "$CIRCLE_BUILD_NUM" -g "$CIRCLE_BRANCH"
