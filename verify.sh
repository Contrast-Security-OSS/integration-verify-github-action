#!/usr/bin/env bash

[[ -n $debug ]] && set -x

# Check required variables are defined
REQUIRED_VARS=(INPUT_CONTRAST_API_KEY INPUT_CONTRAST_AUTHORIZATION INPUT_CONTRAST_ORG_ID INPUT_APP_NAME)
invalid_env=false
for key in ${REQUIRED_VARS[*]}; do
    if [[ -v "$key" ]]; then continue ; else echo "ERROR: environment variable $key is not set" && invalid_env=true; fi;
done
if [ $invalid_env == true ]; then exit 1 ; fi

# Define some variables we'll use several times
BASEURL="https://${INPUT_CONTRAST_HOST:-app.contrastsecurity.com}/Contrast/api/ng/$INPUT_CONTRAST_ORG_ID"
CURLCMD="curl --silent -HAccept:application/json -HAPI-Key:$INPUT_CONTRAST_API_KEY -HAuthorization:$INPUT_CONTRAST_AUTHORIZATION"
SEVERITIES=${INPUT_SEVERITIES-CRITICAL,HIGH}
FAIL_THRESHOLD=${INPUT_FAIL_THRESHOLD-0}

#Lookup the application ID of the named application
declare -a MYARRAY=$($CURLCMD -G --data-urlencode "filterText=$INPUT_APP_NAME" "$BASEURL/applications/name")
APP_ID=$( echo ${MYARRAY[@]} | jq -r '.applications[0].app_id' )
[[ -n $debug ]] && echo ${MYARRAY[@]}
echo "The app id for the app called $INPUT_APP_NAME is $APP_ID. Checking for $SEVERITIES vulnerabilities with commitHash=$CI_COMMIT_SHORT_SHA."

#Lookup session metadata fields on this application
declare -a MYARRAY=$($CURLCMD -G $BASEURL/metadata/session/$APP_ID/filters)
#Find the session metadata field IDs for the buildNumber and commitHash fields
BUILDNUMID=$( echo ${MYARRAY[@]} | jq -r '.filters|map(select(any(.label; contains("Build Number")))|.id)[0]' )
COMMITHASHID=$( echo ${MYARRAY[@]} | jq -r '.filters|map(select(any(.label; contains("Commit Hash")))|.id)[0]' )

#Build the Job Outcome Policy body
JOP_REQUEST_DATA="{\"application_id\":\"$APP_ID\",\"security_check_filter\":{\"query_by\":\"APP_VERSION_TAG\", \"app_version_tags\":[\"$CI_COMMIT_SHORT_SHA\"]},\"origin\":\"GitHub/Bash\"}"
#Check for Job Outcome Policy results on this application
declare -a MYARRAY=$($CURLCMD -HContent-Type:application/json -d "$JOP_REQUEST_DATA" $BASEURL/securityChecks)
[[ -n $debug ]] && echo ${MYARRAY[@]}
JOP_RESULT=$( echo ${MYARRAY[@]} | jq -r '.security_check.result' )
JOP_NAME=$( echo ${MYARRAY[@]} | jq -r '.security_check.job_outcome_policy.name' )
JOP_OUTCOME=$( echo ${MYARRAY[@]} | jq -r '.security_check.job_outcome_policy.outcome' )
if [ $JOP_RESULT == 'false' ]; then echo "Build gate fails with status $JOP_OUTCOME - Policy '$JOP_NAME' matched" && exit 1; fi #Job Outcome Policy matches this build
if [ $JOP_RESULT == 'true' ]; then echo "Build gate passes" && exit 0; fi #Job Outcome Policy does not match this build
echo 'No Job Outcome Policy found for this application, performing manual threshold check...'

#No Job Outcome Policy exists for this build, so check manually for results
#Search for vulnerabilities on this application found during this test run
declare -a MYARRAY=$($CURLCMD -G --data-urlencode "appVersionTags=[$CI_COMMIT_SHORT_SHA]" --data-urlencode "severities=$SEVERITIES" "$BASEURL/traces/$APP_ID/quick")
[[ -n $debug ]] && echo ${MYARRAY[@]}
VULN_COUNT=$( echo ${MYARRAY[@]} | jq -r '.filters[1].count' )
echo "The vulnerability count is $VULN_COUNT."

#Fail if there are more vulnerabilities than the defined threshold
if [ $VULN_COUNT -gt $FAIL_THRESHOLD ]; then exit 1; fi
