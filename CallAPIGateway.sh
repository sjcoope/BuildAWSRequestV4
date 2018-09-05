#!/bin/bash

function sha256_hash(){
    a="$@"
    printf "$a" | openssl dgst -binary -sha256
}

function sha256_hash_in_hex(){
    a="$@"
    printf "$a" | openssl dgst -binary -sha256 | od -An -vtx1 | sed 's/[ \n]//g' | sed 'N;s/\n//'
}

function hex_of_sha256_hmac_with_string_key_and_value() {
    KEY=$1
    DATA="$2"
    shift 2
    
    printf "$DATA" | openssl dgst -binary -sha256 -hmac "$KEY" | od -An -vtx1 | sed 's/[ \n]//g' | sed 'N;s/\n//'
}

function hex_of_sha256_hmac_with_hex_key_and_value() {
    KEY="$1"
    DATA="$2"
    shift 2
    
    printf "$DATA" | openssl dgst -binary -sha256 -mac HMAC -macopt "hexkey:$KEY" | od -An -vtx1 | sed 's/[ \n]//g' | sed 'N;s/\n//'
}

function create_canonical_request() {
    HTTP_REQUEST_METHOD="$1"
    CANONICAL_URL="$2"
    CANONICAL_QUERY_STRING="$3"
    CANONICAL_HEADERS="$4"
    SIGNED_HEADERS="$5"
    REQUEST_PAYLOAD="$6"
    shift 6
    
    REQUEST_PAYLOAD_HASH_HEX=$(sha256_hash_in_hex "${REQUEST_PAYLOAD}")
    CANONICAL_REQUEST_CONTENT="${HTTP_REQUEST_METHOD}\n${CANONICAL_URL}\n${CANONICAL_QUERY_STRING}\n${CANONICAL_HEADERS}\n\n${SIGNED_HEADERS}\n${REQUEST_PAYLOAD_HASH_HEX}"
    
    echo $CANONICAL_REQUEST_CONTENT
}

function sign_canonical_request() {
    CANONICAL_REQUEST_CONTENT="$1"
    CANONICAL_REQUEST=$(sha256_hash_in_hex "${CANONICAL_REQUEST_CONTENT}")
    printf "${CANONICAL_REQUEST}"
}

function create_string_to_sign() {
    TIMESTAMP="$1"
    REQUEST_DATE="$2"
    REGION="$3"
    SERVICE="$4"
    REQUEST_HASH="$5"
    shift 4
    
    ALGORITHM="AWS4-HMAC-SHA256"
    
    CREDENTIAL_SCOPE="${REQUEST_DATE}/${REGION}/${SERVICE}/aws4_request"
    STRING_TO_SIGN="${ALGORITHM}\n${TIMESTAMP}\n${CREDENTIAL_SCOPE}\n${REQUEST_HASH}"
    
    echo $STRING_TO_SIGN
}

function create_signing_key() {
    SECRET_ACCESS_KEY="$1"
    REQUEST_DATE="$2"
    REGION="$3"
    REQUEST_SERVICE="$4"
    shift 4
    
    DATE_HMAC=$(hex_of_sha256_hmac_with_string_key_and_value "AWS4${SECRET_ACCESS_KEY}" ${REQUEST_DATE})
    REGION_HMAC=$(hex_of_sha256_hmac_with_hex_key_and_value "${DATE_HMAC}" ${REGION})
    SERVICE_HMAC=$(hex_of_sha256_hmac_with_hex_key_and_value "${REGION_HMAC}" ${REQUEST_SERVICE})
    SIGNING_HMAC=$(hex_of_sha256_hmac_with_hex_key_and_value "${SERVICE_HMAC}" "aws4_request")
    
    printf "${SIGNING_HMAC}"
}

function create_signature() {
    KEY="$1"
    STRING_TO_SIGN="$2"
    shift 2
    
    Signature=$(hex_of_sha256_hmac_with_hex_key_and_value  "${KEY}" "${STRING_TO_SIGN}")
    
    printf "${Signature}"
}

function create_authorization_header() {
    ACCESS_KEY_ID=$1
    SIGNATURE=$2
    REQUEST_DATE=$3
    REQUEST_REGION=$4
    REQUEST_SERVICE=$5
    shift 5
    
    printf "AWS4-HMAC-SHA256 Credential=$ACCESS_KEY_ID/$REQUEST_DATE/$REQUEST_REGION/$REQUEST_SERVICE/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=$SIGNATURE"
}

# Variables
SecretKey="SECRET KEY"
AccessKey="ACCESS KEY"
RequestRegion="AWS REGION e.g. eu-west-1"
RequestService="execute-api"
RequestHost="API GATEWAY e.g. abcd.execute-api.eu-west-1.amazonaws.com"
RequestURL="API GATEWAY RESOURCE e.g. /dev/pets"

# Generate the timestamp and date
RequestTimestamp=$(date +%Y%m%dT%H%M%SZ)
RequestDate=$(date +%Y%m%d)

# Generate the canonical request
Request=$(create_canonical_request \
    "GET" \
    "$RequestURL" \
    "" \
    "content-type:$ContentType\nhost:$RequestHost\nx-amz-date:$RequestTimestamp" \
    "content-type;host;x-amz-date" \
    ""
)

printf "\n\nCanonical Request:\n-----------------------\n$Request\n\n"

# Hash the canonical request
HashedRequest=$(sign_canonical_request $Request)

printf "Canonical Request Hash:\n-----------------------\n$HashedRequest\n\n"

# Generate the string to sign
StringToSign=$(create_string_to_sign \
    $RequestTimestamp \
    $RequestDate \
    $RequestRegion  \
    $RequestService \
    $HashedRequest
)

printf "String To Sign:\n-----------------------\n$StringToSign\n\n"

# Generate the signing key
SigningKey=$(create_signing_key \
    $SecretKey \
    $RequestDate \
    $RequestRegion \
    $RequestService
)

printf "Signing Key:\n-----------------------\n$SigningKey\n\n"

# Generate the signature
Signature=$(create_signature \
    $SigningKey \
    $StringToSign
)

printf "Signature:\n-----------------------\n$Signature\n\n"

# Generate the authorization header
AuthorizationHeader=$(create_authorization_header $AccessKey $Signature $RequestDate $RequestRegion $RequestService)

printf "Authorization Header:\n-----------------------\n$AuthorizationHeader\n\n"

# Make CURL request
Url="https://$RequestHost$RequestURL"
printf "Making CURL request\n----------------------\nURL: $Url\nAuthorization: $AuthorizationHeader\nContent-Type: $ContentType\nHost: $RequestHost\nX-Amz-Date: $RequestTimestamp\n\nResult:\n"

curl -X GET $Url --http1.1 \
-H "Authorization: $AuthorizationHeader" \
-H "Content-Type: $ContentType" \
-H "Host: $RequestHost" \
-H "X-Amz-Date: $RequestTimestamp"
