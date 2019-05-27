#!/bin/bash

set -e

displayName=$1

if [[ -z $displayName || -n $2 ]]; then 
    echo 'Must provide 1 argument: displayName.'
    exit 1
fi

roles='[
    {
        "allowedMemberTypes": [
            "Application"
        ],
        "description": "A client application can call the API with a transitioned service identity.",
        "displayName": "Service Account Impersonation",
        "value": "app_impersonation"
    },
    {
        "allowedMemberTypes": [
            "User"
        ],
        "description": "A user can sign in to the application with a transitioned identity.",
        "displayName": "Web User",
        "value": "user_web"
    },
    {
        "allowedMemberTypes": [
            "User"
        ],
        "description": "A user can use applications to call the API with a transitioned identity.",
        "displayName": "API User",
        "value": "user_api"
    }
]'

optionalClaims='{
    "idToken": [
        {
            "name": "sid",
            "essential": false,
            "additionalProperties": []
        },
        {
            "name": "onprem_sid",
            "essential": false,
            "additionalProperties": []
        },
        {
            "name": "upn",
            "essential": true,
            "additionalProperties": [
                "include_externally_authenticated_upn"
            ]
        }
    ],
    "accessToken": [
        {
            "name": "onprem_sid",
            "essential": false,
            "additionalProperties": []
        },
        {
            "name": "upn",
            "essential": true,
            "additionalProperties": [
                "include_externally_authenticated_upn"
            ]
        }
    ]
}'

echo 'Creating application...'
objectId=$(az ad app create \
    --display-name "$displayName" \
    --app-roles "$roles" \
    --query 'objectId' \
    --output 'tsv')
echo "Created application object '$objectId'."

# There is a lag where APIs return inconsistent answers from GET
# so checking if the app exists before trying to PATCH is not
# enough. Just keep trying to PATCH.
echo 'Updating application...'
for i in {1..5}; do 
    if az ad app update --id "$objectId" --set "optionalClaims=$optionalClaims"; then 
        echo 'Updated application.'
        break;
    elif [ $i == 5 ]; then
        echo 'Failed to update application.'
        exit 1
    fi
    sleep 1; 
done
echo 'Success!'
