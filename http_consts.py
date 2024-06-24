# File: http_consts.py
#
# Copyright (c) 2016-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

HTTP_VALIDATE_INTEGER_MSG = "Please provide a valid integer value in the {key} parameter"
HTTP_ERR_CODE_MSG = "Error code unavailable"
HTTP_ERR_MSG = "Unknown error occurred. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the HTTP server. " \
                     "Please check the asset configuration and|or the action parameters"
HTTP_SERVER_CONNECTION_ERR_MSG = "Error Connecting to file server. Error:{error}"
HTTP_ERR_FILE_ADD_TO_VAULT = "Error while adding the file to Vault"
HTTP_FILE_NOT_FOUND_ERR_MSG = "Please verify the file destination and make sure the filename is not included in it"
HTTP_UNABLE_TO_RETRIEVE_VAULT_ITEM_ERR_MSG = "Unable to retrieve vault item details"
HTTP_EXCLUDE_FILENAME_ERR_MSG = "Error: Do not include filename in the file destination"
HTTP_PUT_FILE_ERR_MSG = "Error putting file. {error}"
HTTP_JSON_FILE_PATH = 'file_path'
HTTP_INVALID_PATH_ERR = 'Invalid file path, please enter a valid file path'
HTTP_INVALID_URL_ERR = 'Malformed URL, please enter hostname and filepath in proper format'

HTTP_JSON_HOSTNAME = 'hostname'
HTTP_JSON_ACCESS_TOKEN = 'access_token'
HTTP_JSON_HOST = 'host'
HTTP_JSON_VAULT_ID = 'vault_id'
HTTP_JSON_FILE_DEST = 'file_destination'
HTTP_JSON_FILE_NAME = 'file_name'
UNKNOWN_ERR_MSG = "UNKNOWN ERR MSG"
UNKNOWN_ERR_CODE_MSG = "UNKNOWN ERR CODE MSG"
HTTP_ERR_FILENAME_NOT_IN_VAULT = "Could not find file with specified filename in vault, please provide a valid filename"
DEFAULT_REQUEST_TIMEOUT = 30  # in seconds
HTTP_STATE_IS_ENCRYPTED = 'is_encrypted'

# For encryption and decryption
HTTP_ENCRYPT_TOKEN = "Encrypting the {} token"
HTTP_DECRYPT_TOKEN = "Decrypting the {} token"
HTTP_ENCRYPTION_ERR = "Error occurred while encrypting the state file"
HTTP_DECRYPTION_ERR = "Error occurred while decrypting the state file"
