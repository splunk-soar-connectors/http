# File: http_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#

#
# --

HTTP_VALIDATE_INTEGER_MESSAGE = "Please provide a valid integer value in the {key} parameter"
HTTP_ERROR_CODE_MESSAGE = "Error code unavailable"
HTTP_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters"
TYPE_ERROR_MESSAGE = "Error occurred while connecting to the HTTP server. " \
                     "Please check the asset configuration and|or the action parameters"
HTTP_SERVER_CONNECTION_ERROR_MESSAGE = "Error Connecting to file server. Error:{error}"
HTTP_ERR_FILE_ADD_TO_VAULT = "Error while adding the file to Vault"
HTTP_UNABLE_TO_RETRIEVE_VAULT_ITEM_ERR_MSG = "Unable to retrieve vault item details"
HTTP_FILE_NOT_FOUND_ERR_MSG = "Please verify the file destination and make sure the filename is not included in it"
HTTP_UNABLE_TO_RETRIEVE_VAULT_ITEM_ERR_MSG = "Unable to retrieve vault item details"
HTTP_EXCLUDE_FILENAME_ERR_MSG = "Error: Do not include filename in the file destination"
HTTP_PUT_FILE_ERR_MSG = "Error putting file. {error}"

HTTP_JSON_FILE_PATH = 'file_path'
HTTP_JSON_HOSTNAME = 'hostname'
HTTP_JSON_HOST = 'host'
HTTP_JSON_VAULT_ID = 'vault_id'
HTTP_JSON_FILE_DEST = 'file_destination'
