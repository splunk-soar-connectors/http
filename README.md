[comment]: # "Auto-generated SOAR connector documentation"
# HTTP

Publisher: Splunk  
Connector Version: 3.7.1  
Product Vendor: Generic  
Product Name: HTTP  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.1.1  

This App facilitates making HTTP requests as actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
For security reasons, accessing 127.0.0.1 is not allowed.

This app requires access to port 80(for request send over HTTP) or port 443(for request send over
HTTPS) on your Phantom host(s) in order to function.

**Authentication is carried out in following priority order**

1.  Basic Auth (username and password)
2.  OAuth (oauth token url, client id and client secret)
3.  Provided Auth token (auth_token_name, auth_token)


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a HTTP asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | Base URL for making queries. (e.g. https://myservice/)
**test_path** |  optional  | string | Endpoint for test connectivity. (e.g. /some/specific/endpoint , appended to Base URL)
**auth_token_name** |  optional  | string | Type of authentication token
**auth_token** |  optional  | password | Value of authentication token
**username** |  optional  | string | Username (for HTTP basic auth)
**password** |  optional  | password | Password (for HTTP basic auth)
**oauth_token_url** |  optional  | string | URL to fetch oauth token from
**placeholder** |  optional  | ph | 
**client_id** |  optional  | string | Client ID (for OAuth)
**client_secret** |  optional  | password | Client Secret (for OAuth)
**timeout** |  optional  | numeric | Timeout for HTTP calls
**test_http_method** |  optional  | string | HTTP Method for Test Connectivity

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate connection using the configured credentials  
[put data](#action-put-data) - Perform a REST PUT call to the server  
[patch data](#action-patch-data) - Perform a REST PATCH call to the server  
[delete data](#action-delete-data) - Perform a REST DELETE call to the server  
[get headers](#action-get-headers) - Perform a REST HEAD call to the server  
[get options](#action-get-options) - Perform a REST OPTIONS call to the server  
[get data](#action-get-data) - Perform a REST GET call to the server  
[post data](#action-post-data) - Perform a REST POST call to the server  
[get file](#action-get-file) - Retrieve a file from the endpoint and save it to the vault  
[put file](#action-put-file) - Put a file from the vault to another location  

## action: 'test connectivity'
Validate connection using the configured credentials

Type: **test**  
Read only: **True**

This action will perform a GET on the configured <b>base_url</b>. The action will succeed if given a status code between 200 and 399 (inclusive). Therefore, if the given base URL requires no authentication, this action may pass even if the supplied credentials are incorrect. Alternately, if the given base URL does not point to a valid endpoint, this action could fail even if other actions may succeed with valid <b>location</b> parameters.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'put data'
Perform a REST PUT call to the server

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location (e.g. path/to/endpoint?query=string) | string |  `endpoint` 
**body** |  required  | PATCH body (query string, JSON, etc.) | string | 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 
**headers** |  optional  | Additional headers (JSON object with headers) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.body | string |  |   {"name": "Bad IP"} 
action_result.parameter.headers | string |  |   {"Content-Type": "application/json"} 
action_result.parameter.location | string |  `endpoint`  |   /rest/assets 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.data.\*.location | string |  `url`  |   http://192.168.1.26/rest/assets 
action_result.data.\*.method | string |  |   PUT 
action_result.data.\*.parsed_response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_headers | string |  |  
action_result.summary.reason | string |  |   Not Found 
action_result.summary.status_code | numeric |  |   404 
action_result.message | string |  |   Can't process response from server. Status Code: 404 Data from server: {"failed": true, "message": "Requested item not found"} 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   0   

## action: 'patch data'
Perform a REST PATCH call to the server

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location (e.g. path/to/endpoint?query=string) | string |  `endpoint` 
**body** |  optional  | PATCH body (query string, JSON, etc.) | string | 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 
**headers** |  optional  | Additional headers (JSON object with headers) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.body | string |  |   {"name": "Bad IP"} 
action_result.parameter.headers | string |  |   {"Content-Type": "application/json"} 
action_result.parameter.location | string |  `endpoint`  |   /rest/assets 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.data.\*.location | string |  `url`  |   http://192.168.1.26/rest/assets 
action_result.data.\*.method | string |  |   PATCH 
action_result.data.\*.parsed_response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_headers | string |  |  
action_result.summary.reason | string |  |   Not Found 
action_result.summary.status_code | numeric |  |   404 
action_result.message | string |  |   Can't process response from server. Status Code: 404 Data from server: {"failed": true, "message": "Requested item not found"} 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   0   

## action: 'delete data'
Perform a REST DELETE call to the server

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location (e.g. path/to/endpoint?query=string) | string |  `endpoint` 
**body** |  optional  | DELETE body (query string, JSON, etc.) | string | 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 
**headers** |  optional  | Additional headers (JSON object with headers) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.body | string |  |   {"name": "Bad IP"} 
action_result.parameter.headers | string |  |   {"Content-Type": "application/json"} 
action_result.parameter.location | string |  `endpoint`  |   /rest/assets 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.data.\*.location | string |  `url`  |   http://192.168.1.26/rest/assets 
action_result.data.\*.method | string |  |   DELETE 
action_result.data.\*.parsed_response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_headers | string |  |  
action_result.summary.reason | string |  |   Not Found 
action_result.summary.status_code | numeric |  |   404 
action_result.message | string |  |   Can't process response from server. Status Code: 404 Data from server: {"failed": true, "message": "Requested item not found"} 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   0   

## action: 'get headers'
Perform a REST HEAD call to the server

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location (e.g. path/to/endpoint?query=string) | string |  `endpoint` 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 
**headers** |  optional  | Additional headers (JSON object with headers) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.headers | string |  |   {"User-Agent": "automation"} 
action_result.parameter.location | string |  `endpoint`  |   /rest/cont 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.data.\*.location | string |  `url`  |   http://192.168.1.26/rest/cont 
action_result.data.\*.method | string |  |   HEAD 
action_result.data.\*.response_headers | string |  |  
action_result.summary.reason | string |  |   OK 
action_result.summary.status_code | numeric |  |   200 
action_result.message | string |  |   Status code: 200, Reason: OK 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get options'
Perform a REST OPTIONS call to the server

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location (e.g. path/to/endpoint?query=string) | string |  `endpoint` 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 
**headers** |  optional  | Additional headers (JSON object with headers) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.headers | string |  |  
action_result.parameter.location | string |  `endpoint`  |   /rest/cont 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.data.\*.location | string |  `url`  |   http://192.168.1.26/rest/cont 
action_result.data.\*.method | string |  |   OPTIONS 
action_result.data.\*.parsed_response_body | string |  |   GET,HEAD,PUT,POST,DELETE,PATCH 
action_result.data.\*.response_body | string |  |   GET,HEAD,PUT,POST,DELETE,PATCH 
action_result.data.\*.response_headers | string |  |  
action_result.summary.reason | string |  |   OK 
action_result.summary.status_code | numeric |  |   200 
action_result.message | string |  |   Status code: 200, Reason: OK 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get data'
Perform a REST GET call to the server

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location (e.g. path/to/endpoint?query=string) | string |  `endpoint` 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 
**headers** |  optional  | Additional headers (JSON object with headers) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.headers | string |  |   {"Content-Type": "application/json"} 
action_result.parameter.location | string |  `endpoint`  |   /rest/cont 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.data.\*.location | string |  `url`  |   http://192.168.1.26/rest/cont 
action_result.data.\*.method | string |  |   GET 
action_result.data.\*.parsed_response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_headers | string |  |  
action_result.summary.reason | string |  |   Not Found 
action_result.summary.status_code | numeric |  |   404 
action_result.message | string |  |   Can't process response from server. Status Code: 404 Data from server: {"failed": true, "message": "Requested item not found"} 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   0   

## action: 'post data'
Perform a REST POST call to the server

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location (e.g. path/to/endpoint) | string |  `endpoint` 
**body** |  optional  | POST body (query string, JSON, etc.) | string | 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 
**headers** |  optional  | Additional headers (JSON object with headers) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.body | string |  |   {"name": "Bad IP"} 
action_result.parameter.headers | string |  |   {"Content-Type": "application/json"} 
action_result.parameter.location | string |  `endpoint`  |   /rest/assets 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.data.\*.location | string |  `url`  |   http://192.168.1.26/rest/assets 
action_result.data.\*.method | string |  |   POST 
action_result.data.\*.parsed_response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_body | string |  |   {"failed": true, "message": "Requested item not found"} 
action_result.data.\*.response_headers | string |  |  
action_result.summary.reason | string |  |   Not Found 
action_result.summary.status_code | numeric |  |   404 
action_result.message | string |  |   Can't process response from server. Status Code: 404 Data from server: {"failed": true, "message": "Requested item not found"} 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   0   

## action: 'get file'
Retrieve a file from the endpoint and save it to the vault

Type: **investigate**  
Read only: **True**

Provide the file path and file name to download into the vault. For example, <b>/web_storage/file.tgz</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** |  optional  | Hostname to execute command on | string |  `host name` 
**file_path** |  required  | Path of the file to download (include filename) | string |  `file path` 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.file_path | string |  `file path`  |   /web_storage/file.tgz 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.parameter.hostname | string |  `host name`  |   http://192.168.0.1 
action_result.data | string |  |  
action_result.summary.exit_status | numeric |  |   0 
action_result.summary.name | string |  |   file.tgz 
action_result.summary.size | numeric |  |   412 
action_result.summary.vault_id | string |  `vault id`  |   dc871f816c4d179f3a3cea24b4bc81a67562c 
action_result.message | string |  |   Transferred file 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'put file'
Put a file from the vault to another location

Type: **generic**  
Read only: **False**

Provide the path to store the file on the file server. For example, <b>/web_storage/test_repo/</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  optional  | Hostname/IP with port number to execute command on | string |  `host name` 
**vault_id** |  required  | Vault ID of file | string |  `vault id` 
**file_destination** |  required  | File destination path (exclude filename) | string |  `file path` 
**file_name** |  optional  | Name of the file to be put on endpoint | string | 
**verify_certificate** |  optional  | Verify certificates (if using HTTPS) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.file_name | string |  |   test.txt 
action_result.parameter.file_destination | string |  `file path`  |   /web_storage/test_repo/ 
action_result.parameter.host | string |  `host name`  |   http://192.168.0.1:8001 
action_result.parameter.verify_certificate | boolean |  |   False  True 
action_result.parameter.vault_id | string |  `vault id`  |   dc871f816c4d179f3a3cea24b4bc81a67562c 
action_result.data | string |  |  
action_result.summary.file_sent | string |  `file path`  |   http://192.168.0.1:8001/web_storage/test_repo/file.tgz 
action_result.message | string |  |   File sent: http://192.168.0.1:8001/web_storage/test_repo/file.tgz 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 