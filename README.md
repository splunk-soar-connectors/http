[comment]: # "Auto-generated SOAR connector documentation"
# HTTP

Publisher: Splunk  
Connector Version: 3\.6\.0  
Product Vendor: Generic  
Product Name: HTTP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.2\.0  

This App facilitates making HTTP requests as actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
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
**base\_url** |  required  | string | Base URL for making queries\. \(e\.g\. https\://myservice/\)
**test\_path** |  optional  | string | Endpoint for test connectivity\. \(e\.g\. /some/specific/endpoint , appended to Base URL\)
**auth\_token\_name** |  optional  | string | Type of authentication token
**auth\_token** |  optional  | password | Value of authentication token
**username** |  optional  | string | Username \(for HTTP basic auth\)
**password** |  optional  | password | Password \(for HTTP basic auth\)
**oauth\_token\_url** |  optional  | string | URL to fetch oauth token from
**placeholder** |  optional  | ph | 
**client\_id** |  optional  | string | Client ID \(for OAuth\)
**client\_secret** |  optional  | password | Client Secret \(for OAuth\)
**timeout** |  optional  | numeric | Timeout for HTTP calls
**test\_http\_method** |  optional  | string | HTTP Method for Test Connectivity

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

This action will perform a GET on the configured <b>base\_url</b>\. The action will succeed if given a status code between 200 and 399 \(inclusive\)\. Therefore, if the given base URL requires no authentication, this action may pass even if the supplied credentials are incorrect\. Alternately, if the given base URL does not point to a valid endpoint, this action could fail even if other actions may succeed with valid <b>location</b> parameters\.

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
**location** |  required  | Location \(e\.g\. path/to/endpoint?query=string\) | string |  `endpoint` 
**body** |  required  | PATCH body \(query string, JSON, etc\.\) | string | 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 
**headers** |  optional  | Additional headers \(JSON object with headers\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.body | string | 
action\_result\.parameter\.headers | string | 
action\_result\.parameter\.location | string |  `endpoint` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.data\.\*\.location | string |  `url` 
action\_result\.data\.\*\.method | string | 
action\_result\.data\.\*\.parsed\_response\_body | string | 
action\_result\.data\.\*\.response\_body | string | 
action\_result\.data\.\*\.response\_headers | string | 
action\_result\.summary\.reason | string | 
action\_result\.summary\.status\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'patch data'
Perform a REST PATCH call to the server

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location \(e\.g\. path/to/endpoint?query=string\) | string |  `endpoint` 
**body** |  optional  | PATCH body \(query string, JSON, etc\.\) | string | 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 
**headers** |  optional  | Additional headers \(JSON object with headers\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.body | string | 
action\_result\.parameter\.headers | string | 
action\_result\.parameter\.location | string |  `endpoint` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.data\.\*\.location | string |  `url` 
action\_result\.data\.\*\.method | string | 
action\_result\.data\.\*\.parsed\_response\_body | string | 
action\_result\.data\.\*\.response\_body | string | 
action\_result\.data\.\*\.response\_headers | string | 
action\_result\.summary\.reason | string | 
action\_result\.summary\.status\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete data'
Perform a REST DELETE call to the server

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location \(e\.g\. path/to/endpoint?query=string\) | string |  `endpoint` 
**body** |  optional  | DELETE body \(query string, JSON, etc\.\) | string | 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 
**headers** |  optional  | Additional headers \(JSON object with headers\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.body | string | 
action\_result\.parameter\.headers | string | 
action\_result\.parameter\.location | string |  `endpoint` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.data\.\*\.location | string |  `url` 
action\_result\.data\.\*\.method | string | 
action\_result\.data\.\*\.parsed\_response\_body | string | 
action\_result\.data\.\*\.response\_body | string | 
action\_result\.data\.\*\.response\_headers | string | 
action\_result\.summary\.reason | string | 
action\_result\.summary\.status\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get headers'
Perform a REST HEAD call to the server

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location \(e\.g\. path/to/endpoint?query=string\) | string |  `endpoint` 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 
**headers** |  optional  | Additional headers \(JSON object with headers\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.headers | string | 
action\_result\.parameter\.location | string |  `endpoint` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.data\.\*\.location | string |  `url` 
action\_result\.data\.\*\.method | string | 
action\_result\.data\.\*\.response\_headers | string | 
action\_result\.summary\.reason | string | 
action\_result\.summary\.status\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get options'
Perform a REST OPTIONS call to the server

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location \(e\.g\. path/to/endpoint?query=string\) | string |  `endpoint` 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 
**headers** |  optional  | Additional headers \(JSON object with headers\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.headers | string | 
action\_result\.parameter\.location | string |  `endpoint` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.data\.\*\.location | string |  `url` 
action\_result\.data\.\*\.method | string | 
action\_result\.data\.\*\.parsed\_response\_body | string | 
action\_result\.data\.\*\.response\_body | string | 
action\_result\.data\.\*\.response\_headers | string | 
action\_result\.summary\.reason | string | 
action\_result\.summary\.status\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get data'
Perform a REST GET call to the server

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location \(e\.g\. path/to/endpoint?query=string\) | string |  `endpoint` 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 
**headers** |  optional  | Additional headers \(JSON object with headers\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.headers | string | 
action\_result\.parameter\.location | string |  `endpoint` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.data\.\*\.location | string |  `url` 
action\_result\.data\.\*\.method | string | 
action\_result\.data\.\*\.parsed\_response\_body | string | 
action\_result\.data\.\*\.response\_body | string | 
action\_result\.data\.\*\.response\_headers | string | 
action\_result\.summary\.reason | string | 
action\_result\.summary\.status\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'post data'
Perform a REST POST call to the server

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location** |  required  | Location \(e\.g\. path/to/endpoint\) | string |  `endpoint` 
**body** |  required  | POST body \(query string, JSON, etc\.\) | string | 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 
**headers** |  optional  | Additional headers \(JSON object with headers\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.body | string | 
action\_result\.parameter\.headers | string | 
action\_result\.parameter\.location | string |  `endpoint` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.data\.\*\.location | string |  `url` 
action\_result\.data\.\*\.method | string | 
action\_result\.data\.\*\.parsed\_response\_body | string | 
action\_result\.data\.\*\.response\_body | string | 
action\_result\.data\.\*\.response\_headers | string | 
action\_result\.summary\.reason | string | 
action\_result\.summary\.status\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Retrieve a file from the endpoint and save it to the vault

Type: **investigate**  
Read only: **True**

Provide the file path and file name to download into the vault\. For example, <b>/web\_storage/file\.tgz</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** |  optional  | Hostname to execute command on | string |  `host name` 
**file\_path** |  required  | Path of the file to download \(include filename\) | string |  `file path` 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_path | string |  `file path` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.data | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.summary\.name | string | 
action\_result\.summary\.size | numeric | 
action\_result\.summary\.vault\_id | string |  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'put file'
Put a file from the vault to another location

Type: **generic**  
Read only: **False**

Provide the path to store the file on the file server\. For example, <b>/web\_storage/test\_repo/</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  optional  | Hostname/IP with port number to execute command on | string |  `host name` 
**vault\_id** |  required  | Vault ID of file | string |  `vault id` 
**file\_destination** |  required  | File destination path \(exclude filename\) | string |  `file path` 
**file\_name** |  optional  | Name of the file to be put on endpoint | string | 
**verify\_certificate** |  optional  | Verify certificates \(if using HTTPS\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_name | string | 
action\_result\.parameter\.file\_destination | string |  `file path` 
action\_result\.parameter\.host | string |  `host name` 
action\_result\.parameter\.verify\_certificate | boolean | 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data | string | 
action\_result\.summary\.file\_sent | string |  `file path` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 