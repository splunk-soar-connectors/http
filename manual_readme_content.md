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
