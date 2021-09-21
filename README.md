## botCasSP - A CAS Client for Bottle Web Apps

### Description
**botCasSP** is a [CAS (Central Authentication Service)]() client module for [Bottle web framework]() applications.  The **CasSP** instance allows bottle apps to be CAS Service Providers (SP's), authenticating users to a CAS server, and use any assertions the CAS server provides within the client session.

**CAS** is a [legacy single sign-on (SSO) protocol](), still in not uncommon use, especially in academia. CAS uses back channel verification and is simple to add to applications.

### botCasSP Getting started

```python
from botCasSP import CasSP
from BottleSession import BottleSession
from bottle import Bottle

from config import sess_config, cas_config
app = Bottle()
ses = BottleSession(*sess_config)
cas_config ={
  'cas_server_base_url': 'https://cas.example.com/cas/',
  'cas_attr_list' : ['sn', 'givenName', 'uid', 'groups']

}
casc = CasSP(app=app, config=cas_config)

@app.route('/login')
@casc.require_login
def hello():
    return f'Hello {request.session['username']}'

@app.route('/bobAndAlice')
@casc.require_user(['bob','alice'])
def only():
    return 'Hello bob or alice'

@app.route('/sysadmins')
@casc.require_attr('groups': ['sysadmin', 'netadmin'])
def admins():
    return "Hello admin"

@app.route('/logoff')
def bye():
    if casc.is_authenticated:
        casc.initiate_logoff(next=request.url)
    return 'bye'

if __name__ == '__main__':
    app.run()
```
**botCasSP** uses [BottleSessions]() for session management. Install **BottleSessions** before **CasSP**. (BottleSessions is based on **Pallets project** *cachelib*, providing numerous caching back-ends including filesystem, redis, and memcached back-ends.)

At the minimum (cas v1) the CAS server will just authenticate the user. Most v1 and all v2/v3 servers provide the username. With **botCasSP** this can be accessed as `request.session.get('username')` or `casc.my_username`. 

Other Information provided with CAS v2/v3 server authentication is matched against the `cas_attr_list` in the configuration. Attributes with matching names are added to the users session. This is `['sn', 'givenName', 'uid', 'groups']` in the example. If the CAS servers provides these attributes, they are included in the users session and are accessible in a `dict` as `request.session['attributes']` or `casc.my_attrs`. 

The `username` and `attributes` data are available both to views and to any middleware installed in the request stack after *BottleSessions*.  This data can be used by Bottle apps to pre-populate forms, used for identifcation to other systems, etc.

### botCasSP CasSP Class
**botCasSP** is the module, **CasSP** is the class implementing *CAS Service Provider* function.
#### CasSP Class Signature:
```python
from botCasSP import CasSP

casc = CasSP(app=app, 
        config=cas_config, 
        sess_username='username', 
        sess_attr='attributes', logger=None, 
        )
```
#### CasSP Parameters and Configuration:
**app:**
* **Required:** the Bottle app instance

**sess_username='username':**
* **Optional:** Name of the session entry to contain username (default: `username` as in `session['username']`) It's unlikely this needs to be changed.

**sess_attr='attributes':**
* **Optional:** Name of the session entry to contain assertion attributes (default: `attributes` as in `session['attributes']['email']`)  It's unlikely this needs to be changed.

**config={}:**
* **Required:** A Python `dict` of CAS configuration parameters. The most important is the base url and the attribute list:

  * **`cas_server_base_url`** : API base URL of the CAS server **(required)** Typically this is in the form of https://cas.example.org/cas/. CasSP builds out the remainder of the server API from the base url.

  * **`cas_version`** : CAS protocol version: `v1`, `v2`, or `v3` (default: `v2`) There isn't much benefit to v3, and v1 generally only provides the username.

  * **`cas_attr_list`** : Python `list` of attributes. These are the assertions from a v2 or v3 server to be kept in a users session from a successful CAS validation response.
    * *e.g.* ['email', 'sn', 'givenname', 'groups']
    * It's up to the CAS server to provide parameters.
    * *default* is [ ]
  > Example cas_config
    ```python
    cas_config = {
        "cas_server_base_url": "https://cas.example.com/cas",
        "cas_attr_list" : ["sn", "given", "email","groups", "dept"]
    }
    ```

**logger=None:**
* **Optional:** Python `logger` object. CasSP defaults logging to `stderr` if no logger is provided.


#### Properties:

**`casc.is_authenticated`** : `True` if the current session is authenticated.
**`casc.my_username`** Returns username or `None` if not authenticated.
**`casc.my_attrs`** Returns `dict` of retrieved attrs or {} if not authenticated.

#### Methods:

##### Login management
**`casc.initiate_login(next,**kwargs) => redirect`**
* Returns SAML (302) redirect to the CAS server to authenticate via username/password or SSO.
* `next=None` - URL to redirect after login completed (optional)
* Use this in your login view, or decorate with `@casc.require_login` - it does the same thing.

**`casc.initiate_logout(next) => redirect | str`**
* Initiate Logout from iDP by redirecting to the CAS servers logout.
* `next=None` - URL to redirect after logout completed (optional) Some CAS servers ignore this.

**`casc._finish_login() => Response | str`**
  * **route:** *`/casc/finish`*
  * Standard service ticket endpoint from `casc.initiate_login()`
  * Validates the ticket and runs login hooks
  * Construct user session data from validation response.
  * redirects user to route that triggered the login.

##### Login Hooks Decorator

**`@casc.add_login_hook`** or
**`casc.add_login_hook(f)`**
  * Decorates a function `f` that runs after SAML authentication is completed
  * each login hook is run in order of additon
  * data can be updated before being added to the session with login_hooks
```python
@casc.add_login_hook
def my_login_hook(username, attributes):
    
    # massage or transform attributes
    username = username.tolower()
    
    # standaradize naming
    attributes['surname'] = attributes['sn']
    del attributes['sn']
    
    # supplement data from other sources
    attributes['graph'] = get_graph_data_api(username)
    
    # raise exception to thwart login 
    if attributes['affiliation'] != 'employee': 
        raise Exception('Employees only')
    
    # return both username and attributes for the next hook to use.
    return username, attributes
```
##### View Decorators
**`@casc.login_required`** or
**`casc.login_required(f)`**
  * route decorator
  * Decorates a view function `f` to require unauthenticated users to login.
  * After authentication the user is redirected to the view that initaited the login.
  * Order after @app.route decorators:
```python
@app.route('/login')
@casc.login_required
def myview():
    return 'All logged in!'
```

**`@casc.require_user(user_or_list)`** or
**`casc.require_user(f, user_or_list)`**
  * Decorates a function `f` to require session user to be listed
  * a single user or a list of users can be provided
  * Returns *403 Unauthorized* if session username is not in the list
  * Order after @app.route decorators:
```python
@app.route('/onlybob')
@casc.require_user('bob')
def view():
    return 'Hi bob'

@app.route('/boboralice')
@casc.require_user(['bob', 'alice'])
def view2():
    return 'Hi alice or bob'
```
**`@casc.require_attr(attr, value)`** or
**`casc.require_user(f, attr, value)`**
  * Decorates a function `f` to require session to have attr with value listed
  * a single attribute value or a list of values can be provided
  * Returns *403 Unauthorized* if session does not have the required attr/value.
  * Order after @app.route decorators:
```python
@app.route('/dbstuff')
@casc.require_attr('role', 'dba')
def dba_view():
    ...

@app.route('/infrastructure')
@casc.require_attr('groups', ['sysadmin', 'netadmin','storageadmin', 'cloudadmin'])
def infra_view():
    ...
```
##### Proxy Mode Methods 
These are helpers for assembling a CAS proxy service, allowing an SP to request resources from another CAS server on a users behalf. 

**`casc.get_proxy_session(service, resource_urn)`**
  * Acquire and authorize a proxy ticket for `resource_urn` via `service`
  * Returns a [Python Requests]() `Session` object or `None` for application use.
  * **Requests** `Session` object will have any of the service cookies for the `resource_urn`
  * `resource_urn` is optional (will use service)

**`casc.acquire_proxy_ticket(service)`**
  * Returns Proxy Ticket for a `service`
  * `proxy_api` mode only.

**`casc.service_proxy()`**
  * **route:**  *`/casc/proxy`* 
  * Available only in `proxy_api` mode.
  * Returns redirect for service with attached proxy_ticket
  * route front end for `casc.acquire_proxy_ticket`
