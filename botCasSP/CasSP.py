# copyright 2021 r.kras - see LICENSE.txt for details
import sys
import time
from urllib.parse import quote, urlencode

import requests as req

from bottle import response, request

from .casv2xml import CASv2_xml
from .casv3xml import CASv3_xml

CASC_NEXT = '_CASC_NEXT'
CASC_PGTURL = '_CASC_PGTURL'

class _Logger:      # In lieu of being passed a logger
    """ Logger proxy to stderr """

    def info(self, *args, **kwargs):
        """ logger.info() """
        print('INFO', file=sys.stderr,  *args, **kwargs)


class CasSP:
    """ 
    CAS Service Provider (CAS client) for Bottle 
    """
    def __init__(self,
                    app=None,
                    config={},
                    sess_username='username',
                    sess_attr='attributes',
                    logger=None,
                    db = None,
                    **kwargs
                ):
        """
        Create a CAS client.
        """
        self.server_url = config['cas_server_base_url']

        self.sslverify = config.get('ssl_verify', True)
        self.cas_version = config.get('cas_version', 'v2')
        self.attr_list = config.get('cas_attr_list', [])
        self.proxy_api = config.get('cas_proxy', False) and db 

        self.login_url = self.server_url + '/login'
        self.logout_url = self.server_url + '/logout'
        self.proxy_url = self.server_url + '/proxy'

        self.reqtimeout = 8

        if self.cas_version == 'v1':
            self.validate_url = self.server_url + '/validate'
            self.validate_ticket = self.v1_validate_ticket

        elif self.cas_version == 'v2':
            self.validate_url = self.server_url + '/proxyValidate'
            self.validate_ticket = self.v2_validate_ticket
        
        elif self.cas_version == 'v3':
            self.validate_url = self.server_url + '/samlValidate'
            self.validate_ticket = self.v3_validate_ticket

        else:
            raise Exception(
                f'Unsupported cas version "{self.cas_version}" requested')

        self.sess_username = sess_username
        self.sess_attrs = sess_attr

        self.login_hooks = []
        self.authenticator = config.get('authenticator', 'CASC')

        self.app = app
        if logger is None: logger = _Logger()
        self.logger = logger

        # Only required route for ticket delivery and validation
        app.route('/casc/ticketed', name="ticketed", callback=self._finish_login, authn=False)

        if config.get('login_routes', False):
            app.route('/casc/login', name="login", callback=self.initiate_login)
            app.route('/casc/logout', name="logout", callback=self.initiate_logout)

        if self.proxy_api:
            self.sess_pgt = kwargs.get('sess_pgt', 'sess_pgt')
            self.db = db
            app.route('/casc/pgturl', name='pgturl', callback=self.pgt_map, authn=False)


    @property
    def is_authenticated(self):
        """ True if user has authenticated. """

        if self.sess_username in request.session and request.session[self.sess_username]:
            return True
        return False


    @property
    def my_username(self):
        """ Return username for the current session. """

        return request.session[self.sess_username] if self.is_authenticated else None


    @property
    def my_attrs(self):
        """ Return collected assertions for the current session. """

        return request.session[self.sess_attrs] if self.is_authenticated else {}


    def add_login_hook(self, f):
        """ Decorator for adding logout hook. """

        self.login_hooks.append(f)
        return f


    def require_login(self, f):
        """ Decorator for forcing authenticated path. """

        def _wrapper(*args, **kwargs):

            if self.is_authenticated:
                return f(*args, **kwargs)

            return self.initiate_login(next=request.url)

        _wrapper.__name__ = f.__name__
        return _wrapper


    # required route: /casc/ticketed
    def _finish_login(self):
        """ Come here with a ticket. """
        
        ticket = request.query.get('ticket', None)
        resource = request.query.get('resource', None)
        service = resource or request.url.split('?')[0]
        
        if self.proxy_api and self.sess_pgt not in request.session:
            pgturl = self.app.get_url('pgturl', _external=True)
        else:
            pgturl = None

        if ticket:
            if self.validate_ticket(ticket, service, pgturl=pgturl):
                
                url = request.session.pop(CASC_NEXT, None)
                if url:
                    return self.redirect(url)
                elif resource:
                    return prepare_response( f'Resource "{resource}": proxy access granted')
                else:
                    return prepare_response(f'User "{self.my_username}" logged in')
            else:
                # ticket validation failed
                return prepare_response('Validation failed', status=403)
        else:
            return prepare_response('No ticket', status=400)


    # optional route: /casc/pgturl - proxy callback
    def pgt_map(self):
        """ pgtUrl callback. """

        pgtiou = request.query.get('pgtIou')
        pgt = request.query.get('pgtId')
        self.db.set('MAP:' + pgtiou, pgt, 10)

        self.logger.info(f'CASC: recieved pgtIou {pgtiou} for pgt {pgt}')
        return prepare_response('ok')


    # API or optinal route: /casc/login
    def initiate_login(self, next=None, **kwargs):
        """ Initiate CAS login. """

        # if not next:
        #     next = request.url
        if next:
            request.session[CASC_NEXT] = next

        params = {'service': self.get_full_url('ticketed')}

        url = self.login_url + '?' + urlencode(params, doseq=True)
        
        return self.redirect(url)


    # API or optional route: /casc/logout
    def initiate_logout(self, next=None):
        """ Logout client. """

        if self.is_authenticated:
            user = self.my_username
        else:
            user = 'Anonymous'

        request.session.session_delete()

        self.logger.info(f'CASC: Logout user "{user}"')

        url = self.logout_url
        if next:
            url = url + '?service=' + quote(next)

        return self.redirect(url)


    def get_proxy_session(self, service, resource_urn=None):
        """ Return a Requests Session object for service. """

        proxy_ticket = self.acquire_proxy_ticket(resource_urn or service)

        s = req.Session()

        params = {'ticket', proxy_ticket}
        if resource_urn:
            params['resource'] = resource_urn

        s.get(service, params=params, verify=self.sslverify)

        return s if s.ok else None


    def acquire_proxy_ticket(self, service):
        """ Acquire a proxy ticket for a service. """

        if not self.proxy_api:
            raise Exception('CASC: Proxy API is not enabled in this configuration')

        if self.sess_pgt not in request.session:
            raise Exception('CASC: No Proxy Granting Ticket')

        params = {
            'pgt': request.session[self.sess_pgt],
            'targetService': service,
        }
        r = req.get(self.proxy_url, params=params, verify=self.sslverify)

        if r.ok:
            try:
                xml = CASv2_xml(r.text)
                return xml.get_proxy_ticket()

            except Exception as e:
                msg = f'CASC: Failed to obtain proxy ticket: {str(e)}'
                self.logger.info(msg)
                raise Exception(msg)
        else:
            msg = f'CASC: Error obtaining proxy ticket HTTP code {r.status}'
            self.logger.info(msg)
            raise Exception(msg)


    def v1_validate_ticket(self, ticket, service, **kwargs):
        """ Back-channel CASv1 service ticket validation. """

        url = self.validate_url
        params = {
            'service': service,
            'ticket': ticket,
        }

        try:
            resp = req.get(url, params=params,
                           timeout=self.reqtimeout, verify=self.sslverify)

            if resp.status_code == req.codes.ok:
                validate_resp = resp.text.split('\n')

                if len(validate_resp) >= 2 and validate_resp[0] == 'yes':
                    usr = validate_resp[1]

                    self.logger.info(
                        f'CASC: v1 User "{usr}" authenticated with ticket {ticket}')

                    return self.run_authorizors(usr=usr, attrs={})

                else:
                    self.logger.info(f'CASC: v1 service validate failed for {ticket}')

            else:
                msg = f'CASC: v1 validate failure "{resp.status_code}" HTML error'
                self.logger.info(msg)
                raise Exception(msg)

        except Exception as e:
            self.logger.info(
                f'CASC: v1 network error validating {ticket}')
            self.logger.info('CASC ' + str(e))

        return False


    def v2_validate_ticket(self, ticket, service, pgturl=None):
        """ Back-channel CASv2 service ticket validation. """

        params = {
            'service': service,
            'ticket': ticket,
        }
        if pgturl:
            params['pgtUrl'] = pgturl

        try:
            resp = req.get(self.validate_url, params=params,
                           timeout=self.reqtimeout, verify=self.sslverify)

            if resp.status_code == req.codes.ok:
                xml = CASv2_xml(resp.text)

                if xml.is_auth_success():
                    # Auth success

                    user = xml.get_user()
                    pgtiou = xml.get_pgtiou()

                    if pgtiou:
                        key = 'MAP:' + pgtiou
                        pgt = self.db.get(key)
                        if pgt:
                            self.db.delete(key)

                            pgt = pgt.decode('utf-8')
                            request.session[self.sess_pgt] = pgt

                            self.logger.info(
                                f'CASC: "{user}" Obtained {pgt}')
                        else:
                            self.logger.info(
                                f'CASC: "{user}" could not recover pgt for "{pgtiou}"')

                    if user:
                        attrs = xml.get_attributes(self.attr_list)

                        self.logger.info(
                            f'CASC: User "{user}" v2 validated with ticket {ticket}')

                        return self.run_authorizors(usr=user, attrs=attrs)
                    else:
                        self.logger.info('CASC: parse error on get_user')

                else:
                    (failure_code, failure_message) = xml.auth_failure()
                    if failure_code and failure_message:
                        self.logger.info(
                            f'CASC: v2 service validate failure: "{failure_code}" {failure_message}')
                    else:
                        self.logger.info('CASC: parse error on auth_failure')
            else:
                msg = f'CASC: v2 service validate failure "{resp.status_code}" HTTP error'
                self.logger.info(msg)
                raise Exception(msg)

        except Exception as e:
            self.logger.info(f'CASC: v2 protocol error validating {ticket}')
            raise e
            self.logger.info( str(e))

        self.logger.info(f'CASC: v2 service validate for {ticket} FAILED')
        return False


    def v3_validate_ticket(self, ticket, service, **kwargs):
        """ Back-channel CASv3 samlValidate ticket validation. """

        saml_request = CASv3_xml.build_samlValidate_request(ticket)

        r = req.post(self.validate_url, params={'TARGET': service},
            data=saml_request, headers={'Content-Type': 'text/xml'}, verify=self.sslverify)
        
        if r.status_code == req.codes.ok:
            try:
                xml = CASv3_xml(r.text)
                xml.meets_conditions(audience=service)
                
                user = xml.get_user()
                attrs = xml.get_attributes(self.attr_list)

                self.logger.info(
                        f'CASC User "{user}" v3 samlValidated with ticket {ticket}')

                return self.run_authorizors(usr=user, attrs=attrs)

            except Exception as e:
                ### raise e
                self.logger.info(f'CAS samlValidate error: {str(e)}')

        else:
            msg = f'CASC v3 samlValidate failure "{r.status_code}" HTTP error'
            self.logger.info(msg)
        
        return False


    def run_authorizors(self, usr, attrs={}):
        """ Run all login hooks and authenticate session. """

        try:
            for hook in self.login_hooks:
                usr, attrs = hook(usr, attrs)

            # User is authorized.
            request.session[self.sess_attrs] = attrs
            request.session[self.sess_username] = usr
            request.session[self.sess_attrs][self.sess_username] = usr

            self.logger.info(f'CASC: User "{usr}" authorized.')
            return True

        except Exception as e:
            # Authorization failed.
            self.logger.info(f'CASC: User "{usr}" failed authorization.')
            self.logger.info('CASC: ' + str(e))
            return False


    def redirect(self, url):
        """ Set response as 302 redirect """

        response.set_header('Location', url)  
        return prepare_response('', status=302)


    def get_full_url(self, name):
        """ Return Full URL for route """

        path = self.app.get_url(name)
        base = request.url.split(request.fullpath)[0]
        return base+path

#
# Wrappers for protecting flask routes
#
    def require_user(self, user_list):
        """ Decorator passes on specific list of usernames. """

        def _outer_wrapper(f):

            def _wrapper(*args, **kwargs):
                if self.my_username in user_list:
                    return f(*args, **kwargs)

                return prepare_response('Not Authorized', 403)

            _wrapper.__name__ = f.__name__
            return _wrapper

        return _outer_wrapper


    def require_attribute(self, attr, value):
        """ Decorator requires specific attribute value. """

        def test_attrs(challenge, standard):
            """Compare list or val the standard."""

            stand_list = standard if type(standard) is list else [standard]
            chal_list = challenge if type(challenge) is list else [challenge]

            for chal in chal_list:
                if chal in stand_list:
                    return True
            return False

        def _outer_wrapper(f):

            def _wrapper(*args, **kwargs):

                if attr in self.my_attrs:
                    resource = request.session[self.sess_attrs][attr]

                    if test_attrs(resource, value):
                        return f(*args, **kwargs)

                return  prepare_response('Not Authorized', 403)

            _wrapper.__name__ = f.__name__
            return _wrapper

        return _outer_wrapper


def prepare_response(body='', status=200):
    """ Set headers in response. """
    
    response.status = status
    response.headers.update({
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Expires': 'Sun, 25 Jul 2021 15:42:14 GMT'
    })
    return body
