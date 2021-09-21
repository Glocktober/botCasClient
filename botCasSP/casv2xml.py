# copyright 2021 r.kras - see LICENSE.txt for details
import defusedxml.ElementTree as ElementTree

class   CASv2_xml:
    """
    Verify CAS v2 XML messages, extracting provided assertsions.
    """

    def __init__(self,xml):
        """ Verify and extract CAS XML v2 message. """

        self.auth_response = False
        self.prox_response = False
        self.message_success = False
        self.code = None
        self.message = ''

        self.proxy_ticket = None
        self.pgtiou = None
        self.proxy_list = []
        self.attrs = {}
        self.user = None

        self.xml = xml
        try:
            xtr = ElementTree.fromstring(xml)
        except:
            raise Exception('Failure parsing cas v2 Response')

        assert xtr.tag=='{http://www.yale.edu/tp/cas}serviceResponse', 'Not a valid CAS v2 response'
        
        ns = {'cas': 'http://www.yale.edu/tp/cas'}

        # establish what we have here.
        xauthFail = xtr.find('./cas:authenticationFailure',ns)
        xproxFail = xtr.find('./cas:proxyFailure',ns)
        xauthSucc = xtr.find('./cas:authenticationSuccess',ns)
        xproxSucc = xtr.find('./cas:proxySuccess',ns)

        if xauthFail is not None:
            self.auth_response = True
            self.message_success = False

            self.code = xauthFail.attrib['code']
            self.message = xauthFail.text.strip()

        elif xproxFail is not None:
            self.prox_response = True
            self.message_success = False

            self.code = xproxFail.attrib['code']
            self.message = xproxFail.text.strip()

        elif xproxSucc is not None:
            self.prox_response = True
            self.message_success = True
            
            xproxPGT = xproxSucc.find('./cas:proxyTicket',ns)
            self.proxy_ticket = xproxPGT.text.strip()
            
        elif xauthSucc is not None:
            self.auth_response = True
            self.message_success = True

            xusr = xauthSucc.find('./cas:user',ns)
            assert xusr is not None, 'authenticationSuccess does not include cas:user'
            self.user = xusr.text.strip()

            attrs = {}
            xattrs = xauthSucc.find('./cas:attributes',ns)
            if xattrs is not None:
                for xattr in xattrs:
                    key = xattr.tag.split('}')[1]
                    val = xattr.text and xattr.text.strip() or None
                    attrs.setdefault(key,[]).append(val)
                
                for key in attrs:
                    values = attrs[key]
                    if len(values) > 1:
                        pass
                    elif len(values) == 1:
                        attrs[key] = values[0]
                    else:
                        attrs[key] = None
            
            self.attrs = attrs
            
            xpgt = xauthSucc.find('./cas:proxyGrantingTicket',ns)
            if xpgt is not None:
                self.pgtiou = xpgt.text.strip()
            
            xproxsec = xauthSucc.find('./cas:proxies',ns)
            if xproxsec is not None:

                xproxies = xproxsec.findall('./cas:proxy',ns)
                for xproxy in xproxies:
                    self.proxy_list.append(xproxy.text.strip())

        else:
            raise Exception('Unknown cas v2 Authentication Response')

        
    def is_auth_success(self):
        """ True if this is an successful Auth message. """
        return self.auth_response and self.message_success


    def is_proxy_success(self):
        """ True if this is a successful Proxy Auth. """
        return self.prox_response and self.message_success


    def auth_failure(self):
        """ Return Auth failure code and message. """
        if self.auth_response:
            return self.code, self.message
        else:
            raise Exception('Not an authentication response')

    def prox_failure(self):
        """ Return Proxy failure code and message. """
        if self.prox_response:
            return self.code, self.message
        else:
            raise Exception('Not an proxy response')


    def get_user(self):
        """ Return the username from the response. """
        return self.user
    

    def get_pgtiou(self):
        """ Return the pgtiou form the proxy response """

        if self.is_auth_success():
            return self.pgtiou
        else:
            raise Exception('Not an authSuccess response')


    def get_proxy_ticket(self):
        """ Return the pgt from the proxy response """
        if self.is_proxy_success():
            return self.proxy_ticket
        else:
            raise Exception('Not a proxySuccess response')


    def get_attributes(self, requested_attr_list=None):
        """ Return attributes from the response """

        if self.is_auth_success():
            attrs = {}
            
            if requested_attr_list is None:
                requested_attr_list = list(self.attrs.keys())
            
            for key in requested_attr_list:
                if key in self.attrs:
                    attrs[key] = self.attrs[key]
            
            return attrs
        else:
            raise Exception('Not an authSuccess response')
