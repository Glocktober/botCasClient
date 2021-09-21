# copyright 2021 r.kras - see LICENSE.txt for details
import datetime
import os
import time
from secrets import token_urlsafe

import defusedxml.ElementTree as ElementTree
from bottle import jinja2_template, TEMPLATE_PATH

TIMEFMTFRAC = '%Y-%m-%dT%H:%M:%S.%f%z'
TIMEFMT = '%Y-%m-%dT%H:%M:%S%z'
SLOP_TIME = 30      # seconds of slop for 'not before' for time skew
MAX_AGE = 1*60*60   # the oldest we consider IssueInstance valid

# add our view directory to the template path
base_dir = os.path.dirname(__file__)
TEMPLATE_PATH.insert(0, os.path.relpath(os.path.join(base_dir, 'views')))

# Format the current time in ISO Fractional format for SAML use
utc_now_saml = lambda : datetime.datetime.strftime(datetime.datetime.utcnow(),TIMEFMTFRAC) + 'Z'
# Create a random request id
new_request_id = lambda : '_id' + token_urlsafe(12)

def getsamltime(tstring):
    """ Return Unix time for ISO string. """

    format = TIMEFMTFRAC if '.' in tstring else TIMEFMT
    return datetime.datetime.strptime(tstring,format).timestamp()


class   CASv3_xml:
    """
    Verify CAS v3 (SAML1.1) message
    """

    def __init__(self, xml):
        """ verify and extract CAS SAML1.1 message """

        self.max_age = 2*60*60
        self.authen_nameid = None
        self.attrs = None
        ##print(xml)
        self.tree = ElementTree.fromstring(xml)

        self.ns = {
            'saml1': 'urn:oasis:names:tc:SAML:1.0:assertion', 
            'soap': 'http://schemas.xmlsoap.org/soap/envelope/', 
            'samlp': 'urn:oasis:names:tc:SAML:1.0:protocol'
        }

        xresp = self.tree.find('./soap:Body/samlp:Response',self.ns)
        assert xresp, 'Could not find xml Response'

        self.xresponse  = xresp

        self.response_issue_instant = getsamltime(xresp.attrib['IssueInstant'])
        
        major_version = xresp.attrib['MajorVersion']
        minor_version = xresp.attrib['MinorVersion']

        self.response_version = f'{major_version}.{minor_version}'

        self.response_id = xresp.attrib['ResponseID']

        xstatuscode = self.tree.find('./soap:Body/samlp:Response/samlp:Status/samlp:StatusCode',self.ns)

        self.status_code = xstatuscode.attrib['Value']
        self.is_success = self.status_code == 'samlp:Success'

        if self.is_success:
            status_message = 'Success'
        
            # Successful messages include Assertion stanza
            xassert = self.xresponse.find('./saml1:Assertion', self.ns)
            assert xassert, 'check_assertion: assertion does not exist'

            major_version = xassert.attrib['MajorVersion']
            minor_version = xassert.attrib['MinorVersion']

            self.assertion_version = f'{major_version}.{minor_version}'
            
            self.assertion_issue_instance = getsamltime(xassert.attrib['IssueInstant'])

            xconditions = xassert.find('./saml1:Conditions',self.ns)
            self.condition_not_before = getsamltime(xconditions.attrib['NotBefore'])
            self.condition_not_after = getsamltime(xconditions.attrib['NotOnOrAfter'])

            xaudience = xconditions.find('./saml1:AudienceRestrictionCondition/saml1:Audience',self.ns)
            
            self.condition_audience = xaudience.text.strip()
            
            xauthen = xassert.find('./saml1:AuthenticationStatement', self.ns)

            self.authn_instant = getsamltime(xauthen.attrib['AuthenticationInstant'])
            self.authn_method = xauthen.attrib['AuthenticationMethod']

            xnameid = xauthen.find('./saml1:Subject/saml1:NameIdentifier', self.ns)
            self.authen_nameid = xnameid.text.strip()
            
            # Gather attribute section:
            self.attrs = self._build_attributes()
        else:
            # This is NOT a Success response... gather details

            # This may or may not exist - was definitely in early versions
            xstatusmessage = self.tree.find('./soap:Body/samlp:Response/samlp:Status/samlp:StatusMessage',self.ns)

            if xstatusmessage is not None and xstatusmessage.text.strip():
                error_message = xstatusmessage.text.strip()
            else:
                error_message = 'Unspecified error'
        
            raise Exception(f'{self.status_code} : {error_message}')

        self.status_message = status_message
    

    def get_attributes(self, requested_attr_list=None):
        """ Return a dictionary of the selected (or all) attributes from the response """
        
        attrs = {}

        all_keys = list(self.attrs.keys())
        if requested_attr_list is None:
            requested_attr_list = all_keys

        for key in requested_attr_list:
            if key in all_keys:
                attrs[key] = self.attrs[key]
        
        return attrs
    

    def meets_conditions(self, audience):
        """ Lint-pick the XML Response. """
        
        t = time.time()

        assert self.response_version == '1.1', 'Response version error: SAML 1.1 Required'
        assert t + SLOP_TIME > self.response_issue_instant, 'Response IssueInstant in Future'
        assert t + self.max_age > self.response_issue_instant, 'Response IssueInstant too Old'

        assert self.assertion_version == '1.1', 'Assertion version 1.1 Required'
        assert t + SLOP_TIME > self.assertion_issue_instance, 'Assertion IssueInstant in Future' 
        assert t + self.max_age > self.assertion_issue_instance, 'Assertion IssueInstant too old'

        assert t + SLOP_TIME > self.condition_not_before, 'Condition Failed - NotBefore in future'
        assert t < self.condition_not_after, 'Condition Failed - NotOnOrAfter in past'
        assert self.condition_audience == audience, f'Condition Failed - Incorrect Audience'

        assert self.authen_nameid, 'AuthenticationStatement - NameIdentifier missing'

        assert self.is_success, 'Unsuccessful Response'

        return True


    def is_auth_success(self):
        """ True if this is a success Auth response """
        return self.is_success


    def get_user(self):
        """ Return the username (nameid) from the response """
        return self.authen_nameid


    def _build_attributes(self):
        """ Build a Dictionary of Provided Attributes. """

        all_attrs = {}
        xattrs = self.xresponse.findall('./saml1:Assertion/saml1:AttributeStatement/saml1:Attribute', self.ns)
        
        for xattr in xattrs:
            key = xattr.attrib['AttributeName']
            xvals = xattr.findall('./saml1:AttributeValue',self.ns)

            all_vals = []
            for xval in xvals:
                all_vals.append(xval.text.strip())

            all_attrs[key] = all_vals
        
        for key in all_attrs:

            values = all_attrs[key]
                
            if len(values)>1:
                # multiple values
                all_attrs[key] = values
            elif len(values)==1:
                # single value
                all_attrs[key] = values[0]
            else:
                # none found
                all_attrs[key] = None

        
        return all_attrs


    @staticmethod
    def build_samlValidate_request(ticket):
        """ Return XML samlValidate Request. """
        # quicker to build this with a template
        return jinja2_template('v3_cas_saml_request.xml',
            request_id = new_request_id(),
            issue_instant = utc_now_saml(),
            ticket = ticket,
        )

