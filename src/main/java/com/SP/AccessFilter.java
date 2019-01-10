package com.SP;

import com.OpenSAMLUtils;
import com.com.IDP.IDPConstants;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Name;
import javax.persistence.criteria.CriteriaBuilder;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.ws.Endpoint;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;

/*
 * The filter intercepts the user and start the SAML authentication if it is not authenticated
 */
public class AccessFilter implements Filter{
    private static Logger logger = LoggerFactory.getLogger(AccessFilter.class);

    public void init(FilterConfig filterConfig) throws ServletException
    {
        JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
        try{
            javaCryptoValidationInitializer.init();
        }catch (InitializationException e)
        {
            e.printStackTrace();
        }

        for(Provider jceProvider: Security.getProviders()){
            logger.info(jceProvider.getInfo());
        }

        try{
            logger.info("Initializing");
            InitializationService.initialize();
        }catch (InitializationException e)
        {
            throw new RuntimeException("Initialization failed");
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException,ServletException
    {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        if(httpServletRequest.getSession().getAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE) != null){
            chain.doFilter(request,response);
        }else
        {
            setGotoURLOnSession(httpServletRequest);
            redirectUserForAuthentication(httpServletResponse);
        }
    }

    private void setGotoURLOnSession(HttpServletRequest httpServletRequest)
    {
        httpServletRequest.getSession().setAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE,
                httpServletRequest.getRequestURL().toString());
    }

    private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
        AuthnRequest authnRequest = buildAuthenRequest();
        redirectUserWithRequest(httpServletResponse,authnRequest);
    }

    private AuthnRequest buildAuthenRequest()
    {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(getIPDSSODestination());
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
        authnRequest.setIssuer(buildIssuer());
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
        return authnRequest;
    }

    private RequestedAuthnContext buildRequestedAuthnContext()
    {
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
        AuthnContextClassRef passwordAuthContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthContextClassRef);
        return requestedAuthnContext;
    }

    private NameIDPolicy buildNameIdPolicy()
    {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.TRANSIENT);
        return nameIDPolicy;
    }

    private Issuer buildIssuer()
    {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuerValue());
        return issuer;
    }

    private String getSPIssuerValue()
    {
        return SPConstants.SP_ENTITY_ID;
    }

    private String getIPDSSODestination()
    {
        return IDPConstants.SSO_SERVICE;
    }

    private String getAssertionConsumerEndpoint()
    {
        return SPConstants.ASSERTION_CONSUMER_SERVICE;
    }

    private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {
        MessageContext context = new MessageContext();
        context.setMessage(authnRequest);
        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class,true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class,true);
        endpointContext.setEndpoint(getIDPEndpoint());

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(httpServletResponse);

        try
        {
            encoder.initialize();
        }catch(ComponentInitializationException e)
        {
            throw new RuntimeException(e);
        }

        try
        {
            encoder.encode();
        }
        catch (MessageEncodingException e)
        {
            throw new RuntimeException(e);
        }

    }

    private SingleSignOnService getIDPEndpoint()
    {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation((getIPDSSODestination()));
        return endpoint;
    }

    public void destroy()
    {

    }

}
