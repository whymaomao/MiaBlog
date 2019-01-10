package com.SP;

import com.OpenSAMLUtils;
import com.com.IDP.IDPConstants;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.messaging.pipeline.BasicMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.saml1.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.SecurityException;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


@Controller
public class ConsumerServlet {

    private static Logger logger = LoggerFactory.getLogger(ConsumerServlet.class);

    @RequestMapping(path="/sp/consumer")
    void SpConsumer(HttpServletRequest request,HttpServletResponse response)
    {
        logger.info("Artifact received");
        Artifact artifact = buildArtifactFromRequest(request);
        logger.info("Artifact: " + artifact.getArtifact());

        ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
        logger.info("Sending ArtifactResolve");

        ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve, response);
        logger.info("ArtifactResponse received");

        validateDestinationAndLifeTime(artifactResponse,request);
        Assertion assertion = getAssertion(artifactResponse);

        //to-do: log the attributes of the assertion

        setAuthenticatedSession(request);
        redirectToGotoURL(request,response);

    }

    private void redirectToGotoURL(HttpServletRequest request, HttpServletResponse response)
    {
        String gotoURL = (String) request.getSession().getAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE);
        logger.info("Redirecting to requested URL: " + gotoURL);

        try
        {
            response.sendRedirect(gotoURL);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    private void setAuthenticatedSession(HttpServletRequest request) {
        request.getSession().setAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE,true);
    }


    private Assertion getAssertion(ArtifactResponse artifactResponse) {
        Response response = (Response)artifactResponse.getMessage();
        return response.getAssertions().get(0);
    }

    private void validateDestinationAndLifeTime(ArtifactResponse artifactResponse, HttpServletRequest request) {
        MessageContext context = new MessageContext<ArtifactResponse>();
        context.setMessage(artifactResponse);

        SAMLMessageInfoContext messageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class, true);
        messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());

        MessageLifetimeSecurityHandler lifetimeSecurityHandler = new MessageLifetimeSecurityHandler();
        lifetimeSecurityHandler.setClockSkew(1000);
        lifetimeSecurityHandler.setMessageLifetime(2000);
        lifetimeSecurityHandler.setRequiredRule(true);

        ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler = new ReceivedEndpointSecurityHandler();
        receivedEndpointSecurityHandler.setHttpServletRequest(request);

        List handlers = new ArrayList<MessageHandler>();
        handlers.add(lifetimeSecurityHandler);
        handlers.add(receivedEndpointSecurityHandler);

        BasicMessageHandlerChain<ArtifactResponse> handlerChain = new BasicMessageHandlerChain<ArtifactResponse>();
        handlerChain.setHandlers(handlers);

        try{
            handlerChain.initialize();
            handlerChain.doInvoke(context);
        } catch (MessageHandlerException e) {
            e.printStackTrace();
        } catch (ComponentInitializationException e) {
            e.printStackTrace();
        }

    }

    private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve, HttpServletResponse response)
    {
        try
        {
            MessageContext<ArtifactResolve> contextout = new MessageContext<ArtifactResolve>();

            contextout.setMessage(artifactResolve);

            InOutOperationContext<ArtifactResponse, ArtifactResolve> context = new ProfileRequestContext<ArtifactResponse, ArtifactResolve>();
            context.setOutboundMessageContext(contextout);

            //sending SOAP messages
            AbstractPipelineHttpSOAPClient<SAMLObject,SAMLObject> soapClient = new AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject>() {
                @Nonnull
                @Override
                protected HttpClientMessagePipeline<SAMLObject, SAMLObject> newPipeline() throws SOAPException {
                    //creating encoder and decoder of inoutput
                    HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
                    HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();

                    //creating pipeline
                    HttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(encoder,decoder);
                    return pipeline;
                }
            };

            HttpClientBuilder clientBuilder = new HttpClientBuilder();
            soapClient.setHttpClient(clientBuilder.buildClient());
            soapClient.send(IDPConstants.ARTIFACT_RESOLUTION_SERVICE,context);
            return context.getInboundMessageContext().getMessage();
        } catch (SOAPException e) {
            e.printStackTrace();
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private ArtifactResolve buildArtifactResolve(final Artifact artifact)
    {
        ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(SPConstants.SP_ENTITY_ID);
        artifactResolve.setIssuer(issuer);

        //Time of the request
        artifactResolve.setIssueInstant(new DateTime());
        artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());
        artifactResolve.setDestination(IDPConstants.ARTIFACT_RESOLUTION_SERVICE);

        artifactResolve.setArtifact(artifact);
        return artifactResolve;
    }

    private Artifact buildArtifactFromRequest(final HttpServletRequest request)
    {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact(request.getParameter("SAMLart"));
        return artifact;
    }

}
