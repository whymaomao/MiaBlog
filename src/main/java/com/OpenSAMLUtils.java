package com;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.Element;
import javax.xml.namespace.QName;

public class OpenSAMLUtils {
    private static Logger logger = LoggerFactory.getLogger(OpenSAMLUtils.class);
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

    static{
        secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
    }

    public static String generateSecureRandomId(){
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static<T> T buildSAMLObject(final Class<T> tClass)
    {
        T object = null;
        try
        {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName)tClass.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        }catch (IllegalAccessException e)
        {
            throw new IllegalArgumentException("Could not create SAML object");
        }catch(NoSuchFieldException e)
        {
            throw new IllegalArgumentException("Could not create SAML object");
        }
        return object;
    }


}
