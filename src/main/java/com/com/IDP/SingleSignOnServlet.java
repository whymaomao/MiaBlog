package com.com.IDP;

import com.SP.SPConstants;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SingleSignOnServlet {

    @RequestMapping(path="/idp/singleSignOn",method = RequestMethod.GET)
    String SingleSignOn()
    {
        return "singleSignOn";
    }

    @RequestMapping(path="/idp/singleSignOn",method = RequestMethod.POST)
    String IDPSendBack()
    {
        return "redirect:" + SPConstants.ASSERTION_CONSUMER_SERVICE +
                "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D";
    }


}
