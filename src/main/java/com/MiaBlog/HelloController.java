package com.MiaBlog;


import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


@Controller
public class HelloController {

    @RequestMapping("/hello")
    public String hello()
    {
        return "index";
    }

    @RequestMapping("/test")
    public String test()
    {
        return "index";
    }
    /*
     * @description: write the QRCode to a outputstream
     * @Param content: the content of QR Code
     * @Param stream: output stream
     * @Param width
     * @Param height
     */
    private void writeToStream(String content, OutputStream outputStream, int width, int height)
    throws WriterException
    {
        final Map<EncodeHintType,Object> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET,"utf-8");
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H);
        hints.put(EncodeHintType.MARGIN,2);

        try {
            BitMatrix bitMatrix = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, width, height, hints);
            MatrixToImageWriter.writeToStream(bitMatrix, "png", outputStream);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

    }

    private String getUUID()
    {
        String s = UUID.randomUUID().toString();
        return s.substring(0,8)+s.substring(9,13)+s.substring(14,18)+s.substring(19,23)+s.substring(24);
    }

    @RequestMapping("/qrcode")
    public void getQRCode(
                          @RequestParam(defaultValue = "300",required = false)int height,
                          @RequestParam(defaultValue = "300",required = false)int width,
                          HttpServletResponse response) {

        String content = getUUID();
        ServletOutputStream outputStream = null;

        try
        {
            outputStream = response.getOutputStream();
            this.writeToStream(content,outputStream,width,height);
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }finally {
            if(outputStream != null)
            {
                try
                {
                    outputStream.close();
                }catch (IOException e)
                {
                    e.printStackTrace();
                }
            }
        }

    }


}
