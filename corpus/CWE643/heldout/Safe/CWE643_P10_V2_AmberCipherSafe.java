import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AmberCipherSafe {

    public static String data;

    public void runAmberCipher() throws XPathExpressionException {
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AmberCipherSafeSink()).sinkAmberCipher();
    }
}

class CWE643_P10_V2_AmberCipherSafeSink {

    public void sinkAmberCipher() throws XPathExpressionException {
        String data = CWE643_P10_V2_AmberCipherSafe.data;
        String amberCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberCipherTokens = data.split("||");
            if (amberCipherTokens.length < 2) {
                return;
            }
            String amberCipherUser = amberCipherTokens[0];
            String amberCipherPass = amberCipherTokens[1];
            XPath amberCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource amberCipherXml = new InputSource(amberCipherXmlFile);
            String amberCipherQuery = "//users/user[name/text()='" + amberCipherUser
                    + "' and pass/text()='" + amberCipherPass + "']" + "/secret/text()";
            String amberCipherSecret = (String) amberCipherXPath.evaluate(amberCipherQuery, amberCipherXml, XPathConstants.STRING);
            System.out.println(amberCipherSecret);
        }
    }
}
