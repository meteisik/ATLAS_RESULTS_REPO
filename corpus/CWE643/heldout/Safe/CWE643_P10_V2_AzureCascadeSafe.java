import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AzureCascadeSafe {
    private static boolean privateTrue = true;

    public static String data;

    public void runAzureCascade() throws XPathExpressionException {
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AzureCascadeSafeSink()).sinkAzureCascade();
    }
}

class CWE643_P10_V2_AzureCascadeSafeSink {

    public void sinkAzureCascade() throws XPathExpressionException {
        String data = CWE643_P10_V2_AzureCascadeSafe.data;
        String azureCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureCascadeTokens = data.split("||");
            if (azureCascadeTokens.length < 2) {
                return;
            }
            String azureCascadeUser = azureCascadeTokens[0];
            String azureCascadePass = azureCascadeTokens[1];
            XPath azureCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource azureCascadeXml = new InputSource(azureCascadeXmlFile);
            String azureCascadeQuery = "//users/user[name/text()='" + azureCascadeUser
                    + "' and pass/text()='" + azureCascadePass + "']" + "/secret/text()";
            String azureCascadeSecret = (String) azureCascadeXPath.evaluate(azureCascadeQuery, azureCascadeXml, XPathConstants.STRING);
            System.out.println(azureCascadeSecret);
        }
    }
}
