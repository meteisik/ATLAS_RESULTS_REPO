import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_AzureCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureCascade() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_AzureCascadeSafeBase baseObject = new CWE643_P12_V2_AzureCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_AzureCascadeSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_AzureCascadeSafeSink extends CWE643_P12_V2_AzureCascadeSafeBase {

    public void action(String data) throws XPathExpressionException {
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
