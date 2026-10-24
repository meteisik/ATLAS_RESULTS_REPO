import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_AzureCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureCipher() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_AzureCipherSafeBase baseObject = new CWE643_P12_V2_AzureCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_AzureCipherSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_AzureCipherSafeSink extends CWE643_P12_V2_AzureCipherSafeBase {

    public void action(String data) throws XPathExpressionException {
        String azureCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureCipherTokens = data.split("||");
            if (azureCipherTokens.length < 2) {
                return;
            }
            String azureCipherUser = azureCipherTokens[0];
            String azureCipherPass = azureCipherTokens[1];
            XPath azureCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource azureCipherXml = new InputSource(azureCipherXmlFile);
            String azureCipherQuery = "//users/user[name/text()='" + azureCipherUser
                    + "' and pass/text()='" + azureCipherPass + "']" + "/secret/text()";
            String azureCipherSecret = (String) azureCipherXPath.evaluate(azureCipherQuery, azureCipherXml, XPathConstants.STRING);
            System.out.println(azureCipherSecret);
        }
    }
}
