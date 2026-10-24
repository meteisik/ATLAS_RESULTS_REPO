import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_AzureMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureMantis() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_AzureMantisSafeBase baseObject = new CWE643_P12_V2_AzureMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_AzureMantisSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_AzureMantisSafeSink extends CWE643_P12_V2_AzureMantisSafeBase {

    public void action(String data) throws XPathExpressionException {
        String azureMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureMantisTokens = data.split("||");
            if (azureMantisTokens.length < 2) {
                return;
            }
            String azureMantisUser = azureMantisTokens[0];
            String azureMantisPass = azureMantisTokens[1];
            XPath azureMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource azureMantisXml = new InputSource(azureMantisXmlFile);
            String azureMantisQuery = "//users/user[name/text()='" + azureMantisUser
                    + "' and pass/text()='" + azureMantisPass + "']" + "/secret/text()";
            String azureMantisSecret = (String) azureMantisXPath.evaluate(azureMantisQuery, azureMantisXml, XPathConstants.STRING);
            System.out.println(azureMantisSecret);
        }
    }
}
