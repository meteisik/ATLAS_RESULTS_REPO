import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_AzurePrismSafe {

    public void runAzurePrism() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        CWE643_P12_V2_AzurePrismSafeBase baseObject = new CWE643_P12_V2_AzurePrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_AzurePrismSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_AzurePrismSafeSink extends CWE643_P12_V2_AzurePrismSafeBase {

    public void action(String data) throws XPathExpressionException {
        String azurePrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azurePrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azurePrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azurePrismTokens = data.split("||");
            if (azurePrismTokens.length < 2) {
                return;
            }
            String azurePrismUser = azurePrismTokens[0];
            String azurePrismPass = azurePrismTokens[1];
            XPath azurePrismXPath = XPathFactory.newInstance().newXPath();
            InputSource azurePrismXml = new InputSource(azurePrismXmlFile);
            String azurePrismQuery = "//users/user[name/text()='" + azurePrismUser
                    + "' and pass/text()='" + azurePrismPass + "']" + "/secret/text()";
            String azurePrismSecret = (String) azurePrismXPath.evaluate(azurePrismQuery, azurePrismXml, XPathConstants.STRING);
            System.out.println(azurePrismSecret);
        }
    }
}
