import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_AzureSundialSafe {

    public void runAzureSundial() throws XPathExpressionException {
        String data;
        data = "foo";
        String azureSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureSundialTokens = data.split("||");
            if (azureSundialTokens.length < 2) {
                return;
            }
            String azureSundialUser = azureSundialTokens[0];
            String azureSundialPass = azureSundialTokens[1];
            XPath azureSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource azureSundialXml = new InputSource(azureSundialXmlFile);
            String azureSundialQuery = "//users/user[name/text()='" + azureSundialUser
                    + "' and pass/text()='" + azureSundialPass + "']" + "/secret/text()";
            String azureSundialSecret = (String) azureSundialXPath.evaluate(azureSundialQuery, azureSundialXml, XPathConstants.STRING);
            System.out.println(azureSundialSecret);
        }
    }
}
