import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_AzureCipher {

    public void runAzureCipher() throws XPathExpressionException {
        String data;
        data = System.getenv("AZURE_CIPHER_ADD");
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
