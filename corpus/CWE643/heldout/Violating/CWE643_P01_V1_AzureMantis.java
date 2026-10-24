import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_AzureMantis {

    public void runAzureMantis() throws XPathExpressionException {
        String data;
        data = System.getenv("AZURE_MANTIS_ADD");
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
