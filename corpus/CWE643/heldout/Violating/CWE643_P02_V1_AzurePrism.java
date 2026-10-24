import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_AzurePrism {

    public void runAzurePrism() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_PRISM_ADD");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
