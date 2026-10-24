import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_AzureSignal {

    public void runAzureSignal() throws XPathExpressionException {
        String data;
        data = System.getenv("AZURE_SIGNAL_ADD");
        String azureSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureSignalTokens = data.split("||");
            if (azureSignalTokens.length < 2) {
                return;
            }
            String azureSignalUser = azureSignalTokens[0];
            String azureSignalPass = azureSignalTokens[1];
            XPath azureSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource azureSignalXml = new InputSource(azureSignalXmlFile);
            String azureSignalQuery = "//users/user[name/text()='" + azureSignalUser
                    + "' and pass/text()='" + azureSignalPass + "']" + "/secret/text()";
            String azureSignalSecret = (String) azureSignalXPath.evaluate(azureSignalQuery, azureSignalXml, XPathConstants.STRING);
            System.out.println(azureSignalSecret);
        }
    }
}
