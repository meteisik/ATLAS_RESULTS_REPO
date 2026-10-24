import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_AzureAuroraSafe {

    public void runAzureAurora() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String azureAuroraXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                azureAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                azureAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] azureAuroraTokens = data.split("||");
                if (azureAuroraTokens.length < 2) {
                    return;
                }
                String azureAuroraUser = azureAuroraTokens[0];
                String azureAuroraPass = azureAuroraTokens[1];
                XPath azureAuroraXPath = XPathFactory.newInstance().newXPath();
                InputSource azureAuroraXml = new InputSource(azureAuroraXmlFile);
                String azureAuroraQuery = "//users/user[name/text()='" + azureAuroraUser
                        + "' and pass/text()='" + azureAuroraPass + "']" + "/secret/text()";
                String azureAuroraSecret = (String) azureAuroraXPath.evaluate(azureAuroraQuery, azureAuroraXml, XPathConstants.STRING);
                System.out.println(azureAuroraSecret);
            }
        }
    }
}
