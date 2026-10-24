import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_AzureAurora {
    private static boolean privateReturnsTrue() { return true; }

    public void runAzureAurora() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_AURORA_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_AzureAuroraBase baseObject = new CWE643_P12_V2_AzureAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_AzureAuroraBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_AzureAuroraSink extends CWE643_P12_V2_AzureAuroraBase {

    public void action(String data) throws XPathExpressionException {
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
