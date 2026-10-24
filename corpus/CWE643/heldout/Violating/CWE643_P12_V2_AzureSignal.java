import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_AzureSignal {

    public void runAzureSignal() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AZURE_SIGNAL_ADD");
        }
        CWE643_P12_V2_AzureSignalBase baseObject = new CWE643_P12_V2_AzureSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_AzureSignalBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_AzureSignalSink extends CWE643_P12_V2_AzureSignalBase {

    public void action(String data) throws XPathExpressionException {
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
