import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AzureSignal {

    public void runAzureSignal() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AZURE_SIGNAL_ADD");
            break;
        default:
            data = null;
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AzureSignalSink()).sinkAzureSignal(dataHashMap);
    }
}

class CWE643_P11_V2_AzureSignalSink {

    public void sinkAzureSignal(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
