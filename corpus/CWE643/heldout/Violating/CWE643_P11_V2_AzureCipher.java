import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AzureCipher {
    private static boolean privateReturnsTrue() { return true; }

    public void runAzureCipher() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_CIPHER_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AzureCipherSink()).sinkAzureCipher(dataHashMap);
    }
}

class CWE643_P11_V2_AzureCipherSink {

    public void sinkAzureCipher(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
