import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AzureCascadeSafe {
    private static int privateFive = 5;

    public void runAzureCascade() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AzureCascadeSafeSink()).sinkAzureCascade(dataHashMap);
    }
}

class CWE643_P11_V2_AzureCascadeSafeSink {

    public void sinkAzureCascade(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String azureCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureCascadeTokens = data.split("||");
            if (azureCascadeTokens.length < 2) {
                return;
            }
            String azureCascadeUser = azureCascadeTokens[0];
            String azureCascadePass = azureCascadeTokens[1];
            XPath azureCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource azureCascadeXml = new InputSource(azureCascadeXmlFile);
            String azureCascadeQuery = "//users/user[name/text()='" + azureCascadeUser
                    + "' and pass/text()='" + azureCascadePass + "']" + "/secret/text()";
            String azureCascadeSecret = (String) azureCascadeXPath.evaluate(azureCascadeQuery, azureCascadeXml, XPathConstants.STRING);
            System.out.println(azureCascadeSecret);
        }
    }
}
