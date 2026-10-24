import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AzurePrism {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzurePrism() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_PRISM_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AzurePrismSink()).sinkAzurePrism(dataHashMap);
    }
}

class CWE643_P11_V2_AzurePrismSink {

    public void sinkAzurePrism(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
