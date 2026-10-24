import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AzureQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureQuartz() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AzureQuartzSafeSink()).sinkAzureQuartz(dataHashMap);
    }
}

class CWE643_P11_V2_AzureQuartzSafeSink {

    public void sinkAzureQuartz(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String azureQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureQuartzTokens = data.split("||");
            if (azureQuartzTokens.length < 2) {
                return;
            }
            String azureQuartzUser = azureQuartzTokens[0];
            String azureQuartzPass = azureQuartzTokens[1];
            XPath azureQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource azureQuartzXml = new InputSource(azureQuartzXmlFile);
            String azureQuartzQuery = "//users/user[name/text()='" + azureQuartzUser
                    + "' and pass/text()='" + azureQuartzPass + "']" + "/secret/text()";
            String azureQuartzSecret = (String) azureQuartzXPath.evaluate(azureQuartzQuery, azureQuartzXml, XPathConstants.STRING);
            System.out.println(azureQuartzSecret);
        }
    }
}
