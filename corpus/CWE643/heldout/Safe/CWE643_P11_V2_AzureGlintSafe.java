import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AzureGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureGlint() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AzureGlintSafeSink()).sinkAzureGlint(dataHashMap);
    }
}

class CWE643_P11_V2_AzureGlintSafeSink {

    public void sinkAzureGlint(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String azureGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureGlintTokens = data.split("||");
            if (azureGlintTokens.length < 2) {
                return;
            }
            String azureGlintUser = azureGlintTokens[0];
            String azureGlintPass = azureGlintTokens[1];
            XPath azureGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource azureGlintXml = new InputSource(azureGlintXmlFile);
            String azureGlintQuery = "//users/user[name/text()='" + azureGlintUser
                    + "' and pass/text()='" + azureGlintPass + "']" + "/secret/text()";
            String azureGlintSecret = (String) azureGlintXPath.evaluate(azureGlintQuery, azureGlintXml, XPathConstants.STRING);
            System.out.println(azureGlintSecret);
        }
    }
}
