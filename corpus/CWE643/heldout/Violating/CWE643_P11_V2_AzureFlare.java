import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AzureFlare {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureFlare() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("AZURE_FLARE_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AzureFlareSink()).sinkAzureFlare(dataHashMap);
    }
}

class CWE643_P11_V2_AzureFlareSink {

    public void sinkAzureFlare(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String azureFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            azureFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            azureFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] azureFlareTokens = data.split("||");
            if (azureFlareTokens.length < 2) {
                return;
            }
            String azureFlareUser = azureFlareTokens[0];
            String azureFlarePass = azureFlareTokens[1];
            XPath azureFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource azureFlareXml = new InputSource(azureFlareXmlFile);
            String azureFlareQuery = "//users/user[name/text()='" + azureFlareUser
                    + "' and pass/text()='" + azureFlarePass + "']" + "/secret/text()";
            String azureFlareSecret = (String) azureFlareXPath.evaluate(azureFlareQuery, azureFlareXml, XPathConstants.STRING);
            System.out.println(azureFlareSecret);
        }
    }
}
