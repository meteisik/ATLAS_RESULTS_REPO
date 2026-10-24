import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AzureGlintSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void runAzureGlint() throws XPathExpressionException {
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AzureGlintSafeSink()).sinkAzureGlint();
    }
}

class CWE643_P10_V2_AzureGlintSafeSink {

    public void sinkAzureGlint() throws XPathExpressionException {
        String data = CWE643_P10_V2_AzureGlintSafe.data;
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
