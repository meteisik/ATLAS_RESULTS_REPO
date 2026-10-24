import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_AzureGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureGlint() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_GLINT_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_AzureGlintBase baseObject = new CWE643_P12_V2_AzureGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_AzureGlintBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_AzureGlintSink extends CWE643_P12_V2_AzureGlintBase {

    public void action(String data) throws XPathExpressionException {
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
