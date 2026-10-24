import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_AzureGlintSafe {

    public void runAzureGlint() throws XPathExpressionException {
        String data;
        data = "foo";
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
