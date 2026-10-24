import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_AzureQuartzSafe {

    public void runAzureQuartz() throws XPathExpressionException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        CWE643_P12_V2_AzureQuartzSafeBase baseObject = new CWE643_P12_V2_AzureQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_AzureQuartzSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_AzureQuartzSafeSink extends CWE643_P12_V2_AzureQuartzSafeBase {

    public void action(String data) throws XPathExpressionException {
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
