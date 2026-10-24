import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_AzureQuartzSafe {

    private void sinkAzureQuartz(String data) throws XPathExpressionException {
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

    public void runAzureQuartz() throws XPathExpressionException {
        String data;
        data = "foo";
        sinkAzureQuartz(data);
    }
}
