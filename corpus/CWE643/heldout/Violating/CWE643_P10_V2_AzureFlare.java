import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AzureFlare {
    private static int privateFive = 5;

    public static String data;

    public void runAzureFlare() throws XPathExpressionException {
        if (privateFive == 5) {
            data = System.getenv("AZURE_FLARE_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AzureFlareSink()).sinkAzureFlare();
    }
}

class CWE643_P10_V2_AzureFlareSink {

    public void sinkAzureFlare() throws XPathExpressionException {
        String data = CWE643_P10_V2_AzureFlare.data;
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
