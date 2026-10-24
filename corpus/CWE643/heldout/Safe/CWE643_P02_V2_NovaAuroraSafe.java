import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_NovaAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runNovaAurora() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String novaAuroraXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                novaAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                novaAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] novaAuroraTokens = data.split("||");
                if (novaAuroraTokens.length < 2) {
                    return;
                }
                String novaAuroraUser = novaAuroraTokens[0];
                String novaAuroraPass = novaAuroraTokens[1];
                XPath novaAuroraXPath = XPathFactory.newInstance().newXPath();
                InputSource novaAuroraXml = new InputSource(novaAuroraXmlFile);
                String novaAuroraQuery = "//users/user[name/text()='" + novaAuroraUser
                        + "' and pass/text()='" + novaAuroraPass + "']" + "/secret/text()";
                String novaAuroraSecret = (String) novaAuroraXPath.evaluate(novaAuroraQuery, novaAuroraXml, XPathConstants.STRING);
                System.out.println(novaAuroraSecret);
            }
        }
    }
}
