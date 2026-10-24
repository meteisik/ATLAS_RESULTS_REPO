import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V1_NovaAuroraSafe {

    public void runNovaAurora() throws XPathExpressionException {
        String data;
        data = (new CWE643_P07_V1_NovaAuroraSafeSource()).sourceNovaAurora();
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

class CWE643_P07_V1_NovaAuroraSafeSource {

    public String sourceNovaAurora() {
        String data;
        data = "foo";
        return data;
    }
}
