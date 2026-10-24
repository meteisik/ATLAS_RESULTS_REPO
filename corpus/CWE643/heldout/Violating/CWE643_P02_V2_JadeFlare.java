import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_JadeFlare {

    public void runJadeFlare() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = System.getenv("JADE_FLARE_ADD");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String jadeFlareXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                jadeFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                jadeFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] jadeFlareTokens = data.split("||");
                if (jadeFlareTokens.length < 2) {
                    return;
                }
                String jadeFlareUser = jadeFlareTokens[0];
                String jadeFlarePass = jadeFlareTokens[1];
                XPath jadeFlareXPath = XPathFactory.newInstance().newXPath();
                InputSource jadeFlareXml = new InputSource(jadeFlareXmlFile);
                String jadeFlareQuery = "//users/user[name/text()='" + jadeFlareUser
                        + "' and pass/text()='" + jadeFlarePass + "']" + "/secret/text()";
                String jadeFlareSecret = (String) jadeFlareXPath.evaluate(jadeFlareQuery, jadeFlareXml, XPathConstants.STRING);
                System.out.println(jadeFlareSecret);
            }
        }
    }
}
