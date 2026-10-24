import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V1_JadeFlare {

    public void runJadeFlare() throws XPathExpressionException {
        String data;
        data = System.getenv("JADE_FLARE_ADD");
        (new CWE643_P06_V1_JadeFlareSink()).sinkJadeFlare(data);
    }
}

class CWE643_P06_V1_JadeFlareSink {

    public void sinkJadeFlare(String data) throws XPathExpressionException {
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
