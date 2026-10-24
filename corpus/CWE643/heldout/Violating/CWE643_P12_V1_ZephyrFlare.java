import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ZephyrFlare {

    public void runZephyrFlare() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_FLARE_ADD");
        CWE643_P12_V1_ZephyrFlareBase baseObject = new CWE643_P12_V1_ZephyrFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ZephyrFlareBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ZephyrFlareSink extends CWE643_P12_V1_ZephyrFlareBase {

    public void action(String data) throws XPathExpressionException {
        String zephyrFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrFlareTokens = data.split("||");
            if (zephyrFlareTokens.length < 2) {
                return;
            }
            String zephyrFlareUser = zephyrFlareTokens[0];
            String zephyrFlarePass = zephyrFlareTokens[1];
            XPath zephyrFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrFlareXml = new InputSource(zephyrFlareXmlFile);
            String zephyrFlareQuery = "//users/user[name/text()='" + zephyrFlareUser
                    + "' and pass/text()='" + zephyrFlarePass + "']" + "/secret/text()";
            String zephyrFlareSecret = (String) zephyrFlareXPath.evaluate(zephyrFlareQuery, zephyrFlareXml, XPathConstants.STRING);
            System.out.println(zephyrFlareSecret);
        }
    }
}
