import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ZephyrSundial {

    public void runZephyrSundial() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_SUNDIAL_ADD");
        CWE643_P12_V1_ZephyrSundialBase baseObject = new CWE643_P12_V1_ZephyrSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ZephyrSundialBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ZephyrSundialSink extends CWE643_P12_V1_ZephyrSundialBase {

    public void action(String data) throws XPathExpressionException {
        String zephyrSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrSundialTokens = data.split("||");
            if (zephyrSundialTokens.length < 2) {
                return;
            }
            String zephyrSundialUser = zephyrSundialTokens[0];
            String zephyrSundialPass = zephyrSundialTokens[1];
            XPath zephyrSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrSundialXml = new InputSource(zephyrSundialXmlFile);
            String zephyrSundialQuery = "//users/user[name/text()='" + zephyrSundialUser
                    + "' and pass/text()='" + zephyrSundialPass + "']" + "/secret/text()";
            String zephyrSundialSecret = (String) zephyrSundialXPath.evaluate(zephyrSundialQuery, zephyrSundialXml, XPathConstants.STRING);
            System.out.println(zephyrSundialSecret);
        }
    }
}
