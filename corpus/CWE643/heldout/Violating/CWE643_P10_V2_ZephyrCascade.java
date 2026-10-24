import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrCascade {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void runZephyrCascade() throws XPathExpressionException {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_CASCADE_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ZephyrCascadeSink()).sinkZephyrCascade();
    }
}

class CWE643_P10_V2_ZephyrCascadeSink {

    public void sinkZephyrCascade() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrCascade.data;
        String zephyrCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrCascadeTokens = data.split("||");
            if (zephyrCascadeTokens.length < 2) {
                return;
            }
            String zephyrCascadeUser = zephyrCascadeTokens[0];
            String zephyrCascadePass = zephyrCascadeTokens[1];
            XPath zephyrCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrCascadeXml = new InputSource(zephyrCascadeXmlFile);
            String zephyrCascadeQuery = "//users/user[name/text()='" + zephyrCascadeUser
                    + "' and pass/text()='" + zephyrCascadePass + "']" + "/secret/text()";
            String zephyrCascadeSecret = (String) zephyrCascadeXPath.evaluate(zephyrCascadeQuery, zephyrCascadeXml, XPathConstants.STRING);
            System.out.println(zephyrCascadeSecret);
        }
    }
}
