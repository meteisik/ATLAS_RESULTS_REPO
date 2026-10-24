import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrAurora {
    private static boolean privateTrue = true;

    public static String data;

    public void runZephyrAurora() throws XPathExpressionException {
        if (privateTrue) {
            data = System.getenv("ZEPHYR_AURORA_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ZephyrAuroraSink()).sinkZephyrAurora();
    }
}

class CWE643_P10_V2_ZephyrAuroraSink {

    public void sinkZephyrAurora() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrAurora.data;
        String zephyrAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrAuroraTokens = data.split("||");
            if (zephyrAuroraTokens.length < 2) {
                return;
            }
            String zephyrAuroraUser = zephyrAuroraTokens[0];
            String zephyrAuroraPass = zephyrAuroraTokens[1];
            XPath zephyrAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrAuroraXml = new InputSource(zephyrAuroraXmlFile);
            String zephyrAuroraQuery = "//users/user[name/text()='" + zephyrAuroraUser
                    + "' and pass/text()='" + zephyrAuroraPass + "']" + "/secret/text()";
            String zephyrAuroraSecret = (String) zephyrAuroraXPath.evaluate(zephyrAuroraQuery, zephyrAuroraXml, XPathConstants.STRING);
            System.out.println(zephyrAuroraSecret);
        }
    }
}
