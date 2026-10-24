import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrPrism {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runZephyrPrism() throws XPathExpressionException {
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ZEPHYR_PRISM_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ZephyrPrismSink()).sinkZephyrPrism();
    }
}

class CWE643_P10_V2_ZephyrPrismSink {

    public void sinkZephyrPrism() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrPrism.data;
        String zephyrPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrPrismTokens = data.split("||");
            if (zephyrPrismTokens.length < 2) {
                return;
            }
            String zephyrPrismUser = zephyrPrismTokens[0];
            String zephyrPrismPass = zephyrPrismTokens[1];
            XPath zephyrPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrPrismXml = new InputSource(zephyrPrismXmlFile);
            String zephyrPrismQuery = "//users/user[name/text()='" + zephyrPrismUser
                    + "' and pass/text()='" + zephyrPrismPass + "']" + "/secret/text()";
            String zephyrPrismSecret = (String) zephyrPrismXPath.evaluate(zephyrPrismQuery, zephyrPrismXml, XPathConstants.STRING);
            System.out.println(zephyrPrismSecret);
        }
    }
}
