import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runZephyrMantis() throws XPathExpressionException {
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ZephyrMantisSafeSink()).sinkZephyrMantis();
    }
}

class CWE643_P10_V2_ZephyrMantisSafeSink {

    public void sinkZephyrMantis() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrMantisSafe.data;
        String zephyrMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrMantisTokens = data.split("||");
            if (zephyrMantisTokens.length < 2) {
                return;
            }
            String zephyrMantisUser = zephyrMantisTokens[0];
            String zephyrMantisPass = zephyrMantisTokens[1];
            XPath zephyrMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrMantisXml = new InputSource(zephyrMantisXmlFile);
            String zephyrMantisQuery = "//users/user[name/text()='" + zephyrMantisUser
                    + "' and pass/text()='" + zephyrMantisPass + "']" + "/secret/text()";
            String zephyrMantisSecret = (String) zephyrMantisXPath.evaluate(zephyrMantisQuery, zephyrMantisXml, XPathConstants.STRING);
            System.out.println(zephyrMantisSecret);
        }
    }
}
