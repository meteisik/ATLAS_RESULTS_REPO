import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrSignalSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runZephyrSignal() throws XPathExpressionException {
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ZephyrSignalSafeSink()).sinkZephyrSignal();
    }
}

class CWE643_P10_V2_ZephyrSignalSafeSink {

    public void sinkZephyrSignal() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrSignalSafe.data;
        String zephyrSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrSignalTokens = data.split("||");
            if (zephyrSignalTokens.length < 2) {
                return;
            }
            String zephyrSignalUser = zephyrSignalTokens[0];
            String zephyrSignalPass = zephyrSignalTokens[1];
            XPath zephyrSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrSignalXml = new InputSource(zephyrSignalXmlFile);
            String zephyrSignalQuery = "//users/user[name/text()='" + zephyrSignalUser
                    + "' and pass/text()='" + zephyrSignalPass + "']" + "/secret/text()";
            String zephyrSignalSecret = (String) zephyrSignalXPath.evaluate(zephyrSignalQuery, zephyrSignalXml, XPathConstants.STRING);
            System.out.println(zephyrSignalSecret);
        }
    }
}
