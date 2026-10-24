import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runZephyrGlint() throws XPathExpressionException {
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ZephyrGlintSafeSink()).sinkZephyrGlint();
    }
}

class CWE643_P10_V2_ZephyrGlintSafeSink {

    public void sinkZephyrGlint() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrGlintSafe.data;
        String zephyrGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrGlintTokens = data.split("||");
            if (zephyrGlintTokens.length < 2) {
                return;
            }
            String zephyrGlintUser = zephyrGlintTokens[0];
            String zephyrGlintPass = zephyrGlintTokens[1];
            XPath zephyrGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrGlintXml = new InputSource(zephyrGlintXmlFile);
            String zephyrGlintQuery = "//users/user[name/text()='" + zephyrGlintUser
                    + "' and pass/text()='" + zephyrGlintPass + "']" + "/secret/text()";
            String zephyrGlintSecret = (String) zephyrGlintXPath.evaluate(zephyrGlintQuery, zephyrGlintXml, XPathConstants.STRING);
            System.out.println(zephyrGlintSecret);
        }
    }
}
