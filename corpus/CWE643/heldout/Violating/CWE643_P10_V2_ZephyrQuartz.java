import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runZephyrQuartz() throws XPathExpressionException {
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_QUARTZ_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ZephyrQuartzSink()).sinkZephyrQuartz();
    }
}

class CWE643_P10_V2_ZephyrQuartzSink {

    public void sinkZephyrQuartz() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrQuartz.data;
        String zephyrQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrQuartzTokens = data.split("||");
            if (zephyrQuartzTokens.length < 2) {
                return;
            }
            String zephyrQuartzUser = zephyrQuartzTokens[0];
            String zephyrQuartzPass = zephyrQuartzTokens[1];
            XPath zephyrQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrQuartzXml = new InputSource(zephyrQuartzXmlFile);
            String zephyrQuartzQuery = "//users/user[name/text()='" + zephyrQuartzUser
                    + "' and pass/text()='" + zephyrQuartzPass + "']" + "/secret/text()";
            String zephyrQuartzSecret = (String) zephyrQuartzXPath.evaluate(zephyrQuartzQuery, zephyrQuartzXml, XPathConstants.STRING);
            System.out.println(zephyrQuartzSecret);
        }
    }
}
