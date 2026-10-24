import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_ZephyrSundial {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void runZephyrSundial() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_SUNDIAL_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_ZephyrSundialSink()).sinkZephyrSundial(dataContainer);
    }
}

class CWE643_P09_V2_ZephyrSundialSink {

    public void sinkZephyrSundial(CWE643_P09_V2_ZephyrSundial.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
