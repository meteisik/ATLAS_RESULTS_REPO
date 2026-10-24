import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ArcticKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runArcticKestrel() throws XPathExpressionException {
        if (IO.staticFive == 5) {
            data = System.getenv("ARCTIC_KESTREL_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ArcticKestrelSink()).sinkArcticKestrel();
    }
}

class CWE643_P10_V2_ArcticKestrelSink {

    public void sinkArcticKestrel() throws XPathExpressionException {
        String data = CWE643_P10_V2_ArcticKestrel.data;
        String arcticKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticKestrelTokens = data.split("||");
            if (arcticKestrelTokens.length < 2) {
                return;
            }
            String arcticKestrelUser = arcticKestrelTokens[0];
            String arcticKestrelPass = arcticKestrelTokens[1];
            XPath arcticKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticKestrelXml = new InputSource(arcticKestrelXmlFile);
            String arcticKestrelQuery = "//users/user[name/text()='" + arcticKestrelUser
                    + "' and pass/text()='" + arcticKestrelPass + "']" + "/secret/text()";
            String arcticKestrelSecret = (String) arcticKestrelXPath.evaluate(arcticKestrelQuery, arcticKestrelXml, XPathConstants.STRING);
            System.out.println(arcticKestrelSecret);
        }
    }
}
