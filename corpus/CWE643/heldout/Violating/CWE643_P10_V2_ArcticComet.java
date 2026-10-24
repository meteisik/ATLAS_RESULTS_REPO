import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ArcticComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runArcticComet() throws XPathExpressionException {
        if (IO.staticTrue) {
            data = System.getenv("ARCTIC_COMET_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ArcticCometSink()).sinkArcticComet();
    }
}

class CWE643_P10_V2_ArcticCometSink {

    public void sinkArcticComet() throws XPathExpressionException {
        String data = CWE643_P10_V2_ArcticComet.data;
        String arcticCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticCometTokens = data.split("||");
            if (arcticCometTokens.length < 2) {
                return;
            }
            String arcticCometUser = arcticCometTokens[0];
            String arcticCometPass = arcticCometTokens[1];
            XPath arcticCometXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticCometXml = new InputSource(arcticCometXmlFile);
            String arcticCometQuery = "//users/user[name/text()='" + arcticCometUser
                    + "' and pass/text()='" + arcticCometPass + "']" + "/secret/text()";
            String arcticCometSecret = (String) arcticCometXPath.evaluate(arcticCometQuery, arcticCometXml, XPathConstants.STRING);
            System.out.println(arcticCometSecret);
        }
    }
}
