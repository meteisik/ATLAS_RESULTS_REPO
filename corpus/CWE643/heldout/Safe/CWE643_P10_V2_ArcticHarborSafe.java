import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ArcticHarborSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runArcticHarbor() throws XPathExpressionException {
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ArcticHarborSafeSink()).sinkArcticHarbor();
    }
}

class CWE643_P10_V2_ArcticHarborSafeSink {

    public void sinkArcticHarbor() throws XPathExpressionException {
        String data = CWE643_P10_V2_ArcticHarborSafe.data;
        String arcticHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticHarborTokens = data.split("||");
            if (arcticHarborTokens.length < 2) {
                return;
            }
            String arcticHarborUser = arcticHarborTokens[0];
            String arcticHarborPass = arcticHarborTokens[1];
            XPath arcticHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticHarborXml = new InputSource(arcticHarborXmlFile);
            String arcticHarborQuery = "//users/user[name/text()='" + arcticHarborUser
                    + "' and pass/text()='" + arcticHarborPass + "']" + "/secret/text()";
            String arcticHarborSecret = (String) arcticHarborXPath.evaluate(arcticHarborQuery, arcticHarborXml, XPathConstants.STRING);
            System.out.println(arcticHarborSecret);
        }
    }
}
