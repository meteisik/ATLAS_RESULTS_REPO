import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_IvoryLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryLotus() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String ivoryLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryLotusTokens = data.split("||");
            if (ivoryLotusTokens.length < 2) {
                return;
            }
            String ivoryLotusUser = ivoryLotusTokens[0];
            String ivoryLotusPass = ivoryLotusTokens[1];
            XPath ivoryLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryLotusXml = new InputSource(ivoryLotusXmlFile);
            String ivoryLotusQuery = "//users/user[name/text()='" + ivoryLotusUser
                    + "' and pass/text()='" + ivoryLotusPass + "']" + "/secret/text()";
            String ivoryLotusSecret = (String) ivoryLotusXPath.evaluate(ivoryLotusQuery, ivoryLotusXml, XPathConstants.STRING);
            System.out.println(ivoryLotusSecret);
        }
    }
}
