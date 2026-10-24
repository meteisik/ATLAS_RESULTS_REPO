import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_OnyxLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runOnyxLotus() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P06_V2_OnyxLotusSafeSink()).sinkOnyxLotus(data);
    }
}

class CWE643_P06_V2_OnyxLotusSafeSink {

    public void sinkOnyxLotus(String data) throws XPathExpressionException {
        String onyxLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxLotusTokens = data.split("||");
            if (onyxLotusTokens.length < 2) {
                return;
            }
            String onyxLotusUser = onyxLotusTokens[0];
            String onyxLotusPass = onyxLotusTokens[1];
            XPath onyxLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxLotusXml = new InputSource(onyxLotusXmlFile);
            String onyxLotusQuery = "//users/user[name/text()='" + onyxLotusUser
                    + "' and pass/text()='" + onyxLotusPass + "']" + "/secret/text()";
            String onyxLotusSecret = (String) onyxLotusXPath.evaluate(onyxLotusQuery, onyxLotusXml, XPathConstants.STRING);
            System.out.println(onyxLotusSecret);
        }
    }
}
