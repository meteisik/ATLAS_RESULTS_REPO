import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_OnyxLotus {
    private static boolean privateTrue = true;

    private String sourceOnyxLotus() {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_LOTUS_ADD");
        } else {
            data = null;
        }
        return data;
    }

    public void runOnyxLotus() throws XPathExpressionException {
        String data = sourceOnyxLotus();
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
