import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrSundialSafe {

    public static String data;

    public void runZephyrSundial() throws XPathExpressionException {
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        (new CWE643_P10_V2_ZephyrSundialSafeSink()).sinkZephyrSundial();
    }
}

class CWE643_P10_V2_ZephyrSundialSafeSink {

    public void sinkZephyrSundial() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrSundialSafe.data;
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
