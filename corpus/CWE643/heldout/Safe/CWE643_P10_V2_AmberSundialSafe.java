import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AmberSundialSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void runAmberSundial() throws XPathExpressionException {
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AmberSundialSafeSink()).sinkAmberSundial();
    }
}

class CWE643_P10_V2_AmberSundialSafeSink {

    public void sinkAmberSundial() throws XPathExpressionException {
        String data = CWE643_P10_V2_AmberSundialSafe.data;
        String amberSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberSundialTokens = data.split("||");
            if (amberSundialTokens.length < 2) {
                return;
            }
            String amberSundialUser = amberSundialTokens[0];
            String amberSundialPass = amberSundialTokens[1];
            XPath amberSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource amberSundialXml = new InputSource(amberSundialXmlFile);
            String amberSundialQuery = "//users/user[name/text()='" + amberSundialUser
                    + "' and pass/text()='" + amberSundialPass + "']" + "/secret/text()";
            String amberSundialSecret = (String) amberSundialXPath.evaluate(amberSundialQuery, amberSundialXml, XPathConstants.STRING);
            System.out.println(amberSundialSecret);
        }
    }
}
