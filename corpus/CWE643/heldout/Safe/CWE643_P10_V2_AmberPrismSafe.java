import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AmberPrismSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void runAmberPrism() throws XPathExpressionException {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AmberPrismSafeSink()).sinkAmberPrism();
    }
}

class CWE643_P10_V2_AmberPrismSafeSink {

    public void sinkAmberPrism() throws XPathExpressionException {
        String data = CWE643_P10_V2_AmberPrismSafe.data;
        String amberPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberPrismTokens = data.split("||");
            if (amberPrismTokens.length < 2) {
                return;
            }
            String amberPrismUser = amberPrismTokens[0];
            String amberPrismPass = amberPrismTokens[1];
            XPath amberPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource amberPrismXml = new InputSource(amberPrismXmlFile);
            String amberPrismQuery = "//users/user[name/text()='" + amberPrismUser
                    + "' and pass/text()='" + amberPrismPass + "']" + "/secret/text()";
            String amberPrismSecret = (String) amberPrismXPath.evaluate(amberPrismQuery, amberPrismXml, XPathConstants.STRING);
            System.out.println(amberPrismSecret);
        }
    }
}
