import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_IvoryOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryOrbit() throws XPathExpressionException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        String ivoryOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryOrbitTokens = data.split("||");
            if (ivoryOrbitTokens.length < 2) {
                return;
            }
            String ivoryOrbitUser = ivoryOrbitTokens[0];
            String ivoryOrbitPass = ivoryOrbitTokens[1];
            XPath ivoryOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryOrbitXml = new InputSource(ivoryOrbitXmlFile);
            String ivoryOrbitQuery = "//users/user[name/text()='" + ivoryOrbitUser
                    + "' and pass/text()='" + ivoryOrbitPass + "']" + "/secret/text()";
            String ivoryOrbitSecret = (String) ivoryOrbitXPath.evaluate(ivoryOrbitQuery, ivoryOrbitXml, XPathConstants.STRING);
            System.out.println(ivoryOrbitSecret);
        }
    }
}
