import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_OnyxOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String onyxOrbitData;

    private void sinkOnyxOrbit() throws XPathExpressionException {
        String data = onyxOrbitData;
        String onyxOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxOrbitTokens = data.split("||");
            if (onyxOrbitTokens.length < 2) {
                return;
            }
            String onyxOrbitUser = onyxOrbitTokens[0];
            String onyxOrbitPass = onyxOrbitTokens[1];
            XPath onyxOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxOrbitXml = new InputSource(onyxOrbitXmlFile);
            String onyxOrbitQuery = "//users/user[name/text()='" + onyxOrbitUser
                    + "' and pass/text()='" + onyxOrbitPass + "']" + "/secret/text()";
            String onyxOrbitSecret = (String) onyxOrbitXPath.evaluate(onyxOrbitQuery, onyxOrbitXml, XPathConstants.STRING);
            System.out.println(onyxOrbitSecret);
        }
    }

    public void runOnyxOrbit() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        onyxOrbitData = data;
        sinkOnyxOrbit();
    }
}
