import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_IvoryLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryLantern() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (IO.staticTrue) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String ivoryLanternXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                ivoryLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                ivoryLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] ivoryLanternTokens = data.split("||");
                if (ivoryLanternTokens.length < 2) {
                    return;
                }
                String ivoryLanternUser = ivoryLanternTokens[0];
                String ivoryLanternPass = ivoryLanternTokens[1];
                XPath ivoryLanternXPath = XPathFactory.newInstance().newXPath();
                InputSource ivoryLanternXml = new InputSource(ivoryLanternXmlFile);
                String ivoryLanternQuery = "//users/user[name/text()='" + ivoryLanternUser
                        + "' and pass/text()='" + ivoryLanternPass + "']" + "/secret/text()";
                String ivoryLanternSecret = (String) ivoryLanternXPath.evaluate(ivoryLanternQuery, ivoryLanternXml, XPathConstants.STRING);
                System.out.println(ivoryLanternSecret);
            }
        }
    }
}
