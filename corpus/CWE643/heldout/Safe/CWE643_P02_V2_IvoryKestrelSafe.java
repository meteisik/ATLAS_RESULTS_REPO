import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_IvoryKestrelSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryKestrel() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (IO.STATIC_FINAL_TRUE) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String ivoryKestrelXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                ivoryKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                ivoryKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] ivoryKestrelTokens = data.split("||");
                if (ivoryKestrelTokens.length < 2) {
                    return;
                }
                String ivoryKestrelUser = ivoryKestrelTokens[0];
                String ivoryKestrelPass = ivoryKestrelTokens[1];
                XPath ivoryKestrelXPath = XPathFactory.newInstance().newXPath();
                InputSource ivoryKestrelXml = new InputSource(ivoryKestrelXmlFile);
                String ivoryKestrelQuery = "//users/user[name/text()='" + ivoryKestrelUser
                        + "' and pass/text()='" + ivoryKestrelPass + "']" + "/secret/text()";
                String ivoryKestrelSecret = (String) ivoryKestrelXPath.evaluate(ivoryKestrelQuery, ivoryKestrelXml, XPathConstants.STRING);
                System.out.println(ivoryKestrelSecret);
            }
        }
    }
}
