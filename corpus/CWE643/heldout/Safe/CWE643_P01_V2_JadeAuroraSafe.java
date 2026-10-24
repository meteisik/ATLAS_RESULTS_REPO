import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_JadeAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runJadeAurora() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String jadeAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadeAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadeAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadeAuroraTokens = data.split("||");
            if (jadeAuroraTokens.length < 2) {
                return;
            }
            String jadeAuroraUser = jadeAuroraTokens[0];
            String jadeAuroraPass = jadeAuroraTokens[1];
            XPath jadeAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource jadeAuroraXml = new InputSource(jadeAuroraXmlFile);
            String jadeAuroraQuery = "//users/user[name/text()='" + jadeAuroraUser
                    + "' and pass/text()='" + jadeAuroraPass + "']" + "/secret/text()";
            String jadeAuroraSecret = (String) jadeAuroraXPath.evaluate(jadeAuroraQuery, jadeAuroraXml, XPathConstants.STRING);
            System.out.println(jadeAuroraSecret);
        }
    }
}
