import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_IvoryNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryNebula() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("IVORY_NEBULA_ADD");
        } else {
            data = null;
        }
        String ivoryNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryNebulaTokens = data.split("||");
            if (ivoryNebulaTokens.length < 2) {
                return;
            }
            String ivoryNebulaUser = ivoryNebulaTokens[0];
            String ivoryNebulaPass = ivoryNebulaTokens[1];
            XPath ivoryNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryNebulaXml = new InputSource(ivoryNebulaXmlFile);
            String ivoryNebulaQuery = "//users/user[name/text()='" + ivoryNebulaUser
                    + "' and pass/text()='" + ivoryNebulaPass + "']" + "/secret/text()";
            String ivoryNebulaSecret = (String) ivoryNebulaXPath.evaluate(ivoryNebulaQuery, ivoryNebulaXml, XPathConstants.STRING);
            System.out.println(ivoryNebulaSecret);
        }
    }
}
