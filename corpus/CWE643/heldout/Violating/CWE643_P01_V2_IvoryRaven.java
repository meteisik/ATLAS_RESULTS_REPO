import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_IvoryRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryRaven() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("IVORY_RAVEN_ADD");
        } else {
            data = null;
        }
        String ivoryRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryRavenTokens = data.split("||");
            if (ivoryRavenTokens.length < 2) {
                return;
            }
            String ivoryRavenUser = ivoryRavenTokens[0];
            String ivoryRavenPass = ivoryRavenTokens[1];
            XPath ivoryRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryRavenXml = new InputSource(ivoryRavenXmlFile);
            String ivoryRavenQuery = "//users/user[name/text()='" + ivoryRavenUser
                    + "' and pass/text()='" + ivoryRavenPass + "']" + "/secret/text()";
            String ivoryRavenSecret = (String) ivoryRavenXPath.evaluate(ivoryRavenQuery, ivoryRavenXml, XPathConstants.STRING);
            System.out.println(ivoryRavenSecret);
        }
    }
}
