import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_OnyxRaven {
    private static boolean privateReturnsTrue() { return true; }

    private String sourceOnyxRaven() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_RAVEN_ADD");
        } else {
            data = null;
        }
        return data;
    }

    public void runOnyxRaven() throws XPathExpressionException {
        String data = sourceOnyxRaven();
        String onyxRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxRavenTokens = data.split("||");
            if (onyxRavenTokens.length < 2) {
                return;
            }
            String onyxRavenUser = onyxRavenTokens[0];
            String onyxRavenPass = onyxRavenTokens[1];
            XPath onyxRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxRavenXml = new InputSource(onyxRavenXmlFile);
            String onyxRavenQuery = "//users/user[name/text()='" + onyxRavenUser
                    + "' and pass/text()='" + onyxRavenPass + "']" + "/secret/text()";
            String onyxRavenSecret = (String) onyxRavenXPath.evaluate(onyxRavenQuery, onyxRavenXml, XPathConstants.STRING);
            System.out.println(onyxRavenSecret);
        }
    }
}
