import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SilentRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSilentRaven() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = (new CWE643_P07_V2_SilentRavenSafeSource()).sourceSilentRaven();
        } else {
            data = null;
        }
        String silentRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentRavenTokens = data.split("||");
            if (silentRavenTokens.length < 2) {
                return;
            }
            String silentRavenUser = silentRavenTokens[0];
            String silentRavenPass = silentRavenTokens[1];
            XPath silentRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource silentRavenXml = new InputSource(silentRavenXmlFile);
            String silentRavenQuery = "//users/user[name/text()='" + silentRavenUser
                    + "' and pass/text()='" + silentRavenPass + "']" + "/secret/text()";
            String silentRavenSecret = (String) silentRavenXPath.evaluate(silentRavenQuery, silentRavenXml, XPathConstants.STRING);
            System.out.println(silentRavenSecret);
        }
    }
}

class CWE643_P07_V2_SilentRavenSafeSource {

    public String sourceSilentRaven() {
        String data;
        data = "foo";
        return data;
    }
}
