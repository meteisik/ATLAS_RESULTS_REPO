import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_VelvetSundialSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runVelvetSundial() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE643_P07_V2_VelvetSundialSafeSource()).sourceVelvetSundial();
        } else {
            data = null;
        }
        String velvetSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetSundialTokens = data.split("||");
            if (velvetSundialTokens.length < 2) {
                return;
            }
            String velvetSundialUser = velvetSundialTokens[0];
            String velvetSundialPass = velvetSundialTokens[1];
            XPath velvetSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetSundialXml = new InputSource(velvetSundialXmlFile);
            String velvetSundialQuery = "//users/user[name/text()='" + velvetSundialUser
                    + "' and pass/text()='" + velvetSundialPass + "']" + "/secret/text()";
            String velvetSundialSecret = (String) velvetSundialXPath.evaluate(velvetSundialQuery, velvetSundialXml, XPathConstants.STRING);
            System.out.println(velvetSundialSecret);
        }
    }
}

class CWE643_P07_V2_VelvetSundialSafeSource {

    public String sourceVelvetSundial() {
        String data;
        data = "foo";
        return data;
    }
}
