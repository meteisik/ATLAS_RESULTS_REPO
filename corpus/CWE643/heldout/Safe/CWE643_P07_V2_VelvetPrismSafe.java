import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_VelvetPrismSafe {
    private static boolean privateTrue = true;

    public void runVelvetPrism() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = (new CWE643_P07_V2_VelvetPrismSafeSource()).sourceVelvetPrism();
        } else {
            data = null;
        }
        String velvetPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetPrismTokens = data.split("||");
            if (velvetPrismTokens.length < 2) {
                return;
            }
            String velvetPrismUser = velvetPrismTokens[0];
            String velvetPrismPass = velvetPrismTokens[1];
            XPath velvetPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetPrismXml = new InputSource(velvetPrismXmlFile);
            String velvetPrismQuery = "//users/user[name/text()='" + velvetPrismUser
                    + "' and pass/text()='" + velvetPrismPass + "']" + "/secret/text()";
            String velvetPrismSecret = (String) velvetPrismXPath.evaluate(velvetPrismQuery, velvetPrismXml, XPathConstants.STRING);
            System.out.println(velvetPrismSecret);
        }
    }
}

class CWE643_P07_V2_VelvetPrismSafeSource {

    public String sourceVelvetPrism() {
        String data;
        data = "foo";
        return data;
    }
}
