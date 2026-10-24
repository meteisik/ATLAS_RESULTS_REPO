import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetPrismSafe {

    public static String data;

    public void runVelvetPrism() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_VelvetPrismSafeSink()).sinkVelvetPrism();
    }
}

class CWE643_P10_V1_VelvetPrismSafeSink {

    public void sinkVelvetPrism() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetPrismSafe.data;
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
