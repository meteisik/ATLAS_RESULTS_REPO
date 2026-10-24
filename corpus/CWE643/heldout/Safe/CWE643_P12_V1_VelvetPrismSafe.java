import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VelvetPrismSafe {

    public void runVelvetPrism() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_VelvetPrismSafeBase baseObject = new CWE643_P12_V1_VelvetPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VelvetPrismSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VelvetPrismSafeSink extends CWE643_P12_V1_VelvetPrismSafeBase {

    public void action(String data) throws XPathExpressionException {
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
