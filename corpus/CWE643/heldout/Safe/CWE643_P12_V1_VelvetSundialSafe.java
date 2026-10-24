import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VelvetSundialSafe {

    public void runVelvetSundial() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_VelvetSundialSafeBase baseObject = new CWE643_P12_V1_VelvetSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VelvetSundialSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VelvetSundialSafeSink extends CWE643_P12_V1_VelvetSundialSafeBase {

    public void action(String data) throws XPathExpressionException {
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
