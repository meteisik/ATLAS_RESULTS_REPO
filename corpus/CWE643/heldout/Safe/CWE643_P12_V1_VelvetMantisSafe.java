import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VelvetMantisSafe {

    public void runVelvetMantis() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_VelvetMantisSafeBase baseObject = new CWE643_P12_V1_VelvetMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VelvetMantisSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VelvetMantisSafeSink extends CWE643_P12_V1_VelvetMantisSafeBase {

    public void action(String data) throws XPathExpressionException {
        String velvetMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetMantisTokens = data.split("||");
            if (velvetMantisTokens.length < 2) {
                return;
            }
            String velvetMantisUser = velvetMantisTokens[0];
            String velvetMantisPass = velvetMantisTokens[1];
            XPath velvetMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetMantisXml = new InputSource(velvetMantisXmlFile);
            String velvetMantisQuery = "//users/user[name/text()='" + velvetMantisUser
                    + "' and pass/text()='" + velvetMantisPass + "']" + "/secret/text()";
            String velvetMantisSecret = (String) velvetMantisXPath.evaluate(velvetMantisQuery, velvetMantisXml, XPathConstants.STRING);
            System.out.println(velvetMantisSecret);
        }
    }
}
