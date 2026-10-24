import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VelvetSignalSafe {

    public void runVelvetSignal() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_VelvetSignalSafeBase baseObject = new CWE643_P12_V1_VelvetSignalSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VelvetSignalSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VelvetSignalSafeSink extends CWE643_P12_V1_VelvetSignalSafeBase {

    public void action(String data) throws XPathExpressionException {
        String velvetSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetSignalTokens = data.split("||");
            if (velvetSignalTokens.length < 2) {
                return;
            }
            String velvetSignalUser = velvetSignalTokens[0];
            String velvetSignalPass = velvetSignalTokens[1];
            XPath velvetSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetSignalXml = new InputSource(velvetSignalXmlFile);
            String velvetSignalQuery = "//users/user[name/text()='" + velvetSignalUser
                    + "' and pass/text()='" + velvetSignalPass + "']" + "/secret/text()";
            String velvetSignalSecret = (String) velvetSignalXPath.evaluate(velvetSignalQuery, velvetSignalXml, XPathConstants.STRING);
            System.out.println(velvetSignalSecret);
        }
    }
}
