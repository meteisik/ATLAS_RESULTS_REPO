import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VelvetFlareSafe {

    public void runVelvetFlare() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_VelvetFlareSafeBase baseObject = new CWE643_P12_V1_VelvetFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VelvetFlareSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VelvetFlareSafeSink extends CWE643_P12_V1_VelvetFlareSafeBase {

    public void action(String data) throws XPathExpressionException {
        String velvetFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetFlareTokens = data.split("||");
            if (velvetFlareTokens.length < 2) {
                return;
            }
            String velvetFlareUser = velvetFlareTokens[0];
            String velvetFlarePass = velvetFlareTokens[1];
            XPath velvetFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetFlareXml = new InputSource(velvetFlareXmlFile);
            String velvetFlareQuery = "//users/user[name/text()='" + velvetFlareUser
                    + "' and pass/text()='" + velvetFlarePass + "']" + "/secret/text()";
            String velvetFlareSecret = (String) velvetFlareXPath.evaluate(velvetFlareQuery, velvetFlareXml, XPathConstants.STRING);
            System.out.println(velvetFlareSecret);
        }
    }
}
