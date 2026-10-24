import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_ArcticLanternSafe {

    public void runArcticLantern() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_ArcticLanternSafeBase baseObject = new CWE643_P12_V2_ArcticLanternSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_ArcticLanternSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_ArcticLanternSafeSink extends CWE643_P12_V2_ArcticLanternSafeBase {

    public void action(String data) throws XPathExpressionException {
        String arcticLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticLanternTokens = data.split("||");
            if (arcticLanternTokens.length < 2) {
                return;
            }
            String arcticLanternUser = arcticLanternTokens[0];
            String arcticLanternPass = arcticLanternTokens[1];
            XPath arcticLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticLanternXml = new InputSource(arcticLanternXmlFile);
            String arcticLanternQuery = "//users/user[name/text()='" + arcticLanternUser
                    + "' and pass/text()='" + arcticLanternPass + "']" + "/secret/text()";
            String arcticLanternSecret = (String) arcticLanternXPath.evaluate(arcticLanternQuery, arcticLanternXml, XPathConstants.STRING);
            System.out.println(arcticLanternSecret);
        }
    }
}
