import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_AmberPrismSafe {

    public void runAmberPrism() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_AmberPrismSafeBase baseObject = new CWE643_P12_V1_AmberPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_AmberPrismSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_AmberPrismSafeSink extends CWE643_P12_V1_AmberPrismSafeBase {

    public void action(String data) throws XPathExpressionException {
        String amberPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberPrismTokens = data.split("||");
            if (amberPrismTokens.length < 2) {
                return;
            }
            String amberPrismUser = amberPrismTokens[0];
            String amberPrismPass = amberPrismTokens[1];
            XPath amberPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource amberPrismXml = new InputSource(amberPrismXmlFile);
            String amberPrismQuery = "//users/user[name/text()='" + amberPrismUser
                    + "' and pass/text()='" + amberPrismPass + "']" + "/secret/text()";
            String amberPrismSecret = (String) amberPrismXPath.evaluate(amberPrismQuery, amberPrismXml, XPathConstants.STRING);
            System.out.println(amberPrismSecret);
        }
    }
}
