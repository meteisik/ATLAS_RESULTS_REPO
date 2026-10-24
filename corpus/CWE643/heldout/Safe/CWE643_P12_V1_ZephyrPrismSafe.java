import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ZephyrPrismSafe {

    public void runZephyrPrism() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_ZephyrPrismSafeBase baseObject = new CWE643_P12_V1_ZephyrPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ZephyrPrismSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ZephyrPrismSafeSink extends CWE643_P12_V1_ZephyrPrismSafeBase {

    public void action(String data) throws XPathExpressionException {
        String zephyrPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrPrismTokens = data.split("||");
            if (zephyrPrismTokens.length < 2) {
                return;
            }
            String zephyrPrismUser = zephyrPrismTokens[0];
            String zephyrPrismPass = zephyrPrismTokens[1];
            XPath zephyrPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrPrismXml = new InputSource(zephyrPrismXmlFile);
            String zephyrPrismQuery = "//users/user[name/text()='" + zephyrPrismUser
                    + "' and pass/text()='" + zephyrPrismPass + "']" + "/secret/text()";
            String zephyrPrismSecret = (String) zephyrPrismXPath.evaluate(zephyrPrismQuery, zephyrPrismXml, XPathConstants.STRING);
            System.out.println(zephyrPrismSecret);
        }
    }
}
