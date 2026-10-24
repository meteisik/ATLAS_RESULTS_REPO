import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ZephyrCascadeSafe {

    public void runZephyrCascade() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_ZephyrCascadeSafeBase baseObject = new CWE643_P12_V1_ZephyrCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ZephyrCascadeSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ZephyrCascadeSafeSink extends CWE643_P12_V1_ZephyrCascadeSafeBase {

    public void action(String data) throws XPathExpressionException {
        String zephyrCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrCascadeTokens = data.split("||");
            if (zephyrCascadeTokens.length < 2) {
                return;
            }
            String zephyrCascadeUser = zephyrCascadeTokens[0];
            String zephyrCascadePass = zephyrCascadeTokens[1];
            XPath zephyrCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrCascadeXml = new InputSource(zephyrCascadeXmlFile);
            String zephyrCascadeQuery = "//users/user[name/text()='" + zephyrCascadeUser
                    + "' and pass/text()='" + zephyrCascadePass + "']" + "/secret/text()";
            String zephyrCascadeSecret = (String) zephyrCascadeXPath.evaluate(zephyrCascadeQuery, zephyrCascadeXml, XPathConstants.STRING);
            System.out.println(zephyrCascadeSecret);
        }
    }
}
