import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ZephyrMantisSafe {

    public void runZephyrMantis() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_ZephyrMantisSafeBase baseObject = new CWE643_P12_V1_ZephyrMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ZephyrMantisSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ZephyrMantisSafeSink extends CWE643_P12_V1_ZephyrMantisSafeBase {

    public void action(String data) throws XPathExpressionException {
        String zephyrMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrMantisTokens = data.split("||");
            if (zephyrMantisTokens.length < 2) {
                return;
            }
            String zephyrMantisUser = zephyrMantisTokens[0];
            String zephyrMantisPass = zephyrMantisTokens[1];
            XPath zephyrMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrMantisXml = new InputSource(zephyrMantisXmlFile);
            String zephyrMantisQuery = "//users/user[name/text()='" + zephyrMantisUser
                    + "' and pass/text()='" + zephyrMantisPass + "']" + "/secret/text()";
            String zephyrMantisSecret = (String) zephyrMantisXPath.evaluate(zephyrMantisQuery, zephyrMantisXml, XPathConstants.STRING);
            System.out.println(zephyrMantisSecret);
        }
    }
}
