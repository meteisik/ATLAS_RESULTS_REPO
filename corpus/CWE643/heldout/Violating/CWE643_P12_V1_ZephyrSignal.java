import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ZephyrSignal {

    public void runZephyrSignal() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_ADD");
        CWE643_P12_V1_ZephyrSignalBase baseObject = new CWE643_P12_V1_ZephyrSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ZephyrSignalBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ZephyrSignalSink extends CWE643_P12_V1_ZephyrSignalBase {

    public void action(String data) throws XPathExpressionException {
        String zephyrSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrSignalTokens = data.split("||");
            if (zephyrSignalTokens.length < 2) {
                return;
            }
            String zephyrSignalUser = zephyrSignalTokens[0];
            String zephyrSignalPass = zephyrSignalTokens[1];
            XPath zephyrSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrSignalXml = new InputSource(zephyrSignalXmlFile);
            String zephyrSignalQuery = "//users/user[name/text()='" + zephyrSignalUser
                    + "' and pass/text()='" + zephyrSignalPass + "']" + "/secret/text()";
            String zephyrSignalSecret = (String) zephyrSignalXPath.evaluate(zephyrSignalQuery, zephyrSignalXml, XPathConstants.STRING);
            System.out.println(zephyrSignalSecret);
        }
    }
}
