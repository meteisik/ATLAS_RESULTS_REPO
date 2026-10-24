import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ZephyrQuartz {

    public void runZephyrQuartz() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_ADD");
        CWE643_P12_V1_ZephyrQuartzBase baseObject = new CWE643_P12_V1_ZephyrQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ZephyrQuartzBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ZephyrQuartzSink extends CWE643_P12_V1_ZephyrQuartzBase {

    public void action(String data) throws XPathExpressionException {
        String zephyrQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrQuartzTokens = data.split("||");
            if (zephyrQuartzTokens.length < 2) {
                return;
            }
            String zephyrQuartzUser = zephyrQuartzTokens[0];
            String zephyrQuartzPass = zephyrQuartzTokens[1];
            XPath zephyrQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrQuartzXml = new InputSource(zephyrQuartzXmlFile);
            String zephyrQuartzQuery = "//users/user[name/text()='" + zephyrQuartzUser
                    + "' and pass/text()='" + zephyrQuartzPass + "']" + "/secret/text()";
            String zephyrQuartzSecret = (String) zephyrQuartzXPath.evaluate(zephyrQuartzQuery, zephyrQuartzXml, XPathConstants.STRING);
            System.out.println(zephyrQuartzSecret);
        }
    }
}
