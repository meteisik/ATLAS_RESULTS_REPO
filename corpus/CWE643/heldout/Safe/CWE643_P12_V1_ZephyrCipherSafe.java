import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ZephyrCipherSafe {

    public void runZephyrCipher() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_ZephyrCipherSafeBase baseObject = new CWE643_P12_V1_ZephyrCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ZephyrCipherSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ZephyrCipherSafeSink extends CWE643_P12_V1_ZephyrCipherSafeBase {

    public void action(String data) throws XPathExpressionException {
        String zephyrCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrCipherTokens = data.split("||");
            if (zephyrCipherTokens.length < 2) {
                return;
            }
            String zephyrCipherUser = zephyrCipherTokens[0];
            String zephyrCipherPass = zephyrCipherTokens[1];
            XPath zephyrCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrCipherXml = new InputSource(zephyrCipherXmlFile);
            String zephyrCipherQuery = "//users/user[name/text()='" + zephyrCipherUser
                    + "' and pass/text()='" + zephyrCipherPass + "']" + "/secret/text()";
            String zephyrCipherSecret = (String) zephyrCipherXPath.evaluate(zephyrCipherQuery, zephyrCipherXml, XPathConstants.STRING);
            System.out.println(zephyrCipherSecret);
        }
    }
}
