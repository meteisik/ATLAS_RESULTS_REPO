import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_ZephyrCipherSafe {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void runZephyrCipher() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_ZephyrCipherSafeSink()).sinkZephyrCipher(dataContainer);
    }
}

class CWE643_P09_V2_ZephyrCipherSafeSink {

    public void sinkZephyrCipher(CWE643_P09_V2_ZephyrCipherSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
