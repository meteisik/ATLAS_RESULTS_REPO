import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ZephyrCipher {
    private static int privateFive = 5;

    public static String data;

    public void runZephyrCipher() throws XPathExpressionException {
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_CIPHER_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_ZephyrCipherSink()).sinkZephyrCipher();
    }
}

class CWE643_P10_V2_ZephyrCipherSink {

    public void sinkZephyrCipher() throws XPathExpressionException {
        String data = CWE643_P10_V2_ZephyrCipher.data;
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
