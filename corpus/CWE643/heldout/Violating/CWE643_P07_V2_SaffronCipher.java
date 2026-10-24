import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SaffronCipher {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronCipher() throws XPathExpressionException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = (new CWE643_P07_V2_SaffronCipherSource()).sourceSaffronCipher();
        } else {
            data = null;
        }
        String saffronCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronCipherTokens = data.split("||");
            if (saffronCipherTokens.length < 2) {
                return;
            }
            String saffronCipherUser = saffronCipherTokens[0];
            String saffronCipherPass = saffronCipherTokens[1];
            XPath saffronCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronCipherXml = new InputSource(saffronCipherXmlFile);
            String saffronCipherQuery = "//users/user[name/text()='" + saffronCipherUser
                    + "' and pass/text()='" + saffronCipherPass + "']" + "/secret/text()";
            String saffronCipherSecret = (String) saffronCipherXPath.evaluate(saffronCipherQuery, saffronCipherXml, XPathConstants.STRING);
            System.out.println(saffronCipherSecret);
        }
    }
}

class CWE643_P07_V2_SaffronCipherSource {

    public String sourceSaffronCipher() {
        String data;
        data = System.getenv("SAFFRON_CIPHER_ADD");
        return data;
    }
}
