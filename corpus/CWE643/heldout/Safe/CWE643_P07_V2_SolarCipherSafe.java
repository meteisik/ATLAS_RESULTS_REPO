import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SolarCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSolarCipher() throws XPathExpressionException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = (new CWE643_P07_V2_SolarCipherSafeSource()).sourceSolarCipher();
        } else {
            data = null;
        }
        String solarCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            solarCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            solarCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] solarCipherTokens = data.split("||");
            if (solarCipherTokens.length < 2) {
                return;
            }
            String solarCipherUser = solarCipherTokens[0];
            String solarCipherPass = solarCipherTokens[1];
            XPath solarCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource solarCipherXml = new InputSource(solarCipherXmlFile);
            String solarCipherQuery = "//users/user[name/text()='" + solarCipherUser
                    + "' and pass/text()='" + solarCipherPass + "']" + "/secret/text()";
            String solarCipherSecret = (String) solarCipherXPath.evaluate(solarCipherQuery, solarCipherXml, XPathConstants.STRING);
            System.out.println(solarCipherSecret);
        }
    }
}

class CWE643_P07_V2_SolarCipherSafeSource {

    public String sourceSolarCipher() {
        String data;
        data = "foo";
        return data;
    }
}
