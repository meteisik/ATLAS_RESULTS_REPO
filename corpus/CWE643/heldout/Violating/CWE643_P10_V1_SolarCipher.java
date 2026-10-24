import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_SolarCipher {

    public static String data;

    public void runSolarCipher() throws XPathExpressionException {
        data = System.getenv("SOLAR_CIPHER_ADD");
        (new CWE643_P10_V1_SolarCipherSink()).sinkSolarCipher();
    }
}

class CWE643_P10_V1_SolarCipherSink {

    public void sinkSolarCipher() throws XPathExpressionException {
        String data = CWE643_P10_V1_SolarCipher.data;
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
