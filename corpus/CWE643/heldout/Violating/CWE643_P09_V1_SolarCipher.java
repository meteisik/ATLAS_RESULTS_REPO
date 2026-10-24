import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SolarCipher {

    static class Container {
        public String containerOne;
    }

    public void runSolarCipher() throws XPathExpressionException {
        String data;
        data = System.getenv("SOLAR_CIPHER_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SolarCipherSink()).sinkSolarCipher(dataContainer);
    }
}

class CWE643_P09_V1_SolarCipherSink {

    public void sinkSolarCipher(CWE643_P09_V1_SolarCipher.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
