import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SolarFlare {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSolarFlare() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = (new CWE643_P07_V2_SolarFlareSource()).sourceSolarFlare();
        } else {
            data = null;
        }
        String solarFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            solarFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            solarFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] solarFlareTokens = data.split("||");
            if (solarFlareTokens.length < 2) {
                return;
            }
            String solarFlareUser = solarFlareTokens[0];
            String solarFlarePass = solarFlareTokens[1];
            XPath solarFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource solarFlareXml = new InputSource(solarFlareXmlFile);
            String solarFlareQuery = "//users/user[name/text()='" + solarFlareUser
                    + "' and pass/text()='" + solarFlarePass + "']" + "/secret/text()";
            String solarFlareSecret = (String) solarFlareXPath.evaluate(solarFlareQuery, solarFlareXml, XPathConstants.STRING);
            System.out.println(solarFlareSecret);
        }
    }
}

class CWE643_P07_V2_SolarFlareSource {

    public String sourceSolarFlare() {
        String data;
        data = System.getenv("SOLAR_FLARE_ADD");
        return data;
    }
}
