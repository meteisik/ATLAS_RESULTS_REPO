import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_SolarFlare {

    public void runSolarFlare() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SOLAR_FLARE_ADD");
            break;
        default:
            data = null;
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_SolarFlareSink()).sinkSolarFlare(dataArray);
    }
}

class CWE643_P08_V2_SolarFlareSink {

    public void sinkSolarFlare(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
