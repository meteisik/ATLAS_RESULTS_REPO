import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SolarFlareSafe {

    static class Container {
        public String containerOne;
    }

    public void runSolarFlare() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SolarFlareSafeSink()).sinkSolarFlare(dataContainer);
    }
}

class CWE643_P09_V1_SolarFlareSafeSink {

    public void sinkSolarFlare(CWE643_P09_V1_SolarFlareSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
