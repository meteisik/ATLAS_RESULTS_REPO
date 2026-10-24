import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_AmberFlare {

    static class Container {
        public String containerOne;
    }

    public void runAmberFlare() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AMBER_FLARE_ADD");
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_AmberFlareSink()).sinkAmberFlare(dataContainer);
    }
}

class CWE643_P09_V2_AmberFlareSink {

    public void sinkAmberFlare(CWE643_P09_V2_AmberFlare.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String amberFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberFlareTokens = data.split("||");
            if (amberFlareTokens.length < 2) {
                return;
            }
            String amberFlareUser = amberFlareTokens[0];
            String amberFlarePass = amberFlareTokens[1];
            XPath amberFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource amberFlareXml = new InputSource(amberFlareXmlFile);
            String amberFlareQuery = "//users/user[name/text()='" + amberFlareUser
                    + "' and pass/text()='" + amberFlarePass + "']" + "/secret/text()";
            String amberFlareSecret = (String) amberFlareXPath.evaluate(amberFlareQuery, amberFlareXml, XPathConstants.STRING);
            System.out.println(amberFlareSecret);
        }
    }
}
