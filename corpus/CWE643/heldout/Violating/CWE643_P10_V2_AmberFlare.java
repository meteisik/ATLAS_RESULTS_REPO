import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AmberFlare {

    public static String data;

    public void runAmberFlare() throws XPathExpressionException {
        if (5 == 5) {
            data = System.getenv("AMBER_FLARE_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AmberFlareSink()).sinkAmberFlare();
    }
}

class CWE643_P10_V2_AmberFlareSink {

    public void sinkAmberFlare() throws XPathExpressionException {
        String data = CWE643_P10_V2_AmberFlare.data;
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
