import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_VelvetFlare {

    public void runVelvetFlare() throws XPathExpressionException {
        String data;
        if (true) {
            data = (new CWE643_P07_V2_VelvetFlareSource()).sourceVelvetFlare();
        } else {
            data = null;
        }
        String velvetFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetFlareTokens = data.split("||");
            if (velvetFlareTokens.length < 2) {
                return;
            }
            String velvetFlareUser = velvetFlareTokens[0];
            String velvetFlarePass = velvetFlareTokens[1];
            XPath velvetFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetFlareXml = new InputSource(velvetFlareXmlFile);
            String velvetFlareQuery = "//users/user[name/text()='" + velvetFlareUser
                    + "' and pass/text()='" + velvetFlarePass + "']" + "/secret/text()";
            String velvetFlareSecret = (String) velvetFlareXPath.evaluate(velvetFlareQuery, velvetFlareXml, XPathConstants.STRING);
            System.out.println(velvetFlareSecret);
        }
    }
}

class CWE643_P07_V2_VelvetFlareSource {

    public String sourceVelvetFlare() {
        String data;
        data = System.getenv("VELVET_FLARE_ADD");
        return data;
    }
}
