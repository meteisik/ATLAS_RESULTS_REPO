import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetFlare {

    public static String data;

    public void runVelvetFlare() throws XPathExpressionException {
        data = System.getenv("VELVET_FLARE_ADD");
        (new CWE643_P10_V1_VelvetFlareSink()).sinkVelvetFlare();
    }
}

class CWE643_P10_V1_VelvetFlareSink {

    public void sinkVelvetFlare() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetFlare.data;
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
