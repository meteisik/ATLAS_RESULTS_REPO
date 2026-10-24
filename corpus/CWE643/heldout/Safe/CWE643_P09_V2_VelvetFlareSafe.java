import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_VelvetFlareSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String containerOne;
    }

    public void runVelvetFlare() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_VelvetFlareSafeSink()).sinkVelvetFlare(dataContainer);
    }
}

class CWE643_P09_V2_VelvetFlareSafeSink {

    public void sinkVelvetFlare(CWE643_P09_V2_VelvetFlareSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
