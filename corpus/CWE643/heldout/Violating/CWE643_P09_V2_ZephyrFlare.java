import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_ZephyrFlare {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String containerOne;
    }

    public void runZephyrFlare() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_FLARE_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_ZephyrFlareSink()).sinkZephyrFlare(dataContainer);
    }
}

class CWE643_P09_V2_ZephyrFlareSink {

    public void sinkZephyrFlare(CWE643_P09_V2_ZephyrFlare.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String zephyrFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrFlareTokens = data.split("||");
            if (zephyrFlareTokens.length < 2) {
                return;
            }
            String zephyrFlareUser = zephyrFlareTokens[0];
            String zephyrFlarePass = zephyrFlareTokens[1];
            XPath zephyrFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrFlareXml = new InputSource(zephyrFlareXmlFile);
            String zephyrFlareQuery = "//users/user[name/text()='" + zephyrFlareUser
                    + "' and pass/text()='" + zephyrFlarePass + "']" + "/secret/text()";
            String zephyrFlareSecret = (String) zephyrFlareXPath.evaluate(zephyrFlareQuery, zephyrFlareXml, XPathConstants.STRING);
            System.out.println(zephyrFlareSecret);
        }
    }
}
