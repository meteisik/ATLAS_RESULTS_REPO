import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_ZephyrAurora {

    static class Container {
        public String containerOne;
    }

    public void runZephyrAurora() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = System.getenv("ZEPHYR_AURORA_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_ZephyrAuroraSink()).sinkZephyrAurora(dataContainer);
    }
}

class CWE643_P09_V2_ZephyrAuroraSink {

    public void sinkZephyrAurora(CWE643_P09_V2_ZephyrAurora.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String zephyrAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrAuroraTokens = data.split("||");
            if (zephyrAuroraTokens.length < 2) {
                return;
            }
            String zephyrAuroraUser = zephyrAuroraTokens[0];
            String zephyrAuroraPass = zephyrAuroraTokens[1];
            XPath zephyrAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrAuroraXml = new InputSource(zephyrAuroraXmlFile);
            String zephyrAuroraQuery = "//users/user[name/text()='" + zephyrAuroraUser
                    + "' and pass/text()='" + zephyrAuroraPass + "']" + "/secret/text()";
            String zephyrAuroraSecret = (String) zephyrAuroraXPath.evaluate(zephyrAuroraQuery, zephyrAuroraXml, XPathConstants.STRING);
            System.out.println(zephyrAuroraSecret);
        }
    }
}
