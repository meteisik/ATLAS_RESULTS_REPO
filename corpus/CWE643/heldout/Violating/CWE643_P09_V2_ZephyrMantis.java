import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_ZephyrMantis {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void runZephyrMantis() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_MANTIS_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_ZephyrMantisSink()).sinkZephyrMantis(dataContainer);
    }
}

class CWE643_P09_V2_ZephyrMantisSink {

    public void sinkZephyrMantis(CWE643_P09_V2_ZephyrMantis.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String zephyrMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrMantisTokens = data.split("||");
            if (zephyrMantisTokens.length < 2) {
                return;
            }
            String zephyrMantisUser = zephyrMantisTokens[0];
            String zephyrMantisPass = zephyrMantisTokens[1];
            XPath zephyrMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrMantisXml = new InputSource(zephyrMantisXmlFile);
            String zephyrMantisQuery = "//users/user[name/text()='" + zephyrMantisUser
                    + "' and pass/text()='" + zephyrMantisPass + "']" + "/secret/text()";
            String zephyrMantisSecret = (String) zephyrMantisXPath.evaluate(zephyrMantisQuery, zephyrMantisXml, XPathConstants.STRING);
            System.out.println(zephyrMantisSecret);
        }
    }
}
