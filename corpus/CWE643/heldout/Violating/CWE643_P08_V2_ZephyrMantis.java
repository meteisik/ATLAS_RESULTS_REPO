import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_ZephyrMantis {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runZephyrMantis() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_MANTIS_ADD");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_ZephyrMantisSink()).sinkZephyrMantis(dataArray);
    }
}

class CWE643_P08_V2_ZephyrMantisSink {

    public void sinkZephyrMantis(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
