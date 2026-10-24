import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_ZephyrPrism {
    private static int privateFive = 5;

    public void runZephyrPrism() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_PRISM_ADD");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_ZephyrPrismSink()).sinkZephyrPrism(dataArray);
    }
}

class CWE643_P08_V2_ZephyrPrismSink {

    public void sinkZephyrPrism(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String zephyrPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrPrismTokens = data.split("||");
            if (zephyrPrismTokens.length < 2) {
                return;
            }
            String zephyrPrismUser = zephyrPrismTokens[0];
            String zephyrPrismPass = zephyrPrismTokens[1];
            XPath zephyrPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrPrismXml = new InputSource(zephyrPrismXmlFile);
            String zephyrPrismQuery = "//users/user[name/text()='" + zephyrPrismUser
                    + "' and pass/text()='" + zephyrPrismPass + "']" + "/secret/text()";
            String zephyrPrismSecret = (String) zephyrPrismXPath.evaluate(zephyrPrismQuery, zephyrPrismXml, XPathConstants.STRING);
            System.out.println(zephyrPrismSecret);
        }
    }
}
