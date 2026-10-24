import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_ZephyrAuroraSafe {

    public void runZephyrAurora() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_ZephyrAuroraSafeSink()).sinkZephyrAurora(dataArray);
    }
}

class CWE643_P08_V2_ZephyrAuroraSafeSink {

    public void sinkZephyrAurora(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
