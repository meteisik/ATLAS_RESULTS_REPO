import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_ZephyrCascade {

    public void runZephyrCascade() throws XPathExpressionException {
        String data;
        if (true) {
            data = System.getenv("ZEPHYR_CASCADE_ADD");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_ZephyrCascadeSink()).sinkZephyrCascade(dataArray);
    }
}

class CWE643_P08_V2_ZephyrCascadeSink {

    public void sinkZephyrCascade(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String zephyrCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrCascadeTokens = data.split("||");
            if (zephyrCascadeTokens.length < 2) {
                return;
            }
            String zephyrCascadeUser = zephyrCascadeTokens[0];
            String zephyrCascadePass = zephyrCascadeTokens[1];
            XPath zephyrCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrCascadeXml = new InputSource(zephyrCascadeXmlFile);
            String zephyrCascadeQuery = "//users/user[name/text()='" + zephyrCascadeUser
                    + "' and pass/text()='" + zephyrCascadePass + "']" + "/secret/text()";
            String zephyrCascadeSecret = (String) zephyrCascadeXPath.evaluate(zephyrCascadeQuery, zephyrCascadeXml, XPathConstants.STRING);
            System.out.println(zephyrCascadeSecret);
        }
    }
}
