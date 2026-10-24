import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_ZephyrFlareSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runZephyrFlare() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_ZephyrFlareSafeSink()).sinkZephyrFlare(dataArray);
    }
}

class CWE643_P08_V2_ZephyrFlareSafeSink {

    public void sinkZephyrFlare(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
