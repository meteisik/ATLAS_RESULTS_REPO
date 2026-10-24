import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_ZephyrQuartzSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runZephyrQuartz() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_ZephyrQuartzSafeSink()).sinkZephyrQuartz(dataArray);
    }
}

class CWE643_P08_V2_ZephyrQuartzSafeSink {

    public void sinkZephyrQuartz(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String zephyrQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrQuartzTokens = data.split("||");
            if (zephyrQuartzTokens.length < 2) {
                return;
            }
            String zephyrQuartzUser = zephyrQuartzTokens[0];
            String zephyrQuartzPass = zephyrQuartzTokens[1];
            XPath zephyrQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrQuartzXml = new InputSource(zephyrQuartzXmlFile);
            String zephyrQuartzQuery = "//users/user[name/text()='" + zephyrQuartzUser
                    + "' and pass/text()='" + zephyrQuartzPass + "']" + "/secret/text()";
            String zephyrQuartzSecret = (String) zephyrQuartzXPath.evaluate(zephyrQuartzQuery, zephyrQuartzXml, XPathConstants.STRING);
            System.out.println(zephyrQuartzSecret);
        }
    }
}
