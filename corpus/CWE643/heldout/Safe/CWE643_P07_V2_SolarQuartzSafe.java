import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SolarQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSolarQuartz() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = (new CWE643_P07_V2_SolarQuartzSafeSource()).sourceSolarQuartz();
        } else {
            data = null;
        }
        String solarQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            solarQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            solarQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] solarQuartzTokens = data.split("||");
            if (solarQuartzTokens.length < 2) {
                return;
            }
            String solarQuartzUser = solarQuartzTokens[0];
            String solarQuartzPass = solarQuartzTokens[1];
            XPath solarQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource solarQuartzXml = new InputSource(solarQuartzXmlFile);
            String solarQuartzQuery = "//users/user[name/text()='" + solarQuartzUser
                    + "' and pass/text()='" + solarQuartzPass + "']" + "/secret/text()";
            String solarQuartzSecret = (String) solarQuartzXPath.evaluate(solarQuartzQuery, solarQuartzXml, XPathConstants.STRING);
            System.out.println(solarQuartzSecret);
        }
    }
}

class CWE643_P07_V2_SolarQuartzSafeSource {

    public String sourceSolarQuartz() {
        String data;
        data = "foo";
        return data;
    }
}
