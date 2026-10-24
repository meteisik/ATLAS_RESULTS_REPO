import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SaffronAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronAurora() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = (new CWE643_P07_V2_SaffronAuroraSafeSource()).sourceSaffronAurora();
        } else {
            data = null;
        }
        String saffronAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronAuroraTokens = data.split("||");
            if (saffronAuroraTokens.length < 2) {
                return;
            }
            String saffronAuroraUser = saffronAuroraTokens[0];
            String saffronAuroraPass = saffronAuroraTokens[1];
            XPath saffronAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronAuroraXml = new InputSource(saffronAuroraXmlFile);
            String saffronAuroraQuery = "//users/user[name/text()='" + saffronAuroraUser
                    + "' and pass/text()='" + saffronAuroraPass + "']" + "/secret/text()";
            String saffronAuroraSecret = (String) saffronAuroraXPath.evaluate(saffronAuroraQuery, saffronAuroraXml, XPathConstants.STRING);
            System.out.println(saffronAuroraSecret);
        }
    }
}

class CWE643_P07_V2_SaffronAuroraSafeSource {

    public String sourceSaffronAurora() {
        String data;
        data = "foo";
        return data;
    }
}
