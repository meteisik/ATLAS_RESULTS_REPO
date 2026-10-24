import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_SaffronFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronFlare() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P06_V2_SaffronFlareSafeSink()).sinkSaffronFlare(data);
    }
}

class CWE643_P06_V2_SaffronFlareSafeSink {

    public void sinkSaffronFlare(String data) throws XPathExpressionException {
        String saffronFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronFlareTokens = data.split("||");
            if (saffronFlareTokens.length < 2) {
                return;
            }
            String saffronFlareUser = saffronFlareTokens[0];
            String saffronFlarePass = saffronFlareTokens[1];
            XPath saffronFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronFlareXml = new InputSource(saffronFlareXmlFile);
            String saffronFlareQuery = "//users/user[name/text()='" + saffronFlareUser
                    + "' and pass/text()='" + saffronFlarePass + "']" + "/secret/text()";
            String saffronFlareSecret = (String) saffronFlareXPath.evaluate(saffronFlareQuery, saffronFlareXml, XPathConstants.STRING);
            System.out.println(saffronFlareSecret);
        }
    }
}
