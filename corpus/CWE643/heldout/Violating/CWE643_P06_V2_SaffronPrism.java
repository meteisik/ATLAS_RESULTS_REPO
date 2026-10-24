import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_SaffronPrism {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronPrism() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("SAFFRON_PRISM_ADD");
        } else {
            data = null;
        }
        (new CWE643_P06_V2_SaffronPrismSink()).sinkSaffronPrism(data);
    }
}

class CWE643_P06_V2_SaffronPrismSink {

    public void sinkSaffronPrism(String data) throws XPathExpressionException {
        String saffronPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronPrismTokens = data.split("||");
            if (saffronPrismTokens.length < 2) {
                return;
            }
            String saffronPrismUser = saffronPrismTokens[0];
            String saffronPrismPass = saffronPrismTokens[1];
            XPath saffronPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronPrismXml = new InputSource(saffronPrismXmlFile);
            String saffronPrismQuery = "//users/user[name/text()='" + saffronPrismUser
                    + "' and pass/text()='" + saffronPrismPass + "']" + "/secret/text()";
            String saffronPrismSecret = (String) saffronPrismXPath.evaluate(saffronPrismQuery, saffronPrismXml, XPathConstants.STRING);
            System.out.println(saffronPrismSecret);
        }
    }
}
