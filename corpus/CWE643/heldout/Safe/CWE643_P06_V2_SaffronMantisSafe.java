import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_SaffronMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronMantis() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P06_V2_SaffronMantisSafeSink()).sinkSaffronMantis(data);
    }
}

class CWE643_P06_V2_SaffronMantisSafeSink {

    public void sinkSaffronMantis(String data) throws XPathExpressionException {
        String saffronMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronMantisTokens = data.split("||");
            if (saffronMantisTokens.length < 2) {
                return;
            }
            String saffronMantisUser = saffronMantisTokens[0];
            String saffronMantisPass = saffronMantisTokens[1];
            XPath saffronMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronMantisXml = new InputSource(saffronMantisXmlFile);
            String saffronMantisQuery = "//users/user[name/text()='" + saffronMantisUser
                    + "' and pass/text()='" + saffronMantisPass + "']" + "/secret/text()";
            String saffronMantisSecret = (String) saffronMantisXPath.evaluate(saffronMantisQuery, saffronMantisXml, XPathConstants.STRING);
            System.out.println(saffronMantisSecret);
        }
    }
}
