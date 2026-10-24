import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_SaffronGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronGlint() throws XPathExpressionException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P06_V2_SaffronGlintSafeSink()).sinkSaffronGlint(data);
    }
}

class CWE643_P06_V2_SaffronGlintSafeSink {

    public void sinkSaffronGlint(String data) throws XPathExpressionException {
        String saffronGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronGlintTokens = data.split("||");
            if (saffronGlintTokens.length < 2) {
                return;
            }
            String saffronGlintUser = saffronGlintTokens[0];
            String saffronGlintPass = saffronGlintTokens[1];
            XPath saffronGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronGlintXml = new InputSource(saffronGlintXmlFile);
            String saffronGlintQuery = "//users/user[name/text()='" + saffronGlintUser
                    + "' and pass/text()='" + saffronGlintPass + "']" + "/secret/text()";
            String saffronGlintSecret = (String) saffronGlintXPath.evaluate(saffronGlintQuery, saffronGlintXml, XPathConstants.STRING);
            System.out.println(saffronGlintSecret);
        }
    }
}
