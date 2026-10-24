import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SaffronCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronCascade() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = (new CWE643_P07_V2_SaffronCascadeSafeSource()).sourceSaffronCascade();
        } else {
            data = null;
        }
        String saffronCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronCascadeTokens = data.split("||");
            if (saffronCascadeTokens.length < 2) {
                return;
            }
            String saffronCascadeUser = saffronCascadeTokens[0];
            String saffronCascadePass = saffronCascadeTokens[1];
            XPath saffronCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronCascadeXml = new InputSource(saffronCascadeXmlFile);
            String saffronCascadeQuery = "//users/user[name/text()='" + saffronCascadeUser
                    + "' and pass/text()='" + saffronCascadePass + "']" + "/secret/text()";
            String saffronCascadeSecret = (String) saffronCascadeXPath.evaluate(saffronCascadeQuery, saffronCascadeXml, XPathConstants.STRING);
            System.out.println(saffronCascadeSecret);
        }
    }
}

class CWE643_P07_V2_SaffronCascadeSafeSource {

    public String sourceSaffronCascade() {
        String data;
        data = "foo";
        return data;
    }
}
