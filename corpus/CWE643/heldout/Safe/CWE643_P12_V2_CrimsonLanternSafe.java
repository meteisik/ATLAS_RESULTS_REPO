import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonLantern() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_CrimsonLanternSafeBase baseObject = new CWE643_P12_V2_CrimsonLanternSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonLanternSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonLanternSafeSink extends CWE643_P12_V2_CrimsonLanternSafeBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonLanternTokens = data.split("||");
            if (crimsonLanternTokens.length < 2) {
                return;
            }
            String crimsonLanternUser = crimsonLanternTokens[0];
            String crimsonLanternPass = crimsonLanternTokens[1];
            XPath crimsonLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonLanternXml = new InputSource(crimsonLanternXmlFile);
            String crimsonLanternQuery = "//users/user[name/text()='" + crimsonLanternUser
                    + "' and pass/text()='" + crimsonLanternPass + "']" + "/secret/text()";
            String crimsonLanternSecret = (String) crimsonLanternXPath.evaluate(crimsonLanternQuery, crimsonLanternXml, XPathConstants.STRING);
            System.out.println(crimsonLanternSecret);
        }
    }
}
