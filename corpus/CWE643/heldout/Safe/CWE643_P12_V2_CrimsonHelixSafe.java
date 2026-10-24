import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonHelix() throws XPathExpressionException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_CrimsonHelixSafeBase baseObject = new CWE643_P12_V2_CrimsonHelixSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonHelixSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonHelixSafeSink extends CWE643_P12_V2_CrimsonHelixSafeBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonHelixXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonHelixTokens = data.split("||");
            if (crimsonHelixTokens.length < 2) {
                return;
            }
            String crimsonHelixUser = crimsonHelixTokens[0];
            String crimsonHelixPass = crimsonHelixTokens[1];
            XPath crimsonHelixXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonHelixXml = new InputSource(crimsonHelixXmlFile);
            String crimsonHelixQuery = "//users/user[name/text()='" + crimsonHelixUser
                    + "' and pass/text()='" + crimsonHelixPass + "']" + "/secret/text()";
            String crimsonHelixSecret = (String) crimsonHelixXPath.evaluate(crimsonHelixQuery, crimsonHelixXml, XPathConstants.STRING);
            System.out.println(crimsonHelixSecret);
        }
    }
}
