import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonHarborSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonHarbor() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_CrimsonHarborSafeBase baseObject = new CWE643_P12_V2_CrimsonHarborSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonHarborSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonHarborSafeSink extends CWE643_P12_V2_CrimsonHarborSafeBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonHarborTokens = data.split("||");
            if (crimsonHarborTokens.length < 2) {
                return;
            }
            String crimsonHarborUser = crimsonHarborTokens[0];
            String crimsonHarborPass = crimsonHarborTokens[1];
            XPath crimsonHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonHarborXml = new InputSource(crimsonHarborXmlFile);
            String crimsonHarborQuery = "//users/user[name/text()='" + crimsonHarborUser
                    + "' and pass/text()='" + crimsonHarborPass + "']" + "/secret/text()";
            String crimsonHarborSecret = (String) crimsonHarborXPath.evaluate(crimsonHarborQuery, crimsonHarborXml, XPathConstants.STRING);
            System.out.println(crimsonHarborSecret);
        }
    }
}
