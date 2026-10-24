import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonKestrel() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_KESTREL_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_CrimsonKestrelBase baseObject = new CWE643_P12_V2_CrimsonKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonKestrelBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonKestrelSink extends CWE643_P12_V2_CrimsonKestrelBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonKestrelTokens = data.split("||");
            if (crimsonKestrelTokens.length < 2) {
                return;
            }
            String crimsonKestrelUser = crimsonKestrelTokens[0];
            String crimsonKestrelPass = crimsonKestrelTokens[1];
            XPath crimsonKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonKestrelXml = new InputSource(crimsonKestrelXmlFile);
            String crimsonKestrelQuery = "//users/user[name/text()='" + crimsonKestrelUser
                    + "' and pass/text()='" + crimsonKestrelPass + "']" + "/secret/text()";
            String crimsonKestrelSecret = (String) crimsonKestrelXPath.evaluate(crimsonKestrelQuery, crimsonKestrelXml, XPathConstants.STRING);
            System.out.println(crimsonKestrelSecret);
        }
    }
}
