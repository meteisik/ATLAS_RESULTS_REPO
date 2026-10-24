import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonComet() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("CRIMSON_COMET_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_CrimsonCometBase baseObject = new CWE643_P12_V2_CrimsonCometSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonCometBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonCometSink extends CWE643_P12_V2_CrimsonCometBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonCometTokens = data.split("||");
            if (crimsonCometTokens.length < 2) {
                return;
            }
            String crimsonCometUser = crimsonCometTokens[0];
            String crimsonCometPass = crimsonCometTokens[1];
            XPath crimsonCometXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonCometXml = new InputSource(crimsonCometXmlFile);
            String crimsonCometQuery = "//users/user[name/text()='" + crimsonCometUser
                    + "' and pass/text()='" + crimsonCometPass + "']" + "/secret/text()";
            String crimsonCometSecret = (String) crimsonCometXPath.evaluate(crimsonCometQuery, crimsonCometXml, XPathConstants.STRING);
            System.out.println(crimsonCometSecret);
        }
    }
}
