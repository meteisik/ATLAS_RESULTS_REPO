import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_OnyxNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runOnyxNebula() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ONYX_NEBULA_ADD");
        } else {
            data = null;
        }
        (new CWE643_P06_V2_OnyxNebulaSink()).sinkOnyxNebula(data);
    }
}

class CWE643_P06_V2_OnyxNebulaSink {

    public void sinkOnyxNebula(String data) throws XPathExpressionException {
        String onyxNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxNebulaTokens = data.split("||");
            if (onyxNebulaTokens.length < 2) {
                return;
            }
            String onyxNebulaUser = onyxNebulaTokens[0];
            String onyxNebulaPass = onyxNebulaTokens[1];
            XPath onyxNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxNebulaXml = new InputSource(onyxNebulaXmlFile);
            String onyxNebulaQuery = "//users/user[name/text()='" + onyxNebulaUser
                    + "' and pass/text()='" + onyxNebulaPass + "']" + "/secret/text()";
            String onyxNebulaSecret = (String) onyxNebulaXPath.evaluate(onyxNebulaQuery, onyxNebulaXml, XPathConstants.STRING);
            System.out.println(onyxNebulaSecret);
        }
    }
}
