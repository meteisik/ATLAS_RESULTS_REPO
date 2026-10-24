import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_LunarHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runLunarHelix() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (IO.staticReturnsTrue()) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String lunarHelixXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                lunarHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                lunarHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] lunarHelixTokens = data.split("||");
                if (lunarHelixTokens.length < 2) {
                    return;
                }
                String lunarHelixUser = lunarHelixTokens[0];
                String lunarHelixPass = lunarHelixTokens[1];
                XPath lunarHelixXPath = XPathFactory.newInstance().newXPath();
                InputSource lunarHelixXml = new InputSource(lunarHelixXmlFile);
                String lunarHelixQuery = "//users/user[name/text()='" + lunarHelixUser
                        + "' and pass/text()='" + lunarHelixPass + "']" + "/secret/text()";
                String lunarHelixSecret = (String) lunarHelixXPath.evaluate(lunarHelixQuery, lunarHelixXml, XPathConstants.STRING);
                System.out.println(lunarHelixSecret);
            }
        }
    }
}
