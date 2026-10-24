import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_LunarComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void sinkLunarComet(String data) throws XPathExpressionException {
        String lunarCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            lunarCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            lunarCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] lunarCometTokens = data.split("||");
            if (lunarCometTokens.length < 2) {
                return;
            }
            String lunarCometUser = lunarCometTokens[0];
            String lunarCometPass = lunarCometTokens[1];
            XPath lunarCometXPath = XPathFactory.newInstance().newXPath();
            InputSource lunarCometXml = new InputSource(lunarCometXmlFile);
            String lunarCometQuery = "//users/user[name/text()='" + lunarCometUser
                    + "' and pass/text()='" + lunarCometPass + "']" + "/secret/text()";
            String lunarCometSecret = (String) lunarCometXPath.evaluate(lunarCometQuery, lunarCometXml, XPathConstants.STRING);
            System.out.println(lunarCometSecret);
        }
    }

    public void runLunarComet() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("LUNAR_COMET_ADD");
        } else {
            data = null;
        }
        sinkLunarComet(data);
    }
}
