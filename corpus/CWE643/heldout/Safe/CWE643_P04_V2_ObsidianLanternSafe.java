import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_ObsidianLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String sourceObsidianLantern() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianLantern() throws XPathExpressionException {
        String data = sourceObsidianLantern();
        String obsidianLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianLanternTokens = data.split("||");
            if (obsidianLanternTokens.length < 2) {
                return;
            }
            String obsidianLanternUser = obsidianLanternTokens[0];
            String obsidianLanternPass = obsidianLanternTokens[1];
            XPath obsidianLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianLanternXml = new InputSource(obsidianLanternXmlFile);
            String obsidianLanternQuery = "//users/user[name/text()='" + obsidianLanternUser
                    + "' and pass/text()='" + obsidianLanternPass + "']" + "/secret/text()";
            String obsidianLanternSecret = (String) obsidianLanternXPath.evaluate(obsidianLanternQuery, obsidianLanternXml, XPathConstants.STRING);
            System.out.println(obsidianLanternSecret);
        }
    }
}
