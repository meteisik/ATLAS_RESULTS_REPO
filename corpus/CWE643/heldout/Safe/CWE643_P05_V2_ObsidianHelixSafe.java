import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_ObsidianHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianHelixData;

    private void sinkObsidianHelix() throws XPathExpressionException {
        String data = obsidianHelixData;
        String obsidianHelixXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianHelixTokens = data.split("||");
            if (obsidianHelixTokens.length < 2) {
                return;
            }
            String obsidianHelixUser = obsidianHelixTokens[0];
            String obsidianHelixPass = obsidianHelixTokens[1];
            XPath obsidianHelixXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianHelixXml = new InputSource(obsidianHelixXmlFile);
            String obsidianHelixQuery = "//users/user[name/text()='" + obsidianHelixUser
                    + "' and pass/text()='" + obsidianHelixPass + "']" + "/secret/text()";
            String obsidianHelixSecret = (String) obsidianHelixXPath.evaluate(obsidianHelixQuery, obsidianHelixXml, XPathConstants.STRING);
            System.out.println(obsidianHelixSecret);
        }
    }

    public void runObsidianHelix() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        obsidianHelixData = data;
        sinkObsidianHelix();
    }
}
