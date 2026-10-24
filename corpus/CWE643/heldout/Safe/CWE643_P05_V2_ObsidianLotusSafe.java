import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_ObsidianLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianLotusData;

    private void sinkObsidianLotus() throws XPathExpressionException {
        String data = obsidianLotusData;
        String obsidianLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianLotusTokens = data.split("||");
            if (obsidianLotusTokens.length < 2) {
                return;
            }
            String obsidianLotusUser = obsidianLotusTokens[0];
            String obsidianLotusPass = obsidianLotusTokens[1];
            XPath obsidianLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianLotusXml = new InputSource(obsidianLotusXmlFile);
            String obsidianLotusQuery = "//users/user[name/text()='" + obsidianLotusUser
                    + "' and pass/text()='" + obsidianLotusPass + "']" + "/secret/text()";
            String obsidianLotusSecret = (String) obsidianLotusXPath.evaluate(obsidianLotusQuery, obsidianLotusXml, XPathConstants.STRING);
            System.out.println(obsidianLotusSecret);
        }
    }

    public void runObsidianLotus() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        obsidianLotusData = data;
        sinkObsidianLotus();
    }
}
