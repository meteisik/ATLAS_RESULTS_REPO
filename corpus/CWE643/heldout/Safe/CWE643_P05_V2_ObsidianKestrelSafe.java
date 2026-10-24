import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_ObsidianKestrelSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianKestrelData;

    private void sinkObsidianKestrel() throws XPathExpressionException {
        String data = obsidianKestrelData;
        String obsidianKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianKestrelTokens = data.split("||");
            if (obsidianKestrelTokens.length < 2) {
                return;
            }
            String obsidianKestrelUser = obsidianKestrelTokens[0];
            String obsidianKestrelPass = obsidianKestrelTokens[1];
            XPath obsidianKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianKestrelXml = new InputSource(obsidianKestrelXmlFile);
            String obsidianKestrelQuery = "//users/user[name/text()='" + obsidianKestrelUser
                    + "' and pass/text()='" + obsidianKestrelPass + "']" + "/secret/text()";
            String obsidianKestrelSecret = (String) obsidianKestrelXPath.evaluate(obsidianKestrelQuery, obsidianKestrelXml, XPathConstants.STRING);
            System.out.println(obsidianKestrelSecret);
        }
    }

    public void runObsidianKestrel() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        obsidianKestrelData = data;
        sinkObsidianKestrel();
    }
}
