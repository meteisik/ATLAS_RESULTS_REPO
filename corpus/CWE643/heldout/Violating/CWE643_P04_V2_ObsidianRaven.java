import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_ObsidianRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String sourceObsidianRaven() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("OBSIDIAN_RAVEN_ADD");
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianRaven() throws XPathExpressionException {
        String data = sourceObsidianRaven();
        String obsidianRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianRavenTokens = data.split("||");
            if (obsidianRavenTokens.length < 2) {
                return;
            }
            String obsidianRavenUser = obsidianRavenTokens[0];
            String obsidianRavenPass = obsidianRavenTokens[1];
            XPath obsidianRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianRavenXml = new InputSource(obsidianRavenXmlFile);
            String obsidianRavenQuery = "//users/user[name/text()='" + obsidianRavenUser
                    + "' and pass/text()='" + obsidianRavenPass + "']" + "/secret/text()";
            String obsidianRavenSecret = (String) obsidianRavenXPath.evaluate(obsidianRavenQuery, obsidianRavenXml, XPathConstants.STRING);
            System.out.println(obsidianRavenSecret);
        }
    }
}
