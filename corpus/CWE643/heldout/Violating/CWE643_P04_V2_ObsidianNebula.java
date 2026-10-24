import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_ObsidianNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String sourceObsidianNebula() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("OBSIDIAN_NEBULA_ADD");
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianNebula() throws XPathExpressionException {
        String data = sourceObsidianNebula();
        String obsidianNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianNebulaTokens = data.split("||");
            if (obsidianNebulaTokens.length < 2) {
                return;
            }
            String obsidianNebulaUser = obsidianNebulaTokens[0];
            String obsidianNebulaPass = obsidianNebulaTokens[1];
            XPath obsidianNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianNebulaXml = new InputSource(obsidianNebulaXmlFile);
            String obsidianNebulaQuery = "//users/user[name/text()='" + obsidianNebulaUser
                    + "' and pass/text()='" + obsidianNebulaPass + "']" + "/secret/text()";
            String obsidianNebulaSecret = (String) obsidianNebulaXPath.evaluate(obsidianNebulaQuery, obsidianNebulaXml, XPathConstants.STRING);
            System.out.println(obsidianNebulaSecret);
        }
    }
}
