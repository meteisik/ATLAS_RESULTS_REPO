import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_ObsidianHarbor {
    private static boolean privateReturnsTrue() { return true; }

    private String obsidianHarborData;

    private void sinkObsidianHarbor() throws XPathExpressionException {
        String data = obsidianHarborData;
        String obsidianHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianHarborTokens = data.split("||");
            if (obsidianHarborTokens.length < 2) {
                return;
            }
            String obsidianHarborUser = obsidianHarborTokens[0];
            String obsidianHarborPass = obsidianHarborTokens[1];
            XPath obsidianHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianHarborXml = new InputSource(obsidianHarborXmlFile);
            String obsidianHarborQuery = "//users/user[name/text()='" + obsidianHarborUser
                    + "' and pass/text()='" + obsidianHarborPass + "']" + "/secret/text()";
            String obsidianHarborSecret = (String) obsidianHarborXPath.evaluate(obsidianHarborQuery, obsidianHarborXml, XPathConstants.STRING);
            System.out.println(obsidianHarborSecret);
        }
    }

    public void runObsidianHarbor() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_HARBOR_ADD");
        } else {
            data = null;
        }
        obsidianHarborData = data;
        sinkObsidianHarbor();
    }
}
