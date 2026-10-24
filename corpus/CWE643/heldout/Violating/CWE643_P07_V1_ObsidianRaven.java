import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V1_ObsidianRaven {

    public void runObsidianRaven() throws XPathExpressionException {
        String data;
        data = (new CWE643_P07_V1_ObsidianRavenSource()).sourceObsidianRaven();
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

class CWE643_P07_V1_ObsidianRavenSource {

    public String sourceObsidianRaven() {
        String data;
        data = System.getenv("OBSIDIAN_RAVEN_ADD");
        return data;
    }
}
