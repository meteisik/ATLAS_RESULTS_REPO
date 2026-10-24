import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V1_ObsidianHelixSafe {

    public void runObsidianHelix() throws XPathExpressionException {
        String data;
        data = (new CWE643_P07_V1_ObsidianHelixSafeSource()).sourceObsidianHelix();
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
}

class CWE643_P07_V1_ObsidianHelixSafeSource {

    public String sourceObsidianHelix() {
        String data;
        data = "foo";
        return data;
    }
}
