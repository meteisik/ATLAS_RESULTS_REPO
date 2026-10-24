import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V1_ObsidianHelix {

    public void runObsidianHelix() throws XPathExpressionException {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_ADD");
        (new CWE643_P06_V1_ObsidianHelixSink()).sinkObsidianHelix(data);
    }
}

class CWE643_P06_V1_ObsidianHelixSink {

    public void sinkObsidianHelix(String data) throws XPathExpressionException {
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
