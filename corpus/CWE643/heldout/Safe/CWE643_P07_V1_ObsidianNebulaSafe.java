import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V1_ObsidianNebulaSafe {

    public void runObsidianNebula() throws XPathExpressionException {
        String data;
        data = (new CWE643_P07_V1_ObsidianNebulaSafeSource()).sourceObsidianNebula();
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

class CWE643_P07_V1_ObsidianNebulaSafeSource {

    public String sourceObsidianNebula() {
        String data;
        data = "foo";
        return data;
    }
}
