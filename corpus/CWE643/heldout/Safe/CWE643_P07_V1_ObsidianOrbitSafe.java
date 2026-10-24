import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V1_ObsidianOrbitSafe {

    public void runObsidianOrbit() throws XPathExpressionException {
        String data;
        data = (new CWE643_P07_V1_ObsidianOrbitSafeSource()).sourceObsidianOrbit();
        String obsidianOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianOrbitTokens = data.split("||");
            if (obsidianOrbitTokens.length < 2) {
                return;
            }
            String obsidianOrbitUser = obsidianOrbitTokens[0];
            String obsidianOrbitPass = obsidianOrbitTokens[1];
            XPath obsidianOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianOrbitXml = new InputSource(obsidianOrbitXmlFile);
            String obsidianOrbitQuery = "//users/user[name/text()='" + obsidianOrbitUser
                    + "' and pass/text()='" + obsidianOrbitPass + "']" + "/secret/text()";
            String obsidianOrbitSecret = (String) obsidianOrbitXPath.evaluate(obsidianOrbitQuery, obsidianOrbitXml, XPathConstants.STRING);
            System.out.println(obsidianOrbitSecret);
        }
    }
}

class CWE643_P07_V1_ObsidianOrbitSafeSource {

    public String sourceObsidianOrbit() {
        String data;
        data = "foo";
        return data;
    }
}
