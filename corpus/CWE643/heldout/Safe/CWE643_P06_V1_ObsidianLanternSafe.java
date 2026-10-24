import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V1_ObsidianLanternSafe {

    public void runObsidianLantern() throws XPathExpressionException {
        String data;
        data = "foo";
        (new CWE643_P06_V1_ObsidianLanternSafeSink()).sinkObsidianLantern(data);
    }
}

class CWE643_P06_V1_ObsidianLanternSafeSink {

    public void sinkObsidianLantern(String data) throws XPathExpressionException {
        String obsidianLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianLanternTokens = data.split("||");
            if (obsidianLanternTokens.length < 2) {
                return;
            }
            String obsidianLanternUser = obsidianLanternTokens[0];
            String obsidianLanternPass = obsidianLanternTokens[1];
            XPath obsidianLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianLanternXml = new InputSource(obsidianLanternXmlFile);
            String obsidianLanternQuery = "//users/user[name/text()='" + obsidianLanternUser
                    + "' and pass/text()='" + obsidianLanternPass + "']" + "/secret/text()";
            String obsidianLanternSecret = (String) obsidianLanternXPath.evaluate(obsidianLanternQuery, obsidianLanternXml, XPathConstants.STRING);
            System.out.println(obsidianLanternSecret);
        }
    }
}
