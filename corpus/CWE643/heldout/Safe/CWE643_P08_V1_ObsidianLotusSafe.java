import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_ObsidianLotusSafe {

    public void runObsidianLotus() throws XPathExpressionException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_ObsidianLotusSafeSink()).sinkObsidianLotus(dataArray);
    }
}

class CWE643_P08_V1_ObsidianLotusSafeSink {

    public void sinkObsidianLotus(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String obsidianLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianLotusTokens = data.split("||");
            if (obsidianLotusTokens.length < 2) {
                return;
            }
            String obsidianLotusUser = obsidianLotusTokens[0];
            String obsidianLotusPass = obsidianLotusTokens[1];
            XPath obsidianLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianLotusXml = new InputSource(obsidianLotusXmlFile);
            String obsidianLotusQuery = "//users/user[name/text()='" + obsidianLotusUser
                    + "' and pass/text()='" + obsidianLotusPass + "']" + "/secret/text()";
            String obsidianLotusSecret = (String) obsidianLotusXPath.evaluate(obsidianLotusQuery, obsidianLotusXml, XPathConstants.STRING);
            System.out.println(obsidianLotusSecret);
        }
    }
}
