import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_ObsidianKestrel {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void sinkObsidianKestrel(String data) throws XPathExpressionException {
        String obsidianKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianKestrelTokens = data.split("||");
            if (obsidianKestrelTokens.length < 2) {
                return;
            }
            String obsidianKestrelUser = obsidianKestrelTokens[0];
            String obsidianKestrelPass = obsidianKestrelTokens[1];
            XPath obsidianKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianKestrelXml = new InputSource(obsidianKestrelXmlFile);
            String obsidianKestrelQuery = "//users/user[name/text()='" + obsidianKestrelUser
                    + "' and pass/text()='" + obsidianKestrelPass + "']" + "/secret/text()";
            String obsidianKestrelSecret = (String) obsidianKestrelXPath.evaluate(obsidianKestrelQuery, obsidianKestrelXml, XPathConstants.STRING);
            System.out.println(obsidianKestrelSecret);
        }
    }

    public void runObsidianKestrel() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_KESTREL_ADD");
        } else {
            data = null;
        }
        sinkObsidianKestrel(data);
    }
}
