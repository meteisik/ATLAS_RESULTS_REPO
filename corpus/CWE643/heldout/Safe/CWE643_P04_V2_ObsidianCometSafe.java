import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_ObsidianCometSafe {
    private static boolean privateTrue = true;

    private String sourceObsidianComet() {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianComet() throws XPathExpressionException {
        String data = sourceObsidianComet();
        String obsidianCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianCometTokens = data.split("||");
            if (obsidianCometTokens.length < 2) {
                return;
            }
            String obsidianCometUser = obsidianCometTokens[0];
            String obsidianCometPass = obsidianCometTokens[1];
            XPath obsidianCometXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianCometXml = new InputSource(obsidianCometXmlFile);
            String obsidianCometQuery = "//users/user[name/text()='" + obsidianCometUser
                    + "' and pass/text()='" + obsidianCometPass + "']" + "/secret/text()";
            String obsidianCometSecret = (String) obsidianCometXPath.evaluate(obsidianCometQuery, obsidianCometXml, XPathConstants.STRING);
            System.out.println(obsidianCometSecret);
        }
    }
}
