import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_ZephyrGlintSafe {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void runZephyrGlint() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_ZephyrGlintSafeSink()).sinkZephyrGlint(dataContainer);
    }
}

class CWE643_P09_V2_ZephyrGlintSafeSink {

    public void sinkZephyrGlint(CWE643_P09_V2_ZephyrGlintSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String zephyrGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrGlintTokens = data.split("||");
            if (zephyrGlintTokens.length < 2) {
                return;
            }
            String zephyrGlintUser = zephyrGlintTokens[0];
            String zephyrGlintPass = zephyrGlintTokens[1];
            XPath zephyrGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrGlintXml = new InputSource(zephyrGlintXmlFile);
            String zephyrGlintQuery = "//users/user[name/text()='" + zephyrGlintUser
                    + "' and pass/text()='" + zephyrGlintPass + "']" + "/secret/text()";
            String zephyrGlintSecret = (String) zephyrGlintXPath.evaluate(zephyrGlintQuery, zephyrGlintXml, XPathConstants.STRING);
            System.out.println(zephyrGlintSecret);
        }
    }
}
