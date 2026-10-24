import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_VividGlintSafe {

    static class Container {
        public String containerOne;
    }

    public void runVividGlint() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_VividGlintSafeSink()).sinkVividGlint(dataContainer);
    }
}

class CWE643_P09_V2_VividGlintSafeSink {

    public void sinkVividGlint(CWE643_P09_V2_VividGlintSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String vividGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividGlintTokens = data.split("||");
            if (vividGlintTokens.length < 2) {
                return;
            }
            String vividGlintUser = vividGlintTokens[0];
            String vividGlintPass = vividGlintTokens[1];
            XPath vividGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource vividGlintXml = new InputSource(vividGlintXmlFile);
            String vividGlintQuery = "//users/user[name/text()='" + vividGlintUser
                    + "' and pass/text()='" + vividGlintPass + "']" + "/secret/text()";
            String vividGlintSecret = (String) vividGlintXPath.evaluate(vividGlintQuery, vividGlintXml, XPathConstants.STRING);
            System.out.println(vividGlintSecret);
        }
    }
}
