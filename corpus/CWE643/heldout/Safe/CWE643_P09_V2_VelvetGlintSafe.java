import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_VelvetGlintSafe {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void runVelvetGlint() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_VelvetGlintSafeSink()).sinkVelvetGlint(dataContainer);
    }
}

class CWE643_P09_V2_VelvetGlintSafeSink {

    public void sinkVelvetGlint(CWE643_P09_V2_VelvetGlintSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String velvetGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetGlintTokens = data.split("||");
            if (velvetGlintTokens.length < 2) {
                return;
            }
            String velvetGlintUser = velvetGlintTokens[0];
            String velvetGlintPass = velvetGlintTokens[1];
            XPath velvetGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetGlintXml = new InputSource(velvetGlintXmlFile);
            String velvetGlintQuery = "//users/user[name/text()='" + velvetGlintUser
                    + "' and pass/text()='" + velvetGlintPass + "']" + "/secret/text()";
            String velvetGlintSecret = (String) velvetGlintXPath.evaluate(velvetGlintQuery, velvetGlintXml, XPathConstants.STRING);
            System.out.println(velvetGlintSecret);
        }
    }
}
