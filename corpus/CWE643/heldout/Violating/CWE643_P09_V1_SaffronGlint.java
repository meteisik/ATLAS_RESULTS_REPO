import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SaffronGlint {

    static class Container {
        public String containerOne;
    }

    public void runSaffronGlint() throws XPathExpressionException {
        String data;
        data = System.getenv("SAFFRON_GLINT_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SaffronGlintSink()).sinkSaffronGlint(dataContainer);
    }
}

class CWE643_P09_V1_SaffronGlintSink {

    public void sinkSaffronGlint(CWE643_P09_V1_SaffronGlint.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String saffronGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronGlintTokens = data.split("||");
            if (saffronGlintTokens.length < 2) {
                return;
            }
            String saffronGlintUser = saffronGlintTokens[0];
            String saffronGlintPass = saffronGlintTokens[1];
            XPath saffronGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronGlintXml = new InputSource(saffronGlintXmlFile);
            String saffronGlintQuery = "//users/user[name/text()='" + saffronGlintUser
                    + "' and pass/text()='" + saffronGlintPass + "']" + "/secret/text()";
            String saffronGlintSecret = (String) saffronGlintXPath.evaluate(saffronGlintQuery, saffronGlintXml, XPathConstants.STRING);
            System.out.println(saffronGlintSecret);
        }
    }
}
