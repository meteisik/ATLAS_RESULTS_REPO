import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_RuneLantern {

    static class Container {
        public String containerOne;
    }

    public void runRuneLantern() throws XPathExpressionException {
        String data;
        data = System.getenv("RUNE_LANTERN_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_RuneLanternSink()).sinkRuneLantern(dataContainer);
    }
}

class CWE643_P09_V1_RuneLanternSink {

    public void sinkRuneLantern(CWE643_P09_V1_RuneLantern.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String runeLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeLanternTokens = data.split("||");
            if (runeLanternTokens.length < 2) {
                return;
            }
            String runeLanternUser = runeLanternTokens[0];
            String runeLanternPass = runeLanternTokens[1];
            XPath runeLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource runeLanternXml = new InputSource(runeLanternXmlFile);
            String runeLanternQuery = "//users/user[name/text()='" + runeLanternUser
                    + "' and pass/text()='" + runeLanternPass + "']" + "/secret/text()";
            String runeLanternSecret = (String) runeLanternXPath.evaluate(runeLanternQuery, runeLanternXml, XPathConstants.STRING);
            System.out.println(runeLanternSecret);
        }
    }
}
