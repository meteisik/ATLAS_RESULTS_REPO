import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_RuneLotusSafe {

    static class Container {
        public String containerOne;
    }

    public void runRuneLotus() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_RuneLotusSafeSink()).sinkRuneLotus(dataContainer);
    }
}

class CWE643_P09_V1_RuneLotusSafeSink {

    public void sinkRuneLotus(CWE643_P09_V1_RuneLotusSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String runeLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeLotusTokens = data.split("||");
            if (runeLotusTokens.length < 2) {
                return;
            }
            String runeLotusUser = runeLotusTokens[0];
            String runeLotusPass = runeLotusTokens[1];
            XPath runeLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource runeLotusXml = new InputSource(runeLotusXmlFile);
            String runeLotusQuery = "//users/user[name/text()='" + runeLotusUser
                    + "' and pass/text()='" + runeLotusPass + "']" + "/secret/text()";
            String runeLotusSecret = (String) runeLotusXPath.evaluate(runeLotusQuery, runeLotusXml, XPathConstants.STRING);
            System.out.println(runeLotusSecret);
        }
    }
}
