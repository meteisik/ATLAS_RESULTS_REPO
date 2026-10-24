import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_VividSignalSafe {

    static class Container {
        public String containerOne;
    }

    public void runVividSignal() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_VividSignalSafeSink()).sinkVividSignal(dataContainer);
    }
}

class CWE643_P09_V2_VividSignalSafeSink {

    public void sinkVividSignal(CWE643_P09_V2_VividSignalSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String vividSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividSignalTokens = data.split("||");
            if (vividSignalTokens.length < 2) {
                return;
            }
            String vividSignalUser = vividSignalTokens[0];
            String vividSignalPass = vividSignalTokens[1];
            XPath vividSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource vividSignalXml = new InputSource(vividSignalXmlFile);
            String vividSignalQuery = "//users/user[name/text()='" + vividSignalUser
                    + "' and pass/text()='" + vividSignalPass + "']" + "/secret/text()";
            String vividSignalSecret = (String) vividSignalXPath.evaluate(vividSignalQuery, vividSignalXml, XPathConstants.STRING);
            System.out.println(vividSignalSecret);
        }
    }
}
