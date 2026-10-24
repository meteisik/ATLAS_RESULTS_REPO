import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SilentLanternSafe {

    static class Container {
        public String containerOne;
    }

    public void runSilentLantern() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SilentLanternSafeSink()).sinkSilentLantern(dataContainer);
    }
}

class CWE643_P09_V1_SilentLanternSafeSink {

    public void sinkSilentLantern(CWE643_P09_V1_SilentLanternSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String silentLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentLanternTokens = data.split("||");
            if (silentLanternTokens.length < 2) {
                return;
            }
            String silentLanternUser = silentLanternTokens[0];
            String silentLanternPass = silentLanternTokens[1];
            XPath silentLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource silentLanternXml = new InputSource(silentLanternXmlFile);
            String silentLanternQuery = "//users/user[name/text()='" + silentLanternUser
                    + "' and pass/text()='" + silentLanternPass + "']" + "/secret/text()";
            String silentLanternSecret = (String) silentLanternXPath.evaluate(silentLanternQuery, silentLanternXml, XPathConstants.STRING);
            System.out.println(silentLanternSecret);
        }
    }
}
