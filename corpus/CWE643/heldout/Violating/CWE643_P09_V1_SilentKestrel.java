import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SilentKestrel {

    static class Container {
        public String containerOne;
    }

    public void runSilentKestrel() throws XPathExpressionException {
        String data;
        data = System.getenv("SILENT_KESTREL_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SilentKestrelSink()).sinkSilentKestrel(dataContainer);
    }
}

class CWE643_P09_V1_SilentKestrelSink {

    public void sinkSilentKestrel(CWE643_P09_V1_SilentKestrel.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String silentKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentKestrelTokens = data.split("||");
            if (silentKestrelTokens.length < 2) {
                return;
            }
            String silentKestrelUser = silentKestrelTokens[0];
            String silentKestrelPass = silentKestrelTokens[1];
            XPath silentKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource silentKestrelXml = new InputSource(silentKestrelXmlFile);
            String silentKestrelQuery = "//users/user[name/text()='" + silentKestrelUser
                    + "' and pass/text()='" + silentKestrelPass + "']" + "/secret/text()";
            String silentKestrelSecret = (String) silentKestrelXPath.evaluate(silentKestrelQuery, silentKestrelXml, XPathConstants.STRING);
            System.out.println(silentKestrelSecret);
        }
    }
}
