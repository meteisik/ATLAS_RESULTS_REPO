import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SilentLotus {

    static class Container {
        public String containerOne;
    }

    public void runSilentLotus() throws XPathExpressionException {
        String data;
        data = System.getenv("SILENT_LOTUS_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SilentLotusSink()).sinkSilentLotus(dataContainer);
    }
}

class CWE643_P09_V1_SilentLotusSink {

    public void sinkSilentLotus(CWE643_P09_V1_SilentLotus.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String silentLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentLotusTokens = data.split("||");
            if (silentLotusTokens.length < 2) {
                return;
            }
            String silentLotusUser = silentLotusTokens[0];
            String silentLotusPass = silentLotusTokens[1];
            XPath silentLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource silentLotusXml = new InputSource(silentLotusXmlFile);
            String silentLotusQuery = "//users/user[name/text()='" + silentLotusUser
                    + "' and pass/text()='" + silentLotusPass + "']" + "/secret/text()";
            String silentLotusSecret = (String) silentLotusXPath.evaluate(silentLotusQuery, silentLotusXml, XPathConstants.STRING);
            System.out.println(silentLotusSecret);
        }
    }
}
