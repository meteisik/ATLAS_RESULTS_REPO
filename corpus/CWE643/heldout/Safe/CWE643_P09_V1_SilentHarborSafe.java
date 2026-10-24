import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SilentHarborSafe {

    static class Container {
        public String containerOne;
    }

    public void runSilentHarbor() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SilentHarborSafeSink()).sinkSilentHarbor(dataContainer);
    }
}

class CWE643_P09_V1_SilentHarborSafeSink {

    public void sinkSilentHarbor(CWE643_P09_V1_SilentHarborSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String silentHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentHarborTokens = data.split("||");
            if (silentHarborTokens.length < 2) {
                return;
            }
            String silentHarborUser = silentHarborTokens[0];
            String silentHarborPass = silentHarborTokens[1];
            XPath silentHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource silentHarborXml = new InputSource(silentHarborXmlFile);
            String silentHarborQuery = "//users/user[name/text()='" + silentHarborUser
                    + "' and pass/text()='" + silentHarborPass + "']" + "/secret/text()";
            String silentHarborSecret = (String) silentHarborXPath.evaluate(silentHarborQuery, silentHarborXml, XPathConstants.STRING);
            System.out.println(silentHarborSecret);
        }
    }
}
