import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxHarbor {

    static class Container {
        public String containerOne;
    }

    public void runOnyxHarbor() throws XPathExpressionException {
        String data;
        data = System.getenv("ONYX_HARBOR_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxHarborSink()).sinkOnyxHarbor(dataContainer);
    }
}

class CWE643_P09_V1_OnyxHarborSink {

    public void sinkOnyxHarbor(CWE643_P09_V1_OnyxHarbor.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxHarborTokens = data.split("||");
            if (onyxHarborTokens.length < 2) {
                return;
            }
            String onyxHarborUser = onyxHarborTokens[0];
            String onyxHarborPass = onyxHarborTokens[1];
            XPath onyxHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxHarborXml = new InputSource(onyxHarborXmlFile);
            String onyxHarborQuery = "//users/user[name/text()='" + onyxHarborUser
                    + "' and pass/text()='" + onyxHarborPass + "']" + "/secret/text()";
            String onyxHarborSecret = (String) onyxHarborXPath.evaluate(onyxHarborQuery, onyxHarborXml, XPathConstants.STRING);
            System.out.println(onyxHarborSecret);
        }
    }
}
