import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxLanternSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxLantern() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxLanternSafeSink()).sinkOnyxLantern(dataContainer);
    }
}

class CWE643_P09_V1_OnyxLanternSafeSink {

    public void sinkOnyxLantern(CWE643_P09_V1_OnyxLanternSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxLanternTokens = data.split("||");
            if (onyxLanternTokens.length < 2) {
                return;
            }
            String onyxLanternUser = onyxLanternTokens[0];
            String onyxLanternPass = onyxLanternTokens[1];
            XPath onyxLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxLanternXml = new InputSource(onyxLanternXmlFile);
            String onyxLanternQuery = "//users/user[name/text()='" + onyxLanternUser
                    + "' and pass/text()='" + onyxLanternPass + "']" + "/secret/text()";
            String onyxLanternSecret = (String) onyxLanternXPath.evaluate(onyxLanternQuery, onyxLanternXml, XPathConstants.STRING);
            System.out.println(onyxLanternSecret);
        }
    }
}
