import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxHelixSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxHelix() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxHelixSafeSink()).sinkOnyxHelix(dataContainer);
    }
}

class CWE643_P09_V1_OnyxHelixSafeSink {

    public void sinkOnyxHelix(CWE643_P09_V1_OnyxHelixSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxHelixXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxHelixTokens = data.split("||");
            if (onyxHelixTokens.length < 2) {
                return;
            }
            String onyxHelixUser = onyxHelixTokens[0];
            String onyxHelixPass = onyxHelixTokens[1];
            XPath onyxHelixXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxHelixXml = new InputSource(onyxHelixXmlFile);
            String onyxHelixQuery = "//users/user[name/text()='" + onyxHelixUser
                    + "' and pass/text()='" + onyxHelixPass + "']" + "/secret/text()";
            String onyxHelixSecret = (String) onyxHelixXPath.evaluate(onyxHelixQuery, onyxHelixXml, XPathConstants.STRING);
            System.out.println(onyxHelixSecret);
        }
    }
}
