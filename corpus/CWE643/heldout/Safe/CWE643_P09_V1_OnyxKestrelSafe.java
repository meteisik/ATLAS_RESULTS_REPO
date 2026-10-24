import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxKestrelSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxKestrel() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxKestrelSafeSink()).sinkOnyxKestrel(dataContainer);
    }
}

class CWE643_P09_V1_OnyxKestrelSafeSink {

    public void sinkOnyxKestrel(CWE643_P09_V1_OnyxKestrelSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxKestrelTokens = data.split("||");
            if (onyxKestrelTokens.length < 2) {
                return;
            }
            String onyxKestrelUser = onyxKestrelTokens[0];
            String onyxKestrelPass = onyxKestrelTokens[1];
            XPath onyxKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxKestrelXml = new InputSource(onyxKestrelXmlFile);
            String onyxKestrelQuery = "//users/user[name/text()='" + onyxKestrelUser
                    + "' and pass/text()='" + onyxKestrelPass + "']" + "/secret/text()";
            String onyxKestrelSecret = (String) onyxKestrelXPath.evaluate(onyxKestrelQuery, onyxKestrelXml, XPathConstants.STRING);
            System.out.println(onyxKestrelSecret);
        }
    }
}
