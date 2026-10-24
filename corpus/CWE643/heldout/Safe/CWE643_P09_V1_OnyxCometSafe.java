import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxCometSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxComet() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxCometSafeSink()).sinkOnyxComet(dataContainer);
    }
}

class CWE643_P09_V1_OnyxCometSafeSink {

    public void sinkOnyxComet(CWE643_P09_V1_OnyxCometSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxCometTokens = data.split("||");
            if (onyxCometTokens.length < 2) {
                return;
            }
            String onyxCometUser = onyxCometTokens[0];
            String onyxCometPass = onyxCometTokens[1];
            XPath onyxCometXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxCometXml = new InputSource(onyxCometXmlFile);
            String onyxCometQuery = "//users/user[name/text()='" + onyxCometUser
                    + "' and pass/text()='" + onyxCometPass + "']" + "/secret/text()";
            String onyxCometSecret = (String) onyxCometXPath.evaluate(onyxCometQuery, onyxCometXml, XPathConstants.STRING);
            System.out.println(onyxCometSecret);
        }
    }
}
