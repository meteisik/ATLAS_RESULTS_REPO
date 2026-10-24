import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxRaven {

    static class Container {
        public String containerOne;
    }

    public void runOnyxRaven() throws XPathExpressionException {
        String data;
        data = System.getenv("ONYX_RAVEN_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxRavenSink()).sinkOnyxRaven(dataContainer);
    }
}

class CWE643_P09_V1_OnyxRavenSink {

    public void sinkOnyxRaven(CWE643_P09_V1_OnyxRaven.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxRavenTokens = data.split("||");
            if (onyxRavenTokens.length < 2) {
                return;
            }
            String onyxRavenUser = onyxRavenTokens[0];
            String onyxRavenPass = onyxRavenTokens[1];
            XPath onyxRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxRavenXml = new InputSource(onyxRavenXmlFile);
            String onyxRavenQuery = "//users/user[name/text()='" + onyxRavenUser
                    + "' and pass/text()='" + onyxRavenPass + "']" + "/secret/text()";
            String onyxRavenSecret = (String) onyxRavenXPath.evaluate(onyxRavenQuery, onyxRavenXml, XPathConstants.STRING);
            System.out.println(onyxRavenSecret);
        }
    }
}
