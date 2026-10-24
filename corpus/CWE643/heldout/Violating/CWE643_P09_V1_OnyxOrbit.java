import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxOrbit {

    static class Container {
        public String containerOne;
    }

    public void runOnyxOrbit() throws XPathExpressionException {
        String data;
        data = System.getenv("ONYX_ORBIT_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxOrbitSink()).sinkOnyxOrbit(dataContainer);
    }
}

class CWE643_P09_V1_OnyxOrbitSink {

    public void sinkOnyxOrbit(CWE643_P09_V1_OnyxOrbit.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxOrbitTokens = data.split("||");
            if (onyxOrbitTokens.length < 2) {
                return;
            }
            String onyxOrbitUser = onyxOrbitTokens[0];
            String onyxOrbitPass = onyxOrbitTokens[1];
            XPath onyxOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxOrbitXml = new InputSource(onyxOrbitXmlFile);
            String onyxOrbitQuery = "//users/user[name/text()='" + onyxOrbitUser
                    + "' and pass/text()='" + onyxOrbitPass + "']" + "/secret/text()";
            String onyxOrbitSecret = (String) onyxOrbitXPath.evaluate(onyxOrbitQuery, onyxOrbitXml, XPathConstants.STRING);
            System.out.println(onyxOrbitSecret);
        }
    }
}
