import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SilentOrbit {

    static class Container {
        public String containerOne;
    }

    public void runSilentOrbit() throws XPathExpressionException {
        String data;
        data = System.getenv("SILENT_ORBIT_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SilentOrbitSink()).sinkSilentOrbit(dataContainer);
    }
}

class CWE643_P09_V1_SilentOrbitSink {

    public void sinkSilentOrbit(CWE643_P09_V1_SilentOrbit.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String silentOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentOrbitTokens = data.split("||");
            if (silentOrbitTokens.length < 2) {
                return;
            }
            String silentOrbitUser = silentOrbitTokens[0];
            String silentOrbitPass = silentOrbitTokens[1];
            XPath silentOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource silentOrbitXml = new InputSource(silentOrbitXmlFile);
            String silentOrbitQuery = "//users/user[name/text()='" + silentOrbitUser
                    + "' and pass/text()='" + silentOrbitPass + "']" + "/secret/text()";
            String silentOrbitSecret = (String) silentOrbitXPath.evaluate(silentOrbitQuery, silentOrbitXml, XPathConstants.STRING);
            System.out.println(silentOrbitSecret);
        }
    }
}
