import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_SilentOrbit {

    public static String data;

    public void runSilentOrbit() throws XPathExpressionException {
        data = System.getenv("SILENT_ORBIT_ADD");
        (new CWE643_P10_V1_SilentOrbitSink()).sinkSilentOrbit();
    }
}

class CWE643_P10_V1_SilentOrbitSink {

    public void sinkSilentOrbit() throws XPathExpressionException {
        String data = CWE643_P10_V1_SilentOrbit.data;
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
