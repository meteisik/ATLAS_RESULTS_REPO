import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_SilentRavenSafe {

    public static String data;

    public void runSilentRaven() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_SilentRavenSafeSink()).sinkSilentRaven();
    }
}

class CWE643_P10_V1_SilentRavenSafeSink {

    public void sinkSilentRaven() throws XPathExpressionException {
        String data = CWE643_P10_V1_SilentRavenSafe.data;
        String silentRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentRavenTokens = data.split("||");
            if (silentRavenTokens.length < 2) {
                return;
            }
            String silentRavenUser = silentRavenTokens[0];
            String silentRavenPass = silentRavenTokens[1];
            XPath silentRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource silentRavenXml = new InputSource(silentRavenXmlFile);
            String silentRavenQuery = "//users/user[name/text()='" + silentRavenUser
                    + "' and pass/text()='" + silentRavenPass + "']" + "/secret/text()";
            String silentRavenSecret = (String) silentRavenXPath.evaluate(silentRavenQuery, silentRavenXml, XPathConstants.STRING);
            System.out.println(silentRavenSecret);
        }
    }
}
